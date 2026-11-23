#!/usr/bin/env python3
"""Exercise native Form rendering and posts with a pinned pfSense classes directory."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
import json
import re
from pathlib import Path
from queue import Queue
import shutil
import subprocess
import tempfile
from threading import Thread
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "files/usr/local"


class Choices(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.fields, self.field = {}, None
        self.tokens = []
        self.revisions = []
        self.links = []
        self.posts = 0
        self.gets = 0
        self.forms = []
        self.form = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.form = (attrs, {})
            self.forms.append(self.form)
        if tag == "input" and self.form is not None and "name" in attrs and "value" in attrs:
            self.form[1][attrs["name"]] = attrs["value"]
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "select":
            self.field = attrs["name"]
            self.fields[self.field] = []
        if tag == "form" and attrs.get("method") == "post":
            self.posts += 1
        if tag == "form" and attrs.get("method") == "get":
            self.gets += 1
        if tag == "input" and attrs.get("name") == "__csrf_magic":
            self.tokens.append(attrs["value"])
        if tag == "input" and attrs.get("name") == "revision":
            self.revisions.append(attrs["value"])
        if self.field and tag == "option":
            self.fields[self.field].append((attrs["value"], "selected" in attrs))

    def handle_endtag(self, tag):
        if tag == "select":
            self.field = None
        if tag == "form":
            self.form = None


def screenshots(directory, www, pages):
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        raise RuntimeError("A Chromium browser is required to capture the WebGUI.")
    directory.mkdir(parents=True, exist_ok=True)
    requests = Queue()
    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8")
            requests.put((self.path, parse_qs(body)))
            self.send_response(409 if self.path == "/status_services.php" else 200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<title>Native system log fixture</title>")
    with tempfile.TemporaryDirectory() as folder:
        site = Path(folder)
        for assets in ("css", "csrf", "js", "vendor/bootstrap", "vendor/font-awesome", "vendor/jquery", "vendor/jquery-ui"):
            source = www / assets
            if not source.is_dir():
                raise RuntimeError(f"Missing upstream pfSense assets: {source}")
            target = site / assets
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(source, target_is_directory=True)
        with ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=folder)) as server:
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                for name, theme, size in [("status", "pfSense", "1440,900"), ("status", "pfSense-dark", "390,844"),
                                          ("diagnostics", "pfSense", "1440,900"), ("diagnostics", "pfSense-dark", "390,844"),
                                          ("members", "pfSense", "1440,900"),
                                          ("members-edit", "pfSense-dark", "1440,900"), ("updates", "pfSense", "1440,900"),
                                          ("updates", "pfSense-dark", "390,844"), ("forwarding", "pfSense", "1440,900"),
                                          ("forwarding", "pfSense-dark", "390,844")]:
                    preview = name + "-" + theme
                    styles = ('<link rel="stylesheet" href="/vendor/font-awesome/css/all.min.css">'
                              f'<link rel="stylesheet" href="/css/{theme}.css">')
                    html = pages[name].replace("</head>", styles + "</head>")
                    (site / (preview + ".html")).write_text(html)
                    out = directory / (preview + ".png")
                    subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                    f"--user-data-dir={folder}/chrome", f"--window-size={size}",
                                    f"--screenshot={out.resolve()}", f"http://127.0.0.1:{server.server_port}/{preview}.html"],
                                   capture_output=True, check=True, timeout=35)
                    assert out.read_bytes().startswith(b"\x89PNG"), out
                # pfSense.js focuses the first visible input before running the page callbacks.
                native_scripts = ("/vendor/jquery/jquery-3.7.1.min.js", "/vendor/jquery-ui/jquery-ui-1.13.2.min.js",
                                  "/vendor/bootstrap/js/bootstrap.min.js", "/js/pfSense.js")
                focus_probe = """
                    <script>
                    const logs = document.querySelector('button[form="sdwan-system-logs"]');
                    let automaticFocus = 0;
                    logs.addEventListener('focus', function () { automaticFocus++; });
                    events.push(function () {
                        const filter = document.querySelector('select[name="policy"]');
                        const correctInitialFocus = filter ? document.activeElement === filter && automaticFocus === 0 :
                            document.activeElement !== logs && automaticFocus === 1;
                        const noOutline = getComputedStyle(logs).outlineStyle === 'none';
                        logs.focus({preventScroll: true});
                        const focusStillWorks = document.activeElement === logs && logs.tabIndex === 0 &&
                            getComputedStyle(logs).outlineStyle !== 'none';
                        document.body.dataset.sdwanFocus = correctInitialFocus && noOutline && focusStillWorks ? 'pass' : 'fail';
                    });
                    </script>
                """
                for name, theme in (("status", "pfSense"), ("status", "pfSense-dark"), ("diagnostics", "pfSense")):
                    focus_page = pages[name].replace("</head>", f'<link rel="stylesheet" href="/css/{theme}.css"></head>')
                    footer = focus_probe + "".join(f'<script src="{url}"></script>' for url in native_scripts)
                    focus_page = focus_page.replace("</body>", footer + "</body>")
                    filename = f"{name}-{theme}-focus.html"
                    (site / filename).write_text(focus_page)
                    output = subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                             f"--user-data-dir={folder}/chrome", "--virtual-time-budget=1000", "--dump-dom",
                                             f"http://127.0.0.1:{server.server_port}/{filename}"],
                                            capture_output=True, text=True, check=True, timeout=35)
                    assert 'data-sdwan-focus="pass"' in output.stdout, (name, theme, output.stdout.split("<body")[1][:140])
                print("ok - native startup clears the System Logs outline, preserves the policy field and keeps the button focusable")

                sample_test = """
                    <script>
                    async function testInterfaceTraffic() {
                        const sample = (revision, at_ns, inbytes) => ({revision, interfaces: {
                            igb0: {at_ns, inbytes, outbytes: '0'}
                        }});
                        const before = sample('revision', '1000000000', '9007199254740993');
                        const samples = [before, sample('revision', '3000000000', '9007199254990993'),
                            before, sample('revision', '3000000000', '3'),
                            before, sample('changed', '3000000000', '9007199254990993')];
                        window.fetch = async () => ({ok: true, json: async () => samples.shift()});
                        document.documentElement.lang = 'pt_BR';
                        events.forEach(callback => callback());
                        const button = document.getElementById('sdwan-traffic-measure');
                        const results = document.getElementById('sdwan-traffic-results');
                        const measure = () => new Promise(resolve => {
                            const watcher = new MutationObserver(() => {
                                if (!button.disabled) { watcher.disconnect(); resolve(); }
                            });
                            watcher.observe(button, {attributes: true, attributeFilter: ['disabled']});
                            button.click();
                        });
                        await measure();
                        const correct = !results.hidden && [...results.querySelectorAll('tbody td')]
                            .map(cell => cell.textContent).join(',') === '1 Mbit/s,0 bit/s';
                        await measure();
                        const rejectsReset = results.hidden;
                        await measure();
                        document.body.dataset.sdwanTraffic = correct && rejectsReset && results.hidden &&
                            samples.length === 0 ? 'pass' : 'fail';
                    }
                    testInterfaceTraffic();
                    </script>
                """
                path = site / "diagnostics-traffic.html"
                path.write_text(pages["diagnostics"].replace("</body>", sample_test + "</body>"), encoding="utf-8")
                output = subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                         f"--user-data-dir={folder}/chrome", "--virtual-time-budget=6000", "--dump-dom",
                                         f"http://127.0.0.1:{server.server_port}/{path.name}"],
                                        capture_output=True, text=True, check=True, timeout=35)
                assert 'data-sdwan-traffic="pass"' in output.stdout
                print("ok - the browser calculates live interface rates and rejects resets and changed policies")

                page = pages["status"].replace("</body>",
                    '<script>document.querySelector(\'button[form="sdwan-system-logs"]\').click();</script></body>')
                (site / "system-logs-click.html").write_text(page)
                subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                f"--user-data-dir={folder}/chrome", "--dump-dom",
                                f"http://127.0.0.1:{server.server_port}/system-logs-click.html"],
                               capture_output=True, check=True, timeout=35)
                path, fields = requests.get(timeout=5)
                assert path == "/status_logs.php" and fields.get("logfile") == ["system"], (path, fields)
                assert fields.get("filterlogentries_process") == ["sdwan"] and fields.get("filterlogentries_submit") == ["1"]
                assert fields.get("__csrf_magic")
                print("ok - the browser submits a native System Logs POST with its filter and CSRF token")
                (site / "sdwan").mkdir()
                for mode, page_name in (("startservice", "status-stopped"), ("stopservice", "status"), ("restartservice", "status")):
                    page = pages[page_name]
                    token = Choices(page).tokens[0]
                    scripts = (*native_scripts, "/js/pfSenseHelpers.js")
                    footer = "".join(f'<script src="{url}"></script>' for url in scripts)
                    footer += f'<script>events.push(function () {{ document.getElementById("{mode}-sdwan").click(); }});</script>'
                    filename = f"sdwan/{mode}.html"
                    (site / filename).write_text(page.replace("</body>", footer + "</body>"))
                    subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                    f"--user-data-dir={folder}/chrome", "--virtual-time-budget=1000", "--dump-dom",
                                    f"http://127.0.0.1:{server.server_port}/{filename}"],
                                   capture_output=True, check=True, timeout=35)
                    path, fields = requests.get(timeout=5)
                    assert path == "/status_services.php" and fields.get("ajax") == ["ajax"], (path, fields)
                    assert fields.get("mode") == [mode] and fields.get("service") == ["sdwan"], fields
                    assert fields.get("__csrf_magic") == [token], fields
                print("ok - native start, stop and restart buttons submit CSRF-protected requests to Status Services")
                page = pages["updates"].replace("</head>", "<script>var events = [];</script></head>").replace(
                    "</body>", '<script>events.forEach(function (init) { init(); });'
                    'document.getElementById("upgrade_release").click();</script></body>')
                (site / "upgrade-click.html").write_text(page)
                subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                f"--user-data-dir={folder}/chrome", "--dump-dom",
                                f"http://127.0.0.1:{server.server_port}/upgrade-click.html"],
                               capture_output=True, check=True, timeout=35)
                path, fields = requests.get(timeout=5)
                assert path == "/sdwan/updates.php" and fields.get("target_version") == ["0.4.8"], (path, fields)
                assert fields.get("target_sha256") and "__csrf_magic" in fields and "upgrade_release" in fields
                print("ok - the browser submits the selected release and CSRF token through Upgrade")
                page = pages["large-policy"].replace("</body>",
                    '<script>events.forEach(function (init) { init(); });'
                    'document.getElementById("sdwan-policy-editor").requestSubmit();</script></body>')
                (site / "large-policy.html").write_text(page, encoding="utf-8")
                subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                f"--user-data-dir={folder}/chrome", "--dump-dom",
                                f"http://127.0.0.1:{server.server_port}/large-policy.html"],
                               capture_output=True, check=True, timeout=35)
                path, fields = requests.get(timeout=5)
                selection = json.loads(fields["policy_selection"][0])
                assert path == "/sdwan/policies.php" and "__csrf_magic" in fields and "revision" in fields
                assert "members[]" not in fields and not any(key.startswith("primary_check_") for key in fields)
                assert len(selection["members"]) == 350 and len(selection["overrides"]) == 700
                print("ok - native browser sends a large policy and probe overrides as bounded form data")
            finally:
                server.shutdown()
                worker.join()


def run(php, classes, screenshot_dir=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(SOURCE / "www/sdwan", root / "sdwan")
        for module in ("sdwan.inc", "sdwan_engine.inc", "sdwan_preflight.inc", "sdwan_steering.inc",
                       "sdwan_release.inc", "sdwan_log.inc", "sdwan_probe.inc"):
            shutil.copyfile(SOURCE / "pkg" / module, root / module)
        for ui in (root / "sdwan/ui.inc.php", root / "sdwan/editor.inc.php", root / "sdwan/forwarding.php",
                   root / "sdwan/updates.php", root / "sdwan/diagnostics.php"):
            ui.write_text(ui.read_text().replace("'/usr/local/pkg/", "__DIR__ . '/../"))
        probe = root / "sdwan_probe.inc"
        probe.write_text(re.sub(r"(?m)^function (sdwan_probe_fib_count|sdwan_probe_path)\(",
                                r"function fixture_native_\1(", probe.read_text()))
        version = root / "pfsense-version"
        supervisor = root / "sdwand.pid"
        supervisor.write_text("501\n")
        release = root / "sdwan_release.inc"
        release.write_text(release.read_text().replace("'/etc/version'", repr(str(version))).replace(
            "'/var/run/sdwand.pid'", repr(str(supervisor))).replace("sys_get_temp_dir() . '/sdwan-upgrade-'",
                                                                 "__DIR__ . '/sdwan-upgrade-'"))
        engine = root / "sdwan_engine.inc"
        engine.write_text(engine.read_text().replace("'/var/run/sdwan-observer.json'", "__DIR__ . '/observer.json'"))
        upstream = (classes.parent / "guiconfig.inc").read_text()
        native = [re.search(r"^function " + routine + r"\(.*?^\}", upstream, re.M | re.S)[0]
                  for routine in ("display_top_tabs", "genhtmltitle", "print_input_errors", "sprint_info_box", "print_info_box")]
        (root / "guiconfig.inc").write_text("<?php require dirname($classes) . '/csrf/csrf-magic.php';\n" + "\n".join(native))
        for name in ("pfsense-utils.inc", "pkg-utils.inc"):
            (root / name).touch()
        (root / "phpsessionmanager.inc").write_text("<?php function phpsession_end() {}")
        service_source = (classes.parents[3] / "etc/inc/service-utils.inc").read_text()
        service_functions = ("find_service_by_name", "get_service_status", "is_service_enabled", "get_service_control_links")
        service_functions = [re.search(r"^function " + name + r"\(.*?^\}", service_source, re.M | re.S)[0]
                             for name in service_functions]
        (root / "service-utils.inc").write_text("<?php\n" + "\n".join(service_functions))
        shortcut_source = (classes.parent / "shortcuts.inc").read_text()
        shortcut_functions = [re.search(r"^function get_shortcut_" + name + r"_link\(.*?^\}", shortcut_source, re.M | re.S)[0]
                              for name in ("main", "status", "log")]
        (root / "shortcuts.inc").write_text("<?php\n" + "\n".join(shortcut_functions))
        shutil.copyfile(SOURCE / "pkg/shortcuts/pkg_sdwan.inc", root / "pkg_sdwan.inc")
        toolbar = (classes.parent / "head.inc").read_text().split("/* Determine shortcut section for XML-based packages */", 1)[1].split("?>", 1)[0]
        (root / "head.inc").write_text('<?php require_once "service-utils.inc"; require "shortcuts.inc"; require "pkg_sdwan.inc"; '
                                      '$hide_service_status = false; $xmlfile = null; ?>'
                                      '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                                      '<meta name="viewport" content="width=device-width, initial-scale=1">'
                                      '<script>var events = [];</script></head>'
                                      '<body><main class="container"><header class="header"><?=genhtmltitle($pgtitle)?>'
                                      '<ul class="list-inline pull-right"><?php ' + toolbar + ' ?></ul></header>')
        (root / "foot.inc").write_text("</main></body></html>")

        native = {"interfaces": {"wan": {"enable": ""}}, "gateways/gateway_item": [
            {"interface": "wan", "name": "GW1"}, {"interface": "wan", "name": "GW2"},
            {"interface": "wan", "name": "FREE"}, {"interface": "wan", "name": "OFF", "monitor_disable": ""},
        ]}
        config = {"version": "1", "members": [
            {"name": "1", "gateway": "GW1", "cost": "3"}, {"name": "01", "gateway": "GW2", "cost": "3"},
            {"name": "backup", "gateway": "GONE", "cost": "3"}],
            "slas": [{"name": n, "latency_ms": "25", "loss_pct": "0"} for n in ("1", "01")],
            "policies": [{"name": "VOICE", "members": ["backup", "01"], "sla": "01", "strategy": "cost"}]}

        def request(page, *, platform_version="2.9.1-RELEASE", **params):
            version.write_text(platform_version + "\n")
            (root / "observer.json").unlink(missing_ok=True)
            data = {"native": native, "config": config, **params}
            result = subprocess.run([php, "-d", "disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo",
                                     str(ROOT / "tests/fixtures/gui_request.php"), str(root), str(classes), page], input=json.dumps(data), text=True,
                                    capture_output=True)
            assert result.returncode == 0 and not result.stderr, result.stderr or result.stdout[-1500:]
            return result.stdout

        html = request("policies", get={"edit": "VOICE"})
        rendered = Choices(html)
        fields = rendered.fields
        assert len(rendered.tokens) == rendered.posts == 1 and 'value="delete"' not in html, html
        assert fields["members[]"] == [(":backup", True), (":01", True), (":1", False)], fields
        assert [v for v, enabled in fields["sla"] if enabled] == [":01"]
        posted = {"name": "VOICE", "original": "VOICE", "action": "save", "sla": ":01", "strategy": "cost",
                  "members": [v for v, enabled in fields["members[]"] if enabled]}
        result = request("policies", post=posted)
        assert "CSRF check failed" in result and json.loads(result.split("SAVED=")[1]) == [0, config], result
        posted["__csrf_magic"] = rendered.tokens[-1]
        result = request("policies", post=posted)
        assert "CSRF check failed" not in result, result
        assert json.loads(result.split("SAVED=")[1]) == [0, config], result
        changed = request("policies", post={**posted, "strategy": "latency"})
        writes, stored = json.loads(changed.split("SAVED=")[1])
        assert writes == 1 and stored["policies"] == [{**config["policies"][0], "strategy": "latency"}]
        stale = request("policies", post={**posted, "revision": "previous-revision"})
        assert "Configuration changed" in stale and json.loads(stale.split("SAVED=")[1]) == [0, config]
        timers = request("policies", post={**posted, "degrade_samples": "3", "recover_seconds": "0"})
        writes, timed_config = json.loads(timers.split("SAVED=")[1])
        assert writes == 1 and timed_config["policies"][0]["degrade_samples"] == "3"
        assert timed_config["policies"][0]["recover_seconds"] == "0"
        invalid_timer = request("policies", post={**posted, "recover_seconds": "301"})
        assert json.loads(invalid_timer.split("SAVED=")[1]) == [0, config], invalid_timer
        print("ok - native policy form round-trip preserves restored tie order and distinct numeric names")

        probe_config = {**config, "members": [dict(member) for member in config["members"]]}
        for index, member in enumerate(probe_config["members"], 20):
            member["probe_primary"] = f"tcp://192.0.2.{index}:443"
            member["probe_secondary"] = f"dns://example.com 198.51.100.{index}"
        probe_form = Choices(request("policies", config=probe_config, get={"edit": "VOICE"}))
        assert probe_form.fields["primary_check"] == [
            ("", True), ("ignored", False), ("optional", False), ("required", False),
        ]
        assert "primary_check_1" in probe_form.fields and "primary_check_01" in probe_form.fields
        probe_post = {**posted, "__csrf_magic": probe_form.tokens[0], "revision": probe_form.revisions[0],
                      "primary_check": "required", "secondary_check": "optional",
                      "primary_check_01": "ignored", "secondary_check_01": "required"}
        changed = request("policies", config=probe_config, post=probe_post)
        writes, stored = json.loads(changed.split("SAVED=")[1])
        requirements = [{"member": "01", "primary_check": "ignored", "secondary_check": "required"}]
        assert writes == 1 and stored["policies"] == [
            {**probe_config["policies"][0], "primary_check": "required", "secondary_check": "optional",
             "probe_requirements": requirements},
        ], changed
        selected_checks = Choices(request("policies", config=stored, get={"edit": "VOICE"})).fields
        assert ("required", True) in selected_checks["primary_check"]
        assert ("ignored", True) in selected_checks["primary_check_01"]
        assert ("required", True) in selected_checks["secondary_check_01"]
        assert ("", True) in selected_checks["primary_check_1"]
        malformed = request("policies", config=probe_config, post={**probe_post, "secondary_check_01": ["required"]})
        assert "Select a valid member service check requirement." in malformed
        assert json.loads(malformed.split("SAVED=")[1]) == [0, probe_config]
        saved_probe_form = Choices(request("policies", config=stored, get={"edit": "VOICE"}))
        cleared = request("policies", config=stored, post={
            **probe_post, "__csrf_magic": saved_probe_form.tokens[0], "revision": saved_probe_form.revisions[0],
            "primary_check": "", "secondary_check": "", "primary_check_01": "", "secondary_check_01": "",
        })
        assert json.loads(cleared.split("SAVED=")[1]) == [1, probe_config], cleared
        print("ok - native policy form saves and clears policy and member requirements")

        large_members = [{"name": f"member_{n}", "gateway": f"GW_{n}", "cost": "3",
                          "probe_primary": f"tcp://192.0.{2 + n // 250}.{1 + n % 250}:443",
                          "probe_secondary": f"dns://example.com 198.51.{100 + n // 250}.{1 + n % 250}"}
                         for n in range(350)]
        member_names = [member["name"] for member in large_members]
        large_policy = {**config["policies"][0], "members": member_names}
        large_config = {**config, "members": large_members, "policies": [large_policy]}
        large_native = {**native, "gateways/gateway_item": [
            {"interface": "wan", "name": member["gateway"]} for member in large_members]}
        large_html = request("policies", config=large_config, native=large_native, get={"edit": "VOICE"})
        large_form = Choices(large_html)
        assert len(large_form.fields["members[]"]) == 350 and "primary_check_member_349" in large_form.fields
        overrides = {f"{slot}_check_{name}": value for name in member_names
                     for slot, value in (("primary", "required"), ("secondary", "optional"))}
        compact = {"members": [":" + name for name in member_names], "overrides": overrides}
        large_post = {key: value for key, value in posted.items() if key != "members"}
        large_post.update({"__csrf_magic": large_form.tokens[0], "revision": large_form.revisions[0],
                           "policy_selection": json.dumps(compact)})
        updated = request("policies", config=large_config, native=large_native, post=large_post)
        writes, large_stored = json.loads(updated.split("SAVED=")[1])
        expected = [{"member": name, "primary_check": "required", "secondary_check": "optional"}
                    for name in member_names]
        assert writes == 1 and large_stored["policies"] == [{**large_policy, "probe_requirements": expected}], updated[-1500:]
        invalid_selection = {**compact, "overrides": {"primary_check_member_349": ["required"]}}
        invalid = request("policies", config=large_config, native=large_native,
                          post={**large_post, "policy_selection": json.dumps(invalid_selection)})
        assert "Select a valid member service check requirement." in invalid
        assert json.loads(invalid.split("SAVED=")[1]) == [0, large_config]
        print("ok - policy saves 350 members and 700 overrides below the PHP form input limit")

        form = Choices(request("members", get={"add": "1"}))
        assert form.fields["gateway"] == [("", True), (":FREE", False)], form.fields
        restored = request("members", get={"edit": "backup"})
        assert (":GONE", True) in Choices(restored).fields["gateway"] and "GONE (unavailable)" in restored
        review_config = {**config, "members": [dict(member) for member in config["members"]]}
        review_config["members"][0]["probe_primary"] = "fib=1 tcp://192.0.2.45:7"
        review_form = Choices(request("members", config=review_config, get={"edit": "01"}))
        review_post = {"action": "save", "review_routes": "1", "name": "01", "original": "01",
                       "gateway": ":GW2", "cost": "3", "probe_primary": "fib=1 tcp://192.0.2.45:7",
                       "__csrf_magic": review_form.tokens[0], "revision": review_form.revisions[0]}
        duplicate = request("members", config=review_config, post=review_post, probe_fib_count=3, probe_path=False)
        assert "The target already has another check in this routing table." in duplicate
        assert "<code>fib=2 tcp://192.0.2.45:7</code>" in duplicate
        assert json.loads(duplicate.split("SAVED=")[1]) == [0, review_config]
        path = {"fib": 2, "address": "192.0.2.45", "interface": "wan", "match": True,
                "expected": {"device": "vtnet2", "source": "203.0.113.1", "next_hop": "203.0.113.2"}}
        ready_post = {**review_post, "probe_primary": "fib=2 tcp://192.0.2.45:7"}
        ready = request("members", config=review_config, post=ready_post, probe_fib_count=3, probe_path=path)
        assert "Host route verified" in ready and "Expected interface vtnet2, source 203.0.113.1, next hop 203.0.113.2." in ready
        assert "<code>route -n get -inet 192.0.2.45 -fib 2</code>" in ready
        assert json.loads(ready.split("SAVED=")[1]) == [0, review_config]
        wrong = request("members", config=review_config, post=ready_post, probe_fib_count=3,
                        probe_path={**path, "match": False})
        assert "Host route unverified" in wrong
        absent = request("members", config=review_config, post=ready_post, probe_fib_count=2, probe_path=False)
        assert "This routing table is unavailable" in absent
        malformed = request("members", config=review_config, post={**ready_post, "review_routes": ["1"]},
                            probe_fib_count=3, probe_path=False)
        assert json.loads(malformed.split("SAVED=")[1]) == [0, review_config]
        assert "Select an available gateway" in malformed
        skipped = request("members", config=review_config, post={**ready_post, "probe_primary": "tcp://127.0.0.1:7"},
                          probe_fib_count=3, probe_path=False)
        assert "Enter a valid check." in skipped
        bad_token = request("members", config=review_config, post={**ready_post, "__csrf_magic": "invalid"},
                            probe_fib_count=3, probe_path=False)
        assert "CSRF check failed" in bad_token and "Host route verified" not in bad_token
        print("ok - member probe route preview checks FIB conflicts and live route scope without saving")
        blocked = request("members", post={"action": "delete", "original": "backup", "__csrf_magic": form.tokens[0]})
        assert "following policies first: VOICE." in blocked
        assert json.loads(blocked.split("SAVED=")[1]) == [0, config]
        shared = {**config, "policies": [config["policies"][0], {**config["policies"][0], "name": "ERP"}]}
        for page, name in (("members", "01"), ("slas", "01")):
            shared_form = Choices(request(page, config=shared))
            blocked = request(page, config=shared, post={"action": "delete", "original": name,
                               "__csrf_magic": shared_form.tokens[0], "revision": shared_form.revisions[0]})
            assert "following policies first: VOICE, ERP." in blocked, blocked
            assert json.loads(blocked.split("SAVED=")[1]) == [0, shared]
        sole_member = {**config, "members": [config["members"][1]],
                       "policies": [{**config["policies"][0], "members": ["01"]}]}
        sole_form = Choices(request("policies", config=sole_member, get={"edit": "VOICE"}))
        blocked = request("policies", config=sole_member, post={
            **posted, "members": [], "__csrf_magic": sole_form.tokens[0], "revision": sole_form.revisions[0]})
        assert "Select at least one member" in blocked
        assert json.loads(blocked.split("SAVED=")[1]) == [0, sole_member]
        binding = {"group": "PBR", "policy": "VOICE", "gateways": {"item": ["GW1", "GW2"]},
                   "trackers": {"item": ["50321"]}, "policy_revision": "a" * 64, "rules_revision": "b" * 64}
        active_policy = {**native, "gateways/sdwan_bindings": {"item": [binding]},
                         "gateways/sdwan_bindings/item": [binding]}
        for privileges in ({}, {"/firewall_rules.php": False}):
            active_list = request("policies", native=active_policy, privileges=privileges)
            assert "Remove the forwarding binding before deleting this policy" in active_list, active_list
            assert 'value="review-delete"' not in active_list, active_list
            if privileges:
                assert "PBR" not in active_list, active_list
            controls = Choices(active_list)
            deleted = request("policies", native=active_policy, privileges=privileges, post={
                "action": "delete", "original": "VOICE", "__csrf_magic": controls.tokens[0],
                "revision": controls.revisions[0]})
            assert "Remove the forwarding binding before deleting this policy" in deleted, deleted
            assert json.loads(deleted.split("SAVED=")[1]) == [0, config]
        invalid_bindings = {**active_policy, "gateways/sdwan_bindings": {"item": [None]}}
        invalid_list = request("policies", native=invalid_bindings)
        assert "Review the saved forwarding bindings before deleting policies" in invalid_list
        assert 'value="review-delete"' not in invalid_list
        controls = Choices(invalid_list)
        blocked = request("policies", native=invalid_bindings, post={
            "action": "delete", "original": "VOICE", "__csrf_magic": controls.tokens[0],
            "revision": controls.revisions[0]})
        assert "Review the saved forwarding bindings before deleting policies" in blocked
        assert json.loads(blocked.split("SAVED=")[1]) == [0, config]
        for page, name in (("members", "1"), ("slas", "1"), ("policies", "VOICE")):
            list_page = request(page)
            assert 'value="review-delete"' in list_page and 'value="delete"' not in list_page
            controls = next(post for _, post in Choices(list_page).forms if post.get("original") == name)
            direct = request(page, post={**controls, "action": "delete"})
            assert "Review this entry before confirming its deletion" in direct
            assert json.loads(direct.split("SAVED=")[1]) == [0, config]
            review = request(page, post={**controls, "action": "review-delete"})
            assert f"Delete {name}?" in review and f'href="/sdwan/{page}.php">Cancel' in review
            assert json.loads(review.split("SAVED=")[1]) == [0, config]
            confirm = {**Choices(review).forms[0][1], "action": "delete"}
            stale = request(page, post={**confirm, "revision": "old-revision"})
            assert "Configuration changed" in stale
            assert json.loads(stale.split("SAVED=")[1]) == [0, config]
            wrong = request(page, post={**confirm, "confirm_delete": "another-entry"})
            assert "Review this entry before confirming its deletion" in wrong
            assert json.loads(wrong.split("SAVED=")[1]) == [0, config]
            if page == "policies":
                newly_bound = request(page, native=active_policy, post=confirm)
                assert "Remove the forwarding binding before deleting this policy" in newly_bound
                assert json.loads(newly_bound.split("SAVED=")[1]) == [0, config]
            deleted = request(page, post=confirm)
            remaining = [entry for entry in config[page] if entry["name"] != name]
            assert json.loads(deleted.split("SAVED=")[1]) == [1, {**config, page: remaining}], deleted
        print("ok - deletion needs confirmation and rechecks the revision and dependencies before saving")

        thresholds = [dict(sla, rttsd_ms="1.5") for sla in config["slas"]]
        optional_config = {**probe_config, "slas": thresholds}
        for page, name, required, optional_field, html_value in (
            ("members", "01", {"gateway": ":GW2", "cost": "3", "probe_primary": "tcp://192.0.2.21:443"},
             "probe_secondary", "dns://example.com 198.51.100.21"),
            ("slas", "01", {"latency_ms": "25", "loss_pct": "0"}, "rttsd_ms", "1.5"),
        ):
            controls = Choices(request(page, config=optional_config, get={"edit": name}))
            edit = {**required, "action": "save", "name": name, "original": name,
                    "__csrf_magic": controls.tokens[0], "revision": controls.revisions[0]}
            omission = request(page, config=optional_config, post=edit)
            assert json.loads(omission.split("SAVED=")[1]) == [0, optional_config], omission
            for malformed_value in ([], None, "\u0000", "x" * 513):
                invalid = request(page, config=optional_config, post={**edit, optional_field: malformed_value})
                assert "Enter a valid value for" in invalid, invalid
                assert Choices(invalid).forms[0][1][optional_field] == html_value, invalid
                assert json.loads(invalid.split("SAVED=")[1]) == [0, optional_config], invalid
            cleared = request(page, config=optional_config, post={**edit, optional_field: ""})
            writes, cleared_config = json.loads(cleared.split("SAVED=")[1])
            cleared_rows = [r for r in cleared_config[page] if r["name"] == name]
            assert writes == 1 and optional_field not in cleared_rows[0], cleared
        required_checks = {**optional_config, "policies": [
            {**config["policies"][0], "secondary_check": "required"}]}
        controls = Choices(request("members", config=required_checks, get={"edit": "01"}))
        blocked = request("members", config=required_checks, post={
            "action": "save", "original": "01", "name": "01", "gateway": ":GW2", "cost": "3",
            "probe_primary": "tcp://192.0.2.21:443", "probe_secondary": "",
            "__csrf_magic": controls.tokens[0], "revision": controls.revisions[0]})
        assert "Configure the required service check on 01 for policy VOICE" in blocked
        assert json.loads(blocked.split("SAVED=")[1]) == [0, required_checks]
        print("ok - missing or malformed optional inputs preserve settings and only an explicit blank clears them")

        add_form = Choices(request("members", get={"add": "1"}))
        new_member = {"action": "save", "name": "free", "gateway": ":FREE", "cost": "7",
                      "__csrf_magic": add_form.tokens[0], "revision": add_form.revisions[0]}
        for bad_identity in (new_member, {**new_member, "original": []}):
            blocked = request("members", post=bad_identity)
            assert "This entry could not be identified" in blocked
            assert json.loads(blocked.split("SAVED=")[1]) == [0, config]
        added = request("members", post={**new_member, "original": ""})
        writes, added_config = json.loads(added.split("SAVED=")[1])
        assert writes == 1 and added_config["members"][-1] == {"name": "free", "gateway": "FREE", "cost": "7"}
        assert "Entry not found" in request("members", get={"edit": []})

        empty = {**config, "members": [], "slas": [], "policies": []}
        for page, message in [("policies", "one member and one performance SLA"), ("members", "unused gateway")]:
            html = request(page, config=empty, native={}, get={"add": "1"})
            assert message in html and 'name="save"' not in html
        print("ok - editor explains prerequisites, preserves unavailable gateways and protects policy references")
        member_list = request("members")
        assert 'table-rowdblclickedit' in member_list and 'class="fa-solid fa-pencil"' in member_list
        assert 'class="action-buttons"' in member_list and 'icon-embed-btn' in member_list
        assert Choices(member_list).tokens and 'value="review-delete"' in member_list

        assert "diagnostics.php?policy=VOICE" in request("status")
        assert "diagnostics.php?policy=VOICE" not in request("status", inspect=False)
        history = ("Apr  8 10:00:00 pfSense sdwan[27]: SD-WAN Policy VOICE: "
                   "PF confirmed gateway BACKUP in group VOICEGROUP.\n"
                   "Apr  8 10:00:01 pfSense sdwan[27]: SD-WAN Policy VOICE: "
                   "recommended member &<marker>.\n"
                   "Apr  8 10:00:02 pfSense sdwan[27]: SD-WAN Policy OTHER: "
                   "recommended member PRIVATE.\n")
        history_report = request("diagnostics", system_log=history)
        assert "Recent policy events" in history_report and "Confirmed by PF" in history_report
        assert "VOICEGROUP." in history_report and "&amp;&lt;marker&gt;" in history_report
        assert "PRIVATE" not in history_report
        restricted_history = request("diagnostics", system_log=history, privileges={"/status_logs.php": False})
        assert "Recent policy events" not in restricted_history and "VOICEGROUP." not in restricted_history
        print("ok - policy history is filtered, escaped and requires the System Logs privilege")
        native_without_backup = native
        native = {**native, "gateways/gateway_item": [*native["gateways/gateway_item"],
                  {"interface": "wan", "name": "GONE"}]}
        sample = {"status": "online", "rtt_ms": 1, "rttsd_ms": 0, "loss_pct": 0}
        policy = {"candidates": {"backup": "Eligible", "01": "Eligible"}, "selected": "backup",
                  "path_status": "alternatives", "eligible_count": 2, "shared_interface": False,
                  "shared_underlay": True, "reason": "Lowest configured cost within SLA"}
        snapshot = {"members": {"backup": sample, "01": sample}, "policies": {"VOICE": policy}}
        fresh = request("status", snapshot=snapshot)
        assert "2 of 2" in fresh and "Members share a transport interface" in fresh
        observed = json.loads((root / "observer.json").read_text())
        disabled_monitor = {**native, "gateways/gateway_item": [
            {**gateway, "monitor_disable": ""} if gateway["name"] == "GONE" else gateway
            for gateway in native["gateways/gateway_item"]]}
        for changed_native, issue in (
            (native_without_backup, "Gateway unavailable"),
            ({**native, "interfaces": {"wan": {}}}, "Gateway unavailable"),
            (disabled_monitor, "Gateway monitoring disabled"),
        ):
            changed_status = request("status", native=changed_native, snapshot=observed)
            assert issue in changed_status and "2 of 2" not in changed_status and "1.00 ms" not in changed_status
            changed_report = request("diagnostics", native=changed_native, snapshot=observed)
            assert f"backup (GONE): {issue}." in changed_report and "System &gt; Routing" in changed_report
            assert 'aria-label="Member evaluation"' not in changed_report and "Recommended</strong>" not in changed_report
        deleted = {**config, "policies": []}
        deleted_status = request("status", config=deleted, snapshot=observed)
        assert "No policies configured" in deleted_status and "2 of 2" not in deleted_status
        deleted_policy = request("diagnostics", config=deleted, get={"policy": "VOICE"}, snapshot=observed)
        assert "no longer configured" in deleted_policy and 'aria-label="Member evaluation"' not in deleted_policy
        print("ok - deleted policies, native gateways and monitor settings cannot display stale health")
        excluded = {**policy, "candidates": {"backup": "Loss above SLA", "01": "Loss above SLA"},
                    "selected": None, "eligible_count": 0, "path_status": "no_eligible"}
        unavailable = request("status", snapshot={**snapshot, "policies": {"VOICE": excluded}})
        assert "No eligible path" in unavailable and 'class="bg-danger"' in unavailable
        stale = request("status", snapshot={**snapshot, "generated_at": 1})
        assert "The last SD-WAN observation expired." in stale and "2 of 2" not in stale
        retargeted = {**snapshot, "gateway_inventory_revision": "0" * 64}
        fresh_snapshot_wrong_gateway = request("status", snapshot=retargeted)
        assert "current configuration or gateway paths" in fresh_snapshot_wrong_gateway and "2 of 2" not in fresh_snapshot_wrong_gateway
        assert 'aria-label="Member evaluation"' not in request("diagnostics", snapshot=retargeted)
        print("ok - native CSRF verifies posts; Status and Diagnostics suppress outdated observations")
        assert "Multiple eligible paths" in fresh and 'class="bg-success"' in fresh
        assert 'id="restartservice-sdwan"' in fresh and 'id="stopservice-sdwan"' in fresh and 'id="startservice-sdwan"' not in fresh
        stopped = request("status", snapshot=snapshot, service_state="stopped")
        assert 'id="startservice-sdwan"' in stopped and 'id="stopservice-sdwan"' not in stopped
        assert "Multiple eligible paths" not in stopped and "The SD-WAN service is stopped." in stopped
        missing = request("status", snapshot=snapshot, service_state="unregistered")
        assert 'service-sdwan"' not in missing and "Multiple eligible paths" not in missing
        read_only = request("status", snapshot=snapshot, privileges={"/status_services.php": False})
        assert 'service-sdwan"' not in read_only and "Multiple eligible paths" in read_only
        for status in (fresh, stopped, missing, read_only):
            assert "sdwan-observer-state" not in status and "View in Services" not in status
            assert "/status_services.php" not in Choices(status).links
        past = request("diagnostics", snapshot=snapshot, service_state="stopped")
        assert "The SD-WAN service is stopped." in past and 'aria-label="Member evaluation"' not in past
        print("ok - Status omits the service banner and keeps the native toolbar and sample checks")
        assert 'data-sortable' in fresh and "RTTsd" in fresh and 'class="action-buttons"' in fresh
        event_form = next((form for form in Choices(fresh).forms if form[0].get("action") == "/status_logs.php"), None)
        assert event_form is not None
        event_attrs, event_post = event_form
        assert event_attrs.get("method") == "post" and event_attrs.get("id") == "sdwan-system-logs"
        assert 'form="sdwan-system-logs"' in fresh and "__csrf_magic" in event_post
        assert 'form="sdwan-system-logs" class="btn btn-default btn-sm"' in fresh
        assert fresh.index('Gateway Status') < fresh.index('Policy Status')
        assert 'class="btn btn-default btn-sm" role="button" href="/status_gateways.php"' in fresh
        assert 'class="fa-solid fa-network-wired fa-fw"' in fresh
        assert "Last sample" not in fresh and "<time" not in fresh
        assert event_post["logfile"] == "system" and event_post["filterlogentries_process"] == "sdwan"
        delegated = request("status", privileges={"/firewall_rules.php": False}, snapshot=snapshot)
        assert "/sdwan/forwarding.php" not in Choices(delegated).links and 'form="sdwan-system-logs"' in delegated
        diagnostics = request("diagnostics", get={"policy": "VOICE"}, snapshot=snapshot)
        decisions = re.findall(r'<tr>\s*<th scope="row">(.*?)</tr>', diagnostics, re.S)
        assert "Maximum RTT" in diagnostics and "Maximum loss" in diagnostics and "1.00 ms" in diagnostics
        assert "2 of 2" in diagnostics and "Lowest configured cost within SLA" in diagnostics
        assert len(decisions) == 2 and "backup" in decisions[0] and "GONE" in decisions[0]
        assert "Recommended</strong>" in decisions[0] and "Eligible" in decisions[1], decisions
        assert "RTTsd" in diagnostics and ">Cost</th>" in diagnostics
        check_report = request("diagnostics", config=stored, snapshot={**snapshot, "members": {
            "backup": {**sample, "checks": {"probe_primary": "Passed"}},
            "01": {**sample, "checks": {"probe_primary": "Path not verified", "probe_secondary": "Passed"}},
        }})
        assert "Primary · Passed · Required" in check_report
        assert "Primary · Path not verified · Ignored" in check_report
        assert "Secondary · Passed · Required" in check_report

        latency = {**config, "policies": [{**config["policies"][0], "strategy": "latency"}]}
        failed = {**policy, "selected": None, "reason": "No eligible member",
                  "eligible_count": 0, "path_status": "no_eligible",
                  "candidates": {"backup": "RTT exceeds the SLA", "01": "Gateway is down"}}
        unsuitable = {**snapshot, "members": {"backup": {**sample, "rtt_ms": 25.25, "loss_pct": 0.1},
                                             "01": {**sample, "status": "down", "loss_pct": 100}},
                      "policies": {"VOICE": failed}}
        report = request("diagnostics", config=latency, snapshot=unsuitable)
        decisions = re.findall(r'<tr>\s*<th scope="row">(.*?)</tr>', report, re.S)
        assert "No eligible member" in report and "0 of 2" in report and ">Cost</th>" not in report
        assert len(decisions) == 2 and "RTT exceeds the SLA" in decisions[0] and "Gateway is down" in decisions[1]
        assert decisions[0].count('text-nowrap bg-warning') == 2 and 'text-nowrap bg-warning' not in decisions[1]
        boundary = {**snapshot, "members": {"backup": {**sample, "rtt_ms": 25}, "01": sample}}
        assert 'text-nowrap bg-warning' not in request("diagnostics", snapshot=boundary), "SLA limits are inclusive"
        for args, notice in [({"snapshot": {**snapshot, "generated_at": 1}}, "The last SD-WAN observation expired."),
                             ({"snapshot": snapshot, "service_state": "unregistered"}, "not registered")]:
            report = request("diagnostics", **args)
            assert notice in report and 'aria-label="Member evaluation"' not in report and "2 of 2" not in report
        print("ok - diagnostics reports the policy decision, both SLA breaches, gateway state and sample availability")
        assert 'class="sdwan-filter"' in diagnostics
        diagnostic_form = Choices(diagnostics)
        assert diagnostic_form.gets == 1 and diagnostic_form.posts == 1 and len(diagnostic_form.tokens) == 1
        assert all("__csrf_magic" not in values for form, values in diagnostic_form.forms if form.get("method") == "get")
        assert diagnostic_form.fields["policy"] == [(":VOICE", True)]
        assert "fa-solid fa-magnifying-glass" in diagnostics
        numeric = {**config, "policies": [{**config["policies"][0], "name": n} for n in ("1", "01")]}
        numeric_options = Choices(request("diagnostics", config=numeric, get={"policy": ":01"})).fields["policy"]
        assert numeric_options == [(":1", False), (":01", True)], numeric_options
        assert "no longer configured" in request("diagnostics", get={"policy": "deleted"})
        assert 'form="sdwan-system-logs"' not in request("diagnostics", privileges={"/status_logs.php": False})
        sample_traffic = {"policy": ":VOICE", "traffic": "sample"}
        inventory = {**native, "interfaces": {"wan": {"enable": "", "if": "igb0"}}}
        counters = {"igb0": {"inbytes": "18446744073709551615", "outbytes": 0},
                    "lan0": {"inbytes": 100, "outbytes": 200}}
        traffic = json.loads(request("diagnostics", native=inventory, get={**sample_traffic, "interface": "lan0"},
                                     interface_counters=counters, service_state="stopped"))
        assert re.fullmatch(r"[a-f0-9]{64}", traffic["revision"])
        assert list(traffic["interfaces"]) == ["igb0"]
        assert traffic["interfaces"]["igb0"]["at_ns"].isdigit()
        assert traffic["interfaces"]["igb0"]["inbytes"] == "18446744073709551615"
        assert traffic["interfaces"]["igb0"]["outbytes"] == "0"
        native_float = json.loads(request("diagnostics", native=inventory, get=sample_traffic,
                                          interface_counters={"igb0": {"inbytes": 2.0,
                                                                       "outbytes": float(2**53 - 1)}}))
        assert native_float["interfaces"]["igb0"]["inbytes"] == "2"
        assert native_float["interfaces"]["igb0"]["outbytes"] == "9007199254740991"
        for options in ({}, {"interface_counters": {"igb0": {"inbytes": "18446744073709551616", "outbytes": 0}}},
                        {"interface_counters": {"igb0": {"inbytes": 100}}},
                        {"interface_counters": {"igb0": {"inbytes": 2.5, "outbytes": 0}}},
                        {"interface_counters": {"igb0": {"inbytes": 0, "outbytes": float(2**53)}}}):
            missing = json.loads(request("diagnostics", native=inventory, get=sample_traffic, **options))
            assert missing["interfaces"] == {}
        assert not request("diagnostics", native=inventory, get={**sample_traffic, "policy": ":deleted"},
                           interface_counters=counters)
        assert 'id="sdwan-traffic-measure"' not in diagnostics
        print("ok - interface sampling is read-only, policy-scoped and independent of the observer")
        updates = request("updates")
        assert Choices(updates).posts == 1 and len(Choices(updates).tokens) == 1
        assert "/pkg_mgr_installed.php" not in Choices(updates).links and "Installed Packages" not in updates
        assert 'name="upgrade_release"' not in updates
        unreadable = {**config, "slas": []}
        assert "The stored SD-WAN configuration cannot be read" in request("status", config=unreadable)
        repair_updates = request("updates", config=unreadable)
        assert "Installed Version" in repair_updates and "0.4.7" in repair_updates and "Check GitHub" in repair_updates
        assert Choices(repair_updates).posts == 1 and len(Choices(repair_updates).tokens) == 1
        checked = {"check_release": "1", "__csrf_magic": Choices(updates).tokens[0]}
        offered = request("updates", post=checked)
        assert "Upgrade to 0.4.8" in offered and "/pkg_mgr_installed.php" not in Choices(offered).links
        offered_form = Choices(offered).forms[0][1]
        action = {k: offered_form[k] for k in ("__csrf_magic", "target_version", "target_sha256")}
        action["upgrade_release"] = "1"
        assert "UPGRADES=0" in request("updates", get=action)
        csrf_failure = request("updates", post={**action, "__csrf_magic": "invalid"})
        assert "CSRF check failed" in csrf_failure and "UPGRADES=0" in csrf_failure
        privileges = {"/pkg_mgr_install.php": False}
        denied = request("updates", privileges=privileges, post=action)
        assert "UPGRADES=0 HTTP=403" in denied
        assert 'name="upgrade_release"' not in request("updates", privileges=privileges, post=checked)
        for options, message in [
            ({"abi": "FreeBSD:15:amd64"}, "incompatible"),
            ({"release_http_failure": 1}, "asset could not be verified"),
            ({"installed_release": "0.4.8"}, "up to date"),
        ]:
            result = request("updates", post=checked, **options)
            assert 'name="upgrade_release"' not in result and message in result
        assert "UPGRADES=0" in request("updates", post={**action, "target_sha256": "0" * 64})
        assert "UPGRADES=0" in request("updates", post=action, installed_release="0.4.9")
        busy = request("updates", post=action, upgrade_busy=True)
        assert "already in progress" in busy and "UPGRADES=0" in busy
        failed = request("updates", post=action, corrupt_release=True)
        assert "failed SHA-256 verification" in failed and "UPGRADES=0" in failed
        failed = request("updates", post=action, install_failure=True)
        assert "the previous SD-WAN package was restored" in failed
        assert "UPGRADES=1" in failed and "ROLLBACKS=1 RECOVERY=1" in failed
        failed = request("updates", post=action, install_hook_failure=True)
        assert "the previous SD-WAN package was restored" in failed and "ROLLBACKS=1" in failed
        failed = request("updates", post=action, broken_upgrade=True)
        assert "the previous SD-WAN package was restored" in failed
        assert "UPGRADES=1" in failed and "ROLLBACKS=1" in failed
        failed = request("updates", post=action, install_failure=True, rollback_failure=True)
        assert "automatic rollback failed" in failed and "ROLLBACKS=1" in failed
        blocked = request("updates", post=action, backup_failure=True)
        assert "could not be prepared for rollback" in blocked
        assert "UPGRADES=0" in blocked and "ROLLBACKS=0" in blocked
        failed = request("updates", post=action, service_failure=True)
        assert "Service readiness still requires verification" in failed and "ROLLBACKS=1 RECOVERY=1" in failed
        failed = request("updates", post=action, registration_failure=True)
        assert "the previous SD-WAN package was restored" in failed and "ROLLBACKS=1 RECOVERY=1" in failed
        failed = request("updates", post=action, worker_failure=True)
        assert "observer readiness could not be verified" in failed and "UPGRADES=1" in failed
        assert 'name="verify_installation"' in failed and 'name="upgrade_release"' not in failed
        retry_form = Choices(failed).forms[0][1]
        retry = {k: retry_form[k] for k in ("__csrf_magic", "target_version", "target_sha256")}
        retry["verify_installation"] = "1"
        installed_state = {"installed_release": "0.4.8", "release_http_failure": 0}
        denied = request("updates", privileges=privileges, post=retry, **installed_state)
        assert "UPGRADES=0 HTTP=403 REQUESTS=0" in denied
        rejected = request("updates", post={**retry, "__csrf_magic": "invalid"}, **installed_state)
        assert "CSRF check failed" in rejected and "UPGRADES=0" in rejected and "REQUESTS=0" in rejected
        still_unready = request("updates", post=retry, worker_failure=True, snapshot=snapshot, **installed_state)
        assert "observer readiness could not be verified" in still_unready and "UPGRADES=0" in still_unready
        assert "REQUESTS=0" in still_unready
        prior = {**snapshot, "observer": {"pid": 502, "version": "0.4.7"}}
        stale = request("updates", post=retry, snapshot=prior, **installed_state)
        assert "observer readiness could not be verified" in stale and "UPGRADES=0" in stale and "REQUESTS=0" in stale
        recovered = request("updates", post=retry, snapshot=snapshot, **installed_state)
        assert "0.4.8 is installed and the observer has a current sample" in recovered and "REQUESTS=0" in recovered
        assert "UPGRADES=0" in recovered and 'name="verify_installation"' not in recovered
        changed = request("updates", post=retry, installed_release="0.4.7", release_http_failure=0)
        assert "installed version changed" in changed and "UPGRADES=0" in changed and "REQUESTS=0" in changed
        files_bad = request("updates", post=retry, installed_checksum_failure=True, **installed_state)
        assert "version or files could not be verified" in files_bad and "UPGRADES=0" in files_bad and "REQUESTS=0" in files_bad
        installed = request("updates", post=action, snapshot=snapshot)
        assert "0.4.8 was installed and the observer has a current sample" in installed and "UPGRADES=1" in installed
        ce292 = {"platform_version": "2.9.2-RELEASE"}
        assert "Upgrade to 0.4.8" in request("updates", post=checked, **ce292)
        installed = request("updates", post=action, snapshot=snapshot, **ce292)
        assert "0.4.8 was installed and the observer has a current sample" in installed and "UPGRADES=1" in installed
        current = request("updates", post=checked, installed_release="0.4.8", **ce292)
        assert 'name="upgrade_release"' not in current and "up to date" in current
        replay = request("updates", post=action, snapshot=snapshot, **installed_state, **ce292)
        assert "0.4.8 is installed and the observer has a current sample" in replay and "UPGRADES=0" in replay and "REQUESTS=0" in replay
        for options in [
            {"platform_version": "2.9.0-RELEASE"},
            {"platform_version": "2.9.2-DEVELOPMENT"},
            {**ce292, "abi": "FreeBSD:16:aarch64"},
        ]:
            checked_platform = request("updates", post=checked, **options)
            assert 'name="upgrade_release"' not in checked_platform and "incompatible" in checked_platform
            denied_platform = request("updates", post=action, **options)
            assert "incompatible" in denied_platform and "UPGRADES=0" in denied_platform
        print("ok - native CSRF, install permission, stale target, compatibility, checksum and upgrade results")

        if screenshot_dir:
            demo = {**config, "members": [{"name": "Fiber", "gateway": "FIBER_GW", "cost": "10"},
                                          {"name": "LTE", "gateway": "CELL_GW", "cost": "30"}],
                    "slas": [{"name": "Voice", "latency_ms": "40", "loss_pct": "1"}],
                    "policies": [{"name": "Office", "sla": "Voice", "members": ["Fiber", "LTE"], "strategy": "cost"}]}
            demo_snapshot = {"members": {"Fiber": {**sample, "rtt_ms": 15.2, "rttsd_ms": 1.1, "loss_pct": 0},
                                        "LTE": {**sample, "status": "degraded", "rtt_ms": 76.1, "rttsd_ms": 5.8}},
                             "policies": {"Office": {**policy, "candidates": {"Fiber": "Eligible", "LTE": "RTT exceeds the SLA"},
                                 "selected": "Fiber", "path_status": "degraded", "eligible_count": 1, "shared_underlay": False}}}
            demo_native = {**native, "gateways/gateway_item": [
                {"interface": "wan", "name": member["gateway"]} for member in demo["members"]]}
            pages = {page: request(page, config=demo, native=demo_native, snapshot=demo_snapshot,
                                   **({"interface_counters": {}} if page == "diagnostics" else {}))
                     for page in ("status", "diagnostics", "members", "updates")}
            pages["members-edit"] = request("members", get={"edit": "1"})
            pages["large-policy"] = large_html
            pages["updates"] = offered.split("</html>", 1)[0] + "</html>"
            pages["status-stopped"] = request("status", config=demo, native=demo_native, snapshot=demo_snapshot,
                                              service_state="stopped")

        native_group = {"name": "PBR", "item": ["GW1|1|address", "GW2|2|address"]}
        rule = {"tracker": "50321", "interface": "lan", "gateway": "PBR", "ipprotocol": "inet", "type": "pass",
                "source": {"address": "192.0.2.9"}, "destination": {"address": "198.51.100.6"},
                "descr": "Voice <A>", "log": ""}
        guard = {**rule, "tracker": "50322", "type": "block", "descr": "Guard for Voice"}
        del guard["gateway"]
        fixture = {"gateways/gateway_group": [native_group], "filter/rule": [rule, guard],
                   "interfaces": {n: {"enable": "", "if": d} for n, d in
                                  (("lan", "em0"), ("wan", "em1"), ("opt1", "em2"))},
                   "gateways/gateway_item": [{"name": "GW1", "interface": "wan"}, {"name": "GW2", "interface": "opt1"}]}
        config = {**config, "policies": [{**config["policies"][0], "members": ["1", "01"]}]}
        names = {"policy": "VOICE", "group": "PBR"}
        stock = request("forwarding", native=fixture, get=names)
        assert "matches the native group" in stock and "50321" in stock and "Voice &lt;A&gt;" in stock, stock
        assert "Preview mode" in stock and 'value="bind"' not in stock
        assert 'class="sdwan-filter"' in stock and 'aria-label="Firewall Rules"' in stock
        assert stock.index("Gateway Group PBR") < stock.index('aria-label="Firewall Rules"') < stock.index("Set up forwarding")
        shared_monitor = dict(fixture, fixture_dynamic_targets={"wan": "192.0.2.1", "opt1": "192.0.2.1"})
        blocked = request("forwarding", native=shared_monitor, get=names, steering_abi=True)
        assert "shares its Monitor IP" in blocked and 'value="bind"' not in blocked
        generated_selection = request("forwarding", native=fixture, get={"policy": ":VOICE", "group": ":PBR"})
        assert "matches the native group" in generated_selection
        assert Choices(generated_selection).fields["group"] == [("", False), (":PBR", True)]
        if screenshot_dir:
            pages["forwarding"] = stock
            screenshots(screenshot_dir, classes.parent, pages)
        tracker_url = next(url for url in Choices(stock).links if "filterlogentries_tracker" in url)
        visible = request("forwarding", native=fixture, get=names, privileges={tracker_url: False})
        assert tracker_url not in Choices(visible).links and "50321" in visible
        # Exercise pfSense's native readers with the rendered POST and GET fields.
        common = (classes.parent / "status_logs_common.inc").read_text()
        tracker_query = {key: values[0] for key, values in parse_qs(urlsplit(tracker_url).query).items()}
        for submitted, method, routine, field in (
            (event_post, "post", "log_filter_form_system_submit", "process"),
            (tracker_query, "get", "log_filter_form_firewall_submit", "tracker"),
        ):
            handler = re.search(r"^function " + routine + r"\(.*?^\}", common, re.M | re.S)[0]
            getter = re.search(r"^function getGETPOSTsettingvalue\(.*?^\}", upstream, re.M | re.S)[0]
            defaults = {key: "" for key in re.findall(r"getGETPOSTsettingvalue\('([^']+)'", handler)}
            data = json.dumps([defaults | submitted, defaults] if method == "get" else [defaults, defaults | submitted])
            output = subprocess.run([php, "-r", getter + handler + "; [$_GET,$_POST]=json_decode(stream_get_contents(STDIN),true);"
                                     + routine + "(); echo json_encode([$filter_active,$filterfieldsarray]);"],
                                    input=data, capture_output=True, text=True, check=True)
            active, filters = json.loads(output.stdout)
            assert active and filters[field] == submitted["filterlogentries_" + field] and not output.stderr
        print("ok - native log filters open on the observer process and enabled rule tracker with page privilege checks")
        denied = request("forwarding", native=fixture, get=names, privileges={"/firewall_rules.php": False})
        assert "Access to Firewall" in denied and "50321" not in denied
        protected = request("forwarding", native={**fixture, "gateways/defaultgw4": "PBR"},
                            steering_abi=True, get=names)
        assert "system default gateway group" in protected and 'value="bind"' not in protected

        lab = request("forwarding", native=fixture, steering_abi=True, get=names)
        assert "Experimental" in lab and 'value="bind"' in lab and "Block · rule 50322" in lab, lab
        controls = Choices(lab)
        post = {**names, "action": "bind", "revision": controls.revisions[0], "__csrf_magic": controls.tokens[0]}
        for options, message in [({}, "previews only"), ({"steering_abi": True,
                                "privileges": {"/system_gateway_groups_edit.php": False}}, "additional privileges"),
                                 ({"steering_abi": True, "boot_ready": False}, "Reboot pfSense with the installed SD-WAN adapter")]:
            forbidden = request("forwarding", native=fixture, post=post, **options)
            assert message in forbidden and json.loads(forbidden.split("SAVED=")[1])[0] == 0
        bound = request("forwarding", native=fixture, post=post, steering_abi=True, capture_bindings=True)
        assert json.loads(bound.split("SAVED=")[1])[0] == 1, bound
        data = json.loads(bound.split("BINDINGS=")[1].split("\nSAVED=")[0])
        active = {**fixture, "gateways/sdwan_bindings": data, "gateways/sdwan_bindings/item": data["item"]}
        active_page = request("forwarding", native=active, steering_abi=True)
        assert "Active filter" in active_page and "PBR" in active_page and 'value="unbind"' in active_page
        assert "No current observation" in active_page
        unobserved = {"members": {"1": sample, "01": sample}, "policies": {"VOICE": {
            "selected": "1", "reason": "Lowest configured cost within SLA", "candidates": {"1": "Eligible", "01": "Eligible"},
        }}}
        activating = request("forwarding", native=active, steering_abi=True, snapshot=unobserved)
        assert "Waiting for an observation of this binding" in activating
        edit_page = request("slas", native=active, steering_abi=True, get={"edit": "01"})
        edit_controls = Choices(edit_page)
        tuning = {"action": "save", "original": "01", "name": "01", "latency_ms": "35", "rttsd_ms": "1.5", "loss_pct": "1",
                  "__csrf_magic": edit_controls.tokens[0], "revision": edit_controls.revisions[0]}
        rejected = request("slas", native=active, steering_abi=True, post=tuning,
                           privileges={"/firewall_rules_edit.php": False})
        assert "Editing an active forwarding policy requires access" in rejected and 'SAVED=[0,' in rejected
        tuned = request("slas", native=active, steering_abi=True, post=tuning, capture_bindings=True)
        assert json.loads(tuned.split("SAVED=")[1])[0] == 1
        new_binding = json.loads(tuned.split("BINDINGS=")[1].split("\nSAVED=")[0])["item"][0]
        assert new_binding["policy_revision"] != data["item"][0]["policy_revision"]
        assert new_binding["rules_revision"] == data["item"][0]["rules_revision"]
        active_controls = Choices(request("policies", native=active, steering_abi=True, get={"edit": "VOICE"}))
        active_probe_edit = {"name": "VOICE", "original": "VOICE", "action": "save", "sla": ":01",
                             "strategy": "cost", "members": [":1", ":01"], "primary_check": "ignored",
                             "__csrf_magic": active_controls.tokens[0], "revision": active_controls.revisions[0]}
        denied = request("policies", native=active, steering_abi=True, post=active_probe_edit,
                         privileges={"/firewall_rules_edit.php": False})
        assert "Editing an active forwarding policy requires access" in denied and "SAVED=[0," in denied
        revised = request("policies", native=active, steering_abi=True, post=active_probe_edit, capture_bindings=True)
        assert json.loads(revised.split("SAVED=")[1])[0] == 1
        probe_binding = json.loads(revised.split("BINDINGS=")[1].split("\nSAVED=")[0])["item"][0]
        assert probe_binding["policy_revision"] != data["item"][0]["policy_revision"]
        assert probe_binding["rules_revision"] == data["item"][0]["rules_revision"]
        unbound_rule = {key: value for key, value in rule.items() if key != "gateway"}
        orphan = {**active, "gateways/gateway_group": [], "filter/rule": [unbound_rule, guard]}
        blocked = request("forwarding", native=orphan, steering_abi=True)
        assert "Firewall rule 50321 has no valid native gateway" in blocked and 'value="unbind"' not in blocked
        rollback_ready = {**orphan, "filter/rule": [{**unbound_rule, "disabled": ""}, guard]}
        rollback = request("forwarding", native=rollback_ready)
        assert 'value="unbind"' in rollback and 'value="bind"' not in rollback, rollback
        controls = Choices(rollback)
        post = {**names, "action": "unbind", "revision": controls.revisions[0], "__csrf_magic": controls.tokens[0]}
        denied = request("forwarding", native=orphan, post=post)
        assert "Settings changed" in denied and "SAVED=[0," in denied
        reverted = request("forwarding", native=rollback_ready, post=post, capture_bindings=True)
        assert json.loads(reverted.split("SAVED=")[1])[0] == 1 and '"item":[]' in reverted, reverted
        print("ok - stock preview, native permissions, opt-in binding and guarded orphan rollback")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--classes", type=Path, required=True)
    parser.add_argument("--screenshots-dir", type=Path, help="capture synthetic page fixtures with upstream light and dark styles")
    args = parser.parse_args()
    run(args.php, args.classes.resolve(), args.screenshots_dir)
