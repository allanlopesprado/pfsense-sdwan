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
                                          ("diagnostics", "pfSense", "1440,900"), ("members", "pfSense", "1440,900"),
                                          ("members-edit", "pfSense-dark", "1440,900"), ("updates", "pfSense", "1440,900"),
                                          ("updates", "pfSense-dark", "390,844"), ("forwarding", "pfSense", "1440,900")]:
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
                    footer = '<script>var csrfMagicToken = ' + json.dumps(token) + ';</script>'
                    scripts = ("/csrf/csrf-magic.js", *native_scripts, "/js/pfSenseHelpers.js")
                    footer += "".join(f'<script src="{url}"></script>' for url in scripts)
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
            finally:
                server.shutdown()
                worker.join()


def run(php, classes, screenshot_dir=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(SOURCE / "www/sdwan", root / "sdwan")
        for module in ("sdwan.inc", "sdwan_engine.inc", "sdwan_preflight.inc", "sdwan_steering.inc", "sdwan_release.inc", "sdwan_log.inc"):
            shutil.copyfile(SOURCE / "pkg" / module, root / module)
        for ui in (root / "sdwan/ui.inc.php", root / "sdwan/forwarding.php", root / "sdwan/updates.php"):
            ui.write_text(ui.read_text().replace("'/usr/local/pkg/", "__DIR__ . '/../"))
        version = root / "pfsense-version"
        version.write_text("2.9.1-RELEASE\n")
        release = root / "sdwan_release.inc"
        release.write_text(release.read_text().replace("'/etc/version'", repr(str(version))))
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

        def request(page, **params):
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
        print("ok - native policy form round-trip preserves restored tie order and distinct numeric names")

        form = Choices(request("members", get={"add": "1"}))
        assert form.fields["gateway"] == [("", True), (":FREE", False)], form.fields
        restored = request("members", get={"edit": "backup"})
        assert (":GONE", True) in Choices(restored).fields["gateway"] and "GONE (unavailable)" in restored
        blocked = request("members", post={"action": "delete", "original": "backup", "__csrf_magic": form.tokens[0]})
        assert "following policies first: VOICE." in blocked
        assert json.loads(blocked.split("SAVED=")[1]) == [0, config]
        empty = {**config, "members": [], "slas": [], "policies": []}
        for page, message in [("policies", "one member and one performance SLA"), ("members", "unused gateway")]:
            html = request(page, config=empty, native={}, get={"add": "1"})
            assert message in html and 'name="save"' not in html
        print("ok - editor explains prerequisites, preserves unavailable gateways and protects policy references")
        member_list = request("members")
        assert 'table-rowdblclickedit' in member_list and 'class="fa-solid fa-pencil"' in member_list
        assert 'class="action-buttons"' in member_list and 'icon-embed-btn' in member_list
        assert Choices(member_list).tokens and 'value="delete"' in member_list

        assert "diagnostics.php?policy=VOICE" in request("status")
        assert "diagnostics.php?policy=VOICE" not in request("status", inspect=False)
        sample = {"status": "online", "rtt_ms": 1, "rttsd_ms": 0, "loss_pct": 0}
        policy = {"candidates": {"backup": "Eligible", "01": "Eligible"}, "selected": "backup",
                  "path_status": "alternatives", "eligible_count": 2, "shared_interface": False,
                  "shared_underlay": True, "reason": "Lowest configured cost within SLA"}
        snapshot = {"members": {"backup": sample, "01": sample}, "policies": {"VOICE": policy}}
        fresh = request("status", snapshot=snapshot)
        assert "2 of 2" in fresh and "Members share a transport interface" in fresh
        excluded = {**policy, "candidates": {"backup": "Loss above SLA", "01": "Loss above SLA"},
                    "selected": None, "eligible_count": 0, "path_status": "no_eligible"}
        unavailable = request("status", snapshot={**snapshot, "policies": {"VOICE": excluded}})
        assert "No eligible path" in unavailable and 'class="bg-danger"' in unavailable
        stale = request("status", snapshot={**snapshot, "generated_at": 1})
        assert "Waiting for current gateway measurements" in stale and "2 of 2" not in stale
        print("ok - native CSRF verifies form posts; status checks permissions, path diversity and sample freshness")
        assert "Multiple eligible paths" in fresh and 'class="bg-success"' in fresh
        assert "SD-WAN service" in fresh and "Running" in fresh and "/status_services.php" in Choices(fresh).links
        assert 'id="restartservice-sdwan"' in fresh and 'id="stopservice-sdwan"' in fresh and 'id="startservice-sdwan"' not in fresh
        stopped = request("status", snapshot=snapshot, service_state="stopped")
        assert "> Stopped" in stopped and 'id="startservice-sdwan"' in stopped and 'id="stopservice-sdwan"' not in stopped
        assert "Multiple eligible paths" not in stopped and "Waiting for current gateway measurements" not in stopped
        missing = request("status", snapshot=snapshot, service_state="unregistered")
        assert "Not registered" in missing and 'service-sdwan"' not in missing and "Multiple eligible paths" not in missing
        read_only = request("status", snapshot=snapshot, privileges={"/status_services.php": False})
        assert "/status_services.php" not in Choices(read_only).links and 'service-sdwan"' not in read_only and "Running" in read_only
        past = request("diagnostics", snapshot=snapshot, service_state="stopped")
        assert "The SD-WAN service is stopped." in past and "2.00%" not in past
        print("ok - native service state distinguishes running, stopped, unregistered and read-only access")
        assert 'data-sortable' in fresh and "RTTsd" in fresh and 'class="action-buttons"' in fresh
        event_form = next((form for form in Choices(fresh).forms if form[0].get("action") == "/status_logs.php"), None)
        assert event_form is not None
        event_attrs, event_post = event_form
        assert event_attrs.get("method") == "post" and event_attrs.get("id") == "sdwan-system-logs"
        assert 'form="sdwan-system-logs"' in fresh and "__csrf_magic" in event_post
        assert 'form="sdwan-system-logs" class="btn btn-primary btn-sm"' in fresh
        assert 'class="btn btn-default btn-sm" role="button" href="/status_gateways.php"' in fresh
        assert 'class="fa-solid fa-network-wired fa-fw"' in fresh
        assert 'class="panel-footer"><small>Last sample' in fresh
        assert event_post["logfile"] == "system" and event_post["filterlogentries_process"] == "sdwan"
        delegated = request("status", privileges={"/firewall_rules.php": False}, snapshot=snapshot)
        assert "/sdwan/forwarding.php" not in Choices(delegated).links and 'form="sdwan-system-logs"' in delegated
        diagnostics = request("diagnostics", get={"policy": "VOICE"}, snapshot=snapshot)
        assert "Maximum RTT" in diagnostics and "Maximum loss" in diagnostics and "1.00 ms" in diagnostics
        diagnostic_form = Choices(diagnostics)
        assert diagnostic_form.gets == 1 and diagnostic_form.posts == 1 and len(diagnostic_form.tokens) == 1
        assert all("__csrf_magic" not in values for form, values in diagnostic_form.forms if form.get("method") == "get")
        assert diagnostic_form.fields["policy"] == [(":VOICE", True)]
        assert "fa-solid fa-search" in diagnostics
        numeric = {**config, "policies": [{**config["policies"][0], "name": n} for n in ("1", "01")]}
        numeric_options = Choices(request("diagnostics", config=numeric, get={"policy": ":01"})).fields["policy"]
        assert numeric_options == [(":1", False), (":01", True)], numeric_options
        assert "no longer configured" in request("diagnostics", get={"policy": "deleted"})
        assert 'form="sdwan-system-logs"' not in request("diagnostics", privileges={"/status_logs.php": False})
        updates = request("updates")
        assert Choices(updates).posts == 1 and len(Choices(updates).tokens) == 1
        assert "/pkg_mgr_installed.php" not in Choices(updates).links and "Installed Packages" not in updates
        assert 'name="upgrade_release"' not in updates
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
        assert "could not install the update" in failed and "UPGRADES=1" in failed
        failed = request("updates", post=action, service_failure=True)
        assert "could not be verified" in failed and "UPGRADES=1" in failed
        installed = request("updates", post=action)
        assert "0.4.8 was installed and the observer is running" in installed and "UPGRADES=1" in installed
        print("ok - native CSRF, install permission, stale target, compatibility, checksum and upgrade results")

        if screenshot_dir:
            demo = {**config, "members": [{"name": "Fiber", "gateway": "FIBER_GW", "cost": "10"},
                                          {"name": "LTE", "gateway": "CELL_GW", "cost": "30"}],
                    "slas": [{"name": "Voice", "latency_ms": "40", "loss_pct": "1"}],
                    "policies": [{"name": "Office", "sla": "Voice", "members": ["Fiber", "LTE"], "strategy": "cost"}]}
            demo_snapshot = {"members": {"Fiber": {**sample, "rtt_ms": 15.2, "rttsd_ms": 1.1, "loss_pct": 0},
                                        "LTE": {**sample, "status": "degraded", "rtt_ms": 76.1, "rttsd_ms": 5.8}},
                             "policies": {"Office": {**policy, "candidates": {"Fiber": "Eligible", "LTE": "RTT above SLA"},
                                 "selected": "Fiber", "path_status": "degraded", "eligible_count": 1, "shared_underlay": False}}}
            pages = {page: request(page, config=demo, snapshot=demo_snapshot)
                     for page in ("status", "diagnostics", "members", "updates")}
            pages["members-edit"] = request("members", get={"edit": "1"})
            pages["updates"] = offered.split("</html>", 1)[0] + "</html>"
            pages["status-stopped"] = request("status", config=demo, snapshot=demo_snapshot, service_state="stopped")

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
        assert "Experimental" in lab and 'value="bind"' in lab, lab
        controls = Choices(lab)
        post = {**names, "action": "bind", "revision": controls.revisions[0], "__csrf_magic": controls.tokens[0]}
        for options, message in [({}, "previews only"), ({"steering_abi": True,
                                "privileges": {"/system_gateway_groups_edit.php": False}}, "additional privileges")]:
            forbidden = request("forwarding", native=fixture, post=post, **options)
            assert message in forbidden and json.loads(forbidden.split("SAVED=")[1])[0] == 0
        bound = request("forwarding", native=fixture, post=post, steering_abi=True, capture_bindings=True)
        assert json.loads(bound.split("SAVED=")[1])[0] == 1, bound
        data = json.loads(bound.split("BINDINGS=")[1].split("\nSAVED=")[0])
        orphan = {**fixture, "gateways/sdwan_bindings": data, "gateways/gateway_group": []}
        rollback = request("forwarding", native=orphan)
        assert 'value="unbind"' in rollback and 'value="bind"' not in rollback, rollback
        controls = Choices(rollback)
        post = {**names, "action": "unbind", "revision": controls.revisions[0], "__csrf_magic": controls.tokens[0]}
        reverted = request("forwarding", native=orphan, post=post, capture_bindings=True)
        assert json.loads(reverted.split("SAVED=")[1])[0] == 1 and '"item":[]' in reverted, reverted
        print("ok - stock preview, native permissions, identified rules, opt-in hook and orphan rollback form")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--classes", type=Path, required=True)
    parser.add_argument("--screenshots-dir", type=Path, help="capture synthetic page fixtures with upstream light and dark styles")
    args = parser.parse_args()
    run(args.php, args.classes.resolve(), args.screenshots_dir)
