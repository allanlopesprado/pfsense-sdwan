#!/usr/bin/env python3
"""Exercise native Form rendering and posts with a pinned pfSense classes directory."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "files/usr/local"


class Choices(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.fields, self.field = {}, None
        self.tokens = []
        self.posts = 0
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "select":
            self.field = attrs["name"]
            self.fields[self.field] = []
        if tag == "form" and attrs.get("method") == "post":
            self.posts += 1
        if tag == "input" and attrs.get("name") == "__csrf_magic":
            self.tokens.append(attrs["value"])
        if self.field and tag == "option":
            self.fields[self.field].append((attrs["value"], "selected" in attrs))

    def handle_endtag(self, tag):
        if tag == "select":
            self.field = None


def run(php, classes):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(SOURCE / "www/sdwan", root / "sdwan")
        for module in ("sdwan.inc", "sdwan_engine.inc"):
            shutil.copyfile(SOURCE / "pkg" / module, root / module)
        ui = root / "sdwan/ui.inc.php"
        ui.write_text(ui.read_text().replace("'/usr/local/pkg/", "__DIR__ . '/../"))
        engine = root / "sdwan_engine.inc"
        engine.write_text(engine.read_text().replace("'/var/run/sdwan-observer.json'", "__DIR__ . '/observer.json'"))
        (root / "guiconfig.inc").write_text("<?php require dirname($classes) . '/csrf/csrf-magic.php';")
        (root / "phpsessionmanager.inc").write_text("<?php function phpsession_end() {}")
        (root / "head.inc").write_text("<html><head></head><body>")
        (root / "foot.inc").write_text("</body></html>")

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
            result = subprocess.run([php, str(ROOT / "tests/fixtures/gui_request.php"), str(root),
                                     str(classes), page], input=json.dumps(data), text=True,
                                    capture_output=True, check=True)
            assert not result.stderr, result.stderr
            return result.stdout

        html = request("policies", get={"edit": "VOICE"})
        rendered = Choices(html)
        fields = rendered.fields
        assert len(rendered.tokens) == rendered.posts == 2, html
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

        assert "diagnostics.php?policy=VOICE" in request("status")
        assert "diagnostics.php?policy=VOICE" not in request("status", inspect=False)
        sample = {"status": "online", "rtt_ms": 1, "rttsd_ms": 0, "loss_pct": 0}
        policy = {"candidates": {"backup": "Eligible", "01": "Eligible"}, "selected": "backup",
                  "path_status": "alternatives", "eligible_count": 2, "shared_interface": False,
                  "shared_underlay": True, "reason": "Lowest configured cost within SLA"}
        snapshot = {"members": {"backup": sample, "01": sample}, "policies": {"VOICE": policy}}
        fresh = request("status", snapshot=snapshot)
        assert "2 of 2" in fresh and "Members share a transport interface" in fresh
        stale = request("status", snapshot={**snapshot, "generated_at": 1})
        assert "Waiting for current gateway measurements" in stale and "2 of 2" not in stale
        print("ok - native CSRF verifies form posts; status checks permissions, path diversity and sample freshness")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--classes", type=Path, required=True)
    args = parser.parse_args()
    run(args.php, args.classes.resolve())
