#!/usr/bin/env python3
"""Exercise the shipped dashboard include and its separate refresh endpoint."""
import argparse
import json
from pathlib import Path
import tempfile
import time

from daemon_integration import ROOT, php, stage


def check(binary, directory):
    stage(directory)
    widget = ROOT / "files/usr/local/www/widgets"
    source = (widget / "widgets/sdwan.widget.php").read_text()
    (directory / "sdwan.widget.php").write_text(source.replace("/usr/local/pkg/", f"{directory}/"))
    (directory / "metadata.inc").write_bytes((widget / "include/sdwan.inc").read_bytes())
    (directory / "guiconfig.inc").write_text("""<?php
if (!function_exists('gettext')) { function gettext($s) { return $s; } }
function isAllowedPage($page) {
    $role = $GLOBALS['allowed'];
    return match ($page) {
        '/sdwan/status.php' => $role !== 'no',
        '/sdwan/diagnostics.php' => $role === 'view',
        default => false,
    };
}
function is_valid_widgetkey($key, $settings, $file) {
    return in_array($key, $settings, true) && basename($file) === 'sdwan.widget.php';
}
""")
    script = """error_reporting(E_ALL);
set_error_handler(function ($n, $s) {
    if (error_reporting() & $n) { throw new ErrorException($s); }
    return false;
});
require 'guiconfig.inc';
[$mode, $allowed, $key] = array_slice($argv, 1);
$user_settings = ['sdwan-0'];
if ($mode === 'embed') { $widgetkey = 'sdwan-0'; }
$_SERVER['REQUEST_METHOD'] = $mode === 'get' ? 'GET' : 'POST';
$_POST = ['ajax' => 'ajax', 'widgetkey' => $key];
require 'metadata.inc';
ob_start();
require 'sdwan.widget.php';
$body = ob_get_clean();
echo json_encode([http_response_code() ?: 200, $body, $sdwan_title_link,
                  function_exists('sdwan_read_snapshot')]);"""

    def render(mode, allowed="view", key="sdwan-0"):
        return json.loads(php(binary, "-d", f"include_path={directory}",
                              "-r", script, "--", mode, allowed, key))

    def package_value(expression):
        return php(binary, "-d", f"include_path={directory}", "-r",
                   "require 'sdwan.inc'; require 'config.inc'; echo " + expression + ";")

    for mode, code in (("embed", 200), ("ajax", 403)):
        status, body, link, loaded = render(mode, allowed="no")
        assert status == code and link == "" and not loaded and "permission" in body, mode
    for mode, key in (("get", "sdwan-0"), ("ajax", "other-0"), ("ajax", "sdwan-2")):
        status, body, _, loaded = render(mode, key=key)
        assert status == 400 and not loaded and body == "", (mode, key)
    print("ok - dashboard and refresh require status access and validate the active widget")

    status, body, link, _ = render("embed")
    assert status == 200 and link == "/sdwan/status.php" and "register_ajax" in body
    assert "GW_A" in body and "GW_B" in body and body.count("No data") == 2
    assert "<time" not in body and "Last sample" not in body

    config = directory / "fixture.json"
    fixture = json.loads(config.read_text())
    settings = fixture["installedpackages/sdwan"]
    rules = settings["policies"]["item"]
    rules[0]["name"] = "Voice"
    rules.extend([dict(rules[0], name="BranchVPN"), dict(rules[0], name="Backups")])
    fixture["interfaces"]["opt3"] = {"enable": ""}
    fixture["gateways/gateway_item"].append({"name": "GW_C", "gateway": "203.0.113.1", "interface": "opt3"})
    settings["members"]["item"].append({"name": "c", "gateway": "GW_C", "cost": "30"})
    fixture["gateways/sdwan_bindings"] = {"item": [{"group": "PrivateForwardingGroup"}]}
    config.write_text(json.dumps(fixture))
    revision = package_value("sdwan_config_revision(sdwan_get_config())")
    runtime = directory / "snapshot.json"
    samples = {
        "a": {"status": "degraded", "rtt_ms": 23.45, "rttsd_ms": 11.4, "loss_pct": 2},
        "b": {"status": "online", "rtt_ms": 9.8, "rttsd_ms": 0, "loss_pct": 0},
        "c": {"status": "down", "rtt_ms": 0, "rttsd_ms": 0, "loss_pct": 100},
    }

    def policy(selected, a, b):
        return {"selected": selected, "reason": "SLA evaluation", "candidates": {"a": a, "b": b}}

    snapshot = {
        "generated_at": int(time.time()), "config_revision": revision, "members": samples,
        "policies": {"Voice": policy("a", "Eligible", "Eligible"),
                     "BranchVPN": policy("b", "High RTT", "Eligible"),
                     "Backups": policy(None, "High RTT", "Packet loss")},
        "steering": {"PrivateForwardingGroup": {"gateway": "PrivateGateway"}},
    }
    runtime.write_text(json.dumps(snapshot))
    status, body, _, _ = render("ajax")
    assert status == 200 and "<script>" not in body
    for label in ("GW_A", "GW_B", "GW_C", "23.45 ms", "9.8 ms", "2%", "0%", "100%",
                  "Warning", "Online", "Down", "Preferred:", "No eligible path:"):
        assert label in body, label
    assert ">0 ms<" not in body
    assert 'class="table table-striped table-hover table-condensed"' in body and 'scope="row"' in body
    assert all(label not in body for label in ("<time", "Last sample", "Requested gateway",
                                               "PrivateForwardingGroup", "PrivateGateway", "Forwarding requests"))
    assert 'href="/sdwan/diagnostics.php?policy=Voice"' in body
    restricted = render("ajax", "status")[1]
    assert 'href="/sdwan/diagnostics.php?' not in restricted and "Voice" in restricted
    preview = render("embed")[1]

    for changed in (dict(snapshot, generated_at=int(time.time()) - 300),
                    dict(snapshot, config_revision="0" * 64)):
        runtime.write_text(json.dumps(changed))
        stale = render("ajax")[1]
        assert stale.count("No data") == 3
        assert "23.45 ms" not in stale and "Preferred:" not in stale and "No eligible path:" not in stale

    runtime.write_text(json.dumps(snapshot))
    fixture["gateways/gateway_item"][0]["monitor_disable"] = ""
    fixture["gateways/gateway_item"][1]["force_down"] = ""
    del fixture["interfaces"]["opt3"]
    config.write_text(json.dumps(fixture))
    unavailable = render("ajax")[1]
    assert "Unmonitored" in unavailable and unavailable.count("> Down</td>") == 2
    assert all(label not in unavailable for label in ("23.45 ms", "9.8 ms", "100%", "Preferred:"))

    fixture["gateways/gateway_item"][0].pop("monitor_disable")
    fixture["gateways/gateway_item"][1].pop("force_down")
    fixture.pop("installedpackages/sdwan")
    config.write_text(json.dumps(fixture))
    native = {"generated_at": int(time.time()), "members": [], "policies": [],
              "config_revision": package_value("sdwan_config_revision(sdwan_get_config())"),
              "gateway_inventory_revision": package_value("sdwan_config_revision(sdwan_gateways())"),
              "gateways": {"GW_A": samples["a"], "GW_B": samples["b"]}}
    runtime.write_text(json.dumps(native))
    native_dashboard = render("ajax")[1]
    assert "GW_A" in native_dashboard and "GW_B" in native_dashboard and "23.45 ms" in native_dashboard
    assert "GW_C" not in native_dashboard and "Preferred:" not in native_dashboard
    assert "<time" not in native_dashboard
    runtime.write_text(json.dumps(dict(native, gateways={"GW_A": dict(samples["a"], loss_pct=800)})))
    assert "23.45 ms" not in render("ajax")[1]
    fixture["gateways/gateway_item"][0]["monitor"] = "192.0.2.2"
    config.write_text(json.dumps(fixture))
    runtime.write_text(json.dumps(native))
    assert render("ajax")[1].count("No data") == 2
    config.write_text("{}")
    assert "No available gateways." in render("ajax")[1]
    config.write_text(json.dumps({"installedpackages/sdwan": {"version": "invalid"}}))
    assert "cannot be read" in render("ajax")[1]
    print("ok - gateway telemetry with or without policies, SLA hints, stale data and role-scoped diagnostic links")
    return preview, body


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("php", nargs="?", default="php")
    parser.add_argument("--visual-core", type=Path, help="Pinned pfSense source checkout")
    parser.add_argument("--screenshots", type=Path, help="Save dashboard theme screenshots and layout metrics")
    args = parser.parse_args()
    if bool(args.visual_core) != bool(args.screenshots):
        parser.error("--visual-core and --screenshots must be supplied together")
    with tempfile.TemporaryDirectory() as temp:
        preview, refresh = check(args.php, Path(temp))
        if args.visual_core:
            from fixtures.widget_preview import verify_dashboard_layout
            verify_dashboard_layout(args.visual_core, args.screenshots, preview, refresh)
