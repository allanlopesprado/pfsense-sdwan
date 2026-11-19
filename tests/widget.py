#!/usr/bin/env python3
"""Exercise the shipped dashboard include and its separate refresh endpoint."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import time

from daemon_integration import ROOT, php, stage


def check(binary, directory):
    stage(directory)
    for name in ("sdwan_steering.inc", "sdwan_preflight.inc"):
        shutil.copy(ROOT / "files/usr/local/pkg" / name, directory / name)
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
        '/sdwan/diagnostics.php' => in_array($role, ['view', 'manage', 'rules-only', 'groups-only'], true),
        '/sdwan/forwarding.php' => in_array($role, ['manage', 'rules-only', 'groups-only'], true),
        '/firewall_rules.php' => in_array($role, ['manage', 'rules-only'], true),
        '/system_gateway_groups.php' => in_array($role, ['manage', 'groups-only'], true),
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

    for mode, code in (("embed", 200), ("ajax", 403)):
        status, body, link, loaded = render(mode, allowed="no")
        assert status == code and link == "" and not loaded and "permission" in body, mode
    for mode, key in (("get", "sdwan-0"), ("ajax", "other-0"), ("ajax", "sdwan-2")):
        status, body, _, loaded = render(mode, key=key)
        assert status == 400 and not loaded and body == "", (mode, key)
    print("ok - dashboard and refresh require status access and validate the active widget")

    status, body, link, _ = render("embed")
    assert status == 200 and link == "/sdwan/status.php" and "register_ajax" in body
    assert "Waiting for current" in body
    def package_value(expression):
        return php(binary, "-d", f"include_path={directory}", "-r",
                   "require 'sdwan_steering.inc'; require 'config.inc'; echo " + expression + ";")

    config = directory / "fixture.json"
    fixture = json.loads(config.read_text())
    rules = fixture["installedpackages/sdwan"]["policies"]["item"]
    rules[0]["name"] = "Voice"
    rules.extend([dict(rules[0], name="BranchVPN"), dict(rules[0], name="Backups")])
    members = fixture["installedpackages/sdwan"]["members"]["item"]
    members[0]["name"] = "Fiber"
    members[1]["name"] = "Broadband"
    for rule in rules:
        rule["members"] = {"item": ["Fiber", "Broadband"]}
    config.write_text(json.dumps(fixture))
    raw_binding = {"group": "Branch_WAN", "policy": "Voice", "gateways": {"item": ["GW_A", "GW_B"]},
                   "trackers": {"item": ["42"]}, "policy_revision": package_value(
                       "sdwan_steering_policy_revision(sdwan_get_config(), 'Voice')"),
                   "rules_revision": "1" * 64}
    fixture["gateways/sdwan_bindings"] = {"item": [raw_binding]}
    config.write_text(json.dumps(fixture))
    revision = package_value("sdwan_config_revision(sdwan_get_config())")
    binding_revision = package_value("sdwan_config_revision(sdwan_steering_bindings()['Branch_WAN'])")
    runtime = directory / "snapshot.json"
    sample = {"status": "online", "rtt_ms": 2, "rttsd_ms": 0, "loss_pct": 0}
    def policy(selected, fiber, broadband):
        return {"selected": selected, "reason": "SLA evaluation",
                "candidates": {"Fiber": fiber, "Broadband": broadband}}
    snapshot = {
        "generated_at": int(time.time()), "config_revision": revision,
        "members": {"Fiber": sample, "Broadband": sample},
        "policies": {"Voice": policy("Fiber", "Eligible", "Eligible"),
                     "BranchVPN": policy("Broadband", "High RTT", "Eligible"),
                     "Backups": policy(None, "High RTT", "Packet loss")},
        "steering": {"Branch_WAN": {"revision": binding_revision, "gateway": "GW_B"}},
    }
    runtime.write_text(json.dumps(snapshot))
    status, body, _, _ = render("ajax")
    assert status == 200 and "Voice" in body and "<script>" not in body
    assert all(label in body for label in ("2 of 2 eligible", "1 of 2 eligible", "0 of 2 eligible", "No recommendation"))
    assert all(f'class="bg-{state}"' in body for state in ("success", "warning", "danger"))
    assert "Requested gateway" not in body and "Branch_WAN" not in body and "<time datetime=" in body
    assert 'scope="row"' in body and "aria-hidden=" in body and 'href="/sdwan/diagnostics.php?policy=Voice"' in body
    assert 'href="/sdwan/diagnostics.php?' not in render("ajax", "status")[1]
    managed = render("ajax", "manage")[1]
    assert "Recommended member" in managed and "Requested gateway · Branch_WAN" in managed and "GW_B" in managed
    assert "Forwarding requests unavailable." not in managed
    for allowed in ("rules-only", "groups-only"):
        restricted = render("ajax", allowed)[1]
        assert "Voice" in restricted and "Branch_WAN" not in restricted and "GW_B" not in restricted
    preview = render("embed", "manage")[1]
    for changed_state, expected in [
        ({"revision": binding_revision, "gateway": None}, "No gateway requested"),
        ({"revision": binding_revision, "gateway": "<em>foreign</em>"}, "Awaiting request"),
        ({"revision": "0" * 64, "gateway": "GW_B"}, "Awaiting request"),
        ({}, "Awaiting request"),
    ]:
        runtime.write_text(json.dumps(dict(snapshot, steering={"Branch_WAN": changed_state})))
        text = render("ajax", "manage")[1]
        assert expected in text and "<em>" not in text and "GW_B" not in text
    raw_binding["group"] = "<b>changed</b>"
    config.write_text(json.dumps(fixture))
    text = render("ajax", "manage")[1]
    assert "&lt;b&gt;changed&lt;/b&gt;" in text and "<b>changed</b>" not in text
    fixture["gateways/sdwan_bindings"] = {"broken": True}
    config.write_text(json.dumps(fixture))
    assert "Forwarding requests unavailable." in render("ajax", "manage")[1]
    assert "Forwarding requests unavailable." not in render("ajax", "view")[1]
    for changed in (dict(snapshot, generated_at=int(time.time()) - 300),
                    dict(snapshot, config_revision="0" * 64)):
        runtime.write_text(json.dumps(changed))
        assert "Waiting for current" in render("ajax")[1]
    config.write_text("{}")
    assert "No SD-WAN policies configured." in render("ajax")[1]
    config.write_text(json.dumps({"installedpackages/sdwan": {"version": "invalid"}}))
    assert "cannot be read" in render("ajax")[1]
    print("ok - path health, role-scoped requests, stale decisions, unavailable and malformed data")
    return preview, managed


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
