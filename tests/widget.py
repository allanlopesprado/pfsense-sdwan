#!/usr/bin/env python3
"""Exercise the shipped dashboard include and its separate refresh endpoint."""
import argparse
import json
from pathlib import Path
import tempfile
import time

from daemon_integration import PKG, ROOT, php, stage


def check(binary, directory):
    stage(directory)
    (directory / "sdwan_preflight.inc").write_bytes((PKG / "sdwan_preflight.inc").read_bytes())
    steering = (PKG / "sdwan_steering.inc").read_text()
    begin = steering.index("function sdwan_steering_pf_rules(): ?array {")
    end = steering.index("\n}", begin)
    (directory / "sdwan_steering.inc").write_text(
        steering[:begin] + "function sdwan_steering_pf_rules(): ?array {"
        + "return config_get_path('fixture_pf_rules');" + steering[end:])
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
        '/sdwan/diagnostics.php' => in_array($role, ['view', 'manage', 'admin'], true),
        '/sdwan/forwarding.php' => in_array($role, ['manage', 'admin'], true),
        '/firewall_rules.php', '/system_gateway_groups.php', '/sdwan/policies.php' => $role === 'admin',
        default => false,
    };
}
function filter_sdwan_binding_api() { return 2; }
function is_valid_widgetkey($key, $settings, $file) {
    return in_array($key, $settings, true) && basename($file) === 'sdwan.widget.php';
}
""")
    (directory / "service-utils.inc").write_text("""<?php
function find_service_by_name($name) { return $name; }
function get_service_status($service) { return config_get_path('fixture_service_running', true); }
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

    def render(mode, allowed="admin", key="sdwan-0"):
        return json.loads(php(binary, "-d", f"include_path={directory}",
                              "-d", "arg_separator.output=&amp;", "-r", script, "--", mode, allowed, key))

    def package_value(expression):
        return php(binary, "-d", f"include_path={directory}", "-r",
                   "require 'sdwan.inc'; require 'config.inc'; require 'sdwan_steering.inc'; echo " + expression + ";")

    for mode, code in (("embed", 200), ("ajax", 403)):
        status, body, link, loaded = render(mode, allowed="no")
        assert status == code and link == "" and not loaded and "permission" in body, mode
    for mode, key in (("get", "sdwan-0"), ("ajax", "other-0"), ("ajax", "sdwan-2")):
        status, body, _, loaded = render(mode, key=key)
        assert status == 400 and not loaded and body == "", (mode, key)
    print("ok - dashboard and refresh require status access and validate the active widget")

    status, body, link, _ = render("embed")
    assert status == 200 and link == "/sdwan/status.php" and "register_ajax" in body
    assert "Monitor only" in body and "No current data" in body and "GW_A" not in body
    assert "<time" not in body and "Last sample" not in body

    config = directory / "fixture.json"
    fixture = json.loads(config.read_text())
    fixture["interfaces"]["opt1"]["if"] = "igb0"
    fixture["interfaces"]["opt2"]["if"] = "igb1"
    fixture["interfaces"]["lan"] = {"enable": "", "if": "igb2"}
    fixture["fixture_devices"] = {"opt1": "igb0", "opt2": "igb1", "lan": "igb2"}
    settings = fixture["installedpackages/sdwan"]
    rules = settings["policies"]["item"]
    rules[0]["name"] = "Voice"
    rules.extend([dict(rules[0], name="BranchVPN"), dict(rules[0], name="Backups"),
                  dict(rules[0], name="Lab")])
    groups = {"Voice": "LAN_SDWAN", "BranchVPN": "PRIVATE_VPN", "Backups": "BACKUP_NET"}
    bindings = []
    fixture["gateways/gateway_group"] = []
    fixture["filter/rule"] = []

    def register_binding(policy, group, tracker, host):
        fixture["gateways/gateway_group"].append({"name": group, "item": ["GW_A|1|", "GW_B|1|"]})
        rule = {"type": "pass", "interface": "lan", "tracker": str(tracker), "gateway": group,
                "ipprotocol": "inet", "source": {"address": host}, "destination": {"any": ""}}
        guard = dict(rule, type="block", tracker=str(tracker + 100))
        del guard["gateway"]
        fixture["filter/rule"].extend([rule, guard])
        config.write_text(json.dumps(fixture))
        preflight = json.loads(package_value(f"json_encode(sdwan_steering_preview(sdwan_get_config(), '{policy}', '{group}'))"))
        assert not preflight["errors"], preflight
        approved = preflight["binding"]
        for key in ("gateways", "trackers"):
            approved[key] = {"item": approved[key]}
        bindings.append(approved)

    for index, (policy, group) in enumerate(groups.items(), 1):
        register_binding(policy, group, 300 + index, f"203.0.113.{index}")
    fixture["gateways/sdwan_bindings"] = {"item": bindings}
    fixture["fixture_pf_rules"] = [
        'pass in quick on igb2 route-to (igb1 198.51.100.1) inet from 203.0.113.1 to any label "gw=1:LAN_SDWAN" label "descr=Voice" ridentifier 301',
        'pass in quick on igb2 route-to (igb0 192.0.2.1) inet from 203.0.113.2 to any label "gw=1:PRIVATE_VPN" ridentifier 302',
        'block drop in quick on igb2 inet from 203.0.113.3 to any ridentifier 303',
        *[f'block drop in quick on igb2 inet from 203.0.113.{index} to any ridentifier {400 + index}'
          for index in (1, 2, 3)],
    ]
    config.write_text(json.dumps(fixture))
    revision = package_value("sdwan_config_revision(sdwan_get_config())")
    runtime = directory / "snapshot.json"
    samples = {
        "a": {"status": "online", "rtt_ms": 23.45, "rttsd_ms": 11.4, "loss_pct": 0},
        "b": {"status": "online", "rtt_ms": 9.8, "rttsd_ms": 0, "loss_pct": 0},
    }

    def policy(selected, a, b):
        count = [a, b].count("Eligible")
        return {"selected": selected, "reason": "SLA evaluation", "candidates": {"a": a, "b": b},
                "eligible_count": count, "path_status": ("no_eligible", "degraded", "alternatives")[count],
                "shared_interface": False, "shared_underlay": False}

    def binding_revision(group):
        return package_value(f"sdwan_config_revision(sdwan_steering_bindings()['{group}'])")

    snapshot = {
        "generated_at": int(time.time()), "config_revision": revision, "members": samples,
        "gateway_inventory_revision": package_value("sdwan_gateway_inventory_revision(sdwan_get_config(), sdwan_gateways())"),
        "policies": {"Voice": policy("a", "Eligible", "Eligible"),
                     "BranchVPN": policy("b", "High RTT", "Eligible"),
                     "Backups": policy(None, "High RTT", "Packet loss"),
                     "Lab": policy("b", "High RTT", "Eligible")},
        "steering": {
            "LAN_SDWAN": {"gateway": "GW_B", "candidate": "GW_A", "revision": binding_revision("LAN_SDWAN")},
            "PRIVATE_VPN": {"gateway": "GW_B", "revision": binding_revision("PRIVATE_VPN")},
            "BACKUP_NET": {"gateway": None, "revision": binding_revision("BACKUP_NET")},
        },
    }

    def save(override=None):
        current = dict(snapshot, generated_at=int(time.time()))
        current.update(override or {})
        runtime.write_text(json.dumps(current))

    def row(html, name):
        return next(part for part in html.split("<tr>")[2:] if name in part.split("</th>")[0])

    save()
    status, body, _, _ = render("ajax")
    assert status == 200 and "<script>" not in body
    assert "Backup: GW_A" in row(body, "Voice") and "GW_B" in row(body, "Voice"), row(body, "Voice")
    assert "Applied" in row(body, "Voice") and "bg-success" in row(body, "Voice")
    assert "Rules pending" in row(body, "BranchVPN") and "GW_B" not in row(body, "BranchVPN")
    assert "Blocked" in row(body, "Backups") and "No eligible link" in row(body, "Backups")
    assert "Monitor only" in row(body, "Lab") and "GW_B" not in row(body, "Lab")
    assert "Egress for new connections" in body and 'scope="row"' in body
    assert all(label not in body for label in ("<time", "Last sample", ">RTT<", "23.450ms", "192.0.2.1", "Preferred:"))
    assert '/sdwan/forwarding.php?policy=Voice&amp;group=LAN_SDWAN' in body
    assert '/sdwan/diagnostics.php?policy=Lab' in body
    fixture["fixture_service_running"] = False
    config.write_text(json.dumps(fixture))
    stopped = render("ajax")[1]
    assert "No current data" in stopped and "Applied" not in stopped and "GW_B" not in stopped
    fixture.pop("fixture_service_running")
    guard = fixture["fixture_pf_rules"].pop(3)
    config.write_text(json.dumps(fixture))
    assert "Rules pending" in row(render("ajax")[1], "Voice")
    fixture["fixture_pf_rules"].insert(3, guard)
    config.write_text(json.dumps(fixture))
    restricted = render("ajax", "view")[1]
    assert "Within SLA" in row(restricted, "Voice") and "No eligible link" in row(restricted, "Backups")
    assert all(label not in restricted for label in ("LAN_SDWAN", "GW_B", "Applied", "/sdwan/forwarding.php"))
    assert 'href="/sdwan/diagnostics.php?policy=Voice"' in restricted
    assert 'href="/sdwan/diagnostics.php?' not in render("ajax", "status")[1]
    assert "/sdwan/forwarding.php" not in render("ajax", "manage")[1]
    preview = render("embed")[1]

    for changed in ({"generated_at": int(time.time()) - 300}, {"config_revision": "0" * 64}):
        save(changed)
        stale = render("ajax")[1]
        assert "No current data" in stale and all(label not in stale for label in ("GW_B", "Applied", "Blocked"))
    save()
    fixture["gateways/gateway_item"][0]["monitor"] = "192.0.2.55"
    config.write_text(json.dumps(fixture))
    retargeted = render("ajax")[1]
    assert "No current data" in retargeted and "GW_B" not in retargeted
    fixture["gateways/gateway_item"][0].pop("monitor")
    config.write_text(json.dumps(fixture))
    gateway = fixture["gateways/gateway_item"].pop(0)
    config.write_text(json.dumps(fixture))
    removed = render("ajax")[1]
    assert "No current data" in removed and all(label not in removed for label in ("GW_A", "GW_B", "Applied"))
    fixture["gateways/gateway_item"].insert(0, {**gateway, "monitor_disable": ""})
    config.write_text(json.dumps(fixture))
    disabled = render("ajax")[1]
    assert "No current data" in disabled and all(label not in disabled for label in ("GW_A", "GW_B", "Applied"))
    fixture["gateways/gateway_item"][0] = gateway
    config.write_text(json.dumps(fixture))

    def voice_paths(voice):
        save({"policies": dict(snapshot["policies"], Voice=voice)})

    voice_paths(dict(snapshot["policies"]["Voice"], shared_underlay=True))
    shared = row(render("ajax")[1], "Voice")
    assert "Shared link" in shared and "Backup:" not in shared
    voice_paths(policy("b", "High RTT", "Eligible"))
    assert "No SLA backup" in row(render("ajax")[1], "Voice")
    voice_paths(policy("a", "Eligible", "High RTT"))
    assert "Outside SLA" in row(render("ajax")[1], "Voice")
    voice_paths({"selected": "a", "reason": "Incomplete snapshot", "candidates": {"a": "Eligible"}})
    assert "No SLA backup" not in row(render("ajax")[1], "Voice")
    save()

    pool = ('pass in quick on igb2 route-to { (igb1 198.51.100.1), (igb0 192.0.2.1) } round-robin '
            'inet from 203.0.113.1 to any label "gw=1:LAN_SDWAN" ridentifier 301')
    fixture["fixture_pf_rules"][0] = pool
    config.write_text(json.dumps(fixture))
    multipath = dict(snapshot["steering"], LAN_SDWAN=dict(snapshot["steering"]["LAN_SDWAN"], pool=["GW_B", "GW_A"]))
    save({"steering": multipath})
    balanced = row(render("ajax")[1], "Voice")
    assert "Applied" in balanced and "GW_B, GW_A" in balanced and "Backup:" not in balanced
    save({"steering": dict(snapshot["steering"], LAN_SDWAN="unreadable")})
    invalid = render("ajax")[1]
    assert "No current data" in invalid and "Applied" not in invalid

    register_binding("Voice", "OPT_SDWAN", 305, "203.0.113.5")
    fixture["fixture_pf_rules"].extend([
        'pass in quick on igb2 route-to (igb0 192.0.2.1) inet from 203.0.113.5 to any label "gw=1:OPT_SDWAN" ridentifier 305',
        'block drop in quick on igb2 inet from 203.0.113.5 to any ridentifier 405',
    ])
    config.write_text(json.dumps(fixture))
    multipath["OPT_SDWAN"] = {"gateway": "GW_A", "revision": binding_revision("OPT_SDWAN")}
    save({"steering": multipath})
    multi = render("ajax")[1]
    assert multi.count("policy=Voice") == 2 and "LAN_SDWAN</small>" in multi and "OPT_SDWAN</small>" in multi

    fixture["fixture_pf_rules"] = None
    config.write_text(json.dumps(fixture))
    assert "Rules unverified" in row(render("ajax")[1], "Voice")
    fixture["gateways/sdwan_bindings"] = {"item": [{"group": "Invalid"}]}
    config.write_text(json.dumps(fixture))
    assert "Bindings unreadable" in row(render("ajax")[1], "Voice")
    fixture["gateways/sdwan_bindings"] = {"item": bindings}
    settings["policies"]["item"] = [rule for rule in rules if rule["name"] != "Voice"]
    config.write_text(json.dumps(fixture))
    orphaned = render("ajax")[1]
    assert 'href="/sdwan/forwarding.php">Review Forwarding' in orphaned and "policy that no longer exists" in orphaned
    assert "policy=Voice" not in orphaned and "Applied" not in orphaned
    assert "policy that no longer exists" not in render("ajax", "view")[1]
    settings.pop("policies")
    config.write_text(json.dumps(fixture))
    orphaned = render("ajax")[1]
    assert "policy that no longer exists" in orphaned and "No SD-WAN policies configured" in orphaned
    config.write_text("{}")
    assert "No SD-WAN policies configured." in render("ajax")[1]
    config.write_text(json.dumps({"installedpackages/sdwan": {"version": "invalid"}}))
    assert "cannot be read" in render("ajax")[1]
    print("ok - verified egress and standby paths, stale data, native gateway drift and role-scoped orphan warnings")
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
