#!/usr/bin/env python3
"""Exercise the shipped dashboard include and its separate refresh endpoint."""
import json
from pathlib import Path
import sys
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
function isAllowedPage($page) { return $page === '/sdwan/status.php' && $GLOBALS['allowed']; }
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
$allowed = ($allowed === 'yes');
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

    def render(mode, allowed="yes", key="sdwan-0"):
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
    runtime = directory / "snapshot.json"
    revision = php(binary, "-d", f"include_path={directory}", "-r",
                   "require 'sdwan.inc'; echo sdwan_config_revision(sdwan_get_config());")
    # A corrupted runtime file may carry display strings that configuration validation rejects.
    name = "<b>bad</b>"
    snapshot = {"generated_at": int(time.time()), "config_revision": revision,
                "members": {name: {"status": "online", "rtt_ms": 2, "rttsd_ms": 0, "loss_pct": 0}},
                "policies": {"calls": {"selected": name, "candidates": {name: "Eligible"}, "reason": "Eligible"}}}
    runtime.write_text(json.dumps(snapshot))
    status, body, _, _ = render("ajax")
    assert status == 200 and "calls" in body and "&lt;b&gt;" in body
    assert "<b>bad" not in body and "<script>" not in body
    for changed in (dict(snapshot, generated_at=int(time.time()) - 300),
                    dict(snapshot, config_revision="0" * 64)):
        runtime.write_text(json.dumps(changed))
        assert "Waiting for current" in render("ajax")[1]
    config = directory / "fixture.json"
    config.write_text("{}")
    assert "No SD-WAN policies configured." in render("ajax")[1]
    config.write_text(json.dumps({"installedpackages/sdwan": {"version": "invalid"}}))
    assert "cannot be read" in render("ajax")[1]
    print("ok - current, expired, mismatched, missing and invalid data in dashboard and refresh")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp:
        check(sys.argv[1] if len(sys.argv) > 1 else "php", Path(temp))
