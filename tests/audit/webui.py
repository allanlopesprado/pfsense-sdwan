"""Compare the actual dashboard and diagnostics pages using synthetic snapshots."""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
if os.name == "nt":
    sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))
from daemon_integration import php, stage


def stage_pages(directory):
    stage(directory)
    web = ROOT / "files/usr/local/www"
    for name, source in {
        "widget.php": web / "widgets/widgets/sdwan.widget.php",
        "ui.inc.php": web / "sdwan/ui.inc.php",
        "diagnostics.php": web / "sdwan/diagnostics.php",
    }.items():
        (directory / name).write_text(source.read_text(encoding="utf-8").replace(
            "/usr/local/pkg/", directory.as_posix() + "/"), encoding="utf-8")
    (directory / "guiconfig.inc").write_text("""<?php
require_once __DIR__ . '/config.inc';
if (!function_exists('gettext')) { function gettext(string $message): string { return $message; } }
function isAllowedPage($page) { return in_array($page, ['/sdwan/status.php', '/sdwan/diagnostics.php'], true); }
function is_valid_widgetkey($key, $settings, $file) { return $key === 'sdwan-0'; }
function display_top_tabs($tabs) {}
function print_input_errors($errors) { echo implode("\n", $errors); }
function print_info_box($message, $severity) { echo $message; }
""")
    (directory / "service-utils.inc").write_text("""<?php
function find_service_by_name($name) { return config_get_path('service_state') === 'unregistered' ? null : $name; }
function get_service_status($service) { return config_get_path('service_state') === 'running'; }
""")
    for name in ("head.inc", "foot.inc"):
        (directory / name).write_text("")


def observation(case, expected, observed, known=None):
    row = {"id": "webui." + case, "expected": expected, "observed": observed}
    if known is not None:
        row["known_observed"] = known
    return row


def check(binary, directory):
    stage_pages(directory)
    config_path = directory / "fixture.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["installedpackages/sdwan"]["members"]["item"][0]["probe_primary"] = "tcp://192.0.2.50:443"
    config["service_state"] = "running"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    prefix = ("require 'config.inc'; require 'sdwan.inc'; require 'sdwan_engine.inc';"
              "$settings = sdwan_get_config(); $inventory = sdwan_gateways(); ")
    options = ["-d", f"include_path={directory}"]
    base = json.loads(php(binary, *options, "-r", prefix + """
$sample = ['status'=>'online', 'substatus'=>'none', 'delay'=>'5ms', 'stddev'=>'1ms', 'loss'=>'0%'];
$snapshot = sdwan_evaluate($settings, ['GW_A'=>$sample, 'GW_B'=>$sample], time(), $inventory,
    ['a'=>['probe_primary'=>'Passed']]);
$snapshot['config_revision'] = sdwan_config_revision($settings);
$snapshot['gateway_inventory_revision'] = sdwan_gateway_inventory_revision($settings, $inventory);
echo json_encode($snapshot);
"""))
    snapshot_path = directory / "snapshot.json"

    def snapshot(checks, age=0):
        base["generated_at"] = int(time.time()) - age
        if checks is None:
            base["members"]["a"].pop("checks", None)
        else:
            base["members"]["a"]["checks"] = checks
        snapshot_path.write_text(json.dumps(base), encoding="utf-8")

    def render_widget_and_observation():
        script = """
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['ajax'=>'ajax', 'widgetkey'=>'sdwan-0'];
$user_settings = [];
ob_start();
require 'widget.php';
$widget = ob_get_clean();
define('SDWAN_GUI', true);
require 'ui.inc.php';
echo json_encode([str_contains($widget, 'Within SLA'), sdwan_ui_snapshot($sdwan) !== null]);
"""
        widget, page = json.loads(php(binary, *options, "-r", script))
        return f"widget_{'healthy' if widget else 'unavailable'}_status_{'healthy' if page else 'unavailable'}"

    def render_diagnostics():
        try:
            html = php(binary, *options, "-r", "$_GET = []; require 'diagnostics.php';")
        except RuntimeError as error:
            if "gettext()" in str(error) and "array given" in str(error):
                return "gettext_type_error"
            raise
        if "Primary" in html and "Passed" in html:
            return "rendered_passed"
        if "Awaiting evaluation" in html:
            return "rendered_without_current_data"
        return "rendered_unavailable" if "Primary" in html and "Unavailable" in html else "missing_check_status"

    results = []
    for state, age, expected, known in (
        ("running", 0, "widget_healthy_status_healthy", None),
        ("stopped", 0, "widget_unavailable_status_unavailable", "widget_healthy_status_unavailable"),
        ("unregistered", 0, "widget_unavailable_status_unavailable", "widget_healthy_status_unavailable"),
        ("stopped", 45, "widget_unavailable_status_unavailable", None),
        ("running", 45, "widget_unavailable_status_unavailable", None),
    ):
        config["service_state"] = state
        config_path.write_text(json.dumps(config), encoding="utf-8")
        snapshot({"probe_primary": "Passed"}, age)
        results.append(observation(f"service_{state}_{'stale' if age else 'fresh'}", expected,
                                   render_widget_and_observation(), known))

    config["service_state"] = "running"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    snapshot({"probe_primary": "Passed"})
    results.append(observation("service_recovered_with_fresh_sample", "widget_healthy_status_healthy",
                               render_widget_and_observation()))
    for label, checks, age, expected, known in (
        ("valid_check", {"probe_primary": "Passed"}, 0, "rendered_passed", None),
        ("absent_checks", None, 0, "rendered_unavailable", None),
        ("explicit_null_check", {"probe_primary": None}, 0, "rendered_unavailable", None),
        ("scalar_check_container", "Passed", 0, "rendered_unavailable", None),
        ("map_missing_primary_check", {"probe_secondary": "Unavailable"}, 0, "rendered_unavailable", None),
        ("non_string_check_result", {"probe_primary": ["Passed"]}, 0,
         "rendered_without_current_data", "gettext_type_error"),
        ("stale_non_string_check", {"probe_primary": ["Passed"]}, 45,
         "rendered_without_current_data", None),
    ):
        snapshot(checks, age)
        results.append(observation(label, expected, render_diagnostics(), known))
    base["config_revision"] = "0" * 64
    snapshot({"probe_primary": ["Passed"]})
    results.append(observation("non_string_check_from_different_revision", "rendered_without_current_data",
                               render_diagnostics()))
    return results


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="sdwan-webui-audit-") as workspace:
        print(json.dumps(check(os.environ.get("PHP_BIN", "php"), Path(workspace))))
