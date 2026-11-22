#!/usr/bin/env python3
"""Audit observer receipts and package readiness without a firewall or network."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
if os.name == "nt":
    # The fixture helpers do not use fcntl. Their other tests use it on Unix.
    sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))
from daemon_integration import PKG, fixture, php, stage


def case(name, expected, observed, known_observed=None):
    result = {"id": "lifecycle." + name, "expected": expected, "observed": observed}
    if known_observed is not None:
        result["known_observed"] = known_observed
    return result


def replace_native_boundary(source, signature, body):
    start = source.index(signature) + len(signature)
    end = source.index("\n}", start)
    return source[:start] + body + source[end:]


def observer(binary, *, two_bindings=False):
    with tempfile.TemporaryDirectory(prefix="sdwan-audit-") as temporary:
        work = Path(temporary)
        stage(work)
        daemon = work / "sdwand.php"
        steering = work / "sdwan_steering.inc"
        daemon.write_text(daemon.read_text().replace("/usr/local/pkg/sdwan_steering.inc", steering.as_posix()))
        shutil.copy(PKG / "sdwan_preflight.inc", work)
        source = (PKG / steering.name).read_text()
        source = replace_native_boundary(source, "function sdwan_steering_pf_rules(): ?array {",
                                         "return config_get_path('fixture_pf_rules');")
        source = replace_native_boundary(
            source, "function sdwan_steering_request_reload(): bool {",
            "file_put_contents(SDWAN_SNAPSHOT_PATH . '.attempts', 'x', FILE_APPEND);"
            "return config_get_path('fixture_reload_accepted', false);")
        steering.write_text(source)
        (work / "filter.inc").write_text(
            "<?php function filter_sdwan_binding_api(): int { return 1; }\n"
            "function is_platform_booting(): bool { return config_get_path('booting', false); }\n")

        config = fixture(work)
        config["processes"] = {}
        config["booting"] = True
        config["interfaces"].update({"lan": {"enable": "", "if": "igb0"},
                                     "opt1": {"enable": "", "if": "igb1"},
                                     "opt2": {"enable": "", "if": "igb2"}})
        groups = [("G", 301, "192.0.2.0/24")]
        if two_bindings:
            groups.append(("H", 311, "198.51.100.0/24"))
        config["gateways/gateway_group"] = []
        config["filter/rule"] = []
        for name, tracker, network in groups:
            rule = {"type": "pass", "interface": "lan", "ipprotocol": "inet", "tracker": str(tracker),
                    "gateway": name, "source": {"address": network}, "destination": {"any": ""}}
            guard = dict(rule, type="block", tracker=str(tracker + 1))
            del guard["gateway"]
            config["gateways/gateway_group"].append({"name": name, "item": ["GW_A|1|", "GW_B|2|"]})
            config["filter/rule"].extend([rule, guard])
        settings = work / "fixture.json"
        settings.write_text(json.dumps(config))

        params = ["-d", f"include_path={work}"]
        include = "require " + json.dumps(steering.as_posix()) + "; "
        rows = []
        for name, _, _ in groups:
            try_binding = f"echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', '{name}'));"
            preview = json.loads(php(binary, *params, "-r", include + try_binding))
            if preview["errors"]:
                raise RuntimeError(preview)
            row = preview["binding"]
            for key in ("trackers", "gateways"):
                row[key] = {"item": row[key]}
            rows.append(row)
        config["gateways/sdwan_bindings"] = {"item": rows}
        config["gateways/sdwan_bindings/item"] = rows

        def observe():
            settings.write_text(json.dumps(config))
            php(binary, *params, str(daemon), "--once")

        observe()
        snapshot = work / "snapshot.json"
        receipt = work / "snapshot.json.forwarded"
        events = work / "snapshot.json.events"
        signature = php(binary, *params, "-r", include +
                        "echo sdwan_steering_runtime_signature(sdwan_read_snapshot(), sdwan_gateways());")
        config["booting"] = False
        receipt.write_text(json.dumps({"signature": signature, "requested_at": int(time.time()) - 3600,
                                       "attempts": 3, "accepted": True, "confirmed": False}))
        if two_bindings:
            return unbind_one_of_two(observe, config, receipt, rows[1])

        # Leave PF unreadable after an old, accepted request for five observations.
        for _ in range(5):
            observe()
        log = json.loads(events.read_bytes())
        reported = "filter_unavailable" in log.get("filter_event_at", {}) or log.get("failure_reported", False)
        results = [case("accepted_with_unreadable_pf", "reported", "reported" if reported else "silent", "silent")]

        # The same receipt is reconciled as soon as PF becomes readable.
        config["fixture_pf_rules"] = ["pass in quick on igb0 inet all ridentifier 301"]
        observe()
        logged = "filter_divergent" in json.loads(events.read_bytes()).get("filter_event_at", {})
        results.append(case("accepted_with_divergent_pf", "reported", "reported" if logged else "silent"))
        config["fixture_pf_rules"] = ["block drop in quick on igb0 inet all ridentifier 301",
                                      "block drop in quick on igb0 inet all ridentifier 302"]
        observe()
        current = json.loads(receipt.read_bytes())
        state = "confirmed_with_fresh_budget" if current["confirmed"] and current["attempts"] == 0 else "unconfirmed"
        results.append(case("pf_recovery", "confirmed_with_fresh_budget", state))

        old = json.loads(snapshot.read_bytes())
        old["generated_at"] = int(time.time()) - 31
        snapshot.write_text(json.dumps(old))
        lookup = php(binary, *params, "-r", include + "echo json_encode(sdwan_read_snapshot());")
        results.append(case("expired_observation", "withdrawn", "withdrawn" if lookup == "null" else "usable"))
        results.extend(unbind_cleanup(observe, config, receipt, events))
        return results


def unbind_cleanup(observe, config, receipt, events):
    # A former steering rule remains loaded after deletion of the last binding.
    config["fixture_pf_rules"] = ["pass in quick on igb0 route-to (igb2 198.51.100.1) inet all ridentifier 301"]
    del config["gateways/sdwan_bindings"]
    del config["gateways/sdwan_bindings/item"]
    events.unlink(missing_ok=True)
    requests = receipt.with_name("snapshot.json.attempts")
    try:
        observe()
    except RuntimeError as error:
        if "Observation failed" not in str(error):
            raise
        replied = json.loads(receipt.read_bytes())
        retained = not replied["accepted"] and replied["attempts"] == 1
    else:
        retained = False
    results = [case("unbind_rejected_cleanup", "retained", "retained" if retained else "lost")]

    # The second queue request is acknowledged but the fixture still has the old PF rule.
    replied = json.loads(receipt.read_bytes())
    replied["requested_at"] = int(time.time()) - 60
    receipt.write_text(json.dumps(replied))
    config["fixture_reload_accepted"] = True
    observe()
    pending = receipt.exists()
    results.append(case("unbind_acknowledged_cleanup", "pending",
                        "pending" if pending else "retired_while_stale", "retired_while_stale"))

    # Subsequent cycles exercise the old receipt after the normal retry interval.
    if pending:
        replied = json.loads(receipt.read_bytes())
        replied["requested_at"] = int(time.time()) - 60
        receipt.write_text(json.dumps(replied))
    count = len(requests.read_bytes())
    for _ in range(5):
        observe()
    log = json.loads(events.read_bytes())
    followed_up = len(requests.read_bytes()) > count or "filter_divergent" in log.get("filter_event_at", {})
    results.append(case("unbind_stale_pf_followup", "reported_or_retried",
                        "reported_or_retried" if followed_up else "passive_while_stale", "passive_while_stale"))

    count = len(requests.read_bytes())
    config["fixture_pf_rules"] = []
    observe()
    results.append(case("unbind_independent_pf_repair", "passive",
                        "passive" if len(requests.read_bytes()) == count else "requested"))
    return results


def unbind_one_of_two(observe, config, receipt, retained_binding):
    g_block = "block drop in quick on igb0 inet all ridentifier 301"
    h_block = "block drop in quick on igb0 inet all ridentifier 311"
    g_guard = g_block.replace("301", "302")
    h_guard = h_block.replace("311", "312")
    config["fixture_pf_rules"] = [g_block, g_guard, h_block, h_guard]
    observe()
    if not json.loads(receipt.read_bytes())["confirmed"]:
        raise RuntimeError("The fixture did not confirm both original bindings")

    # Native tier 1 restores GW_A. Keep the old GW_B path loaded for the removed group.
    g_native = "pass in quick on igb0 route-to (igb1 192.0.2.1) inet all ridentifier 301"
    g_stale = g_native.replace("igb1 192.0.2.1", "igb2 198.51.100.1")
    config["gateways/sdwan_bindings"] = {"item": [retained_binding]}
    config["gateways/sdwan_bindings/item"] = [retained_binding]
    config["fixture_reload_accepted"] = True
    config["fixture_pf_rules"] = [g_stale, g_guard, h_block, h_guard]
    observe()
    observe()
    state = json.loads(receipt.read_bytes())
    results = [case("unbind_partial_stale_tracker", "pending",
                    "confirmed_while_stale" if state["confirmed"] else "pending", "confirmed_while_stale")]

    config["fixture_pf_rules"] = [g_stale, g_guard, h_block.replace("311", "399"), h_guard]
    observe()
    state = json.loads(receipt.read_bytes())
    results.append(case("unbind_partial_remaining_tracker_changed", "pending",
                        "confirmed" if state["confirmed"] else "pending"))

    config["fixture_pf_rules"] = [g_native, g_guard, h_block, h_guard]
    observe()
    state = json.loads(receipt.read_bytes())
    results.append(case("unbind_partial_native_rules_restored", "confirmed",
                        "confirmed" if state["confirmed"] and state["attempts"] == 0 else "pending"))
    return results


SNAPSHOT_FIXTURE = r"""<?php
ob_start();
require 'tests/steering.php';
ob_end_clean();
$current = $before;
$ready = array_replace($snapshot, ['generated_at' => time()]);
$gateways = sdwan_gateways();
$state = $ready['steering']['G'];
$cases = [
    'snapshot_valid_binding' => $ready,
    'snapshot_observation_only' => array_diff_key($ready, ['steering' => true]),
    'snapshot_empty_steering' => array_replace($ready, ['steering' => []]),
    'snapshot_weighted_pool' => array_replace($ready, ['steering' => ['G' => $state + ['pool' => ['A', 'B']]]]),
    'snapshot_blocked_pool' => array_replace($ready, ['steering' => ['G' => array_replace($state, ['gateway' => null, 'pool' => []])]]),
    'snapshot_optional_steering_metadata' => array_replace($ready, ['steering' => ['G' => $state + ['guard' => '302']]]),
    'snapshot_steering_string' => array_replace($ready, ['steering' => 'damaged']),
    'snapshot_steering_group_boolean' => array_replace($ready, ['steering' => ['G' => true]]),
    'snapshot_steering_missing_gateway' => array_replace($ready, ['steering' => ['G' => ['revision' => str_repeat('0', 64)]]]),
    'snapshot_steering_pool_string' => array_replace_recursive($ready, ['steering' => ['G' => ['pool' => 'A']]]),
    'snapshot_steering_null' => array_replace($ready, ['steering' => null]),
    'snapshot_invalid_binding_revision' => array_replace_recursive($ready, ['steering' => ['G' => ['revision' => 'old']]]),
    'snapshot_steering_gateway_boolean' => array_replace_recursive($ready, ['steering' => ['G' => ['gateway' => true]]]),
    'snapshot_steering_pool_map' => array_replace($ready, ['steering' => ['G' => $state + ['pool' => ['first' => 'A']]]]),
    'snapshot_steering_pool_null_entry' => array_replace($ready, ['steering' => ['G' => $state + ['pool' => ['A', null]]]]),
    'snapshot_steering_pool_mismatched_gateway' => array_replace($ready, ['steering' => ['G' => $state + ['pool' => ['B', 'A']]]]),
    'snapshot_steering_pool_duplicate' => array_replace($ready, ['steering' => ['G' => $state + ['pool' => ['A', 'A']]]]),
    'snapshot_malformed_steering_expired' => array_replace($ready, ['generated_at' => time() - 31, 'steering' => 'damaged']),
    'snapshot_wrong_inventory_revision' => array_replace($ready, ['gateway_inventory_revision' => str_repeat('0', 64)]),
    'snapshot_wrong_config_revision' => array_replace($ready, ['config_revision' => str_repeat('0', 64)]),
];
$results = [];
foreach ($cases as $label => $data) {
    file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($data, JSON_THROW_ON_ERROR));
    $sample = sdwan_current_snapshot($config, $gateways);
    $status = $sample === null ? 'discarded' : 'usable';
    if ($sample !== null && isset($sample['steering'])) {
        set_error_handler(static function ($severity, $message): never { throw new ErrorException($message, 0, $severity); });
        try {
            sdwan_steering_runtime_signature($sample, $gateways);
        } catch (Throwable $problem) {
            $status = 'accepted_but_signature_invalid';
        } finally {
            restore_error_handler();
        }
    }
    $results[$label] = $status;
}
echo json_encode($results, JSON_THROW_ON_ERROR);
"""


def snapshots(binary):
    states = run_php_fixture(binary, SNAPSHOT_FIXTURE)
    valid = {"snapshot_valid_binding", "snapshot_observation_only", "snapshot_empty_steering",
             "snapshot_weighted_pool", "snapshot_blocked_pool", "snapshot_optional_steering_metadata"}
    malformed = {"snapshot_steering_string", "snapshot_steering_group_boolean",
                 "snapshot_steering_missing_gateway", "snapshot_steering_pool_string"}
    return [
        case(label, "usable" if label in valid else "discarded", state,
             "accepted_but_signature_invalid" if label in malformed else None)
        for label, state in states.items()
    ]


UPGRADE_FIXTURE = r"""<?php
require 'tests/fixtures/release_curl.php';
$versionFile = tempnam(sys_get_temp_dir(), 'sdwan-version-');
file_put_contents($versionFile, "2.9.2-RELEASE\n");
register_shutdown_function(static function () use ($versionFile): void { unlink($versionFile); });
$source = file_get_contents('files/usr/local/pkg/sdwan_release.inc');
$source = str_replace("'/etc/version'", var_export($versionFile, true), $source, $changes);
if ($changes !== 1) { throw new RuntimeException('Cannot isolate native version path'); }
eval(substr($source, 5));

function try_lock($name, $wait) {
    if ($name !== 'sdwan-package-upgrade' || $wait !== 1) { throw new RuntimeException('Unexpected lock'); }
    return $GLOBALS['lockBusy'] ? false : tmpfile();
}
function unlock($lock): void { fclose($lock); }
function pkg_version_compare($installed, $target): string {
    return ['<', '=', '>'][version_compare($installed, $target) + 1];
}
function pkg_exec($command, &$stdout, &$stderr): int {
    $stdout = $stderr = '';
    if ($command === 'config ABI') {
        $stdout = 'FreeBSD:16:amd64';
    } elseif ($command === 'query %v pfSense-pkg-SDWAN') {
        $stdout = $GLOBALS['version'];
    } elseif (str_starts_with($command, 'query -F ')) {
        $stdout = 'pfSense-pkg-SDWAN 0.4.29 net/pfSense-pkg-SDWAN';
    } elseif (str_starts_with($command, 'add ')) {
        $GLOBALS['adds']++;
        $GLOBALS['version'] = '0.4.29';
    } elseif ($command !== 'check -s pfSense-pkg-SDWAN') {
        throw new RuntimeException('Unexpected fixture command');
    }
    return 0;
}
function mwexec($command, $quiet): int {
    // The supervisor status is the only active command in this fixture.
    // There is no child process or valid observer snapshot.
    return $GLOBALS['supervisorRunning'] && $command === '/usr/local/etc/rc.d/sdwand.sh status' ? 0 : 1;
}

$archive = 'synthetic verified package';
$release_http = fixture_release_http('0.4.29', $archive);
$release_requests = [];
$target = ['version' => '0.4.29', 'sha256' => hash('sha256', $archive)];
$version = '0.4.28';
$adds = 0;
$lockBusy = true;
$supervisorRunning = false;
$locked = sdwan_release_upgrade($target);
if ($adds !== 0 || $release_requests) { throw new RuntimeException('Concurrent request performed work'); }
$lockBusy = false;
$afterInstall = sdwan_release_upgrade($target);
if ($adds !== 1 || $version !== '0.4.29') { throw new RuntimeException('The install fixture did not commit'); }
$retry = sdwan_release_upgrade($target);
if ($adds !== 1) { throw new RuntimeException('The same target installed twice'); }
$version = '0.4.28';
$supervisorRunning = true;
$supervisorOnly = sdwan_release_upgrade($target);
echo json_encode([$locked, $afterInstall, $retry, $supervisorOnly], JSON_THROW_ON_ERROR);
"""


def run_php_fixture(binary, source):
    process = subprocess.run([binary, "-n", "-d", "disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo"],
                             input=source, cwd=ROOT, text=True, capture_output=True, timeout=15)
    if process.returncode:
        raise RuntimeError(f"PHP fixture failed: {process.stderr}{process.stdout}")
    return json.loads(process.stdout)


def upgrade(binary):
    locked, after_install, retry, supervisor_only = run_php_fixture(binary, UPGRADE_FIXTURE)
    return [
        case("upgrade_lock", "busy", locked),
        case("upgrade_verification_when_supervisor_down", "verify", after_install),
        case("upgrade_retry_when_installed_but_unready", "verify", retry, "not_newer"),
        case("upgrade_verification_when_worker_absent", "verify", supervisor_only, "success"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("php", nargs="?", default=os.environ.get("PHP_BIN", "php"))
    args = parser.parse_args()
    print(json.dumps(observer(args.php) + observer(args.php, two_bindings=True) + snapshots(args.php) + upgrade(args.php)))


if __name__ == "__main__":
    main()
