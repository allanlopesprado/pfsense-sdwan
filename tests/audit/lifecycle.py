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
        daemon_source = daemon.read_text().replace("/usr/local/pkg/sdwan_steering.inc", steering.as_posix())
        daemon.write_text(daemon_source.replace("$now = time();", "$now = config_get_path('fixture_now', time());"))
        shutil.copy(PKG / "sdwan_preflight.inc", work)
        source = (PKG / steering.name).read_text()
        source = replace_native_boundary(source, "function sdwan_steering_pf_rules(): ?array {",
                                         "return config_get_path('fixture_pf_rules');")
        source = replace_native_boundary(
            source, "function sdwan_steering_request_reload(): bool {",
            "file_put_contents(SDWAN_SNAPSHOT_PATH . '.attempts', 'x', FILE_APPEND);"
            "return config_get_path('fixture_reload_accepted', false);")
        steering.write_text(source)
        shutil.copy(ROOT / "core" / "filter-sdwan.inc", work)
        (work / "filter.inc").write_text(
            "<?php require_once __DIR__ . '/filter-sdwan.inc';\n"
            "function get_label_tags_from_rule_string($rule) {\n"
            "    return preg_match('/ label \"tags=([^\"]+)\"/', $rule, $m) ? explode(' ', $m[1]) : [];\n"
            "}\n"
            "function g_get($key, $default) { return $key === 'varrun_path' ? __DIR__ : $default; }\n"
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
        config["booting"] = False
        if two_bindings:
            signature = php(binary, *params, "-r", include +
                            "echo sdwan_steering_runtime_signature(sdwan_read_snapshot(), sdwan_gateways());")
            receipt.write_text(json.dumps({"signature": signature, "requested_at": int(time.time()) - 3600,
                                           "attempts": 3, "accepted": True, "confirmed": False}))
            return unbind_one_of_two(observe, config, receipt, rows[1])

        def event_times():
            return json.loads(events.read_bytes()).get("filter_event_at", {})

        config["fixture_reload_accepted"] = True
        observe()
        del config["fixture_reload_accepted"]
        acknowledged = receipt.read_bytes()
        pending = json.loads(acknowledged)
        requests = work / "snapshot.json.attempts"
        if requests.read_bytes() != b"x" or not pending["accepted"] or pending["confirmed"]:
            raise RuntimeError("The fixture did not get a pending queue acknowledgement")
        config["fixture_now"] = pending["requested_at"] + 29
        observe()
        results = [case("accepted_unreadable_before_deadline", "quiet",
                        "reported" if "filter_unavailable" in event_times() else "quiet")]

        # PF remains unreadable at the retry deadline and on subsequent observations.
        config["fixture_now"] += 1
        observe()
        unavailable = event_times().get("filter_unavailable")
        results.append(case("accepted_with_unreadable_pf", "reported",
                            "reported" if unavailable is not None else "silent", "silent"))
        for _ in range(4):
            observe()
        unchanged = receipt.read_bytes() == acknowledged and requests.read_bytes() == b"x"
        results.append(case("accepted_unreadable_budget_preserved", "unchanged", "unchanged" if unchanged else "retried"))

        # An exhausted budget alone cannot establish divergence while PF is unreadable.
        pending["attempts"] = 3
        receipt.write_text(json.dumps(pending))
        observe()
        observed = event_times()
        marked = "filter_divergent" in observed or "filter_applied" in observed
        results.append(case("accepted_unreadable_not_verified", "unverified", "verified" if marked else "unverified"))

        # The same receipt is reconciled as soon as PF becomes readable.
        config["fixture_pf_rules"] = ["pass in quick on igb0 inet all ridentifier 301"]
        observe()
        logged = "filter_divergent" in event_times()
        results.append(case("accepted_with_divergent_pf", "reported", "reported" if logged else "silent"))
        config["fixture_pf_rules"] = [
            "block drop in quick on igb0 inet from 192.0.2.0/24 to any ridentifier 301",
            "block drop in quick on igb0 inet from 192.0.2.0/24 to any ridentifier 302",
        ]
        observe()
        current = json.loads(receipt.read_bytes())
        state = "confirmed_with_fresh_budget" if current["confirmed"] and current["attempts"] == 0 else "unconfirmed"
        results.append(case("pf_recovery", "confirmed_with_fresh_budget", state))
        logged = "filter_applied" in event_times() and requests.read_bytes() == b"x"
        results.append(case("pf_recovery_reported_without_reload", "reported", "reported" if logged else "missing"))
        del config["fixture_now"]

        old = json.loads(snapshot.read_bytes())
        old["observed_at_ns"] -= 31_000_000_000
        snapshot.write_text(json.dumps(old))
        lookup = php(binary, *params, "-r", include + "echo json_encode(sdwan_read_snapshot());")
        results.append(case("expired_observation", "withdrawn", "withdrawn" if lookup == "null" else "usable"))
        observe()
        expired_event = event_times().get("sample_expired")
        results.append(case("expired_observation_noticed_on_next_poll", "reported", "reported" if expired_event else "silent"))
        observe()
        results.append(case("fresh_observation_does_not_repeat_expiry", "unchanged",
                            "unchanged" if event_times().get("sample_expired") == expired_event else "repeated"))
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
                        "passive" if len(requests.read_bytes()) == count and not receipt.exists() else "requested"))
    return results


def unbind_one_of_two(observe, config, receipt, retained_binding):
    g_block = "block drop in quick on igb0 inet from 192.0.2.0/24 to any ridentifier 301"
    h_block = "block drop in quick on igb0 inet from 198.51.100.0/24 to any ridentifier 311"
    g_guard = g_block.replace("301", "302")
    h_guard = h_block.replace("311", "312")
    config["fixture_pf_rules"] = [g_block, g_guard, h_block, h_guard]
    observe()
    if not json.loads(receipt.read_bytes())["confirmed"]:
        raise RuntimeError("The fixture did not confirm both original bindings")

    # Native tier 1 restores GW_A. Keep the old GW_B path loaded for the removed group.
    g_native = "pass in quick on igb0 route-to (igb1 192.0.2.1) inet from 192.0.2.0/24 to any ridentifier 301"
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

    native_hash = "bad5555555555555"
    default_deny = (f'block drop inet all label "tags=ruleset:{native_hash}" '
                    'label "descr=Default deny rule IPv4"')
    config["fixture_pf_rules"] = [default_deny, g_native, g_guard, h_block, h_guard]
    journal = receipt.with_name("sdwan-filter-commit.json")
    state = json.loads(receipt.read_bytes())
    since = state.get("withdrawal", {}).get("since_ns", 1)
    for name, proof in (
        ("unbind_native_pf_without_generation", None),
        ("unbind_rejects_previous_generation", {"started_ns": since - 1, "trackers": ["311"], "ruleset": native_hash}),
        ("unbind_rejects_mismatched_ruleset", {"started_ns": since, "trackers": ["311"], "ruleset": "beef000000000000"}),
        ("unbind_rejects_active_withdrawn_tracker", {"started_ns": since, "trackers": ["301", "311"], "ruleset": native_hash}),
    ):
        if proof is None:
            journal.unlink(missing_ok=True)
        else:
            journal.write_text(json.dumps(proof))
        observe()
        pending = json.loads(receipt.read_bytes())
        results.append(case(name, "pending", "confirmed" if pending["confirmed"] else "pending"))
    journal.write_text(json.dumps({"started_ns": since, "trackers": ["311"], "ruleset": native_hash}))
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
$work = {{FIXTURE_DIR}};
define('SDWAN_LOCK_DIRECTORY', $work);
set_include_path($work);
require $work . '/config.inc';
require $work . '/sdwan.inc';
require $work . '/sdwan_engine.inc';
require $work . '/sdwan_release.inc';

function g_get($key, $default) {
    return $key === 'varrun_path' ? $GLOBALS['work'] : $default;
}

function get_package_id($name) {
    return $name === 'SDWAN' ? 0 : -1;
}

function recovery_archive(): string {
    return sdwan_release_recovery_dir() . '/pfSense-pkg-SDWAN-0.4.28.pkg';
}

function finish_recovery_fixture(): void {
    sdwan_release_clear_recovery(sdwan_release_recovery_dir(), recovery_archive());
}

function publish_sample(int $when, bool $valid = true, ?string $version = null, int $pid = 502): void {
    $config = sdwan_get_config();
    $inventory = sdwan_gateways();
    $snapshot = sdwan_evaluate($config, [], $when, $inventory);
    $snapshot['config_revision'] = sdwan_config_revision($config);
    $snapshot['gateway_inventory_revision'] = $valid ?
        sdwan_gateway_inventory_revision($config, $inventory) : str_repeat('0', 64);
    $snapshot['observer'] = ['pid' => $pid, 'version' => $version ?? $GLOBALS['version']];
    file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($snapshot, JSON_THROW_ON_ERROR));
}

function pkg_version_compare($installed, $target): string {
    return ['<', '=', '>'][version_compare($installed, $target) + 1];
}
function pkg_exec($command, &$stdout, &$stderr): int {
    $stdout = $stderr = '';
    if ($command === 'config ABI') {
        $stdout = 'FreeBSD:16:amd64';
    } elseif ($command === 'query %v pfSense-pkg-SDWAN') {
        $stdout = $GLOBALS['version'];
    } elseif (preg_match('~^create -q -o ([\'"])(.+)\\1 pfSense-pkg-SDWAN$~', $command, $arguments)) {
        if ($GLOBALS['backupFails']) {
            return 1;
        }
        file_put_contents($arguments[2] . '/pfSense-pkg-SDWAN-' . $GLOBALS['version'] . '.pkg', 'rollback fixture');
    } elseif (str_starts_with($command, 'info --raw --raw-format json -F ')) {
        $version = str_contains($command, 'pfSense-pkg-SDWAN-0.4.29.pkg') ? '0.4.29' : $GLOBALS['version'];
        $stdout = json_encode(['name' => 'pfSense-pkg-SDWAN', 'version' => $version,
            'origin' => 'net/pfSense-pkg-SDWAN', 'prefix' => '/usr/local', 'abi' => 'FreeBSD:16:*'], JSON_THROW_ON_ERROR);
    } elseif (str_starts_with($command, '-o DEVELOPER_MODE=yes add -f ')) {
        $GLOBALS['rollbacks']++;
        if ($GLOBALS['rollbackFails']) {
            return 1;
        }
        $GLOBALS['version'] = '0.4.28';
        if ($GLOBALS['publishAfterRollback']) {
            publish_sample(time());
        }
    } elseif (str_starts_with($command, '-o DEVELOPER_MODE=yes add ')) {
        $GLOBALS['adds']++;
        $GLOBALS['version'] = '0.4.29';
        if ($GLOBALS['nativeUpgradeWon']) {
            $GLOBALS['version'] = '0.4.30';
            return 1;
        }
        if ($GLOBALS['installFails']) {
            return 1;
        }
        if ($GLOBALS['installHookFails']) {
            $stdout = "pkg-static: POST-INSTALL script failed\n";
        }
        if ($GLOBALS['publishAfterInstall']) {
            publish_sample($GLOBALS['fixture_install_time'] ?? time());
        }
    } elseif ($command === 'check -s pfSense-pkg-SDWAN') {
        return $GLOBALS['filesValid'] && (!$GLOBALS['newFilesInvalid'] || $GLOBALS['version'] !== '0.4.29') ? 0 : 1;
    } else {
        throw new RuntimeException('Unexpected fixture command');
    }
    return 0;
}
function mwexec($command, $quiet): int {
    if ($quiet && $command === '/usr/local/etc/rc.d/sdwand.sh status') {
        $GLOBALS['statusChecks']++;
        return $GLOBALS['supervisorRunning'] ? 0 : 1;
    }
    if ($quiet && str_starts_with($command, '/bin/pgrep -P 501 -u 0 -fx ') &&
        preg_match('~ \| /usr/bin/grep -Fx ([1-9][0-9]*)\z~', $command, $matches)) {
        return $GLOBALS['workerRunning'] && $matches[1] === '502' ? 0 : 1;
    }
    if ($quiet && str_starts_with($command, escapeshellarg(SDWAN_RELEASE_MINISIGN) . ' -Vq -m ')) {
        $GLOBALS['signatureChecks']++;
        return $GLOBALS['signatureMatches'] ? 0 : 1;
    }
    throw new RuntimeException('Unexpected service verification command');
}
function sdwan_log_emit(int $priority, string $message): void {
    $GLOBALS['updateLog'][] = [$priority, $message];
}

$archive = 'synthetic verified package';
$release_http = fixture_release_http('0.4.29', $archive);
$release_requests = [];
$target = ['version' => '0.4.29', 'sha256' => hash('sha256', $archive)];
$version = '0.4.28';
$adds = 0;
$rollbacks = 0;
$backupFails = $rollbackFails = $installFails = $installHookFails = $newFilesInvalid = $nativeUpgradeWon = false;
$updateLog = [];
$statusChecks = 0;
$signatureChecks = 0;
$signatureMatches = false;
$supervisorRunning = true;
$workerRunning = false;
$filesValid = true;
$publishAfterInstall = false;
$publishAfterRollback = $registrationFails = false;
$held = sdwan_lock('sdwan-package-upgrade', 0);
if (!is_resource($held)) { throw new RuntimeException('Could not hold fixture lock'); }
$locked = sdwan_release_upgrade($target);
if ($adds !== 0 || $release_requests) { throw new RuntimeException('Concurrent request performed work'); }
sdwan_unlock($held);
$afterInstall = sdwan_release_upgrade($target);
if ($adds !== 1 || $version !== '0.4.29') { throw new RuntimeException('The install fixture did not commit'); }
if (!is_file(recovery_archive())) { throw new RuntimeException('Unready installation discarded the recovery archive'); }
$release_requests = [];
$retry = sdwan_release_upgrade($target);
$supervisorRunning = true;
publish_sample(time());
$workerAbsentRetry = sdwan_release_upgrade($target, true);
$workerRunning = true;
publish_sample(time() - 31);
$expired = sdwan_release_upgrade($target, true);
publish_sample(time(), false);
$changedSample = sdwan_release_upgrade($target, true);
publish_sample(time());
$verified = sdwan_release_upgrade($target, true);
if (is_file(recovery_archive())) { throw new RuntimeException('A verified installation kept the recovery archive'); }
$filesValid = false;
$corrupt = sdwan_release_upgrade($target, true);
$filesValid = true;
file_put_contents($work . '/supervisor.pid', 'missing');
$invalidPid = sdwan_release_upgrade($target, true);
file_put_contents($work . '/supervisor.pid', "501\n");
$version = '0.4.30';
$downgrade = sdwan_release_upgrade($target);
$version = '0.4.28';
$verifyAfterRollback = sdwan_release_upgrade($target, true);
if ($adds !== 1 || $release_requests) { throw new RuntimeException('A local verification requested a download or install'); }
$workerRunning = false;
$supervisorOnly = sdwan_release_upgrade($target);
finish_recovery_fixture();
$workerRunning = true;
$version = '0.4.28';
publish_sample(time() - 5, true, '0.4.29');
$previousSample = sdwan_release_upgrade($target);
finish_recovery_fixture();
$version = '0.4.28';
$fixture_install_time = time();
publish_sample($fixture_install_time);
$sameSecond = sdwan_release_upgrade($target);
$sameVersionRetry = sdwan_release_upgrade($target, true);
unset($fixture_install_time);
publish_sample(time(), true, '0.4.29', 503);
$previousWorker = sdwan_release_upgrade($target, true);
$legacy = sdwan_read_snapshot();
unset($legacy['observer']);
file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($legacy, JSON_THROW_ON_ERROR));
$unmarked = sdwan_release_upgrade($target, true);
if (sdwan_read_snapshot() === null) { throw new RuntimeException('A legacy sample should still show observation results'); }
finish_recovery_fixture();
$version = '0.4.28';
$publishAfterInstall = true;
$fixture_install_time = time();
$success = sdwan_release_upgrade($target);
$version = '0.4.28';
$backupFails = true;
$count = $adds;
$noBackup = sdwan_release_upgrade($target);
if ($adds !== $count || $rollbacks !== 0) { throw new RuntimeException('Install without usable backup'); }
$backupFails = false;
$installFails = true;
$rollbackAfterError = sdwan_release_upgrade($target);
if ($version !== '0.4.28' || $rollbacks !== 1) { throw new RuntimeException('Previous package not restored'); }
if (!is_file(recovery_archive()) || sdwan_release_upgrade($target) !== 'recovery_pending') {
    throw new RuntimeException('Unverified restoration lost its independently usable archive');
}
finish_recovery_fixture();
$publishAfterRollback = true;
$installFails = false;
$newFilesInvalid = true;
$rollbackAfterIntegrity = sdwan_release_upgrade($target);
if ($version !== '0.4.28' || $rollbacks !== 2) { throw new RuntimeException('Corrupt package not restored'); }
$rollbackFails = true;
$failedRollback = sdwan_release_upgrade($target);
if ($rollbacks !== 3) { throw new RuntimeException('Rollback was not tried'); }
[$priority, $message] = $updateLog[array_key_last($updateLog)];
if ($priority !== LOG_ERR || !preg_match('~Local recovery archive: (.+)$~', $message, $location) ||
    !is_file($location[1]) || file_get_contents($location[1]) !== 'rollback fixture' ||
    (DIRECTORY_SEPARATOR === '/' && (fileperms(dirname($location[1])) & 0777) !== 0700)) {
    throw new RuntimeException('Usable recovery archive was not retained privately');
}
finish_recovery_fixture();
$newFilesInvalid = $rollbackFails = false;
$nativeUpgradeWon = true;
$version = '0.4.28';
$changedExternally = sdwan_release_upgrade($target);
if ($rollbacks !== 3 || $version !== '0.4.30') { throw new RuntimeException('Rollback overwrote a concurrent update'); }
finish_recovery_fixture();
$nativeUpgradeWon = false;
$version = '0.4.28';
$installHookFails = true;
$rollbackAfterHook = sdwan_release_upgrade($target);
if ($rollbacks !== 4 || $version !== '0.4.28') { throw new RuntimeException('Script error with exit zero was ignored'); }
$installHookFails = false;
$supervisorRunning = false;
$statusChecks = 0;
$rollbackAfterInactive = sdwan_release_upgrade($target);
if ($rollbacks !== 5 || $version !== '0.4.28' || $statusChecks !== 4 || !is_file(recovery_archive())) {
    throw new RuntimeException('Inactive service did not trigger a bounded rollback');
}
finish_recovery_fixture();
$supervisorRunning = true;
$registrationFails = true;
$rollbackAfterRegistration = sdwan_release_upgrade($target);
if ($rollbacks !== 6 || $version !== '0.4.28') { throw new RuntimeException('Missing native registration did not trigger rollback'); }
$registrationFails = false;
$version = '0.4.28';
$unsigned = $release_http;
$release_http = fixture_attach_release_signature($release_http, $target['version'], 'signature fixture');
$signatureWithoutKey = sdwan_release_upgrade($target);
if ($signatureChecks !== 0) { throw new RuntimeException('Verification without a trusted key'); }
$version = '0.4.28';
file_put_contents(SDWAN_RELEASE_SIGNING_KEY, 'public key fixture');
$count = $adds;
$rejectedSignature = sdwan_release_upgrade($target);
if ($adds !== $count || $signatureChecks !== 1) { throw new RuntimeException('Invalid signature allowed installation'); }
$signatureMatches = true;
$validSignature = sdwan_release_upgrade($target);
if ($version !== '0.4.29' || $signatureChecks !== 2) { throw new RuntimeException('Published signature ignored'); }
$version = '0.4.28';
$release_http = $unsigned;
$unsignedWithKey = sdwan_release_upgrade($target);
if ($version !== '0.4.29' || $signatureChecks !== 2) { throw new RuntimeException('Unsigned release regressed'); }
echo json_encode([$locked, $afterInstall, $retry, $supervisorOnly, $workerAbsentRetry, $expired,
    $changedSample, $verified, $corrupt, $invalidPid, $downgrade, $verifyAfterRollback, $previousSample,
    $sameSecond, $sameVersionRetry, $previousWorker, $unmarked, $success, $noBackup, $rollbackAfterError,
    $rollbackAfterIntegrity, $failedRollback, $changedExternally, $rollbackAfterHook, $rollbackAfterInactive, $rollbackAfterRegistration,
    $signatureWithoutKey, $rejectedSignature,
    $validSignature, $unsignedWithKey], JSON_THROW_ON_ERROR);
"""


def run_php_fixture(binary, source):
    process = subprocess.run([binary, "-n", "-d", "disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo"],
                             input=source, cwd=ROOT, text=True, capture_output=True, timeout=15)
    if process.returncode:
        raise RuntimeError(f"PHP fixture failed: {process.stderr}{process.stdout}")
    return json.loads(process.stdout)


def upgrade(binary):
    with tempfile.TemporaryDirectory(prefix="sdwan-audit-upgrade-") as temporary:
        work = Path(temporary)
        stage(work)
        config = work / "config.inc"
        native_config = config.read_text().replace("return !$backup && $cache;", "return !$backup;")
        native_config = native_config.replace("return $config[$path] ?? $default;", """return match ($path) {
            'installedpackages/package/0/version' => $GLOBALS['version'],
            'installedpackages/package/0/configurationfile' => 'sdwan.xml',
            'installedpackages/menu' => [['configfile' => 'sdwan.xml', 'url' => '/sdwan/status.php', 'section' => 'Services']],
            'installedpackages/service' => $GLOBALS['registrationFails'] && $GLOBALS['version'] === '0.4.29' ?
                [] : [['name' => 'sdwan', 'rcfile' => 'sdwand.sh']],
            default => $config[$path] ?? $default,
        };""")
        config.write_text(native_config)
        (work / "pfsense-version").write_text("2.9.2-RELEASE\n")
        (work / "supervisor.pid").write_text("501\n")
        release = (PKG / "sdwan_release.inc").read_text()
        minisign = work / "minisign"
        minisign.touch(mode=0o700)
        for source, fixture_name in [("/etc/version", "pfsense-version"), ("/var/run/sdwand.pid", "supervisor.pid"),
                                     ("/conf/sdwan-minisign.pub", "minisign.pub"), ("/usr/local/bin/minisign", "minisign")]:
            release = release.replace(source, (work / fixture_name).as_posix())
        release = release.replace("!is_executable(SDWAN_RELEASE_MINISIGN)", "!is_file(SDWAN_RELEASE_MINISIGN)")
        release = release.replace("sys_get_temp_dir() . '/sdwan-upgrade-'", "__DIR__ . '/sdwan-upgrade-'")
        release = release.replace("$installed_since = time();", "$installed_since = $GLOBALS['fixture_install_time'] ?? time();")
        if os.name == "nt":
            # Windows lacks POSIX mode bits. Treat the tempfile's inherited private ACL as the fixture boundary.
            release = release.replace("(fileperms($directory) & 0777) !== 0700", "false")
        (work / "sdwan_release.inc").write_text(release)
        observed = run_php_fixture(binary, UPGRADE_FIXTURE.replace("{{FIXTURE_DIR}}", json.dumps(work.as_posix())))
    expected = [
        ("upgrade_lock", "busy", None),
        ("upgrade_verification_before_first_sample", "verify", None),
        ("upgrade_retry_when_installed_but_unready", "verify", "not_newer"),
        ("upgrade_verification_when_worker_absent", "verify", "success"),
        ("upgrade_local_retry_when_worker_absent", "verify", None),
        ("upgrade_local_retry_with_expired_sample", "verify", None),
        ("upgrade_local_retry_after_gateway_change", "verify", None),
        ("upgrade_local_retry_when_observer_recovers", "verified", None),
        ("upgrade_local_retry_with_corrupt_installed_files", "verify_files", None),
        ("upgrade_local_retry_with_invalid_supervisor_pid", "verify", None),
        ("upgrade_rejects_downgrade", "not_newer", None),
        ("upgrade_local_retry_after_rollback", "not_newer", None),
        ("upgrade_does_not_confirm_pre_install_sample", "verify", None),
        ("upgrade_rejects_same_second_prior_version_sample", "verify", "success"),
        ("upgrade_reverification_rejects_prior_version_sample", "verify", "verified"),
        ("upgrade_reverification_rejects_previous_worker_sample", "verify", None),
        ("upgrade_reverification_rejects_unmarked_sample", "verify", None),
        ("upgrade_verifies_fresh_post_install_sample", "success", None),
        ("upgrade_requires_usable_rollback_archive", "backup", None),
        ("upgrade_preserves_archive_until_restored_service_is_ready", "rollback_verify", None),
        ("upgrade_restores_previous_package_on_integrity_error", "rolled_back", None),
        ("upgrade_reports_a_failed_restore", "rollback_failed", None),
        ("upgrade_preserves_a_concurrent_native_upgrade", "rollback_changed", None),
        ("upgrade_restores_previous_package_on_post_install_script_error", "rolled_back", None),
        ("upgrade_retains_archive_after_inactive_service", "rollback_verify", None),
        ("upgrade_restores_previous_package_after_missing_native_registration", "rolled_back", None),
        ("upgrade_without_pinned_key_preserves_checksum_path", "success", None),
        ("upgrade_rejects_invalid_published_signature_with_pinned_key", "signature", None),
        ("upgrade_accepts_valid_published_signature_with_pinned_key", "success", None),
        ("upgrade_accepts_unsigned_release_with_pinned_key", "success", None),
    ]
    return [case(name, value, result, known) for (name, value, known), result in zip(expected, observed, strict=True)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("php", nargs="?", default=os.environ.get("PHP_BIN", "php"))
    args = parser.parse_args()
    print(json.dumps(observer(args.php) + observer(args.php, two_bindings=True) + snapshots(args.php) + upgrade(args.php)))


if __name__ == "__main__":
    main()
