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


def observer(binary):
    with tempfile.TemporaryDirectory(prefix="sdwan-audit-") as temporary:
        work = Path(temporary)
        stage(work)
        daemon = work / "sdwand.php"
        steering = work / "sdwan_steering.inc"
        daemon.write_text(daemon.read_text().replace("/usr/local/pkg/sdwan_steering.inc", steering.as_posix()))
        shutil.copy(PKG / "sdwan_preflight.inc", work)
        source = (PKG / steering.name).read_text()
        start = source.index("function sdwan_steering_pf_rules(): ?array {")
        end = source.index("\n}", start)
        steering.write_text(source[:start] + "function sdwan_steering_pf_rules(): ?array {"
                            + "return config_get_path('fixture_pf_rules');" + source[end:])
        (work / "filter.inc").write_text(
            "<?php function filter_sdwan_binding_api(): int { return 1; }\n"
            "function is_platform_booting(): bool { return config_get_path('booting', false); }\n")

        config = fixture(work)
        config["processes"] = {}
        config["booting"] = True
        config["interfaces"].update({"lan": {"enable": "", "if": "igb0"},
                                     "opt1": {"enable": "", "if": "igb1"},
                                     "opt2": {"enable": "", "if": "igb2"}})
        rule = {"type": "pass", "interface": "lan", "ipprotocol": "inet", "tracker": "301", "gateway": "G",
                "source": {"address": "192.0.2.0/24"}, "destination": {"any": ""}}
        guard = dict(rule, type="block", tracker="302")
        del guard["gateway"]
        config["gateways/gateway_group"] = [{"name": "G", "item": ["GW_A|1|", "GW_B|2|"]}]
        config["filter/rule"] = [rule, guard]
        settings = work / "fixture.json"
        settings.write_text(json.dumps(config))

        params = ["-d", f"include_path={work}"]
        include = "require " + json.dumps(steering.as_posix()) + "; "
        try_binding = "echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', 'G'));"
        preview = json.loads(php(binary, *params, "-r", include + try_binding))
        if preview["errors"]:
            raise RuntimeError(preview)
        row = preview["binding"]
        for key in ("trackers", "gateways"):
            row[key] = {"item": row[key]}
        config["gateways/sdwan_bindings"] = {"item": [row]}
        config["gateways/sdwan_bindings/item"] = [row]

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
        config["fixture_pf_rules"] = ["block drop in quick on igb0 inet all ridentifier 301"]
        observe()
        current = json.loads(receipt.read_bytes())
        state = "confirmed_with_fresh_budget" if current["confirmed"] and current["attempts"] == 0 else "unconfirmed"
        results.append(case("pf_recovery", "confirmed_with_fresh_budget", state))

        old = json.loads(snapshot.read_bytes())
        old["generated_at"] = int(time.time()) - 31
        snapshot.write_text(json.dumps(old))
        lookup = php(binary, *params, "-r", include + "echo json_encode(sdwan_read_snapshot());")
        results.append(case("expired_observation", "withdrawn", "withdrawn" if lookup == "null" else "usable"))
        return results


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


def upgrade(binary):
    process = subprocess.run([binary, "-n", "-d", "disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo"],
                             input=UPGRADE_FIXTURE, cwd=ROOT, text=True, capture_output=True, timeout=15)
    if process.returncode:
        raise RuntimeError(f"Upgrade fixture failed: {process.stderr}{process.stdout}")
    locked, after_install, retry, supervisor_only = json.loads(process.stdout)
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
    print(json.dumps(observer(args.php) + upgrade(args.php)))


if __name__ == "__main__":
    main()
