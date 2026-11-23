#!/usr/bin/env python3
"""Exercise supervised startup with a native reload queue and PF read fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1] / "files/usr/local"


def stage(work):
    def install(filename, text=None):
        path = work / Path(filename).name
        path.write_text(text if text is not None else (ROOT / filename).read_text(), encoding="utf-8")

    daemon = (ROOT / "sbin/sdwand.php").read_text()
    for name in ("sdwan.inc", "sdwan_engine.inc", "sdwan_log.inc", "sdwan_steering.inc"):
        daemon = daemon.replace(f"'/usr/local/pkg/{name}'", f"__DIR__ . '/{name}'")
    install("sdwand.php", daemon)
    for name in ("sdwan.inc", "sdwan_log.inc", "sdwan_preflight.inc"):
        install(f"pkg/{name}")
    engine = (ROOT / "pkg/sdwan_engine.inc").read_text()
    install("sdwan_engine.inc", engine.replace("'/var/run/sdwan-observer.json'", "__DIR__ . '/snapshot.json'"))
    install("gwlb.inc", "<?php\nfunction return_gateways_array() { return []; }\n")
    install("functions.inc", "<?php\n")
    install("shaper.inc", "<?php\n")
    install("config.inc", """<?php
        $fixture = json_decode(file_get_contents(__DIR__ . '/fixture.json'), true, 512, JSON_THROW_ON_ERROR);
        function config_get_path($path, $default = null) {
            if (!$GLOBALS['fixture']['bound'] || (!empty($GLOBALS['direct_reload']) && !empty($GLOBALS['fixture']['unbind_after']))) {
                return $default;
            }
            $row = ['trackers' => ['item' => ['301']]];
            if (!empty($GLOBALS['fixture']['expiry'])) {
                $row += ['group' => ['G'], 'policy' => 'p', 'gateways' => ['item' => ['A', 'B']],
                    'policy_revision' => str_repeat('b', 64), 'rules_revision' => str_repeat('c', 64)];
            }
            return match ($path) {
                'gateways/sdwan_bindings/item' => [$row],
                'gateways/sdwan_bindings' => ['item' => [$row]],
                default => $default,
            };
        }
        function config_read_file($backup, $cache) {
            static $reads = 0;
            if (++$reads > $GLOBALS['fixture']['retirement_reads']) {
                echo 'initial observation';
                exit(77);
            }
            return true;
        }
        function config_path_enabled($section, $key) {
            return !empty($GLOBALS['fixture']['filter_disabled']) ||
                (!empty($GLOBALS['direct_reload']) && !empty($GLOBALS['fixture']['disable_after']));
        }
    """)
    install("filter.inc", """<?php
        function filter_sdwan_binding_api(): int { return $GLOBALS['fixture']['abi']; }
        function is_platform_booting(): bool { return $GLOBALS['fixture']['booting']; }
        function filter_sdwan_withdrawal_proof_api(): int { return 1; }
        function filter_sdwan_ruleset_hash(array $rules): string {
            return hash('sha256', json_encode($rules, JSON_THROW_ON_ERROR));
        }
        function g_get($key, $default) { return $key === 'varrun_path' ? __DIR__ : $default; }
        function filter_configure_sync($delete_states = true): void {
            if ($delete_states || !empty($GLOBALS['queued']) || !is_file(SDWAN_SNAPSHOT_PATH)) {
                exit(79);
            }
            echo 'native compiler; ';
            $GLOBALS['direct_reload'] = true;
            $fixture = $GLOBALS['fixture'];
            if (isset($fixture['after_snapshot'])) {
                file_put_contents(SDWAN_SNAPSHOT_PATH, json_encode($fixture['after_snapshot'], JSON_THROW_ON_ERROR));
            }
            if (isset($fixture['native_tracker_rules'])) {
                file_put_contents(__DIR__ . '/sdwan-filter-commit.json', json_encode([
                    'started_ns' => hrtime(true), 'trackers' => $fixture['proof_trackers'] ?? [],
                    'ruleset' => filter_sdwan_ruleset_hash($fixture['native_tracker_rules']),
                ], JSON_THROW_ON_ERROR));
            }
        }
    """)
    steering = (ROOT / "pkg/sdwan_steering.inc").read_text()
    for name, body in {
        "sdwan_steering_request_reload(): bool": """
            if (is_file(SDWAN_SNAPSHOT_PATH) ||
                sdwan_steering_read_receipt(SDWAN_SNAPSHOT_PATH . '.forwarded')['attempts'] < 1) {
                exit(78);
            }
            echo 'requested reload; ';
            $GLOBALS['queued'] = $GLOBALS['fixture']['ack'];
            return $GLOBALS['queued'];
        """,
        "sdwan_steering_pf_rules(): ?array": """
            if (!empty($GLOBALS['direct_reload']) && isset($GLOBALS['fixture']['native_tracker_rules'])) {
                return $GLOBALS['fixture']['native_tracker_rules'];
            }
            if (!empty($GLOBALS['direct_reload']) && !empty($GLOBALS['fixture']['native_applies'])) {
                echo 'verified direct withdrawal';
                return ['block drop in quick on igb0 inet all ridentifier 301',
                    'pass in quick on igb0 inet all ridentifier 401'];
            }
            static $after_reload = 0;
            if (!empty($GLOBALS['queued']) && ++$after_reload >= 2) {
                echo 'verified PF; ';
                return ['block drop in quick on igb0 inet all ridentifier 301',
                    'pass in quick on igb0 inet all ridentifier 401'];
            }
            return $GLOBALS['fixture']['rules'];
        """,
    }.items():
        start = steering.index(f"function {name} {{")
        end = steering.index("\n}", start)
        steering = steering[:start] + f"function {name} {{" + body + steering[end:]
    install("sdwan_steering.inc", steering)


def run(php):
    with tempfile.TemporaryDirectory(prefix="sdwan-start-") as root:
        work = Path(root)
        stage(work)
        state = work / "snapshot.json"
        receipt = work / "snapshot.json.forwarded"
        old_pass = ["pass in log quick on igb0 inet all ridentifier 301 dnpipe 10"]
        existing = {"bound": True, "booting": False, "abi": 2, "ack": True, "retirement_reads": 1,
                    "rules": old_pass}

        def launch(settings, *, paths=False, mode=None, reset=True):
            if reset:
                for path in (state, receipt):
                    path.unlink(missing_ok=True)
                    if paths:
                        path.write_text("previous observation", encoding="utf-8")
            (work / "fixture.json").write_text(json.dumps(settings), encoding="utf-8")
            return subprocess.run([php, "-n", "-d", f"include_path={work}", str(work / "sdwand.php"),
                                   *([mode] if mode else [])], text=True, capture_output=True, timeout=15)

        for paths in (True, False):
            result = launch(existing, paths=paths)
            assert (result.returncode, result.stdout) == (77, "requested reload; verified PF; initial observation"), result
            assert not state.exists() and not receipt.exists()

        result = launch(existing | {"ack": False}, paths=True)
        assert (result.returncode, result.stdout) == (1, "requested reload; "), result
        assert not state.exists() and json.loads(receipt.read_text())["attempts"] == 1

        for attempt in (2, 3):
            result = launch(existing, reset=False)
            assert (result.returncode, result.stdout) == (1, ""), result
            ledger = json.loads(receipt.read_text())
            ledger["requested_at"] = int(time.time()) - 60
            receipt.write_text(json.dumps(ledger))
            result = launch(existing | {"ack": False}, reset=False)
            assert (result.returncode, result.stdout) == (1, "requested reload; "), result
            assert json.loads(receipt.read_text())["attempts"] == attempt

        ledger = json.loads(receipt.read_text())
        ledger["requested_at"] = int(time.time()) - 60
        receipt.write_text(json.dumps(ledger))
        result = launch(existing, reset=False)
        assert (result.returncode, result.stdout) == (1, ""), result
        result = launch(existing | {"rules": []}, reset=False)
        assert (result.returncode, result.stdout) == (77, "initial observation"), result
        assert not receipt.exists()

        launch(existing | {"ack": False}, paths=True)
        ledger = json.loads(receipt.read_text())
        ledger.update(attempts=3, requested_at=int(time.time()) - 301)
        receipt.write_text(json.dumps(ledger))
        result = launch(existing, reset=False)
        assert (result.returncode, result.stdout) == (77, "requested reload; verified PF; initial observation"), result
        assert not receipt.exists()

        result = launch(existing | {"rules": ["pass in quick on igb0 inet all ridentifier 401"]}, paths=False)
        assert (result.returncode, result.stdout) == (77, "initial observation"), result

        for settings, mode in [({"bound": False}, None), ({"booting": True}, None), ({"abi": 0}, None),
                               ({}, "--once")]:
            result = launch(existing | {"retirement_reads": 0} | settings, paths=True, mode=mode)
            assert (result.returncode, result.stdout) == (77, "initial observation"), result
            assert state.exists() and receipt.exists()

        receipt.unlink(missing_ok=True)
        expiry = {"expiry": True, "native_applies": True, "ack": False, "retirement_reads": 2}
        expired = {"generated_at": int(time.time()) - 31, "config_revision": "a" * 64,
                   "members": [], "policies": []}
        for settings, expected in [
            ({}, (0, "native compiler; verified direct withdrawal")),
            ({"native_applies": False}, (1, "native compiler; ")),
            ({"rules": None}, (1, "")),
            ({"rules": ["pass in quick on igb0 inet all ridentifier 401"]}, (0, "")),
            ({"rules": ['pass in quick on igb0 inet all label "ridentifier 301" ridentifier 401']}, (0, "")),
            ({"abi": 0}, (1, "")),
            ({"booting": True}, (0, "")),
            ({"bound": False}, (0, "")),
            ({"filter_disabled": True}, (0, "")),
        ]:
            state.write_text(json.dumps(expired), encoding="utf-8")
            result = launch(existing | expiry | settings, mode="--expiry-reload", reset=False)
            assert (result.returncode, result.stdout) == expected, (settings, result)
            assert json.loads(state.read_text(encoding="utf-8")) == expired
        recent = expired | {"generated_at": int(time.time())}
        for before, settings, expected in [
            (recent, {}, (0, "native compiler; verified direct withdrawal")),
            (expired, {"after_snapshot": recent, "native_applies": False}, (1, "native compiler; ")),
            (expired, {"disable_after": True}, (1, "native compiler; ")),
            (expired, {"unbind_after": True, "native_applies": False}, (1, "native compiler; ")),
            (expired, {"unbind_after": True, "native_tracker_rules": old_pass}, (0, "native compiler; ")),
        ]:
            (work / "sdwan-filter-commit.json").unlink(missing_ok=True)
            state.write_text(json.dumps(before), encoding="utf-8")
            result = launch(existing | expiry | settings, mode="--expiry-reload", reset=False)
            assert (result.returncode, result.stdout) == expected, (settings, result)

        # The native rule after withdrawal may retain the previous tracker.
        # The fixture has no PF commands or traffic, only rule readback and proof.
        state.write_text(json.dumps(recent), encoding="utf-8")
        ledger = {"signature": "a" * 64, "attempts": 0, "requested_at": 0,
                  "accepted": False, "confirmed": False, "trackers": ["301"]}
        withdrawal = {"trackers": ["301"], "unknown": False, "since_ns": 2}
        proof = work / "sdwan-filter-commit.json"
        for saved in (ledger, ledger | {"withdrawal": withdrawal}):
            for options, expected in [
                ({"native_tracker_rules": old_pass}, (0, "native compiler; ")),
                ({"native_tracker_rules": old_pass, "proof_trackers": ["301"]}, (1, "native compiler; ")),
                ({"native_applies": False}, (1, "native compiler; ")),
                ({"rules": None}, (1, "")),
            ]:
                proof.unlink(missing_ok=True)
                receipt.write_text(json.dumps(saved), encoding="utf-8")
                result = launch(existing | expiry | {"bound": False} | options, mode="--expiry-reload", reset=False)
                assert (result.returncode, result.stdout) == expected, (options, result)
                assert json.loads(receipt.read_text(encoding="utf-8")) == saved
        # Valid readback with no removed tracker already confirms withdrawal.
        proof.unlink(missing_ok=True)
        result = launch(existing | expiry | {"bound": False, "rules": []}, mode="--expiry-reload", reset=False)
        assert (result.returncode, result.stdout) == (0, ""), result
    print("ok - supervised startup withdraws stale bound passes and waits for PF before observing")
    print("ok - watchdog verifies current authority and native withdrawal without the observer lock or state flush")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "php")
