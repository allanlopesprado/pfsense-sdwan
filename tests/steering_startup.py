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
    install("gwlb.inc", "<?php\n")
    install("config.inc", """<?php
        $fixture = json_decode(file_get_contents(__DIR__ . '/fixture.json'), true, 512, JSON_THROW_ON_ERROR);
        function config_get_path($path, $default) {
            return $path === 'gateways/sdwan_bindings/item' && $GLOBALS['fixture']['bound']
                ? [['trackers' => ['item' => ['301']]]] : $default;
        }
        function config_read_file($backup, $cache) {
            static $reads = 0;
            if (++$reads > $GLOBALS['fixture']['retirement_reads']) {
                echo 'initial observation';
                exit(77);
            }
            return true;
        }
        function config_path_enabled($section, $key) { return false; }
    """)
    install("filter.inc", """<?php
        function filter_sdwan_binding_api(): int { return $GLOBALS['fixture']['abi']; }
        function is_platform_booting(): bool { return $GLOBALS['fixture']['booting']; }
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
        old_pass = ["pass in quick on igb0 inet all ridentifier 301"]
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

        result = launch(existing | {"rules": ["pass in quick on igb0 inet all ridentifier 401"]}, paths=False)
        assert (result.returncode, result.stdout) == (77, "initial observation"), result

        for settings, mode in [({"bound": False}, None), ({"booting": True}, None), ({"abi": 0}, None),
                               ({}, "--once")]:
            result = launch(existing | {"retirement_reads": 0} | settings, paths=True, mode=mode)
            assert (result.returncode, result.stdout) == (77, "initial observation"), result
            assert state.exists() and receipt.exists()
    print("ok - supervised startup withdraws stale bound passes and waits for PF before observing")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "php")
