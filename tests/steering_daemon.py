#!/usr/bin/env python3
"""Test the real --once publisher and native reload event boundary without PF."""
import json
from pathlib import Path
import shutil
import sys
import tempfile

from daemon_integration import PKG, fixture, php, stage


def run(binary):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        stage(work)
        daemon = work / "sdwand.php"
        installed = "/usr/local/pkg/sdwan_steering.inc"
        assert daemon.read_text().count(installed) == 1
        daemon.write_text(daemon.read_text().replace(installed, str(work / "sdwan_steering.inc")))
        for name in ("sdwan_preflight.inc", "sdwan_steering.inc"):
            shutil.copy(PKG / name, work)
        events = work / "filter-events"
        (work / "filter.inc").write_text(
            "<?php\nfunction filter_sdwan_binding_api(): int { return config_get_path('abi', 0); }\n"
            "function filter_configure(): void { file_put_contents(" + json.dumps(str(events)) +
            ", file_get_contents(" + json.dumps(str(work / "snapshot.json")) + ") . PHP_EOL, FILE_APPEND); }\n"
        )
        config = fixture(work)
        config["processes"] = {}
        config["abi"] = 1
        config["interfaces"].update(
            {"lan": {"enable": "", "if": "igb0"}, "opt1": {"enable": "", "if": "igb1"},
             "opt2": {"enable": "", "if": "igb2"}})
        rule = {"type": "pass", "interface": "lan", "ipprotocol": "inet", "tracker": "301", "gateway": "G",
                "source": {"address": "10.23.0.0/24"}, "destination": {"any": ""}}
        guard = dict(rule, tracker="302", type="block")
        del guard["gateway"]
        config.update({"gateways/gateway_group": [{"name": "G", "item": ["GW_A|1|", "GW_B|2|"]}],
                       "filter/rule": [rule, guard]})
        settings = work / "fixture.json"
        settings.write_text(json.dumps(config))
        params = ["-d", f"include_path={work}"]
        binding = json.loads(php(binary, *params, "-r",
            f"require {json.dumps(str(work / 'sdwan_steering.inc'))}; "
            "echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', 'G'));"))
        assert binding["errors"] == [], binding
        row = binding["binding"]
        for key in ("trackers", "gateways"):
            row[key] = {"item": row[key]}
        config["gateways/sdwan_bindings"] = {"item": [row]}
        config["gateways/sdwan_bindings/item"] = [row]

        def observe():
            settings.write_text(json.dumps(config))
            php(binary, *params, str(daemon), "--once")
            assert json.loads(settings.read_text()) == config
            return json.loads((work / "snapshot.json").read_text())

        config["abi"] = 0
        assert "steering" not in observe() and not events.exists()
        config["abi"] = 1
        denied = observe()
        assert denied["steering"]["G"]["gateway"] is None
        assert json.loads(events.read_text()) == denied, "event fired before snapshot publication"
        observe()
        assert len(events.read_text().splitlines()) == 1, "unchanged choice produced a filter reload"
        (work / "snapshot.json").unlink()
        observe()
        assert len(events.read_text().splitlines()) == 2, "missing prior snapshot must reconcile"
        config["gateways/sdwan_bindings"] = {"item": []}
        config["gateways/sdwan_bindings/item"] = []
        assert not observe()["steering"]
        assert not (work / "snapshot.json.forwarded").exists()
        observe()
        assert len(events.read_text().splitlines()) == 3, "removed binding must reconcile once"
        print("ok - stock stays passive, patched daemon publishes before queuing and deduplicates native reload requests")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "php")
