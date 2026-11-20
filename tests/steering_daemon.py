#!/usr/bin/env python3
"""Test the publisher against the pfSense reload service's Unix protocol."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import socket
import tempfile
import time

from daemon_integration import PKG, fixture, php, stage


def run(binary, load_filter_extension):
    with tempfile.TemporaryDirectory(prefix="sdwan-queue-", dir="/tmp") as tmp:
        work = Path(tmp)
        stage(work)
        daemon = work / "sdwand.php"
        installed = "/usr/local/pkg/sdwan_steering.inc"
        assert daemon.read_text().count(installed) == 1
        daemon.write_text(daemon.read_text().replace(installed, str(work / "sdwan_steering.inc")))
        for name in ("sdwan_preflight.inc", "sdwan_steering.inc"):
            shutil.copy(PKG / name, work)
        hook = work / "sdwan_steering.inc"
        source = hook.read_text()
        start = source.index("function sdwan_steering_pf_rules(): ?array {")
        end = source.index("\n}", start)
        hook.write_text(source[:start] + "function sdwan_steering_pf_rules(): ?array {"
                        + "return config_get_path('fixture_pf_rules');" + source[end:])
        event_socket = work / "reload.sock"
        (work / "filter.inc").write_text(
            "<?php\nfunction filter_sdwan_binding_api(): int { return config_get_path('abi', 0); }\n"
            "function is_platform_booting(): bool { return config_get_path('booting', false); }\n"
            "function g_get($key, $default) { return $key === 'event_address' ? "
            + json.dumps("unix://" + str(event_socket)) + " : $default; }\n"
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
        if load_filter_extension:
            params += ["-d", "extension=filter"]
        binding = json.loads(php(binary, *params, "-r",
            f"require {json.dumps(str(work / 'sdwan_steering.inc'))}; "
            "echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', 'G'));"))
        assert binding["errors"] == [], binding
        row = binding["binding"]
        for key in ("trackers", "gateways"):
            row[key] = {"item": row[key]}
        config["gateways/sdwan_bindings"] = {"item": [row]}
        config["gateways/sdwan_bindings/item"] = [row]

        snapshot = work / "snapshot.json"
        receipt = work / "snapshot.json.forwarded"

        def observe(fails=False):
            settings.write_text(json.dumps(config))
            try:
                php(binary, *params, str(daemon), "--once")
            except RuntimeError as error:
                if not fails or "PHP failed (1): sdwand: Observation failed." not in str(error):
                    raise
            else:
                assert not fails, "unconfirmed reload reported success"
            assert json.loads(settings.read_text()) == config
            return json.loads(snapshot.read_text())

        config["abi"] = 0
        assert "steering" not in observe() and not receipt.exists()
        config["abi"] = 1
        config["booting"] = True
        assert observe()["steering"]["G"]["gateway"] is None and not receipt.exists()
        config["booting"] = False
        # The installed rule survived a restart but does not reflect the new block decision.
        config["fixture_pf_rules"] = ['pass in quick on igb0 inet all ridentifier 301']

        def reply(listener, response, delay):
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                command = b"filter reload"
                assert connection.recv(len(command), socket.MSG_WAITALL) == command
                published = json.loads(snapshot.read_text())
                if delay:
                    time.sleep(delay)
                if response is not None:
                    connection.sendall(response)
                return published

        with socket.socket(socket.AF_UNIX) as listener, ThreadPoolExecutor(max_workers=1) as pool:
            listener.settimeout(3)
            listener.bind(str(event_socket))
            listener.listen()

            def exchange(response, *, fails=False, delay=0):
                event = pool.submit(reply, listener, response, delay)
                result = observe(fails)
                assert event.result() == result, "event fired before snapshot publication"

            def make_due():
                data = json.loads(receipt.read_text())
                receipt.write_text(json.dumps(dict(data, at=int(time.time()) - 60)))
                return data

            exchange(b"OK\n")
            first = json.loads(receipt.read_text())
            assert first["attempts"] == 1 and first["accepted"]
            observe()  # A new process inherits the budget and the grace period.
            assert json.loads(receipt.read_text()) == first
            # The native queue accepts a request twice without loading the expected rule.
            make_due()
            exchange(b"OK\n")
            assert json.loads(receipt.read_text())["attempts"] == 2
            make_due()
            exchange(b"OK\n")
            assert json.loads(receipt.read_text())["attempts"] == 3
            make_due()
            observe()
            exhausted = json.loads(receipt.read_text())
            assert exhausted["attempts"] == 3
            event_log = json.loads((work / "snapshot.json.events").read_text())
            assert event_log["forwarding_application"]["G"] == "persistent"

            # Convergence clears the budget. A reboot or service restart alone does not.
            block = 'block drop in quick on igb0 inet all ridentifier 301'
            config["fixture_pf_rules"] = [block]
            assert observe()["forwarding_check"]["G"] == "blocked"
            assert json.loads(receipt.read_text())["attempts"] == 0
            config["fixture_pf_rules"] = None
            observe()
            assert json.loads(receipt.read_text())["attempts"] == 0

            config["fixture_pf_rules"] = [block.replace("igb0", "igb9")]
            exchange(b"ERROR\n", fails=True)
            rejected = json.loads(receipt.read_text())
            assert rejected["attempts"] == 1 and not rejected["accepted"]
            make_due()
            exchange(None, fails=True, delay=.75)
            assert json.loads(receipt.read_text())["attempts"] == 2
            make_due()
            exchange(None, fails=True)
            assert json.loads(receipt.read_text())["attempts"] == 3

            # A genuine config change has a different decision ID and budget.
            config["installedpackages/sdwan"]["slas"]["item"].append(
                {"name": "unused", "latency_ms": "99", "loss_pct": "1"})
            exchange(b"OK\n")
            assert json.loads(receipt.read_text())["attempts"] == 1
            assert json.loads(receipt.read_text())["decision"] != rejected["decision"]

            config["gateways/sdwan_bindings"] = {"item": []}
            config["gateways/sdwan_bindings/item"] = []
            exchange(None, fails=True)
            assert receipt.exists()
            make_due()
            exchange(b"OK\n")
            assert not receipt.exists() and not observe().get("steering")
        print("ok - stock and boot stay passive and no request precedes snapshot publication")
        print("ok - three acknowledged but unapplied requests persist across observer restarts and alert once")
        print("ok - wrong ingress, rejected queue requests and timeout use a bounded budget; convergence resets it")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("php", nargs="?", default="php")
    parser.add_argument("--load-filter-extension", action="store_true")
    args = parser.parse_args()
    run(args.php, args.load_filter_extension)
