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
        assert observe(fails=True)["steering"]["G"]["gateway"] is None and not receipt.exists()

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

            for response, delay in [(b"ERROR\n", 0), (None, 0), (None, 0.75)]:
                exchange(response, fails=True, delay=delay)
                assert not receipt.exists()
            exchange(b"OK\n")
            original = receipt.read_text()
            signature, _, at = original.rpartition(":")
            assert signature.startswith("ack:") and int(at) <= int(time.time())
            observe()  # Even a missing rule gets time for the queue to drain.
            assert receipt.read_text() == original
            receipt.write_text(signature)  # Acknowledgement from before PF verification.
            exchange(b"OK\n")
            assert receipt.read_text().rpartition(":")[0] == signature
            snapshot.unlink()
            exchange(b"OK\n")
            assert receipt.read_text().rpartition(":")[0] == signature

            overdue = f"{signature}:{int(time.time()) - 60}"
            receipt.write_text(overdue)
            observe()  # PF is unavailable. Do not poll the reload queue in a loop.
            assert receipt.read_text() == overdue
            config["fixture_pf_rules"] = ['block drop in quick on igb0 inet all ridentifier 301']
            observe()
            assert receipt.read_text() == overdue
            config["fixture_pf_rules"] = ['pass in quick on igb0 inet all ridentifier 301']
            config["booting"] = True
            observe()
            assert receipt.read_text() == overdue
            config["booting"] = False
            exchange(b"ERROR\n", fails=True)
            assert receipt.read_text() == overdue
            exchange(b"OK\n")
            current_receipt = receipt.read_text()
            assert current_receipt != overdue
            observe()  # The acknowledged retry was recent, so it is not requeued yet.
            assert receipt.read_text() == current_receipt
            config["fixture_pf_rules"] = ['block drop in quick on igb0 inet all ridentifier 301']

            # A revision can change without changing the selected route.
            config["installedpackages/sdwan"]["slas"]["item"].append(
                {"name": "unused", "latency_ms": "99", "loss_pct": "1"})
            exchange(b"ERROR\n", fails=True)
            assert receipt.read_text() == current_receipt
            exchange(b"OK\n")
            new_signature = receipt.read_text().rpartition(":")[0]
            assert new_signature != signature
            assert new_signature.rsplit(":", 1)[1] == signature.rsplit(":", 1)[1]

            config["gateways/sdwan_bindings"] = {"item": []}
            config["gateways/sdwan_bindings/item"] = []
            exchange(None, fails=True)
            assert receipt.exists()
            exchange(b"OK\n")
            assert not receipt.exists() and not observe().get("steering")
        print("ok - stock and boot stay passive; reloads recover from refusal, timeout, EOF and rejected acknowledgement")
        print("ok - overdue or mismatched loaded rules are reconciled without touching disabled or unavailable PF")
        print("ok - acknowledged requests are deduplicated; rejected revisions and unbinding retry")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("php", nargs="?", default="php")
    parser.add_argument("--load-filter-extension", action="store_true")
    args = parser.parse_args()
    run(args.php, args.load_filter_extension)
