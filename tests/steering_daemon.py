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
        passive = observe()
        assert "steering" not in passive and not receipt.exists()
        assert passive["timing"] == {"policy_evaluation_ns": passive["timing"]["policy_evaluation_ns"]}
        assert passive["observed_at_ns"] <= passive["timing"]["policy_evaluation_ns"]
        config["abi"] = 1
        config["booting"] = True
        assert observe()["steering"]["G"]["gateway"] is None and not receipt.exists()
        config["booting"] = False
        assert observe(fails=True)["steering"]["G"]["gateway"] is None

        def read_receipt():
            return json.loads(receipt.read_text())

        def retry_due():
            previous = read_receipt()
            previous["requested_at"] = int(time.time()) - 60
            receipt.write_text(json.dumps(previous))
            return previous

        assert read_receipt()["attempts"] == 1 and not read_receipt()["accepted"]

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

            bad_rule = 'pass in quick on igb0 inet all ridentifier 301'
            block_rule = 'block drop in quick on igb0 inet from 10.23.0.0/24 to any ridentifier 301'
            guard_rule = 'block drop in quick on igb0 inet from 10.23.0.0/24 to any ridentifier 302'
            config["fixture_pf_rules"] = [bad_rule]

            # Refusal and EOF consume attempts even without an acknowledgement.
            for response in [b"ERROR\n", None]:
                retry_due()
                exchange(response, fails=True)
            exhausted = retry_due()
            assert exhausted["attempts"] == 3 and not exhausted["accepted"]
            observe()
            assert read_receipt() == exhausted
            events = json.loads((work / "snapshot.json.events").read_text())
            assert "filter_divergent" in events["filter_event_at"]

            # A native reload can repair the rules independently. The observer
            # confirms PF and renews the budget without requesting another reload.
            config["fixture_pf_rules"] = [block_rule, guard_rule]
            proof = observe()
            confirmed = read_receipt()
            assert confirmed["confirmed"] and confirmed["attempts"] == 0
            timing = proof["timing"]
            assert (proof["observed_at_ns"] <= timing["policy_evaluation_ns"]
                    <= timing["steering_decision_ns"] <= timing["pf_readback_ns"])

            # A later divergence starts a new bounded recovery cycle.
            config["fixture_pf_rules"] = [bad_rule]
            exchange(None, fails=True, delay=0.75)
            assert read_receipt()["attempts"] == 1
            retry_due()
            exchange(b"OK\n")
            accepted = read_receipt()
            assert accepted["accepted"] and not accepted["confirmed"] and accepted["attempts"] == 2
            observe()
            assert read_receipt() == accepted

            # Acknowledged, unresolved reloads also stop after three attempts.
            retry_due()
            exchange(b"OK\n")
            overdue = retry_due()
            assert overdue["attempts"] == 3 and not overdue["confirmed"]
            del config["fixture_pf_rules"]
            observe()
            assert read_receipt() == overdue
            config["fixture_pf_rules"] = [bad_rule]
            config["booting"] = True
            observe()
            assert read_receipt() == overdue
            config["booting"] = False
            observe()
            assert read_receipt() == overdue

            config["fixture_pf_rules"] = [block_rule, guard_rule]
            observe()
            assert read_receipt()["confirmed"] and read_receipt()["attempts"] == 0

            # Config revision changes are new decisions even if the route is unchanged.
            old_signature = read_receipt()["signature"]
            config["installedpackages/sdwan"]["slas"]["item"].append(
                {"name": "unused", "latency_ms": "99", "loss_pct": "1"})
            exchange(b"OK\n")
            assert read_receipt()["signature"] != old_signature and read_receipt()["attempts"] == 1
            observe()
            assert read_receipt()["confirmed"]

            receipt.write_text("ack:legacy-receipt")
            exchange(b"OK\n")
            assert read_receipt()["attempts"] == 1

            config["gateways/sdwan_bindings"] = {"item": []}
            config["gateways/sdwan_bindings/item"] = []
            exchange(None, fails=True)
            assert receipt.exists()
            retry_due()
            exchange(b"OK\n")
            assert read_receipt()["withdrawal"]["trackers"] == ["301"]
            assert not read_receipt()["confirmed"]
            config["fixture_pf_rules"] = []
            assert not observe().get("steering")
            assert not receipt.exists() and not observe().get("steering")
        print("ok - stock and boot stay passive; rejected and acknowledged requests have a bounded retry budget")
        print("ok - PF confirmation resets the budget; divergent rules and expired receipts are reported")
        print("ok - duplicate reloads, unavailable PF and legacy receipts are handled without modifying configuration")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("php", nargs="?", default="php")
    parser.add_argument("--load-filter-extension", action="store_true")
    args = parser.parse_args()
    run(args.php, args.load_filter_extension)
