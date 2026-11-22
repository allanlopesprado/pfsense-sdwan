#!/usr/bin/env python3
"""Exercise the package supervisor, reload queue and live PF in the VNET lab."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
from pathlib import Path
import platform
import select
import shutil
import socket
import subprocess
import sys
from threading import Event
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from daemon_integration import PKG, ROOT, answer, fixture, stage


def jexec(node, *command, **options):
    return subprocess.run(["jexec", node, *command], capture_output=True, text=True, timeout=12, **options)


def bind_socket(stack, path):
    listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    listener.bind(str(path))
    listener.listen()
    return listener


def config_fixture(work, lan, wan_a, wan_b):
    config = fixture(work)
    config["interfaces"]["lan"] = {"enable": "", "if": lan}
    config["fixture_devices"] = {"lan": lan, "opt1": wan_a, "opt2": wan_b}
    rule = {"tracker": "41001", "type": "pass", "interface": "lan", "ipprotocol": "inet", "protocol": "tcp",
            "source": {"address": "192.0.2.11"}, "destination": {"address": "192.0.2.162", "port": "7"},
            "gateway": "G"}
    guard = dict(rule, tracker="41002", type="block")
    del guard["gateway"]
    config["filter/rule"] = [rule, guard]
    config["gateways/gateway_group"] = [{"name": "G", "item": ["GW_A|1|", "GW_B|2|"]}]
    for gateway, (device, source, hop) in zip(config["gateways/gateway_item"], [
        (wan_a, "198.51.100.1", "198.51.100.2"), (wan_b, "203.0.113.1", "203.0.113.2"),
    ]):
        gateway["gateway"] = hop
        config["interfaces"][gateway["interface"]]["if"] = device
        config["fixture_sources"][device] = source
        config["processes"][gateway["name"]].update(srcip=source, targetip=hop)
    return config


def run(parent, rendered, client, firewall, lan, wan_a, wan_b):
    if platform.system() != "FreeBSD":
        raise RuntimeError("Run only inside the disposable FreeBSD VNET lab")
    work = parent / "recovery"
    work.mkdir()
    stage(work)
    daemon = work / "sdwand.php"
    daemon.write_text(daemon.read_text().replace("/usr/local/pkg/sdwan_steering.inc", str(work / "sdwan_steering.inc")))
    for name in ("sdwan_steering.inc", "sdwan_preflight.inc"):
        shutil.copy(PKG / name, work)
    queue = work / "reload.sock"
    (work / "filter.inc").write_text(
        "<?php\n"
        "function filter_sdwan_binding_api(): int { return 2; }\n"
        "function is_platform_booting(): bool { return false; }\n"
        "function config_path_enabled($section, $key): bool { return false; }\n"
        "function g_get($key, $default) { return $key === 'event_address' ? "
        + json.dumps("unix://" + str(queue)) + " : $default; }\n"
    )
    config = config_fixture(work, lan, wan_a, wan_b)
    settings = work / "fixture.json"
    settings.write_text(json.dumps(config))
    php = ("/usr/local/bin/php", "-n", "-d", "extension=filter", "-d", f"include_path={work}")
    preview = json.loads(jexec(firewall, *php, "-r",
        "require 'sdwan_steering.inc'; echo json_encode(sdwan_steering_preview(sdwan_get_config(), 'calls', 'G'));",
        check=True).stdout)
    assert not preview["errors"], preview
    binding = preview["binding"]
    for key in ("trackers", "gateways"):
        binding[key] = {"item": binding[key]}
    config["gateways/sdwan_bindings"] = {"item": [binding]}
    config["gateways/sdwan_bindings/item"] = [binding]
    saved = json.dumps(config)
    settings.write_text(saved)

    supervisor = work / "supervisor.pid"
    watchdog = work / "watchdog-supervisor.pid"
    child = work / "child.pid"
    log = work / "worker.log"
    rc = work / "sdwand.sh"
    rc.write_text((ROOT / "files/usr/local/etc/rc.d/sdwand.sh").read_text()
                  .replace("/var/run/sdwand.pid", str(supervisor))
                  .replace("/var/run/sdwan-expiry.pid", str(watchdog))
                  .replace("/usr/local/bin/php /usr/local/sbin/sdwand.php --expiry-watchdog",
                           " ".join([*php, str(daemon), "--expiry-watchdog"]))
                  .replace('/usr/local/bin/php /usr/local/sbin/sdwand.php"',
                           " ".join(["-p", str(child), "-o", str(log), *php, str(daemon)]) + '"'))
    snapshot = work / "snapshot.json"
    receipt = work / "snapshot.json.forwarded"

    def load_rules(variant):
        # This queue fixture loads the rules emitted by the reference pfSense
        # compiler. The jail uses its own kernel PF instance and routing table.
        rule = (rendered / f"{variant}.pf").read_text().replace("$LABLAN", lan)
        rule = rule.replace("labwana", wan_a).replace("labwanb", wan_b)
        rules = work / "filter.pf"
        rules.write_text((parent / "before.pf").read_text() + rule + "\n" + (parent / "after.pf").read_text())
        jexec(firewall, "/sbin/pfctl", "-nf", str(rules), check=True)
        jexec(firewall, "/sbin/pfctl", "-f", str(rules), check=True)

    def request(target, marker):
        return jexec(client, "nc", "-n", "-N", "-w", "3", target, "7", input=marker + "\n")

    def scoped_rule():
        active = jexec(firewall, "/sbin/pfctl", "-sr", check=True).stdout.splitlines()
        scoped = [line for line in active if "ridentifier 41001" in line]
        assert len(scoped) == 1, scoped
        return scoped[0]

    with ExitStack() as stack:
        reloads = bind_socket(stack, queue)
        reloads.settimeout(20)
        monitors = {bind_socket(stack, data["socket"]): name for name, data in config["processes"].items()}
        losses = {"GW_A": 0, "GW_B": 0}
        stopped = Event()

        def serve_monitors():
            while not stopped.is_set():
                for listener in select.select(tuple(monitors), [], [], 0.1)[0]:
                    name = monitors[listener]
                    try:
                        answer(listener, f"{name} 20000 1000 {losses[name]}")
                    except (BrokenPipeError, ConnectionResetError):
                        # The test may kill the worker while a probe reply is in flight.
                        pass

        pool = stack.enter_context(ThreadPoolExecutor(max_workers=1))
        replies = pool.submit(serve_monitors)
        stack.callback(replies.result, timeout=5)
        stack.callback(stopped.set)

        def stop_supervisor():
            jexec(firewall, "env", "SDWAN_PACKAGE_REMOVING=1", "/bin/sh", str(rc), "stop")

        def receive_reload(choice=None, *, retiring=False):
            connection, _ = reloads.accept()
            with connection:
                connection.settimeout(1)
                command = b"filter reload"
                assert connection.recv(len(command), socket.MSG_WAITALL) == command
                if retiring:
                    assert not snapshot.exists(), "The interrupted snapshot survived startup retirement"
                else:
                    current = json.loads(snapshot.read_text())
                    assert current["steering"]["G"]["gateway"] == choice, current
                connection.sendall(b"OK\n")

        load_rules("no-member")
        stack.callback(stop_supervisor)
        try:
            jexec(firewall, "/bin/sh", str(rc), "start", check=True)
            receive_reload("GW_A")
            load_rules("path-a")
            old_snapshot = json.loads(snapshot.read_text())
            old_child = child.read_text().strip()
            old_supervisor = supervisor.read_text().strip()
            assert old_child.isdecimal() and int(old_child) > 1

            with subprocess.Popen(["jexec", client, "nc", "-n", "-N", "-w", "35", "192.0.2.162", "7"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1) as held:
                def established_transaction(marker):
                    held.stdin.write(marker + "\n")
                    held.stdin.flush()
                    assert select.select([held.stdout], [], [], 4)[0], f"No reply on the established flow: {marker}"
                    assert held.stdout.readline().strip() == f"198.51.100.1 {marker}"

                established_transaction("before-crash")
                jexec(firewall, "/bin/kill", "-KILL", old_child, check=True)
                losses["GW_A"] = 100
                receive_reload(retiring=True)
                assert supervisor.read_text().strip() == old_supervisor
                assert child.read_text().strip() not in ("", old_child)
                assert scoped_rule().startswith("pass "), "The old pass should stay active until the queued reload"
                load_rules("no-member")
                receive_reload("GW_B")

                # Queue acknowledgement alone does not restore forwarding.
                assert scoped_rule().startswith("block "), "The retired pass survived the filter reload"
                blocked = request("192.0.2.162", "while-retired")
                assert blocked.returncode and not blocked.stdout, blocked
                established_transaction("during-retirement")
                control = request("192.0.2.163", "control-reachable")
                assert control.returncode == 0 and control.stdout.strip() == "198.51.100.1 control-reachable", control

                load_rules("path-b")
                new = request("192.0.2.162", "recovered-on-B")
                assert new.returncode == 0 and new.stdout.strip() == "203.0.113.1 recovered-on-B", new
                established_transaction("after-recovery")

            fresh = json.loads(snapshot.read_text())
            assert fresh["generated_at"] > old_snapshot["generated_at"]
            assert fresh["config_revision"] == old_snapshot["config_revision"] and settings.read_text() == saved
            for _ in range(150):
                if json.loads(receipt.read_text())["confirmed"]:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("The restarted observer did not confirm the recovered PF path")

            # Losing both processes is different from a supervised worker crash.
            # Stopping the publisher cannot change the rule already in the kernel.
            supervisor_pid, worker_pid = supervisor.read_text().strip(), child.read_text().strip()
            assert supervisor_pid != worker_pid and all(
                pid.isdecimal() and int(pid) > 1 for pid in (supervisor_pid, worker_pid))
            jexec(firewall, "/bin/kill", "-STOP", worker_pid, check=True)
            read_current = ("require 'sdwan_steering.inc'; "
                            "echo sdwan_current_snapshot(sdwan_get_config(), sdwan_gateways()) === null ? "
                            "'expired' : 'current';")
            assert jexec(firewall, *php, "-r", read_current, check=True).stdout == "current"
            watchdog_pid = watchdog.read_text().strip()
            assert watchdog_pid.isdecimal()
            jexec(firewall, "/bin/kill", "-TERM", watchdog_pid, check=True)
            jexec(firewall, "/bin/kill", "-KILL", supervisor_pid, worker_pid, check=True)

            stale = json.loads(snapshot.read_text())
            stale["generated_at"] -= 31
            snapshot.write_text(json.dumps(stale))
            assert jexec(firewall, *php, "-r", read_current, check=True).stdout == "expired"
            assert scoped_rule().startswith("pass "), "The test no longer demonstrates the resident-rule limit"
            still_forwarded = request("192.0.2.162", "supervisor-lost")
            assert still_forwarded.returncode == 0 and still_forwarded.stdout.strip() == (
                "203.0.113.1 supervisor-lost"), still_forwarded

            # An independent reload of the emitted guard changes actual PF.
            load_rules("no-member")
            assert scoped_rule().startswith("block ")
            blocked = request("192.0.2.162", "after-independent-reload")
            assert blocked.returncode and not blocked.stdout, blocked
            control = request("192.0.2.163", "control-after-reload")
            assert control.returncode == 0 and control.stdout.strip() == "198.51.100.1 control-after-reload", control
        except Exception:
            if log.is_file():
                print(log.read_text(), file=sys.stderr)
            raise
    print("ok - the real supervisor restarted the killed worker, withdrew the old pass, and confirmed recovery on WAN B")
    print("ok - the loaded guard blocked a new flow while the old state and independent traffic retained WAN A")
    print("ok - loss of the observer and expiry guard left an expired decision forwarding until an independent reload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("rendered", type=Path)
    for name in ("client", "firewall", "lan", "wan_a", "wan_b"):
        parser.add_argument(name)
    args = parser.parse_args()
    run(args.work, args.rendered, args.client, args.firewall, args.lan, args.wan_a, args.wan_b)
