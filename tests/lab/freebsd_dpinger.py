#!/usr/bin/env python3
"""Exercise three real dpinger probes and simultaneous one-, two- and three-link policies."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from daemon_integration import fixture, php, stage


def jexec(node, *args):
    subprocess.run(["jexec", node, *args], check=True, timeout=10)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def run(firewall, peer, remote_a, remote_b, remote_c, restore):
    if platform.system() != "FreeBSD":
        raise RuntimeError("Run only in the disposable FreeBSD VNET topology")
    subprocess.run(["jail", "-m", "name=" + firewall, "allow.raw_sockets"], check=True, timeout=10)
    with tempfile.TemporaryDirectory(prefix="sdwan-dp-", dir="/tmp") as tmp, ExitStack() as cleanup:
        work = Path(tmp)
        stage(work)
        config = fixture(work)
        config["fixture_sources"] = {"opt1": "198.51.100.1", "opt2": "203.0.113.1", "opt3": "192.0.2.129"}
        peers = (
            ("GW_A", "opt1", "198.51.100.2", remote_a),
            ("GW_B", "opt2", "203.0.113.2", remote_b),
            ("GW_C", "opt3", "192.0.2.130", remote_c),
        )
        config["gateways/gateway_item"].append({"name": "GW_C", "interface": "opt3"})
        config["interfaces"]["opt3"] = {"enable": ""}
        config["processes"]["GW_C"] = {"socket": str(work / "GW_C.sock")}
        settings = config["installedpackages/sdwan"]
        settings["members"]["item"].append({"name": "c", "gateway": "GW_C", "cost": "30"})
        settings["policies"]["item"] = [
            {"name": name, "sla": "voice", "strategy": "cost", "members": {"item": members}}
            for name, members in (("one", ["a"]), ("two", ["a", "b"]), ("three", ["a", "b", "c"]))
        ]
        processes = []

        def start_monitor(name, source, target, socket_path, pid_name):
            monitor = subprocess.Popen(["jexec", firewall, "/usr/local/bin/dpinger",
                "-f", "-i", name, "-B", source, "-r", "0", "-s", "100", "-l", "350", "-t", "2000",
                "-p", str(work / pid_name), "-u", socket_path, target], stdout=subprocess.DEVNULL)
            cleanup.callback(stop, monitor)
            processes.append(monitor)

        for gateway, (name, interface, target, _) in zip(config["gateways/gateway_item"], peers):
            source = config["fixture_sources"][interface]
            gateway["gateway"] = target
            config["processes"][name].update(srcip=source, targetip=target)
            socket_path = config["processes"][name]["socket"]
            start_monitor(name, source, target, socket_path, name + ".pid")
        (work / "fixture.json").write_text(json.dumps(config))
        cleanup.callback(jexec, peer, "pfctl", "-f", str(restore))

        upstream = "192.0.2.162"
        source_a = config["fixture_sources"]["opt1"]

        def apply_loss(blocked, upstream_failed=False):
            lines = []
            for name, interface, target, device in peers:
                if name in blocked:
                    source = config["fixture_sources"][interface]
                    lines.append(f"block drop in quick on {device} inet proto icmp from {source} to {target}")
            if upstream_failed:
                lines.append(f"block drop in quick on {remote_a} inet from {source_a} to {upstream}")
            lines.append("pass all no state")
            rules = work / "monitor.pf"
            rules.write_text("\n".join(lines) + "\n")
            jexec(peer, "pfctl", "-f", str(rules))

        def expect_snapshot(expected, choices):
            expires = time.monotonic() + 15
            while time.monotonic() < expires:
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError("A real dpinger monitor exited prematurely")
                php("php", "-d", "extension=filter", "-d", f"include_path={work}", str(work / "sdwand.php"), "--once")
                snapshot = json.loads((work / "snapshot.json").read_text())
                measured = [snapshot["members"][member]["loss_pct"] for member in "abc"]
                selected = [snapshot["policies"][name]["selected"] for name in ("one", "two", "three")]
                if measured == expected and selected == choices:
                    return
                time.sleep(0.25)
            raise AssertionError(f"Expected loss {expected} and paths {choices}; received {snapshot}")

        # Visit every availability combination, change one link at a time,
        # and finish with all links recovered.
        for mask in (0, 1, 3, 2, 6, 7, 5, 4, 0):
            failed = {name for index, (name, _, _, _) in enumerate(peers) if mask & (1 << index)}
            expected = [100 if name in failed else 0 for name, _, _, _ in peers]
            choices = [next((name for name, loss in zip("abc"[:count], expected) if loss == 0), None)
                       for count in (1, 2, 3)]
            apply_loss(failed)
            expect_snapshot(expected, choices)
            print(f"ok - real dpinger loss {expected}; one-, two-, three-link selections {choices}", flush=True)

        def upstream_transaction():
            result = subprocess.run(["jexec", firewall, "nc", "-n", "-N", "-w", "3", "-s", source_a, upstream, "7"],
                                    capture_output=True, text=True, input="upstream-control\n", timeout=6)
            return result.returncode == 0 and result.stdout.strip() == source_a + " upstream-control"

        config_path = work / "fixture.json"
        next_hop_config = config_path.read_text()
        socket_path = str(work / "upstream-a.sock")
        start_monitor("GW_A", source_a, upstream, socket_path, "upstream-a.pid")
        config["gateways/gateway_item"][0]["monitor"] = upstream
        config["processes"]["GW_A"].update(socket=socket_path, targetip=upstream)
        upstream_config = json.dumps(config)
        config_path.write_text(upstream_config)
        expect_snapshot([0, 0, 0], ["a", "a", "a"])
        assert upstream_transaction(), "The upstream echo service did not respond before the outage"

        config_path.write_text(next_hop_config)
        apply_loss(set(), upstream_failed=True)
        assert not upstream_transaction(), "The upstream echo service remained reachable during the outage"
        expect_snapshot([0, 0, 0], ["a", "a", "a"])
        print("ok - the application failed while the preferred WAN's immediate next hop stayed eligible", flush=True)

        config_path.write_text(upstream_config)
        expect_snapshot([100, 0, 0], [None, "b", "b"])
        print("ok - a farther Monitor IP detected the outage and the policy selected the healthy backup", flush=True)
        apply_loss(set())
        expect_snapshot([0, 0, 0], ["a", "a", "a"])
        assert upstream_transaction(), "The upstream application failed to recover"
        print("ok - the upstream application and probe both recovered", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firewall")
    parser.add_argument("peer")
    parser.add_argument("remote_a")
    parser.add_argument("remote_b")
    parser.add_argument("remote_c")
    parser.add_argument("restore", type=Path)
    run(**vars(parser.parse_args()))
