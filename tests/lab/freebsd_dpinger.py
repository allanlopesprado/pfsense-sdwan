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

        def expect_snapshot(expected, choices, checks=None):
            expires = time.monotonic() + 15
            while time.monotonic() < expires:
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError("A real dpinger monitor exited prematurely")
                args = ["-d", "extension=filter", "-d", f"include_path={work}", str(work / "sdwand.php"), "--once"]
                if checks is None:
                    php("php", *args)
                else:
                    jexec(firewall, "/usr/local/bin/php", "-n", *args)
                snapshot = json.loads((work / "snapshot.json").read_text())
                measured = [snapshot["members"][member]["loss_pct"] for member in "abc"]
                selected = [snapshot["policies"][name]["selected"] for name in ("one", "two", "three")]
                results = {name: snapshot["members"][name].get("checks", {}).get("probe_primary")
                           for name in (checks or {})}
                if measured == expected and selected == choices and results == (checks or {}):
                    return
                time.sleep(0.25)
            raise AssertionError(f"Expected loss {expected}, paths {choices} and service checks {checks}; received {snapshot}")

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


        # Keep every gateway responsive while the DNS application on WAN A fails.
        config = json.loads(next_hop_config)
        settings = config["installedpackages/sdwan"]
        members = settings["members"]["item"]
        members[0]["probe_primary"] = f"dns://health.sdwan.test {upstream}"
        backup = "192.0.2.163"
        members[1]["probe_primary"] = f"tcp://{backup}:7"
        config["fixture_devices"] = {"opt1": remote_a[:-1] + "a", "opt2": remote_b[:-1] + "a"}
        config["fixture_sources"].update({
            device: config["fixture_sources"][interface]
            for interface, device in config["fixture_devices"].items()
        })
        for address, peer_gateway in ((upstream, "198.51.100.2"), (backup, "203.0.113.2")):
            jexec(firewall, "route", "-n", "add", "-host", address, peer_gateway)
            cleanup.callback(jexec, firewall, "route", "-n", "delete", "-host", address)
        config_path.write_text(json.dumps(config))
        dns_status = work / "dns-status"
        dns_status.write_text("available")
        ready = work / "dns-ready"
        server = subprocess.Popen(["jexec", peer, sys.executable, "-c", """
import pathlib
import socket
import struct
import sys

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind((sys.argv[1], 53))
    pathlib.Path(sys.argv[3]).touch()
    while True:
        query, source = server.recvfrom(512)
        if len(query) <= 12:
            continue
        available = pathlib.Path(sys.argv[2]).read_text() == "available"
        flags = 0x8180 if available else 0x8183
        header = query[:2] + struct.pack("!HHHHH", flags, 1, int(available), 0, 0)
        data = struct.pack("!HHHIHBBBB", 0xc00c, 1, 1, 30, 4, 192, 0, 2, 42) if available else b""
        server.sendto(header + query[12:] + data, source)
""", upstream, str(dns_status), str(ready)])
        cleanup.callback(stop, server)
        for _ in range(50):
            if ready.exists() or server.poll() is not None:
                break
            time.sleep(.1)
        assert ready.exists() and server.poll() is None, "The isolated DNS server did not start"

        healthy = {"a": "Passed", "b": "Passed"}
        expect_snapshot([0, 0, 0], ["a", "a", "a"], healthy)
        dns_status.write_text("unavailable")
        expect_snapshot([0, 0, 0], [None, "b", "b"], {"a": "DNS check failed", "b": "Passed"})
        print("ok - a DNS application outage selected the TCP-verified backup while all WAN monitors stayed up", flush=True)
        dns_status.write_text("available")
        expect_snapshot([0, 0, 0], ["a", "a", "a"], healthy)
        print("ok - DNS service recovery restored the primary path", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firewall")
    parser.add_argument("peer")
    parser.add_argument("remote_a")
    parser.add_argument("remote_b")
    parser.add_argument("remote_c")
    parser.add_argument("restore", type=Path)
    run(**vars(parser.parse_args()))
