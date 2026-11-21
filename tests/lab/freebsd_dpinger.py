#!/usr/bin/env python3
"""Exercise three real dpinger probes and simultaneous one-, two- and three-link policies."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core_adapter import render_harness, test_config
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


def start_dns_server(peer, address, status_path, ready_path, cleanup):
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
""", address, str(status_path), str(ready_path)])
    cleanup.callback(stop, server)
    for _ in range(50):
        if ready_path.exists() or server.poll() is not None:
            break
        time.sleep(.1)
    assert ready_path.exists() and server.poll() is None, f"The isolated DNS server on {address} did not start"


def verify_erp(work, core, rules_dir, client, lan, firewall, peer, remote_a, remote_b,
               upstream, standby_probe, config, expect_snapshot, cleanup):
    """Observe isolated endpoint loss and load the filter generator's output."""
    adapter = test_config(work, "inet", 2, False)
    config["filter/rule"] = adapter["filter/rule"][:2]
    config["filter/rule"][0]["descr"] = "erp-policy"
    config["gateways/gateway_group"] = adapter["gateways/gateway_group"]
    config["interfaces"]["lan"] = {"enable": "", "if": lan}
    config["reload_gateways"] = {}
    for gateway in config["gateways/gateway_item"][:2]:
        interface = gateway["interface"]
        device = config["fixture_devices"][interface]
        config["interfaces"][interface]["if"] = device
        config["reload_gateways"][gateway["name"]] = {
            "interface": device, "ipprotocol": "inet", "address": gateway["gateway"], "online": True,
        }
    # Both native monitors remain up. Supply the same first-tier group inventory
    # that the stock gateway-group resolver would pass to filter_generate_gateways().
    native_primary = config["gateways/gateway_group"][0]["item"][0].split("|")[0]
    native_path = config["reload_gateways"][native_primary]
    config["reload_groups"] = {"G": [{
        "gw": native_primary, "int": native_path["interface"], "gwip": native_path["address"], "weight": 1,
    }]}
    settings = config["installedpackages/sdwan"]
    app_policy = adapter["installedpackages/sdwan"]["policies"]["item"][0]
    app_policy["service_check_mode"] = "primary"
    settings["policies"]["item"].append(app_policy)
    for member, target in zip(settings["members"]["item"], (upstream, standby_probe)):
        member["probe_primary"] = f"tcp://{target}:7"
    for member, address, gateway in zip(settings["members"]["item"],
            ("192.0.2.166", "192.0.2.167"), ("198.51.100.2", "203.0.113.2")):
        jexec(peer, "ifconfig", "lo0", "inet", f"{address}/32", "alias")
        cleanup.callback(jexec, peer, "ifconfig", "lo0", "inet", address, "-alias")
        jexec(firewall, "route", "-n", "add", "-host", address, gateway)
        cleanup.callback(jexec, firewall, "route", "-n", "delete", "-host", address)
        start_dns_server(peer, address, work / "dns-status", work / f"dns-{address}.ready", cleanup)
        member["probe_secondary"] = f"dns://health.sdwan.test {address}"
    backup_service = "192.0.2.165"
    jexec(peer, "ifconfig", "lo0", "inet", f"{backup_service}/32", "alias")
    cleanup.callback(jexec, peer, "ifconfig", "lo0", "inet", backup_service, "-alias")
    config_path = work / "fixture.json"
    config_path.write_text(json.dumps(config))

    def render(operation):
        return php("/usr/local/bin/php", "-d", "extension=filter", "-d", "extension=mbstring",
                   "-d", "extension=ctype",
                   str(Path(__file__).resolve().parents[1] / "fixtures/native_filter.php"),
                   str(work), str(core), operation)

    preview = json.loads(render("preview"))
    assert not preview["errors"], preview
    binding = preview["binding"]
    binding["group"] = [binding["group"]]
    for key in ("trackers", "gateways"):
        binding[key] = {"item": binding[key]}
    config["gateways/sdwan_bindings"] = {"item": [binding]}
    config["gateways/sdwan_bindings/item"] = [binding]
    config_path.write_text(json.dumps(config))

    def load_policy():
        generated = json.loads(render("render-pair"))
        rules = work / "erp-firewall.pf"
        rules.write_text("\n".join([
            f'LABLAN = "{lan}"', *generated["macros"], (rules_dir / "before.pf").read_text(),
            f'pass in quick on {lan} inet proto udp from 192.0.2.11 to {upstream} port 53',
            *generated["rules"], (rules_dir / "after.pf").read_text(),
        ]) + "\n")
        jexec(firewall, "pfctl", "-nf", str(rules))
        jexec(firewall, "pfctl", "-f", str(rules))

    def set_service_loss(*devices):
        # Keep the independent backup service, UDP DNS and ICMP flowing.
        rules = work / "erp-peer.pf"
        rules.write_text("\n".join([
            f'block drop in quick on {dev} inet proto tcp to {{ {upstream}, {standby_probe} }} '
            f'port 7 label "erp-drop-{dev}"' for dev in devices
        ] + ["pass all no state", ""]))
        jexec(peer, "pfctl", "-f", str(rules))

    def transaction(node, target, marker, source=None):
        args = ["jexec", node, "nc", "-n", "-N", "-w", "3"]
        if source:
            args.extend(["-s", source])
        return subprocess.run([*args, target, "7"], capture_output=True, text=True,
                              input=marker + "\n", timeout=6).stdout.strip()

    def check_dns():
        jexec(client, "/usr/local/bin/php", "-n", "-r", '''
            require $argv[1];
            $socket = stream_socket_client("udp://{$argv[2]}:53", timeout: 2);
            if ($socket === false || !stream_set_timeout($socket, 2)) { exit(1); }
            $id = random_int(0, 65535);
            $question = sdwan_probe_dns_question("health.sdwan.test");
            $query = pack("nnnnnn", $id, 0x0100, 1, 0, 0, 0) . $question;
            if (fwrite($socket, $query) !== strlen($query)) { exit(1); }
            $reply = fread($socket, 512);
            if (!is_string($reply) || !sdwan_probe_dns_answer($reply, $id, $question) ||
                !str_ends_with($reply, inet_pton("192.0.2.42"))) { exit(1); }
        ''', str(work / "sdwan_probe.inc"), upstream)

    def packets(node, label):
        result = subprocess.run(["jexec", node, "pfctl", "-s", "labels"],
                                capture_output=True, text=True, check=True, timeout=10)
        counters = [fields[-7] for line in result.stdout.splitlines()
                    if len(fields := line.split()) >= 9 and label in fields[:-8]]
        assert counters, (label, result.stdout)
        return sum(map(int, counters))

    def default_path():
        route = subprocess.check_output(["jexec", firewall, "route", "-n", "get", "default"],
                                        text=True, timeout=10)
        return [line.strip() for line in route.splitlines()
                if line.strip().startswith(("gateway:", "interface:"))]

    healthy = {"a": "Passed", "b": "Passed"}
    failed_a = {"a": "Timed out", "b": "Passed"}
    failed_both = {"a": "Timed out", "b": "Timed out"}

    def converge(checks, expected_gateway):
        # Each legacy policy keeps WAN1 because its secondary DNS check passes.
        snapshot = expect_snapshot([0, 0, 0], ["a", "a", "a"], checks, ("G", expected_gateway))
        assert all(snapshot["members"][name]["status"] == "online" for name in "abc"), snapshot
        assert all(snapshot["members"][name]["checks"]["probe_secondary"] == "Passed"
                   for name in "ab"), snapshot
        return_path = snapshot["policies"]["calls"]["selected"]
        expected_member = {None: None, "GW_A": "a", "GW_B": "b"}[expected_gateway]
        assert return_path == expected_member, snapshot
        load_policy()  # The expected gateway is never an input to rule generation.
        check_dns()

    source_a = config["fixture_sources"]["opt1"]
    source_b = config["fixture_sources"]["opt2"]

    def check_backup(phase):
        marker = f"backup-{phase}"
        response = transaction(client, backup_service, marker)
        assert response == f"{source_a} {marker}", (phase, response)
        print(f"ok - backup stayed on WAN1 during {phase}", flush=True)

    nat_before = subprocess.check_output(["jexec", firewall, "pfctl", "-sn"], text=True, timeout=10)
    default_before = default_path()
    assert any(line.partition(":")[2].strip() == native_path["address"]
               for line in default_before if line.startswith("gateway:")), default_before
    converge(healthy, "GW_A")
    with ThreadPoolExecutor(max_workers=2) as requests:
        initial_backup = requests.submit(check_backup, "primary")
        standby = requests.submit(transaction, firewall, standby_probe, "erp-standby", source_b)
        initial_backup.result()
        assert standby.result() == f"{source_b} erp-standby"
    session_log = work / "erp-session"
    with session_log.open("w") as output:
        session = subprocess.Popen(["jexec", client, "nc", "-n", "-N", "-w", "60", upstream, "7"],
                                   stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL, text=True)
        try:
            session.stdin.write("erp-established\n")
            session.stdin.flush()
            deadline = time.monotonic() + 5
            established = f"{source_a} erp-established\n"
            while time.monotonic() < deadline and established not in session_log.read_text() and session.poll() is None:
                time.sleep(0.1)
            assert established in session_log.read_text(), session_log.read_text()
            check_backup("erp-session-established")

            set_service_loss(remote_a)
            label = f"erp-drop-{remote_a}"
            before = packets(peer, label)
            session.stdin.write("erp-established-after-loss\n")
            session.stdin.flush()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and packets(peer, label) == before:
                time.sleep(0.1)
            assert packets(peer, label) > before, "Established ERP flow did not reach the WAN1 drop rule"
            converge(failed_a, "GW_B")
            assert transaction(client, upstream, "erp-failover") == f"{source_b} erp-failover"
            check_backup("erp-failover")
            assert "erp-established-after-loss" not in session_log.read_text(), "Old ERP session received a reply"
            print("ok - established ERP session hit the WAN1 service drop without another reply", flush=True)
        finally:
            stop(session)
            session.stdin.close()
    assert default_path() == default_before, "ERP failover changed the firewall default route"
    print("ok - ERP-only loss on WAN1 moved a new LAN transaction to WAN2; backup, dpinger and DNS stayed up", flush=True)
    print("ok - the required ERP probe excluded WAN1 for its own policy while independent legacy policies kept it", flush=True)

    set_service_loss()
    converge(healthy, "GW_A")
    assert transaction(client, upstream, "erp-failback") == f"{source_a} erp-failback"
    check_backup("erp-failback")
    print("ok - ERP recovery returned new LAN traffic to WAN1 after the observer's hold", flush=True)

    set_service_loss(remote_a, remote_b)
    converge(failed_both, None)
    blocked = packets(firewall, "descr=erp-policy")
    assert not transaction(client, upstream, "erp-no-path")
    assert packets(firewall, "descr=erp-policy") > blocked, "New ERP flow did not hit the bound deny rule"
    check_backup("both-erp-paths-ineligible")
    print("ok - both ERP paths ineligible: PF denied the new ERP flow and client DNS still answered", flush=True)

    set_service_loss(remote_a)
    converge(failed_a, "GW_B")
    assert transaction(client, upstream, "erp-before-rollback") == f"{source_b} erp-before-rollback"
    check_backup("before-rollback")
    del config["gateways/sdwan_bindings"], config["gateways/sdwan_bindings/item"]
    config_path.write_text(json.dumps(config))
    assert "$GWG" in render("rollback"), "Unbinding did not restore the native gateway-group rule"
    load_policy()
    check_dns()
    before = packets(peer, f"erp-drop-{remote_a}")
    assert not transaction(client, upstream, "erp-native-wan1"), "Stock policy kept steering around the service-only outage"
    assert packets(peer, f"erp-drop-{remote_a}") > before, "Rollback did not take the native WAN1 path"
    check_backup("native-rollback-erp-unavailable")
    set_service_loss()
    assert transaction(client, upstream, "erp-native-recovered") == f"{source_a} erp-native-recovered"
    check_backup("native-rollback-erp-recovered")
    check_dns()
    assert subprocess.check_output(["jexec", firewall, "pfctl", "-sn"], text=True, timeout=10) == nat_before
    assert default_path() == default_before
    print("ok - rollback restored native gateway-group forwarding; NAT was preserved and DNS stayed reachable", flush=True)


def run(firewall, peer, remote_a, remote_b, remote_c, restore, erp=None):
    if platform.system() != "FreeBSD":
        raise RuntimeError("Run only in the disposable FreeBSD VNET topology")
    subprocess.run(["jail", "-m", "name=" + firewall, "allow.raw_sockets"], check=True, timeout=10)
    with tempfile.TemporaryDirectory(prefix="sdwan-dp-", dir="/tmp") as tmp, ExitStack() as cleanup:
        work = Path(tmp)
        if erp:
            core, rules_dir = map(Path, erp[:2])
            client, lan = erp[2:]
            render_harness(work, core.resolve())
            cleanup.callback(jexec, firewall, "pfctl", "-f", str(rules_dir / "main.pf"))
        else:
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

        def expect_snapshot(expected, choices, checks=None, forwarding=None):
            expires = time.monotonic() + (45 if forwarding else 15)
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
                active = snapshot.get("steering", {}).get(forwarding[0], {}) if forwarding else {}
                forwarded = not forwarding or active.get("gateway", "missing") == forwarding[1]
                if measured == expected and selected == choices and results == (checks or {}) and forwarded:
                    return snapshot
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
        start_dns_server(peer, upstream, dns_status, ready, cleanup)

        healthy = {"a": "Passed", "b": "Passed"}
        expect_snapshot([0, 0, 0], ["a", "a", "a"], healthy)
        dns_status.write_text("unavailable")
        expect_snapshot([0, 0, 0], [None, "b", "b"], {"a": "DNS check failed", "b": "Passed"})
        print("ok - a DNS application outage selected the TCP-verified backup while all WAN monitors stayed up", flush=True)
        dns_status.write_text("available")
        expect_snapshot([0, 0, 0], ["a", "a", "a"], healthy)
        print("ok - DNS service recovery restored the primary path", flush=True)
        if erp:
            verify_erp(work, core, rules_dir, client, lan, firewall, peer, remote_a, remote_b,
                       upstream, backup, config, expect_snapshot, cleanup)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firewall")
    parser.add_argument("peer")
    parser.add_argument("remote_a")
    parser.add_argument("remote_b")
    parser.add_argument("remote_c")
    parser.add_argument("restore", type=Path)
    parser.add_argument("--erp", nargs=4, metavar=("CORE", "RULES_DIR", "CLIENT", "LAN"),
                        help="exercise ERP-only failure with the pinned native filter tuple in VNET")
    run(**vars(parser.parse_args()))
