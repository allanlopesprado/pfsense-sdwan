#!/usr/bin/env python3
"""Two-policy traffic acceptance in the disposable FreeBSD VNET topology."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core_adapter import ROOT, render_harness, test_config
from freebsd_dpinger import stop

ERP = "192.0.2.162"
BACKUP = "192.0.2.163"
WAN_IPS = ("198.51.100.1", "203.0.113.1")
NEXT_HOPS = ("198.51.100.2", "203.0.113.2")
PROBES = (("192.0.2.164", "192.0.2.166"), ("192.0.2.165", "192.0.2.167"))


def run(args):
    if platform.system() != "FreeBSD" or os.geteuid() != 0:
        raise RuntimeError("Run only in the disposable FreeBSD VNET topology")

    def jexec(node, *argv, **kwargs):
        result = subprocess.run(["jexec", node, *argv], capture_output=True, timeout=15, **kwargs)
        if result.returncode:
            raise RuntimeError(f"{node} {argv[0]} failed ({result.returncode})\n"
                               f"{result.stderr.decode(errors='replace')}{result.stdout.decode(errors='replace')}")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="sdwan-service-", dir="/tmp") as directory, ExitStack() as cleanup:
        work = Path(directory)
        render_harness(work, args.core)
        socket_path = work / "reload.sock"
        (work / "filter.inc").write_text(
            "<?php require_once(__DIR__.'/filter-sdwan.inc'); function is_platform_booting() { return false; } "
            "function g_get($name, $default=null) { return $name === 'event_address' ? "
            + json.dumps("unix://" + str(socket_path)) + " : $default; }")
        config = test_config(work, "inet", 2, False)
        settings = config["installedpackages/sdwan"]
        erp = settings["policies"]["item"][0]
        erp.update(name="ERP", primary_check="required", secondary_check="ignored", recover_seconds="0")
        settings["policies"]["item"].append(dict(erp, name="Backup", primary_check="ignored", secondary_check="required"))
        config["gateways/gateway_group"].append(dict(config["gateways/gateway_group"][0], name="B"))
        config["interfaces"]["lan"]["if"] = args.lan
        config["filter/rule"][0].update(descr="ERP", log="")
        for rule in config["filter/rule"][2:]:
            rule["destination"] = {"address": BACKUP, "port": "7"}
        config["filter/rule"][2].update(gateway="B", descr="Backup")
        cleanup.callback(jexec, args.peer, "pfctl", "-f", str(args.restore_remote))
        initial = work / "initial.pf"
        initial.write_bytes(jexec(args.firewall, "cat", str(args.main)))
        cleanup.callback(jexec, args.firewall, "pfctl", "-f", str(initial))
        subprocess.run(["jail", "-m", "name=" + args.firewall, "allow.raw_sockets"], check=True, timeout=10)
        for index, (gateway, member, device) in enumerate(zip(
                config["gateways/gateway_item"], settings["members"]["item"], (args.wan_a, args.wan_b))):
            name, interface = gateway["name"], gateway["interface"]
            source, hop = WAN_IPS[index], NEXT_HOPS[index]
            config["reload_gateways"][name]["interface"] = device
            config["interfaces"][interface]["if"] = device
            config["fixture_devices"][interface] = device
            config["fixture_sources"][device] = source
            first, second = PROBES[index]
            member.update(probe_primary=f"tcp://{first}:7", probe_secondary=f"tcp://{second}:7")
            for target in PROBES[index]:
                jexec(args.peer, "ifconfig", "lo0", "inet", f"{target}/32", "alias")
                cleanup.callback(jexec, args.peer, "ifconfig", "lo0", "inet", target, "-alias")
                jexec(args.firewall, "route", "-n", "add", "-host", target, hop)
                cleanup.callback(jexec, args.firewall, "route", "-n", "delete", "-host", target)
            process = subprocess.Popen(["jexec", args.firewall, "/usr/local/bin/dpinger",
                "-f", "-i", name, "-B", source, "-r", "0", "-s", "100", "-l", "350", "-t", "2000",
                "-p", str(work / f"{name}.pid"), "-u", config["processes"][name]["socket"], hop],
                stdout=subprocess.DEVNULL)
            cleanup.callback(stop, process)
        config_path = work / "fixture.json"
        snapshot_path = work / "snapshot.json"

        def save():
            config_path.write_text(json.dumps(config))

        def render(operation, *params):
            return jexec(args.firewall, "/usr/local/bin/php", "-d", f"include_path={work}",
                         str(ROOT / "tests/fixtures/native_filter.php"), str(work), str(args.core), operation, *params).decode()

        save()
        bindings = []
        for policy, group in (("ERP", "G"), ("Backup", "B")):
            result = json.loads(render("preview_policy", policy, group))
            assert not result["errors"], result
            binding = result["binding"]
            binding["group"] = [binding["group"]]
            for key in ("gateways", "trackers"):
                binding[key] = {"item": binding[key]}
            bindings.append(binding)
        config["gateways/sdwan_bindings"] = {"item": bindings}
        config["gateways/sdwan_bindings/item"] = bindings
        save()

        listener = cleanup.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        listener.bind(str(socket_path))
        listener.listen()
        listener.settimeout(.15)
        stop_queue = threading.Event()
        requests = []
        errors = []

        def serve_queue():
            while not stop_queue.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                with conn:
                    try:
                        conn.settimeout(1)
                        assert conn.recv(13, socket.MSG_WAITALL) == b"filter reload"
                        requests.append(json.loads(snapshot_path.read_text())["forwarding_id"])
                        conn.sendall(b"OK\n")
                    except (AssertionError, OSError, ValueError) as error:
                        errors.append(error)

        server = threading.Thread(target=serve_queue, daemon=True)
        server.start()
        cleanup.callback(server.join, 2)
        cleanup.callback(stop_queue.set)

        def observe():
            jexec(args.firewall, "/usr/local/bin/php", "-d", f"include_path={work}", str(work / "sdwand.php"), "--once")
            assert not errors, errors
            return json.loads(snapshot_path.read_text())

        active = work / "policy.pf"
        base = args.before.read_text()
        tail = args.after.read_text()
        default = jexec(args.firewall, "route", "-n", "get", "default")
        nat = jexec(args.firewall, "pfctl", "-sn")

        def load_rules(rollback=False):
            rules = render("paired_rollback" if rollback else "paired")
            macros = (f'GWG = " route-to ({args.wan_a} {NEXT_HOPS[0]}) "\n'
                      f'GWB = " route-to ({args.wan_a} {NEXT_HOPS[0]}) "\n')
            active.write_text(macros + base + rules.replace("$LABLAN", args.lan) + "\n" + tail)
            jexec(args.firewall, "pfctl", "-nf", str(active))
            jexec(args.firewall, "pfctl", "-f", str(active))

        def transition(label, erp_path, backup_path):
            expected = {"G": erp_path, "B": backup_path}
            deadline = time.monotonic() + 14
            while time.monotonic() < deadline:
                snap = observe()
                actual = {group: state["gateway"] for group, state in snap["steering"].items()}
                if actual == expected:
                    break
                time.sleep(.2)
            else:
                raise AssertionError((label, expected, snap))
            if any(status != "applied" and status != "blocked" for status in snap["forwarding_check"].values()):
                assert snap["forwarding_id"] in requests, (label, "no native reload requested")
            load_rules()
            verified = observe()
            assert verified["forwarding_check"] == {k: "blocked" if v is None else "applied" for k, v in expected.items()}, verified
            for line in jexec(args.firewall, "pfctl", "-sr").decode().splitlines():
                if line.endswith(("ridentifier 41001", "ridentifier 41003")):
                    print(f"{label} PF {line}", flush=True)
            assert jexec(args.firewall, "pfctl", "-sn") == nat
            assert jexec(args.firewall, "route", "-n", "get", "default") == default
            return verified

        def pair(label, expected):
            def flow(target):
                proc = subprocess.run(["jexec", args.client, "nc", "-n", "-N", "-w", "2", target, "7"],
                                      input=f"{label}\n".encode(), capture_output=True, timeout=5)
                return proc.stdout.decode().strip()
            with ThreadPoolExecutor(max_workers=2) as pool:
                result = list(pool.map(flow, (ERP, BACKUP)))
            assert result == [f"{source} {label}" if source else "" for source in expected], (label, result)
            print(f"{label} ERP return={result[0]!r}, backup return={result[1]!r}", flush=True)

        def open_flow(target):
            child = subprocess.Popen(["jexec", args.client, "nc", "-n", "-w", "70", target, "7"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            cleanup.callback(stop, child)
            cleanup.callback(child.stdout.close)
            cleanup.callback(child.stdin.close)
            return child

        def send(child, text):
            child.stdin.write(f"{text}\n".encode())
            child.stdin.flush()

        def receive(child, timeout=3):
            if select.select([child.stdout], [], [], timeout)[0]:
                return child.stdout.readline().decode().strip()
            return ""

        # The DNS control uses a real UDP transaction on WAN1 to the peer.
        dns = subprocess.Popen(["jexec", args.peer, sys.executable, "-c",
            """import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind((sys.argv[1],53))
while True:
    q,peer=s.recvfrom(512)
    s.sendto(q[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+q[12:]+struct.pack('!HHHIHBBBB',0xc00c,1,1,30,4,192,0,2,42),peer)
""", NEXT_HOPS[0]])
        cleanup.callback(stop, dns)

        def verify_dns():
            jexec(args.firewall, sys.executable, "-c",
                """import socket,struct,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.bind((sys.argv[1],0))
    s.settimeout(2)
    s.connect((sys.argv[2],53))
    s.send(struct.pack('!HHHHHH',17,0x100,1,0,0,0)+b'\\x06health\\x04test\\0\\0\\1\\0\\1')
    answer=s.recv(512)
    assert answer[:8]==struct.pack('!HHHH',17,0x8180,1,1)
""", WAN_IPS[0], NEXT_HOPS[0])
            print("WAN1 DNS replied with an A record through the WAN1 source", flush=True)

        transition("baseline", "GW_A", "GW_A")
        pair("baseline", WAN_IPS[0:1] * 2)
        held_erp, held_backup = open_flow(ERP), open_flow(BACKUP)
        for workstream in (held_erp, held_backup):
            send(workstream, "established")
            assert receive(workstream) == WAN_IPS[0] + " established"
        before_states = jexec(args.firewall, "pfctl", "-ss", "-vv").decode()
        print("baseline established PF states recorded for ERP and backup", flush=True)

        remote_rules = work / "remote-policy.pf"

        def fault(lines):
            remote_rules.write_text("\n".join(lines + ["pass all no state"]) + "\n")
            jexec(args.peer, "pfctl", "-f", str(remote_rules))

        fault([f"block drop in quick on {args.remote_a} inet proto tcp from {WAN_IPS[0]} "
               f"to {{ {ERP}, {PROBES[0][0]} }} port 7"])
        verify_dns()
        failed = transition("ERP outage", "GW_B", "GW_A")
        assert failed["members"]["a"]["status"] == "online"
        assert failed["policies"]["ERP"]["services"]["a"] == "Failed"
        assert failed["policies"]["Backup"]["services"]["a"] == "Passed"
        pair("ERP outage", (WAN_IPS[1], WAN_IPS[0]))
        send(held_erp, "outage-established")
        assert not receive(held_erp, .7), "Existing ERP socket unexpectedly migrated"
        send(held_backup, "outage-established")
        assert receive(held_backup) == WAN_IPS[0] + " outage-established"
        during_states = jexec(args.firewall, "pfctl", "-ss", "-vv").decode()
        for target in (ERP, BACKUP):
            def ids(states):
                result = set()
                for item in re.split(r"(?=^\S)", states, flags=re.M):
                    if item and f"{target}:7" in item.splitlines()[0]:
                        result.update(re.findall(r"id: ([a-f0-9]+) creatorid: ([a-f0-9]+)", item))
                return result
            same_states = sorted(ids(before_states) & ids(during_states))
            assert same_states, f"Established PF state lost for {target}"
            print(f"preserved PF state for {target}: {same_states}", flush=True)
        print("ERP existing socket stayed on the failed path; backup existing socket remained usable", flush=True)

        fault([])
        transition("recovery", "GW_A", "GW_A")
        pair("recovery", (WAN_IPS[0], WAN_IPS[0]))
        assert receive(held_erp, 7) == WAN_IPS[0] + " outage-established"
        for workstream in (held_erp, held_backup):
            send(workstream, "recovered-established")
            assert receive(workstream) == WAN_IPS[0] + " recovered-established"
        print("both original sockets replied after ERP recovery", flush=True)
        fault([f"block drop in quick on {device} inet from {source} to any"
               for device, source in ((args.remote_a, WAN_IPS[0]), (args.remote_b, WAN_IPS[1]))])
        transition("both WANs down", None, None)
        pair("both WANs down", (None, None))
        for workstream in (held_erp, held_backup):
            send(workstream, "both-down-established")
            assert not receive(workstream, .6)
        fault([])
        transition("WANs recovered", "GW_A", "GW_A")
        pair("WANs recovered", (WAN_IPS[0], WAN_IPS[0]))
        for workstream in (held_erp, held_backup):
            assert receive(workstream, 8) == WAN_IPS[0] + " both-down-established"

        config["gateways/sdwan_bindings"] = {"item": []}
        config["gateways/sdwan_bindings/item"] = []
        save()
        observe()
        load_rules(rollback=True)
        pair("native rollback", (WAN_IPS[0], WAN_IPS[0]))
        for workstream in (held_erp, held_backup):
            send(workstream, "rollback-established")
            assert receive(workstream) == WAN_IPS[0] + " rollback-established"
        assert jexec(args.firewall, "pfctl", "-sn") == nat
        assert jexec(args.firewall, "route", "-n", "get", "default") == default
        print("ok - CE 2.9.1 rule generator, live FreeBSD probes and PF verified two-policy traffic", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core", type=Path)
    for field in ("firewall", "client", "peer", "lan", "wan_a", "wan_b", "remote_a", "remote_b"):
        parser.add_argument(field)
    for field in ("main", "before", "after", "restore_remote"):
        parser.add_argument(field, type=Path)
    run(parser.parse_args())
