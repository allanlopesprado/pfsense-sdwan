#!/usr/bin/env python3
"""Check Suricata host-stack netmap and bound SD-WAN rules in a disposable CE guest."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import time


SCRIPT = Path(__file__).resolve()
WAN_INTERFACES = ("vtnet0", "vtnet2")
PEER_INTERFACES = ("sw-wire0", "sw-wire2")
SID = 9900004
PREFIX = "SDWAN-LAB-"
BLOCK = PREFIX + "BLOCK-"
WORK = "/root/sdwan-ce-ips"


def captured_request(frame):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        return None
    ip_header = (frame[14] & 15) * 4
    tcp = 14 + ip_header
    if ip_header < 20 or len(frame) < tcp + 20 or frame[tcp + 2:tcp + 4] != b"\x00\x07":
        return None
    tcp_header = (frame[tcp + 12] >> 4) * 4
    ip_end = 14 + int.from_bytes(frame[16:18], "big")
    if tcp_header < 20 or ip_end > len(frame):
        return None
    payload = frame[tcp + tcp_header:ip_end]
    if not payload.startswith(PREFIX.encode()) or not payload.endswith(b"\n"):
        return None
    if not payload.isascii():
        return None
    return socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34]), payload[:-1].decode("ascii")


def capture_peer(path):
    # Called only inside the existing disconnected server namespace.
    with open(path, "x", encoding="utf-8", buffering=1) as report:
        captures = [socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
                    for _ in PEER_INTERFACES]
        try:
            for listener, interface in zip(captures, PEER_INTERFACES):
                listener.bind((interface, 0x0800))
            print("ready", flush=True)
            while True:
                ready, _, _ = select.select(captures, [], [])
                for listener in ready:
                    request = captured_request(listener.recv(65536))
                    if request:
                        iface = PEER_INTERFACES[captures.index(listener)]
                        print(json.dumps([iface, *request]), file=report)
        finally:
            for listener in captures:
                listener.close()


def assert_peer(capture, marker, expected, targets):
    deadline = time.monotonic() + 4
    while True:
        observed = set()
        for line in capture.read_text(encoding="utf-8").splitlines(keepends=True):
            if not line.endswith("\n"):
                continue
            interface, source, destination, payload = json.loads(line)
            if payload == marker and destination in targets:
                observed.add((interface, source, destination))
        if observed == expected:
            return
        if observed - expected or time.monotonic() >= deadline:
            raise AssertionError((marker, observed, expected))
        time.sleep(0.1)


def probe(ce, label, expected):
    def request(target):
        return ce.run(*ce.in_ns("sdwan-client", sys.executable, ce.SCRIPT, "flow", target),
                      input=label + "\n", capture_output=True).stdout.strip()

    with ThreadPoolExecutor(max_workers=2) as workers:
        actual = list(workers.map(request, (ce.ERP, ce.BACKUP)))
    wanted = [f"{source} {label}" if source else "" for source in expected]
    if actual != wanted:
        raise AssertionError((label, actual, wanted))


def stage_engine(ce, qemu):
    packages = ce.command(
        qemu,
        "env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR=/root/netgate-repos "
        "pkg-static install -Uy suricata",
        timeout=180,
    )
    print(packages.splitlines()[-8:], flush=True)
    metadata = ce.command(qemu, "pkg query '%n %v' suricata; suricata --build-info | grep -i netmap")
    if not re.search(r"^\s*netmap support:\s*yes\s*$", metadata, re.IGNORECASE | re.MULTILINE):
        raise RuntimeError(f"The signed Suricata engine has no netmap support: {metadata}")
    print(metadata, flush=True)

    yaml = ["%YAML 1.1", "---", "netmap:"]
    for device in WAN_INTERFACES:
        for source, destination in ((device, device + "^"), (device + "^", device)):
            yaml.extend((f"  - interface: {source}", "    threads: 1", "    copy-mode: ips",
                         f"    copy-iface: {destination}", "    checksum-checks: no"))
    ce.command(qemu, f"""mkdir -m 700 {WORK}
test -c /dev/netmap || kldload -n netmap
test -c /dev/netmap
for interface in {" ".join(WAN_INTERFACES)}; do
    ifconfig "$interface" -rxcsum -txcsum -tso -lro
done
cat >{WORK}/netmap.yaml <<'EOF'
{chr(10).join(yaml)}
EOF
cat >{WORK}/local.rules <<'EOF'
drop tcp any any -> {ce.ERP} 7 (msg:"SD-WAN lab marker"; flow:established,to_server; content:"{BLOCK}"; startswith; sid:{SID}; rev:1;)
EOF""")


def start_engine(ce, qemu):
    ce.command(qemu, f"""config=/usr/local/etc/suricata/suricata.yaml
if [ ! -f "$config" ]; then config="$config.sample"; fi
suricata -c "$config" --include {WORK}/netmap.yaml --netmap -S {WORK}/local.rules \\
    --init-errors-fatal --set stream.inline=yes --set unix-command.enabled=no -k none \\
    -l {WORK} -D --pidfile {WORK}/suricata.pid
for attempt in $(seq 1 20); do
    if [ -s {WORK}/suricata.pid ] && [ -f {WORK}/eve.json ] && grep -qi 'engine started' {WORK}/suricata.log; then exit 0; fi
    sleep 1
done
exit 1""", timeout=40)


def stop_engine(ce, qemu):
    ce.command(qemu, f"""if [ ! -s {WORK}/suricata.pid ]; then exit 0; fi
pid=$(cat {WORK}/suricata.pid)
if ! kill -0 "$pid" 2>/dev/null; then exit 0; fi
kill -TERM "$pid"
for attempt in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then exit 0; fi
    sleep 1
done
exit 1""", timeout=40)


def blocked_count(ce, qemu, source):
    result = ce.command(qemu, f"""php -r '
        $events = file("{WORK}/eve.json", FILE_IGNORE_NEW_LINES);
        $count = 0;
        foreach ($events as $event) {{
            $row = json_decode($event, true);
            if (($row["src_ip"] ?? "") === "{source}" && ($row["dest_ip"] ?? "") === "{ce.ERP}" &&
                ($row["dest_port"] ?? 0) === 7 && ($row["alert"]["signature_id"] ?? 0) === {SID} &&
                ($row["alert"]["action"] ?? "") === "blocked") {{ $count++; }}
        }}
        echo $count;
    '""")
    return int(result)


def inspection(ce, qemu, cleanup):
    ce.install_bound_candidate(qemu)
    stage_engine(ce, qemu)
    primary = {"G": "GW_A", "B": "GW_A"}
    ce.wait_paths(qemu, "before netmap inspection", primary)
    baseline = ce.route_and_nat(qemu)
    certificate = ce.management("before netmap inspection")
    directory = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="sdwan-ce-ips-")))
    capture = directory / "peer.jsonl"
    child = subprocess.Popen(ce.in_ns("sdwan-peer", sys.executable, SCRIPT, "capture-peer", capture),
                             stdout=subprocess.PIPE, text=True)
    cleanup.callback(child.stdout.close)
    cleanup.callback(ce.stop, child)
    if not select.select([child.stdout], [], [], 6)[0] or child.stdout.readline().strip() != "ready":
        raise RuntimeError("The disconnected peer could not start packet observation")
    denied = []

    def verify(label, erp_index, blocked):
        erp_source = (ce.A, ce.B)[erp_index]
        marker = (BLOCK if blocked else PREFIX + "ALLOW-") + label
        before = blocked_count(ce, qemu, erp_source) if blocked else 0
        probe(ce, marker, (None if blocked else erp_source, ce.A))
        expected = {(PEER_INTERFACES[0], ce.A, ce.BACKUP)}
        if not blocked:
            expected.add((PEER_INTERFACES[erp_index], erp_source, ce.ERP))
        assert_peer(capture, marker, expected, (ce.ERP, ce.BACKUP))
        proof = f"ERP replied from {erp_source} on {PEER_INTERFACES[erp_index]}"
        if blocked:
            denied.append((marker, expected))
            deadline = time.monotonic() + 5
            count = blocked_count(ce, qemu, erp_source)
            while count <= before:
                if time.monotonic() >= deadline:
                    raise AssertionError(f"No new IPv4 ERP block in EVE from {erp_source}")
                time.sleep(0.2)
                count = blocked_count(ce, qemu, erp_source)
            proof = f"ERP from {erp_source}: {count - before} new EVE blocks, no marker at peer"
        print(f"{label}: {proof}, backup replied from {ce.A} on {PEER_INTERFACES[0]}", flush=True)

    # Prove the drop marker is visible before the inspector opens the WANs.
    marker = BLOCK + "control-before"
    probe(ce, marker, (ce.A, ce.A))
    assert_peer(capture, marker, {(PEER_INTERFACES[0], ce.A, target) for target in (ce.ERP, ce.BACKUP)},
                (ce.ERP, ce.BACKUP))
    try:
        start_engine(ce, qemu)
        remapped = {"G": "GW_B", "B": "GW_A"}
        ce.wait_paths(qemu, "inline primary", primary)
        verify("primary-control", 0, False)
        verify("primary-inspected", 0, True)
        ce.wait_paths(qemu, "inline primary after blocked marker", primary)
        ce.fault(f'iifname "sw-wire0" ip saddr {ce.A} ip daddr {{ {ce.ERP}, 192.0.2.164 }} tcp dport 7 drop')
        decision = ce.wait_paths(qemu, "inline ERP failover", remapped)["snapshot"]
        assert decision["members"]["a"]["status"] == "online", decision
        verify("failover-control", 1, False)
        verify("failover-inspected", 1, True)
        ce.wait_paths(qemu, "inline failover after blocked marker", remapped)
        ce.management("inline failover", certificate)
        assert ce.route_and_nat(qemu) == baseline
    except Exception:
        print(ce.command(qemu, f"tail -n 30 {WORK}/suricata.log || :"), flush=True)
        raise
    finally:
        try:
            stop_engine(ce, qemu)
        finally:
            ce.fault()
    ce.wait_paths(qemu, "after stopping inline inspection", primary)
    marker = BLOCK + "control-after"
    probe(ce, marker, (ce.A, ce.A))
    assert_peer(capture, marker, {(PEER_INTERFACES[0], ce.A, target) for target in (ce.ERP, ce.BACKUP)},
                (ce.ERP, ce.BACKUP))
    for marker, expected in denied:
        assert_peer(capture, marker, expected, (ce.ERP, ce.BACKUP))
    ce.management("after stopping inline inspection", certificate)
    assert ce.route_and_nat(qemu) == baseline
    print("CE_VIRTIO_NETMAP_IPS_SD_WAN_PASSED", flush=True)


def main():
    if sys.argv[1:2] == ["capture-peer"]:
        capture_peer(Path(sys.argv[2]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="disposable raw disk staged for inspection")
    parser.add_argument("version", choices=("2.9.1", "2.9.2"))
    options = parser.parse_args()
    spec = importlib.util.spec_from_file_location("ce_appliance", SCRIPT.with_name("ce291-appliance.py"))
    ce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ce)
    ce.appliance(options.image.resolve(), options.version,
                 scenario=lambda qemu, cleanup, _provider: inspection(ce, qemu, cleanup))


if __name__ == "__main__":
    main()
