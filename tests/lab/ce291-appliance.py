#!/usr/bin/env python3
"""Exercise an installed pfSense system on a disconnected QEMU topology."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import socketserver
import ssl
import struct
import threading
import subprocess
import sys
import time

import pexpect

SCRIPT = Path(__file__).resolve()
LAB = "/root/sdwan-lab"
ERP, BACKUP = "192.0.2.162", "192.0.2.163"
A, B = "198.51.100.1", "203.0.113.1"
WAN2_RENEWED = ("203.0.113.4", "203.0.113.3")
GATEWAYS = {"GW_A": ("vtnet0", "198.51.100.2"), "GW_B": ("vtnet2", "203.0.113.2")}


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=20, **kwargs)


def in_ns(name, *args):
    return ["ip", "netns", "exec", name, *map(str, args)]


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)


def stop_vm(qemu):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if qemu.isalive():
            qemu.kill(sig)
        for _ in range(20):
            if not qemu.isalive():
                qemu.close()
                return
            time.sleep(.1)
    raise RuntimeError("The disposable QEMU process did not stop")


def wire(cleanup):
    for namespace in ("sdwan-client", "sdwan-peer"):
        run("ip", "netns", "add", namespace)
        cleanup.callback(run, "ip", "netns", "del", namespace)
        run("ip", "-n", namespace, "link", "set", "lo", "up")
    net_args = []
    for n, (namespace, address) in enumerate((
        ("sdwan-peer", "198.51.100.2/30"), ("sdwan-client", "192.0.2.11/25"),
        ("sdwan-peer", "203.0.113.2/29"),
    )):
        bridge, tap, outside, inside = (f"sw-{prefix}{n}" for prefix in ("br", "tap", "out", "wire"))
        run("ip", "link", "add", bridge, "type", "bridge")
        cleanup.callback(run, "ip", "link", "del", bridge)
        run("ip", "tuntap", "add", "dev", tap, "mode", "tap")
        cleanup.callback(run, "ip", "link", "del", tap)
        run("ip", "link", "add", outside, "type", "veth", "peer", "name", inside)
        cleanup.callback(run, "ip", "link", "del", outside)
        run("ip", "link", "set", inside, "netns", namespace)
        for device in (outside, tap):
            run("ip", "link", "set", device, "master", bridge)
            run("ip", "link", "set", device, "up")
        run("ip", "link", "set", bridge, "up")
        run("ip", "-n", namespace, "addr", "add", address, "dev", inside)
        run("ip", "-n", namespace, "link", "set", inside, "up")
        net_args += ["-netdev", f"tap,id=lan{n},ifname={tap},script=no,downscript=no",
                     "-device", f"virtio-net-pci,netdev=lan{n}"]
    run("ip", "-n", "sdwan-peer", "addr", "add", f"{WAN2_RENEWED[1]}/29", "dev", "sw-wire2")
    run("ip", "-n", "sdwan-client", "route", "add", "default", "via", "192.0.2.1")
    for n in range(162, 170):
        run("ip", "-n", "sdwan-peer", "addr", "add", f"192.0.2.{n}/32", "dev", "lo")
    run(*in_ns("sdwan-peer", "nft", "-f", "-"), input=
        """table inet test {
 chain input { type filter hook input priority filter; policy accept; }
 chain evidence {
  type filter hook input priority -10; policy accept;
  iifname "sw-wire0" ip saddr 198.51.100.1 ip daddr 192.0.2.168 tcp dport 7 counter comment "probe-a"
  iifname "sw-wire2" ip saddr 203.0.113.1 ip daddr 192.0.2.168 tcp dport 7 counter comment "probe-b"
  ip daddr 192.0.2.169 icmp type echo-request counter comment "vti-clear"
 }
}
""")
    server = subprocess.Popen(in_ns("sdwan-peer", sys.executable, SCRIPT, "serve"),
                              stdout=subprocess.PIPE, text=True)
    cleanup.callback(stop, server)
    cleanup.callback(server.stdout.close)
    if not select.select([server.stdout], [], [], 4)[0] or server.stdout.readline().strip() != "ready":
        raise RuntimeError("The isolated peer failed to start")
    return net_args


def serve_lease(cleanup, address, gateway):
    process = subprocess.Popen(in_ns("sdwan-peer", "dnsmasq", "--keep-in-foreground",
                               "--conf-file=/dev/null", "--interface=sw-wire2", "--bind-interfaces",
                               "--port=0", "--dhcp-authoritative", "--leasefile-ro", "--log-dhcp",
                               f"--dhcp-range={address},{address},255.255.255.248,2m",
                               f"--dhcp-option=option:router,{gateway}"))
    cleanup.callback(stop, process)
    time.sleep(.3)
    if process.poll() is not None:
        raise RuntimeError("The disconnected WAN2 DHCP server did not start")
    return process


def wait_lease(qemu, address, gateway):
    result = command(qemu, f'''i=0
        until ifconfig vtnet2 | grep -Fq 'inet {address} ' &&
            test "$(cat /tmp/vtnet2_router 2>/dev/null)" = '{gateway}'; do
            i=$((i+1)); test "$i" -le 50; sleep 1
        done
        ifconfig vtnet2 | grep -F 'inet {address} '
        cat /tmp/vtnet2_router''', timeout=60)
    print(f"DHCP lease: {result!r}", flush=True)


def fault(*rules):
    run(*in_ns("sdwan-peer", "nft", "-f", "-"),
        input="flush chain inet test input\n" + "".join(f"add rule inet test input {rule}\n" for rule in rules))


def tcp_pair(label, sources):
    def flow(target):
        result = run(*in_ns("sdwan-client", sys.executable, SCRIPT, "flow", target),
                     input=label + "\n", capture_output=True)
        return result.stdout.strip()
    with ThreadPoolExecutor(max_workers=2) as pool:
        actual = list(pool.map(flow, (ERP, BACKUP)))
    print(f"{label}: ERP={actual[0]!r} Backup={actual[1]!r}", flush=True)
    assert actual == [f"{source} {label}" if source else "" for source in sources], actual


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.wfile.write(self.client_address[0].encode() + b" " + line)


class DnsEcho(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        record = struct.pack("!HHHIHBBBB", 0xc00c, 1, 1, 30, 4, 192, 0, 2, 42)
        sock.sendto(header + query[12:] + record, self.client_address)



def client(target, held):
    try:
        with socket.create_connection((target, 7), timeout=3) as conn:
            conn.settimeout(None if held else 3)
            with conn.makefile("rb") as peer:
                for line in sys.stdin.buffer:
                    conn.sendall(line)
                    print(peer.readline().decode().rstrip(), flush=True)
    except OSError:
        if held:
            raise


def command(qemu, script, timeout=60):
    invocation = "sh -ec " + shlex.quote(script)
    if "\n" in script or len(invocation) > 240:
        qemu.sendline("umask 077; cat >/root/sdwan-serial-command <<'SDWAN_SERIAL_END'")
        for line in script.splitlines():
            assert len(line) <= 240 and line != "SDWAN_SERIAL_END", line
            qemu.sendline(line)
        qemu.sendline("SDWAN_SERIAL_END")
        invocation = "sh -e /root/sdwan-serial-command"
    qemu.sendline("echo __START__; " + invocation + "; echo __RESULT__$?")
    qemu.expect(r"\r+\n__START__\r+\n", timeout=timeout)
    qemu.expect(r"(?:\r+\n)?__RESULT__(\d+)\r+\n", timeout=timeout)
    result = qemu.before.replace("\r", "").strip()
    if qemu.match.group(1) != "0":
        raise RuntimeError(f"{script} failed: {result}")
    return result


def expect_console(qemu, pattern, timeout):
    deadline = time.monotonic() + timeout
    while qemu.expect([pattern, r"\x1b\[6n"], timeout=max(0, deadline - time.monotonic())):
        # resizewin asks a real terminal for its cursor position and uses it
        # to determine the dimensions. The serial automation serves that query.
        qemu.send("\x1b[24;80R")


def console_shell(qemu, timeout=300):
    expect_console(qemu, "Enter an option:", timeout)
    qemu.sendline("8")
    expect_console(qemu, r"(?:[#%] |/root(?:\x1b\[[0-9;]*m)*:(?:\x1b\[[0-9;]*m)* )", 75)
    qemu.sendline("exec /bin/sh")
    expect_console(qemu, r"(?:\r+\n|\x1b8)# ", 45)
    qemu.sendcontrol("u")
    qemu.sendline("TERM=dumb; export TERM; echo __SDWAN_SHELL__")
    expect_console(qemu, r"\r+\n__SDWAN_SHELL__\r+\n", 15)


def first_boot(qemu):
    qemu.expect("Enter full pathname of shell", timeout=180)
    qemu.sendline("")
    qemu.expect(r"# ")
    command(qemu, "mount -uw /; mkdir -p /tmp /var/tmp /var/run /var/log; chmod 1777 /tmp /var/tmp")
    command(qemu, """mkdir -p /cf/conf;
        if [ ! -f /etc/master.passwd ]; then
            install -m 600 /dev/null /etc/master.passwd
        fi
        if ! grep -q '^root:' /etc/master.passwd; then
            echo 'root:*:0:0::0:0:root:/root:/bin/sh' >> /etc/master.passwd
        fi
        if ! grep -q '^nobody:' /etc/master.passwd; then
            echo 'nobody:*:65534:65534::0:0:nobody:/nonexistent:/usr/sbin/nologin' >> /etc/master.passwd
        fi
        if ! test -f /etc/group; then
            printf 'wheel:*:0:root\n' > /etc/group
        fi
        if ! grep -q '^nobody:' /etc/group; then
            echo 'nobody:*:65534:' >> /etc/group
        fi
        pwd_mkdb -p /etc/master.passwd; getent passwd nobody""")
    version = command(qemu, "uname -a; pkg query '%n %v' pfSense-base pfSense-kernel-pfSense")
    print(version, flush=True)
    assert "pfSense-kernel-pfSense 2.9.1" in version, version
    command(qemu, "mkdir -p /root/netgate-repos; cp /root/sdwan-lab/pfsense.conf /root/netgate-repos/")
    result = command(qemu, "env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR=/root/netgate-repos "
                     "pkg-static install -Uy pfSense pfSense-default-config-serial", timeout=360)
    print(result.splitlines()[-8:], flush=True)
    print(command(qemu, "pkg query '%n %v' pfSense pfSense-system pfSense-default-config-serial"), flush=True)
    print("CE_OFFLINE_INSTALL_OK", flush=True)
    command(qemu, "ldconfig -m /usr/local/lib; mkdir -p /cf/conf")
    command(qemu, f"/usr/local/bin/php {LAB}/ce291-guest.php topology")
    command(qemu, """sed -i '' '/^boot_single=/d' /boot/loader.conf.local; sync""")
    qemu.sendline("exit")
    console_shell(qemu)
    identity = command(qemu, "cat /etc/version; uname -a; test -S /var/run/check_reload_status")
    assert identity.splitlines()[0] == "2.9.1-RELEASE", identity
    print(identity, flush=True)


def observations(qemu):
    raw = command(qemu, f"php {LAB}/ce291-guest.php observations")
    return json.loads(next(line for line in reversed(raw.splitlines()) if line.startswith("{")))


def wait_paths(qemu, label, expected, wait_ack=False, wan2_hop=None):
    started = time.monotonic()
    deadline = started + 135
    seen = set()
    valid_sample = False
    while time.monotonic() < deadline:
        parsed = observations(qemu)
        snapshot, receipt = parsed["snapshot"] or {}, parsed["receipt"]
        valid_sample |= bool(snapshot)
        if not valid_sample and time.monotonic() - started >= 28:
            break
        if receipt and receipt["accepted"]:
            seen.add(receipt["decision"])
        steering = {name: row["gateway"] for name, row in snapshot.get("steering", {}).items()}
        verified = {name: ("blocked" if value is None else "applied") for name, value in expected.items()}
        if steering == expected and snapshot.get("forwarding_check") == verified:
            if wait_ack:
                assert snapshot["forwarding_id"] in seen, (label, "missing native acknowledgement", seen)
            rules = loaded(qemu)
            assert_rules(rules, expected, wan2_hop)
            for line in rules.values():
                print(f"{label} PF {line}", flush=True)
            return snapshot
        time.sleep(1)
    diagnostics(qemu)
    raise RuntimeError(f"{label} did not converge: last observer response {parsed}")


def diagnostics(qemu):
    raw = command(qemu, """date +%s
        ls -l /var/run/sdwan-observer* /var/run/dpinger*.sock || :
        cat /var/run/sdwan-observer.json || :
        pfctl -sr 2>/dev/null | grep -E 'ridentifier 4100[1-5]$' || :
        grep -iE 'sdwan|check_reload_status|dpinger' /var/log/system.log | tail -22 || :
        php -r '
            require "config.inc";
            require "/usr/local/pkg/sdwan_steering.inc";
            $c=sdwan_get_config();
            echo "config=",sdwan_config_revision($c),PHP_EOL;
            echo "inventory=",sdwan_gateway_inventory_revision($c,sdwan_gateways()),PHP_EOL;
            echo "reader=",sdwan_read_snapshot() === null ? "invalid" : "valid",PHP_EOL;
        '
    """)
    print(raw, flush=True)



def loaded(qemu):
    raw = command(qemu, "pfctl -sr 2>/dev/null | awk '/ridentifier (41001|41003)$/ '")
    return {line.split()[-1]: line for line in raw.splitlines() if re.search(r"ridentifier (41001|41003)$", line)}


def assert_rules(rules, choices, wan2_hop=None):
    assert set(rules) == {"41001", "41003"}, rules
    for group, tracker in (("G", "41001"), ("B", "41003")):
        wanted = choices[group]
        line = rules[tracker]
        if wanted is None:
            assert line.startswith("block "), line
        else:
            device, hop = GATEWAYS[wanted]
            if wanted == "GW_B" and wan2_hop is not None:
                hop = wan2_hop
            assert f"route-to ({device} {hop})" in line, line


def route_and_nat(qemu):
    return command(qemu, """route -n get default | awk '/gateway:|interface:/'"""), command(qemu, "pfctl -sn 2>/dev/null")


def held_connection(target, cleanup):
    child = subprocess.Popen(in_ns("sdwan-client", sys.executable, SCRIPT, "held", target),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    cleanup.callback(stop, child)
    cleanup.callback(child.stdout.close)
    cleanup.callback(child.stdin.close)
    return child


def established(child, label, receive=3):
    child.stdin.write(label + "\n")
    child.stdin.flush()
    return child.stdout.readline().strip() if select.select([child.stdout], [], [], receive)[0] else ""


def evidence_count(name):
    rules = run(*in_ns("sdwan-peer", "nft", "-j", "list", "chain", "inet", "test", "evidence"),
                capture_output=True).stdout
    counters = [item["counter"]["packets"] for obj in json.loads(rules)["nftables"]
                for item in obj.get("rule", {}).get("expr", [])
                if obj["rule"].get("comment") == name and "counter" in item]
    assert len(counters) == 1, (name, counters)
    return counters[0]


def management(label, expected=None):
    result = run(*in_ns("sdwan-client", sys.executable, SCRIPT, "management"), capture_output=True)
    certificate = result.stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{64}", certificate), result
    if expected is not None:
        assert certificate == expected, (label, certificate, expected)
    print(f"{label}: native LAN HTTPS replied with the original certificate", flush=True)
    return certificate


def management_request():
    # The isolated appliance generates a self-signed certificate.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection("192.0.2.1", timeout=6, context=context)
    try:
        connection.connect()
        certificate = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 200 and b"usernamefld" in response.read(), response.status
        print(certificate)
    finally:
        connection.close()


def same_target_probes(qemu):
    reference = route_and_nat(qemu)
    before_a, before_b = evidence_count("probe-a"), evidence_count("probe-b")
    assert int(command(qemu, "sysctl -n net.fibs")) >= 3
    for fib, (device, hop) in enumerate(GATEWAYS.values(), 1):
        command(qemu, f"route -n add -host {hop} -iface {device} -fib {fib}")
        command(qemu, f"route -n add -host 192.0.2.168 {hop} -fib {fib}")
        lookup = command(qemu, f"route -n get -host 192.0.2.168 -fib {fib}")
        assert f"gateway: {hop}" in lookup and f"interface: {device}" in lookup, lookup
    try:
        result = command(qemu, f"""setfib -F 1 php {LAB}/ce291-guest.php probe {A} >{LAB}/fib1.out &
            left=$!
            setfib -F 2 php {LAB}/ce291-guest.php probe {B} >{LAB}/fib2.out &
            right=$!
            wait "$left"; wait "$right"
            cat {LAB}/fib1.out {LAB}/fib2.out""")
        assert result.splitlines() == [f"{A} same-target", f"{B} same-target"], result
        assert evidence_count("probe-a") > before_a and evidence_count("probe-b") > before_b
        assert route_and_nat(qemu) == reference
        print(f"SAME_IP_TWO_FIBS_OK: 192.0.2.168 returned via both physical WANs: {result!r}", flush=True)
    finally:
        for fib, (_, hop) in enumerate(GATEWAYS.values(), 1):
            command(qemu, f"route -n delete -host 192.0.2.168 -fib {fib}; "
                          f"route -n delete -host {hop} -fib {fib}")


def vti_no_sa(qemu):
    before = evidence_count("vti-clear")
    ping = f"ping -n -c 2 -t 5 -S {A} 192.0.2.169"
    command(qemu, ping)
    control = evidence_count("vti-clear")
    assert control >= before + 2
    command(qemu, """if ! ifconfig -C | tr ' ' '\\n' | grep -qx ipsec; then kldload -n ipsec; fi""")
    device = command(qemu, "ifconfig ipsec create").splitlines()[-1]
    assert re.fullmatch(r"ipsec[0-9]+", device), device
    command(qemu, f"ifconfig {device} inet tunnel {A} 198.51.100.2")
    command(qemu, f"ifconfig {device} inet 198.18.0.1/30 198.18.0.2 up")
    command(qemu, "route -n add -host 192.0.2.169 198.18.0.2")
    try:
        route = command(qemu, "route -n get 192.0.2.169")
        assert f"interface: {device}" in route, route
        stats = "netstat -s -p ipsec | awk '/outbound packets? with no SA available/ {print $1; exit}'"
        no_sa = int(command(qemu, stats))
        command(qemu, f"if {ping}; then exit 1; fi")
        assert int(command(qemu, stats)) > no_sa
        assert evidence_count("vti-clear") == control
        print("VTI_WITHOUT_SA_BLOCKS_WITHOUT_CLEARTEXT", flush=True)
    finally:
        command(qemu, f"route -n delete -host 192.0.2.169; ifconfig {device} destroy")
    command(qemu, ping)
    assert evidence_count("vti-clear") >= control + 2


def wait_receipt(qemu, condition, timeout):
    deadline = time.monotonic() + timeout
    state = {}
    while time.monotonic() < deadline:
        state = observations(qemu)
        if condition(state["snapshot"] or {}, state["receipt"]):
            return state["receipt"]
        time.sleep(1)
    diagnostics(qemu)
    raise RuntimeError(f"Reload verification did not converge: {state}")


def verify_unapplied_reload(qemu, primary, certificate):
    adapter = "/etc/inc/filter-sdwan.inc"
    backup = f"{LAB}/filter-sdwan.acceptance.inc"
    command(qemu, f"cp -p {adapter} {backup}")
    try:
        command(qemu, f"php {LAB}/ce291-guest.php hold_renderer; php -l {adapter}")
        fault(f'iifname "sw-wire0" ip saddr {A} ip daddr 192.0.2.164 tcp dport 7 drop')

        def requested(sample, receipt):
            return (sample.get("steering", {}).get("G", {}).get("gateway") == "GW_B"
                    and sample.get("forwarding_check", {}).get("G") == "pending"
                    and receipt.get("accepted"))

        first = wait_receipt(qemu, requested, 35)
        assert first["attempts"] == 1, first
        assert_rules(loaded(qemu), primary)
        management("accepted but divergent", certificate)
        command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart")
        second = wait_receipt(qemu, requested, 20)
        assert second == first, (first, second)
        exhausted = wait_receipt(qemu, lambda s, r: requested(s, r) and r["attempts"] == 3, 80)
        assert exhausted["decision"] == first["decision"]
        command(qemu, """i=0
            until grep -Fq 'persistent PF rule divergence after the reload retry limit' /var/log/system.log; do
                i=$((i+1)); test "$i" -le 40; sleep 1
            done""", timeout=48)
        assert observations(qemu)["receipt"] == exhausted
        assert_rules(loaded(qemu), primary)
        print("NATIVE_RELOAD_ACCEPTED_BUT_DIVERGENT_RESTART_AND_RETRY_LIMIT_OK", flush=True)
        command(qemu, f"cp -p {backup} {adapter}; /etc/rc.filter_configure_sync")
        recovered = wait_paths(qemu, "verified after repairing the renderer", {"G": "GW_B", "B": "GW_A"})
        assert recovered["forwarding_id"] == exhausted["decision"]
        wait_receipt(qemu, lambda _, r: r.get("decision") == exhausted["decision"] and r["attempts"] == 0, 15)
    finally:
        command(qemu, f"mv {backup} {adapter}")
        fault()
    wait_paths(qemu, "restored after divergent reload", primary)
    management("restored after divergence", certificate)


def verify_expired_sample(qemu, primary, certificate):
    worker = command(qemu, 'pgrep -f -P "$(cat /var/run/sdwand.pid)" /usr/local/sbin/sdwand.php')
    assert worker.isdecimal(), worker
    command(qemu, f"kill -STOP {worker}")
    try:
        wait_receipt(qemu, lambda sample, _: not sample, 48)
        command(qemu, "test -s /var/run/sdwan-observer.json; /etc/rc.filter_configure_sync")
        assert_rules(loaded(qemu), {"G": None, "B": None})
        tcp_pair("stale observation", (None, None))
        management("stale observation", certificate)
    finally:
        command(qemu, f"kill -CONT {worker}")
    wait_paths(qemu, "fresh observation after expiry", primary)
    command(qemu, "grep -Fq 'previous observation expired before a new sample' /var/log/system.log")
    tcp_pair("fresh observation after expiry", (A, A))
    print("EXPIRED_SAMPLE_BLOCKED_AND_REPORTED_IN_SYSTEM_LOGS", flush=True)


def verify_native_dhcp(qemu, cleanup, provider, certificate):
    active = {"G": "GW_B", "B": "GW_A"}
    reference = route_and_nat(qemu)
    address, gateway = WAN2_RENEWED
    fault(f'iifname "sw-wire0" ip saddr {A} ip daddr 192.0.2.164 tcp dport 7 drop')
    try:
        initial = wait_paths(qemu, "before WAN2 lease change", active)
        tcp_pair("before WAN2 lease change", (B, A))
        stop(provider)
        renewed_provider = serve_lease(cleanup, address, gateway)
        command(qemu, f"php {LAB}/ce291-guest.php renew_wan2", timeout=90)
        wait_lease(qemu, address, gateway)
        current = wait_paths(qemu, "after WAN2 lease change", active, wan2_hop=gateway)
        assert current["forwarding_id"] != initial["forwarding_id"]
        tcp_pair("after WAN2 lease change", (address, A))
        assert route_and_nat(qemu) == reference
        management("after WAN2 lease change", certificate)
        print("NATIVE_DHCP_LEASE_NEW_ADDRESS_AND_HOP_APPLIED_IN_PF", flush=True)
        stop(renewed_provider)
        serve_lease(cleanup, B, GATEWAYS["GW_B"][1])
        command(qemu, f"php {LAB}/ce291-guest.php renew_wan2", timeout=90)
        wait_lease(qemu, B, GATEWAYS["GW_B"][1])
    finally:
        fault()
    wait_paths(qemu, "original WAN2 lease restored", {"G": "GW_A", "B": "GW_A"})


def acceptance(qemu, cleanup, provider):
    rv = command(qemu, f"pkg add {LAB}/pfSense-pkg-SDWAN-0.4.28.pkg", timeout=180)
    print(rv.splitlines()[-6:], flush=True)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.28"
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    print("PACKAGE_INSTALLED_WITH_NATIVE_HOOKS; STOCK_MODE_OBSERVATION", flush=True)

    command(qemu, f"pkg add -f {LAB}/pfSense-pkg-SDWAN-0.4.27.pkg", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.27"
    command(qemu, f"php {LAB}/ce291-guest.php settings")
    config_hash = "php -r 'require \"config.inc\";echo hash(\"sha256\", serialize(config_get_path(\"installedpackages/sdwan\")));'"
    saved = command(qemu, config_hash)
    command(qemu, f"pkg add -f {LAB}/pfSense-pkg-SDWAN-0.4.28.pkg", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.28"
    assert command(qemu, config_hash) == saved
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    print("NATIVE_UPGRADE_PRESERVES_POLICY_CONFIGURATION", flush=True)
    certificate = management("baseline")
    native_rules = loaded(qemu)
    primary = {"G": "GW_A", "B": "GW_A"}
    assert_rules(native_rules, primary)
    reference = route_and_nat(qemu)
    command(qemu, f"cp -p /etc/inc/filter.inc {LAB}/filter.stock; cp {LAB}/filter*.inc /etc/inc/")
    assert "ABI=2" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart")
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    wait_paths(qemu, "baseline", primary)
    tcp_pair("baseline", (A, A))
    same_target_probes(qemu)
    vti_no_sa(qemu)
    verify_unapplied_reload(qemu, primary, certificate)
    verify_expired_sample(qemu, primary, certificate)
    verify_native_dhcp(qemu, cleanup, provider, certificate)
    old_erp, old_backup = held_connection(ERP, cleanup), held_connection(BACKUP, cleanup)
    assert established(old_erp, "established") == f"{A} established"
    assert established(old_backup, "established") == f"{A} established"
    old_states = command(qemu, "pfctl -ss -vv | grep -A3 ESTABLISHED:ESTABLISHED")

    # Faults are limited to the disconnected fake provider namespace.
    fault(f'iifname "sw-wire0" ip saddr {A} ip daddr {{ {ERP}, 192.0.2.164 }} tcp dport 7 drop')
    dns = command(qemu, "drill @198.51.100.2 health.test A")
    assert "192.0.2.42" in dns, dns
    print("WAN1 DNS replied during the ERP outage", flush=True)
    decision = wait_paths(qemu, "ERP outage", {"G": "GW_B", "B": "GW_A"}, wait_ack=True)
    assert decision["members"]["a"]["status"] == "online"
    assert decision["policies"]["ERP"]["services"]["a"] == "Failed"
    assert decision["policies"]["Backup"]["services"]["a"] == "Passed"
    tcp_pair("ERP outage", (B, A))
    management("ERP outage", certificate)
    assert route_and_nat(qemu) == reference
    assert not established(old_erp, "held-during-erp-fault", .8)
    assert established(old_backup, "held-during-erp-fault") == f"{A} held-during-erp-fault"
    current_states = command(qemu, "pfctl -ss -vv | grep -A3 ESTABLISHED:ESTABLISHED")
    ids = lambda data: set(re.findall(r"id: ([a-f0-9]+) creatorid: ([a-f0-9]+)", data))
    preserved = ids(old_states) & ids(current_states)
    assert len(preserved) >= 2, preserved
    print(f"Native event acknowledged and applied. Preserved established PF states={sorted(preserved)}", flush=True)

    fault()
    wait_paths(qemu, "recovery", primary)
    tcp_pair("recovery", (A, A))
    assert select.select([old_erp.stdout], [], [], 12)[0]
    assert old_erp.stdout.readline().strip() == f"{A} held-during-erp-fault"

    fault(f'iifname "sw-wire0" ip saddr {A} drop', f'iifname "sw-wire2" ip saddr {B} drop')
    wait_paths(qemu, "both WANs down", {"G": None, "B": None})
    tcp_pair("both WANs down", (None, None))
    management("both WANs down", certificate)
    for stream in (old_erp, old_backup):
        assert not established(stream, "held-during-both-down", .8)
    fault()
    wait_paths(qemu, "WANs recovered", primary)
    tcp_pair("WANs recovered", (A, A))
    for stream in (old_erp, old_backup):
        assert select.select([stream.stdout], [], [], 12)[0]
        assert stream.stdout.readline().strip() == f"{A} held-during-both-down"
    assert route_and_nat(qemu) == reference
    print("Original ERP and backup TCP sessions replied after both WANs recovered", flush=True)

    booted = command(qemu, "sysctl -n kern.boottime")
    qemu.sendline("shutdown -r now")
    console_shell(qemu)
    assert command(qemu, "sysctl -n kern.boottime") != booted
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.28"
    command(qemu, "test -S /var/run/check_reload_status; /usr/local/etc/rc.d/sdwand.sh status")
    wait_paths(qemu, "after reboot", primary)
    tcp_pair("after reboot", (A, A))
    assert route_and_nat(qemu) == reference
    print("REBOOT_WITH_NATIVE_SERVICES_OK", flush=True)

    rollback_sessions = [held_connection(target, cleanup) for target in (ERP, BACKUP)]
    for stream in rollback_sessions:
        assert established(stream, "before rollback") == f"{A} before rollback"
    command(qemu, f"php {LAB}/ce291-guest.php unbind")
    command(qemu, f"cp -p {LAB}/filter.stock /etc/inc/filter.inc; rm /etc/inc/filter-sdwan.inc")
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart; /etc/rc.filter_configure_sync")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    assert loaded(qemu) == native_rules
    assert route_and_nat(qemu) == reference
    tcp_pair("native rollback", (A, A))
    management("native rollback", certificate)
    command(qemu, f"pkg add -f {LAB}/pfSense-pkg-SDWAN-0.4.27.pkg", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.27"
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    tcp_pair("package rollback", (A, A))
    for stream in rollback_sessions:
        assert established(stream, "after rollback") == f"{A} after rollback"
    print("NATIVE_AND_PACKAGE_ROLLBACK_OK", flush=True)


def appliance(image):
    assert os.geteuid() == 0 and Path(image).is_file()
    with ExitStack() as cleanup:
        nets = wire(cleanup)
        provider = serve_lease(cleanup, B, GATEWAYS["GW_B"][1])
        log = cleanup.enter_context(open("ce291-console.log", "w", encoding="utf-8"))
        qemu = pexpect.spawn("qemu-system-x86_64", [
            "-machine", "q35,accel=kvm:tcg", "-m", "3072", "-smp", "2",
            "-drive", f"file={image},format=raw,if=virtio", "-display", "none",
            "-serial", "stdio", "-monitor", "none", *nets,
        ], encoding="utf-8", codec_errors="replace", timeout=120)
        cleanup.callback(stop_vm, qemu)
        qemu.logfile_read = log
        first_boot(qemu)
        wait_lease(qemu, B, GATEWAYS["GW_B"][1])
        acceptance(qemu, cleanup, provider)
        print("CE_291_TWO_WAN_APPLIANCE_ACCEPTED", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        with socketserver.UDPServer(("198.51.100.2", 53), DnsEcho) as dns:
            with socketserver.ThreadingTCPServer(("0.0.0.0", 7), Echo) as server:
                threading.Thread(target=dns.serve_forever, daemon=True).start()
                print("ready", flush=True)
                server.serve_forever()
    elif sys.argv[1] == "management":
        management_request()
    elif sys.argv[1] in ("flow", "held"):
        client(sys.argv[2], held=sys.argv[1] == "held")
    else:
        appliance(Path(sys.argv[1]).resolve())
