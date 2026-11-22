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
import tempfile
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


def qmp_command(path, name, **arguments):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        with connection.makefile("rb") as stream:
            if "QMP" not in json.loads(stream.readline()):
                raise RuntimeError("QEMU did not send its QMP greeting")
            for request in ({"execute": "qmp_capabilities"}, {"execute": name, "arguments": arguments}):
                connection.sendall(json.dumps(request).encode() + b"\n")
                while True:
                    result = json.loads(stream.readline())
                    if "event" not in result:
                        break
                if "return" not in result:
                    raise RuntimeError(f"QMP {request['execute']} failed: {result}")
            return result["return"]


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


def wait_lease(qemu, address, gateway, device="vtnet2"):
    result = command(qemu, f'''i=0
        until ifconfig {device} | grep -Fq 'inet {address} ' &&
            test "$(cat /tmp/{device}_router 2>/dev/null)" = '{gateway}'; do
            i=$((i+1)); test "$i" -le 50; sleep 1
        done
        ifconfig {device} | grep -F 'inet {address} '
        cat /tmp/{device}_router''', timeout=60)
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


def first_boot(qemu, ce_version):
    # Kernel messages can interrupt the opening words of the serial prompt.
    expect_console(qemu, r"Enter full pathname of shell|RETURN for /bin/sh:", 180)
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
    for package in ("pfSense-base", "pfSense-kernel-pfSense"):
        assert f"{package} {ce_version}" in version.splitlines(), version
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
    identity = command(qemu, "cat /etc/version; pkg config ABI; uname -a; test -S /var/run/check_reload_status")
    assert identity.splitlines()[:2] == [f"{ce_version}-RELEASE", "FreeBSD:16:amd64"], identity
    print(identity, flush=True)


def observations(qemu):
    raw = command(qemu, f"php {LAB}/ce291-guest.php observations")
    return json.loads(next(line for line in reversed(raw.splitlines()) if line.startswith("{")))


def withdrawal_proven(state, started):
    proof = state["withdrawal_proof"]
    if not isinstance(proof, dict):
        return False
    generated = proof.get("started_ns")
    return (type(generated) is int and started <= generated <= state["monotonic_ns"]
            and proof.get("trackers") == ["41003"] and not state["receipt"].get("withdrawal")
            and state["active_ruleset"] is not None and proof.get("ruleset") == state["active_ruleset"])


def wait_paths(qemu, label, expected, wait_ack=False, wan2_hop=None, native_choices=None, withdrawal_after=None):
    started = time.monotonic()
    deadline = started + 135
    seen = set()
    valid_sample = False
    while time.monotonic() < deadline:
        parsed = observations(qemu)
        snapshot, receipt = parsed["snapshot"] or {}, parsed["receipt"]
        valid_sample |= bool(snapshot)
        if not valid_sample and time.monotonic() - started >= 45:
            break
        if receipt.get("accepted"):
            seen.add(receipt["signature"])
        steering = {name: row["gateway"] for name, row in snapshot.get("steering", {}).items()}
        verified = {name: ("blocked" if value is None else "applied") for name, value in expected.items()}
        signature = parsed["signature"]
        proof_current = withdrawal_after is None or withdrawal_proven(parsed, withdrawal_after)
        if (steering == expected and parsed["pf"] == verified and receipt.get("confirmed")
                and signature == receipt["signature"] and proof_current):
            if wait_ack:
                assert signature in seen, (label, "missing native acknowledgement", seen)
            rules = loaded(qemu)
            assert_rules(rules, {**expected, **(native_choices or {})}, wan2_hop)
            for line in rules.values():
                print(f"{label} PF {line}", flush=True)
            return parsed
        time.sleep(1)
    diagnostics(qemu)
    raise RuntimeError(f"{label} did not converge: last observer response {parsed}")


def diagnostics(qemu):
    raw = command(qemu, """date +%s
        ls -l /var/run/sdwan-observer* /var/run/dpinger*.sock || :
        cat /var/run/sdwan-observer.json || :
        pfctl -sr 2>/dev/null | grep -E 'ridentifier 4100[1-6]$' || :
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
    raw = command(qemu, "pfctl -P -sr 2>/dev/null | awk '/ridentifier (41001|41003)$/ '")
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


def verify_floating_rule(qemu, primary, certificate):
    try:
        command(qemu, f"php {LAB}/ce291-guest.php floating_erp_block on; /etc/rc.filter_configure_sync")
        rules = command(qemu, "pfctl -P -sr 2>/dev/null | awk '/ridentifier (41001|41003|41006)$/'").splitlines()
        assert [line.split()[-1] for line in rules] == ["41006", "41001", "41003"], rules
        assert re.match(r"^block (?:drop )?in quick on vtnet1\b", rules[0]), rules[0]
        print(f"Floating ERP block PF {rules[0]}", flush=True)
        state = observations(qemu)
        assert state["pf"] == {"G": "pending", "B": "applied"}, state
        tcp_pair("Floating blocks ERP only", (None, A))
        management("Floating blocks ERP only", certificate)
    finally:
        command(qemu, f"php {LAB}/ce291-guest.php floating_erp_block off; /etc/rc.filter_configure_sync")
    wait_paths(qemu, "after Floating block removal", primary)
    tcp_pair("after Floating block removal", (A, A))
    print("NATIVE_FLOATING_QUICK_PRECEDENCE_OK", flush=True)


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
        before_a, before_b = evidence_count("probe-a"), evidence_count("probe-b")
        package = json.loads(command(qemu, f"php {LAB}/ce291-guest.php package_fib_probe").splitlines()[-1])
        assert package == {name: {"probe_primary": "Passed"} for name in GATEWAYS}, package
        after_a, after_b = evidence_count("probe-a"), evidence_count("probe-b")
        assert after_a > before_a and after_b > before_b
        reversed_fibs = json.loads(command(qemu, f"php {LAB}/ce291-guest.php package_fib_probe reversed").splitlines()[-1])
        assert reversed_fibs == {name: {"probe_primary": "No matching host route or source"} for name in GATEWAYS}, reversed_fibs
        assert (evidence_count("probe-a"), evidence_count("probe-b")) == (after_a, after_b)
        assert route_and_nat(qemu) == reference
        print(f"SAME_IP_TWO_FIBS_OK: 192.0.2.168 returned via both physical WANs: {result!r}", flush=True)
        print("PACKAGE_SAME_IP_TWO_FIBS_OK: both probes passed, reversed routes were refused before sending", flush=True)
    finally:
        for fib, (_, hop) in enumerate(GATEWAYS.values(), 1):
            command(qemu, f"route -n delete -host 192.0.2.168 -fib {fib}; "
                          f"route -n delete -host {hop} -fib {fib}")
    assert route_and_nat(qemu) == reference


def vti_no_sa(qemu):
    # A ping sourced from a firewall WAN IP uses the native, source-based
    # route-to rule. The protected path must be tested with a LAN client.
    before = evidence_count("vti-clear")
    ping = in_ns("sdwan-client", "ping", "-n", "-c", 2, "-w", 4, "192.0.2.169")
    run(*ping, capture_output=True)
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
        result = subprocess.run(ping, check=False, text=True, capture_output=True, timeout=8)
        after = evidence_count("vti-clear")
        assert result.returncode == 1 and after == control, (result.stdout, result.stderr, control, after)
        assert int(command(qemu, stats)) > no_sa
        print("VTI_WITHOUT_SA_BLOCKS_WITHOUT_CLEARTEXT", flush=True)
    finally:
        command(qemu, f"route -n delete -host 192.0.2.169; ifconfig {device} destroy")
    run(*ping, capture_output=True)
    assert evidence_count("vti-clear") >= control + 2


def wait_receipt(qemu, condition, timeout):
    deadline = time.monotonic() + timeout
    state = {}
    while time.monotonic() < deadline:
        state = observations(qemu)
        if condition(state):
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

        def requested(state):
            sample, receipt = state["snapshot"] or {}, state["receipt"]
            return (sample.get("steering", {}).get("G", {}).get("gateway") == "GW_B"
                    and state["pf"].get("G") == "pending" and receipt.get("accepted")
                    and not receipt.get("confirmed") and receipt.get("signature") == state["signature"])

        first = wait_receipt(qemu, requested, 35)
        assert first["attempts"] == 1, first
        assert_rules(loaded(qemu), primary)
        management("accepted but divergent", certificate)
        exhausted = wait_receipt(qemu, lambda s: requested(s) and s["receipt"]["attempts"] == 3, 90)
        assert exhausted["signature"] == first["signature"]
        command(qemu, """i=0
            until grep -Fq 'Persistent PF divergence. Automatic reload attempts' /var/log/system.log; do
                i=$((i+1)); test "$i" -le 40; sleep 1
            done""", timeout=48)
        assert observations(qemu)["receipt"] == exhausted
        assert_rules(loaded(qemu), primary)
        print("NATIVE_RELOAD_ACCEPTED_BUT_DIVERGENT_RETRY_LIMIT_OK", flush=True)
        command(qemu, f"cp -p {backup} {adapter}; /etc/rc.filter_configure_sync")
        recovered = wait_paths(qemu, "verified after repairing the renderer", {"G": "GW_B", "B": "GW_A"})
        assert recovered["signature"] == exhausted["signature"]
        assert recovered["receipt"]["attempts"] == 0
    finally:
        command(qemu, f"mv {backup} {adapter}")
        fault()
    wait_paths(qemu, "restored after divergent reload", primary)
    management("restored after divergence", certificate)


def verify_expired_sample(qemu, primary, certificate):
    worker = command(qemu, 'pgrep -f -P "$(cat /var/run/sdwand.pid)" /usr/local/sbin/sdwand.php')
    queue = command(qemu, "pgrep -u 0 -x check_reload_status")
    assert worker.isdecimal() and queue.isdecimal(), (worker, queue)
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh watchdog_status")
    command(qemu, f"kill -STOP {worker} {queue}")
    try:
        wait_receipt(qemu, lambda s: not s["snapshot"], 48)
        command(qemu, """i=0
            until grep -Fq 'Active PF rules confirmed withdrawal of the expired forwarding passes.' /var/log/system.log; do
                i=$((i+1)); test "$i" -le 45; sleep 1
            done
            test -s /var/run/sdwan-observer.json""", timeout=52)
        assert_rules(loaded(qemu), {"G": None, "B": None})
        tcp_pair("stale observation", (None, None))
        management("stale observation", certificate)
    finally:
        command(qemu, f"kill -CONT {queue} {worker}")
    wait_paths(qemu, "fresh observation after expiry", primary)
    command(qemu, "grep -Fq 'Previous observation expired. Its result cannot be reused' /var/log/system.log")
    tcp_pair("fresh observation after expiry", (A, A))
    print("EXPIRED_SAMPLE_BLOCKED_AND_REPORTED_IN_SYSTEM_LOGS", flush=True)
    print("INDEPENDENT_EXPIRY_WATCHDOG_BLOCKED_TRAFFIC_WITH_OBSERVER_AND_QUEUE_SUSPENDED", flush=True)


def worker_pid(qemu):
    worker = command(qemu, "pgrep -P \"$(cat /var/run/sdwand.pid)\" -u 0 -fx "
                     "'/usr/local/bin/php /usr/local/sbin/sdwand\\.php'")
    assert worker.isdecimal(), worker
    return int(worker)


def verify_observer_restart(qemu, primary, certificate):
    original = worker_pid(qemu)
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart")
    restarted = wait_paths(qemu, "after observer restart", primary)
    assert restarted["snapshot"]["observer"]["pid"] == worker_pid(qemu) != original
    tcp_pair("after observer restart", (A, A))
    management("after observer restart", certificate)
    print("OBSERVER_RESTART_WITH_PF_CONFIRMATION_OK", flush=True)


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
        assert current["signature"] != initial["signature"]
        tcp_pair("after WAN2 lease change", (address, A))
        default, nat = reference
        expected = "\n".join(
            rule.replace(f" -> {B} ", f" -> {address} ", 1) if rule.startswith("nat on vtnet2 inet ") else rule
            for rule in nat.splitlines()
        )
        assert expected != nat, "The NAT baseline lacks a WAN2 IPv4 translation"
        assert route_and_nat(qemu) == (default, expected)
        management("after WAN2 lease change", certificate)
        print("NATIVE_DHCP_LEASE_NEW_ADDRESS_AND_HOP_APPLIED_IN_PF", flush=True)
        stop(renewed_provider)
        serve_lease(cleanup, B, GATEWAYS["GW_B"][1])
        command(qemu, f"php {LAB}/ce291-guest.php renew_wan2", timeout=90)
        wait_lease(qemu, B, GATEWAYS["GW_B"][1])
    finally:
        fault()
    wait_paths(qemu, "original WAN2 lease restored", {"G": "GW_A", "B": "GW_A"})
    assert route_and_nat(qemu) == reference


def acceptance(qemu, cleanup, provider, *, cold_restart):
    package = f"{LAB}/candidate.pkg"
    rollback = f"{LAB}/rollback.pkg"
    digest = command(qemu, f"sha256 -q {package}")
    assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
    assert digest == command(qemu, f"cat {LAB}/candidate.sha256")
    version = command(qemu, f"pkg query -F {package} '%v'")
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version
    previous_version = command(qemu, f"pkg query -F {rollback} '%v'")
    assert re.fullmatch(r"\d+\.\d+\.\d+", previous_version), previous_version
    assert command(qemu, f"pkg version -t {version} {previous_version}") == ">"
    print(f"CANDIDATE_PACKAGE version={version} sha256={digest}", flush=True)
    rv = command(qemu, f"pkg add {package}", timeout=180)
    print(rv.splitlines()[-6:], flush=True)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == version
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    print("PACKAGE_INSTALLED_WITH_NATIVE_HOOKS; STOCK_MODE_OBSERVATION", flush=True)

    command(qemu, f"pkg add -f {rollback}", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == previous_version
    command(qemu, f"php {LAB}/ce291-guest.php settings")
    config_hash = "php -r 'require \"config.inc\";echo hash(\"sha256\", serialize(config_get_path(\"installedpackages/sdwan\")));'"
    saved = command(qemu, config_hash)
    command(qemu, f"pkg add -f {package}", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == version
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
    assert "INITIAL_BIND_REJECTED_INVALID_PROBE_ROUTE" in command(qemu, f"php {LAB}/ce291-guest.php probe_route_guard")
    tcp_pair("native paths after rejected bind", (A, A))
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    wait_paths(qemu, "baseline", primary)
    tcp_pair("baseline", (A, A))
    assert "ACTIVE_POLICY_REJECTED_INVALID_PROBE_ROUTE" in command(qemu, f"php {LAB}/ce291-guest.php probe_route_guard")
    wait_paths(qemu, "rejected policy edit", primary)
    tcp_pair("applied paths after rejected edit", (A, A))
    management("rejected policy edit", certificate)
    print("PROBE_ROUTE_GUARD_PRESERVES_NATIVE_AND_ACTIVE_TRAFFIC", flush=True)
    verify_floating_rule(qemu, primary, certificate)
    vti_no_sa(qemu)
    verify_unapplied_reload(qemu, primary, certificate)
    verify_expired_sample(qemu, primary, certificate)
    verify_observer_restart(qemu, primary, certificate)
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
    decision = wait_paths(qemu, "ERP outage", {"G": "GW_B", "B": "GW_A"}, wait_ack=True)["snapshot"]
    assert decision["members"]["a"]["status"] == "online"
    assert decision["policies"]["ERP"]["candidates"]["a"] == "Required service check failed"
    assert decision["policies"]["Backup"]["candidates"]["a"] == "Eligible"
    assert decision["members"]["a"]["checks"]["probe_secondary"] == "Passed"
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
    qemu = cold_restart(qemu)
    assert command(qemu, "sysctl -n kern.boottime") != booted
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == version
    command(qemu, "test -S /var/run/check_reload_status; /usr/local/etc/rc.d/sdwand.sh status")
    for device in ("vtnet0", "vtnet2"):
        assert "status: no carrier" in command(qemu, f"ifconfig {device}")
    rebooted_offline = wait_paths(qemu, "cold boot with both carriers down", {"G": None, "B": None})
    assert rebooted_offline["snapshot"]["observer"] == {"pid": worker_pid(qemu), "version": version}
    tcp_pair("cold boot with no WAN", (None, None))
    management("cold boot with no WAN", certificate)
    qmp_command(qemu.sdwan_qmp, "set_link", name="lan2", up=True)
    wait_lease(qemu, B, GATEWAYS["GW_B"][1])
    wait_paths(qemu, "WAN2 restored after cold boot", {"G": "GW_B", "B": "GW_B"})
    tcp_pair("one WAN restored after cold boot", (B, B))
    qmp_command(qemu.sdwan_qmp, "set_link", name="lan0", up=True)
    rebooted = wait_paths(qemu, "after reboot", primary)
    assert rebooted["snapshot"]["observer"] == {"pid": worker_pid(qemu), "version": version}
    tcp_pair("after reboot", (A, A))
    assert route_and_nat(qemu) == reference
    print("COLD_BOOT_WITH_BOTH_WANS_DISCONNECTED_AND_RECOVERY_OK", flush=True)
    same_target_probes(qemu)

    # Keep both upstreams reachable and fail only the ERP probe on WAN1. The
    # restored native route is distinguishable from the last package choice.
    fault(f'iifname "sw-wire0" ip saddr {A} ip daddr 192.0.2.164 tcp dport 7 drop')
    wait_paths(qemu, "before ERP-only withdrawal", {"G": "GW_B", "B": "GW_A"})
    tcp_pair("before ERP-only withdrawal", (B, A))
    request = command(qemu, f"php {LAB}/ce291-guest.php unbind G")
    timestamps = re.findall(r"^WITHDRAWAL_START_NS=(\d+)$", request, flags=re.MULTILINE)
    assert len(timestamps) == 1, request
    started = int(timestamps[0])
    removed = wait_paths(qemu, "after ERP-only withdrawal", {"B": "GW_A"}, native_choices={"G": "GW_A"},
                         withdrawal_after=started)
    tcp_pair("after ERP-only withdrawal", (A, A))
    assert route_and_nat(qemu) == reference
    management("after ERP-only withdrawal", certificate)
    fault()
    print("SINGLE_BINDING_WITHDRAWN_BY_NATIVE_QUEUE_OK "
          f"request_after_ns={started} native_proof={removed['withdrawal_proof']}", flush=True)

    rollback_sessions = [held_connection(target, cleanup) for target in (ERP, BACKUP)]
    for stream in rollback_sessions:
        assert established(stream, "before rollback") == f"{A} before rollback"
    command(qemu, f"php {LAB}/ce291-guest.php unbind B")
    command(qemu, f"cp -p {LAB}/filter.stock /etc/inc/filter.inc; rm /etc/inc/filter-sdwan.inc")
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart; /etc/rc.filter_configure_sync")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    assert loaded(qemu) == native_rules
    assert route_and_nat(qemu) == reference
    tcp_pair("native rollback", (A, A))
    management("native rollback", certificate)
    command(qemu, f"pkg add -f {rollback}", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == previous_version
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    tcp_pair("package rollback", (A, A))
    for stream in rollback_sessions:
        assert established(stream, "after rollback") == f"{A} after rollback"
    print("NATIVE_AND_PACKAGE_ROLLBACK_OK", flush=True)


def recovery(qemu, cleanup, _provider, *, restart, image):
    package = f"{LAB}/candidate.pkg"
    command(qemu, f'test "$(sha256 -q {package})" = "$(cat {LAB}/candidate.sha256)"')
    version = command(qemu, f"pkg query -F {package} '%v'")
    assert command(qemu, "cat /etc/version") == "2.9.1-RELEASE"
    command(qemu, f"pkg add {package}", timeout=180)
    command(qemu, f"php {LAB}/ce291-guest.php settings")
    stock_hash = command(qemu, "sha256 -q /etc/inc/filter.inc")
    command(qemu, f"cp {LAB}/filter*.inc /etc/inc/; /usr/local/etc/rc.d/sdwand.sh restart")
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    primary = {"G": "GW_A", "B": "GW_A"}
    wait_paths(qemu, "before OS transaction", primary)
    tcp_pair("before OS transaction", (A, A))
    certificate = management("before OS transaction")
    config_hash = command(qemu, f"php {LAB}/ce291-guest.php capture_config")
    assert re.fullmatch(r"[0-9a-f]{64}", config_hash)
    reference = route_and_nat(qemu)
    backup_dir = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="sdwan-rollback-", dir=image.parent))
    backup = Path(backup_dir) / "ce291-before.raw"
    qemu = restart(qemu, copy_to=backup)
    command(qemu, f"""env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR={LAB}/ce292-repos \
        /usr/local/sbin/pkg-static install -Uy pfSense pfSense-base pfSense-kernel-pfSense \
        pfSense-system pfSense-default-config-serial""", timeout=430)
    qemu = restart(qemu)
    assert command(qemu, "cat /etc/version") == "2.9.2-RELEASE"
    assert command(qemu, "pkg query '%v' pfSense-base") == "2.9.2"
    assert command(qemu, "pkg query '%v' pfSense-kernel-pfSense") == "2.9.2"
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == version
    command(qemu, "pkg check -s pfSense-pkg-SDWAN")
    assert command(qemu, f"php {LAB}/ce291-guest.php capture_config") == config_hash
    management("after OS transaction", certificate)
    mode = command(qemu, f"php {LAB}/ce291-guest.php mode")
    print(f"OS_PACKAGE_TRANSACTION 2.9.1->2.9.2 adapter_after_reboot={mode}", flush=True)
    if mode == "ABI=0":
        assert command(qemu, "sha256 -q /etc/inc/filter.inc") == stock_hash
        assert_rules(loaded(qemu), primary)
        tcp_pair("stock after OS transaction", (A, A))
        command(qemu, f"cp {LAB}/filter*.inc /etc/inc/; /usr/local/etc/rc.d/sdwand.sh restart")
    else:
        assert mode == "ABI=2", mode
    wait_paths(qemu, "recovered after OS transaction", primary)
    tcp_pair("recovered after OS transaction", (A, A))
    assert route_and_nat(qemu) == reference

    command(qemu, f"php {LAB}/ce291-guest.php restore_remapped")
    qemu = restart(qemu, model="e1000")
    wait_lease(qemu, B, GATEWAYS["GW_B"][1], "em2")
    assert command(qemu, f"php {LAB}/ce291-guest.php capture_config") == config_hash
    management("restored on em interfaces", certificate)
    blocked = loaded(qemu)
    assert set(blocked) == {"41001", "41003"} and all(
        line.startswith("block ") and " on em1 " in line for line in blocked.values()
    ), blocked
    tcp_pair("restored bindings require reapproval", (None, None))
    print("REMAPPED_BINDINGS_REFUSED_PREVIOUS_PHYSICAL_SCOPE", flush=True)
    for group, tracker in (("G", "41001"), ("B", "41003")):
        command(qemu, f"php {LAB}/ce291-guest.php unbind {group}")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            native_rule = loaded(qemu).get(tracker, "")
            if native_rule.startswith("pass ") and "route-to (em0 198.51.100.2)" in native_rule and not (
                observations(qemu)["receipt"].get("withdrawal")
            ):
                break
            time.sleep(1)
        else:
            diagnostics(qemu)
            raise RuntimeError(f"The native rule did not return after unbinding {group}")
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    # Exercise a service-only failure and confirm the new physical devices in PF.
    fault(f'iifname "sw-wire0" ip saddr {A} ip daddr {{ {ERP}, 192.0.2.164 }} tcp dport 7 drop')
    try:
        deadline = time.monotonic() + 135
        while time.monotonic() < deadline:
            state = observations(qemu)
            if state["pf"] == {"G": "applied", "B": "applied"} and state["receipt"].get("confirmed"):
                rules = loaded(qemu)
                if ("route-to (em2 203.0.113.2)" in rules.get("41001", "") and
                        "route-to (em0 198.51.100.2)" in rules.get("41003", "")):
                    break
            time.sleep(1)
        else:
            diagnostics(qemu)
            raise RuntimeError("PF did not converge on the remapped interfaces")
        tcp_pair("after interface remap", (B, A))
    finally:
        fault()
    print("NATIVE_CONFIG_RESTORE_VIRTIO_TO_E1000_OK", flush=True)

    qemu = restart(qemu, disk=backup)
    wait_lease(qemu, B, GATEWAYS["GW_B"][1])
    assert command(qemu, "cat /etc/version") == "2.9.1-RELEASE"
    assert command(qemu, f"php {LAB}/ce291-guest.php capture_config") == config_hash
    wait_paths(qemu, "after disk rollback", primary)
    tcp_pair("after disk rollback", (A, A))
    management("after disk rollback", certificate)
    assert route_and_nat(qemu) == reference
    print("OS_DISK_ROLLBACK_OK", flush=True)


def appliance(image, ce_version, scenario=acceptance):
    assert os.geteuid() == 0 and Path(image).is_file()
    lab = {"2.9.1": "ce291", "2.9.2": "ce292"}[ce_version]
    with ExitStack() as cleanup:
        nets = wire(cleanup)
        provider = serve_lease(cleanup, B, GATEWAYS["GW_B"][1])
        log = cleanup.enter_context(open(f"{lab}-console.log", "w", encoding="utf-8"))
        def spawn(disconnected=(), disk=image, model="virtio-net-pci"):
            control_dir = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="sdwan-qmp-"))
            control = Path(control_dir) / "control.sock"
            process = pexpect.spawn("qemu-system-x86_64", [
                "-machine", "q35,accel=kvm:tcg", "-m", "3072", "-smp", "2",
                "-drive", f"file={disk},format=raw,if=virtio", "-display", "none",
                "-serial", "stdio", "-monitor", "none", "-qmp", f"unix:{control},server=on,wait=off",
                "-S", *(arg.replace("virtio-net-pci,", model + ",") for arg in nets),
            ], encoding="utf-8", codec_errors="replace", timeout=120)
            cleanup.callback(stop_vm, process)
            process.logfile_read = log
            process.sdwan_qmp = control
            deadline = time.monotonic() + 10
            while not control.exists():
                if not process.isalive() or time.monotonic() >= deadline:
                    raise RuntimeError("Could not open the QEMU control socket")
                time.sleep(.05)
            for name in disconnected:
                qmp_command(control, "set_link", name=name, up=False)
            qmp_command(control, "cont")
            return process

        def restart(previous, disconnected=(), disk=image, model="virtio-net-pci", copy_to=None):
            previous.sendline("shutdown -p now")
            previous.expect(pexpect.EOF, timeout=180)
            previous.close()
            if copy_to is not None:
                subprocess.run(["cp", "--sparse=always", "--reflink=auto", image, copy_to],
                               check=True, timeout=120)
            restarted = spawn(disconnected, disk, model)
            console_shell(restarted)
            return restarted

        qemu = spawn()
        first_boot(qemu, ce_version)
        wait_lease(qemu, B, GATEWAYS["GW_B"][1])
        if scenario is acceptance:
            acceptance(qemu, cleanup, provider, cold_restart=lambda previous: restart(previous, ("lan0", "lan2")))
            print(f"CE_{ce_version.replace('.', '')}_TWO_WAN_APPLIANCE_ACCEPTED", flush=True)
        elif scenario is recovery:
            recovery(qemu, cleanup, provider, restart=restart, image=image)
        else:
            scenario(qemu, cleanup, provider)


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
        ce_version = sys.argv[2] if len(sys.argv) > 2 else "2.9.1"
        if ce_version not in ("2.9.1", "2.9.2"):
            raise SystemExit(f"Unsupported pfSense CE release: {ce_version}")
        scenario = sys.argv[3] if len(sys.argv) > 3 else "acceptance"
        if scenario not in ("acceptance", "recovery") or (scenario == "recovery" and ce_version != "2.9.1"):
            raise SystemExit(f"Unsupported scenario for CE {ce_version}: {scenario}")
        appliance(Path(sys.argv[1]).resolve(), ce_version, recovery if scenario == "recovery" else acceptance)
