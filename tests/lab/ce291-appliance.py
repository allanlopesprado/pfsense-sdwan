#!/usr/bin/env python3
"""Exercise an installed pfSense system on a disconnected QEMU topology."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, suppress
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


def qmp_command(path, command_name, **arguments):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        with connection.makefile("rb") as stream:
            if "QMP" not in json.loads(stream.readline()):
                raise RuntimeError("QEMU did not send its QMP greeting")
            for request in ({"execute": "qmp_capabilities"}, {"execute": command_name, "arguments": arguments}):
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
        if len(query) < 17:
            return
        qtype, qclass = struct.unpack_from("!HH", query, len(query) - 4)
        data = None
        if qclass == 1 and qtype == 1:
            data = socket.inet_aton("192.0.2.42")
        elif qclass == 1 and qtype == 28 and not query[12:].startswith(b"\x08ipv4only"):
            data = socket.inet_pton(socket.AF_INET6, "2001:db8::42")
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, int(data is not None), 0, 0)
        record = b"" if data is None else struct.pack("!HHHIH", 0xc00c, qtype, 1, 30, len(data)) + data
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


def verify_overlay_boot(qemu):
    evidence = command(qemu, f"""test -S /var/run/check_reload_status
        cmp -s {LAB}/filter.inc /etc/inc/filter.inc
        cmp -s {LAB}/filter-sdwan.inc /etc/inc/filter-sdwan.inc
        sha256 -q /etc/inc/filter.inc /etc/inc/filter-sdwan.inc
        php {LAB}/ce291-guest.php overlay_boot""").splitlines()
    assert len(evidence) == 3 and evidence[-1] == "OVERLAY_BOOT=ready", evidence
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in evidence[:2]), evidence
    print(f"CE_OVERLAY_BOOT_READY sha256={evidence[:2]!r}", flush=True)


def reboot_with_overlay(qemu):
    boot = command(qemu, "sysctl -n kern.boottime")
    qemu.sendline("shutdown -r now")
    console_shell(qemu)
    wait_lease(qemu, B, GATEWAYS["GW_B"][1])
    boot_after = command(qemu, "sysctl -n kern.boottime")
    assert boot_after != boot, (boot, boot_after)
    verify_overlay_boot(qemu)
    print(f"CE_OVERLAY_BOOT_CHANGED boot={boot_after!r}", flush=True)


def first_boot(qemu, ce_version):
    # Asynchronous kernel messages can split even the path at the end of this prompt.
    expect_console(qemu, r"Enter full pathname of shell|RETURN for /bin/sh:|\r+\nsh: ", 180)
    qemu.sendline("")
    qemu.expect(r"# ")
    command(qemu, "mount -uw /; mkdir -p /tmp /var/tmp /var/run /var/log; chmod 1777 /tmp /var/tmp")
    expected_digest = os.environ.get("SDWAN_EXPECTED_PACKAGE_SHA256")
    if expected_digest is not None:
        actual_digest = command(qemu, f"sha256 -q {LAB}/candidate.pkg")
        if actual_digest != expected_digest:
            raise RuntimeError("The appliance disk candidate differs from the workflow artifact.")
        print(f"CE_CANDIDATE_ARTIFACT_SHA256={actual_digest}", flush=True)
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


def withdrawal_proven(state, started, trackers=("41003",)):
    proof = state["withdrawal_proof"]
    if not isinstance(proof, dict):
        return False
    generated = proof.get("started_ns")
    return (type(generated) is int and started <= generated <= state["monotonic_ns"]
            and proof.get("trackers") == list(trackers) and not state["receipt"].get("withdrawal")
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


def ingress_tcp_states(qemu, targets):
    states = {target: {} for target in targets}
    header = re.compile(r"^(?:vtnet1|all) tcp (\S+):7 <- 192\.0\.2\.11:\d+\s+(\S+)\s*$")
    state_id = re.compile(r"\bid: ([a-f0-9]+) creatorid: ([a-f0-9]+)\b", re.I)
    next_hop = re.compile(r"\b(?:route-to|rt): (\S+@\S+)")
    current = None
    for line in command(qemu, "pfctl -vvss 2>/dev/null", timeout=20).splitlines():
        if line and not line[0].isspace():
            current = header.fullmatch(line)
            continue
        if current is None or current[1] not in states:
            continue
        identifier = state_id.search(line)
        if identifier:
            hop = next_hop.search(line)
            states[current[1]]["/".join(identifier.groups())] = {
                "status": current[2], "next_hop": hop[1] if hop else None,
            }
    return states


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


def verify_updater_readiness(qemu, version, installed_since, *, forwarding):
    deadline = time.monotonic() + 45
    invocation = f"php {LAB}/ce291-guest.php release_readiness {version} {installed_since}"
    expected = {"verification": "verified", "registered": True, "guard_required": forwarding,
                "guard_ready": forwarding}
    state = {}
    while time.monotonic() < deadline:
        output = command(qemu, invocation)
        state = json.loads(next(line for line in reversed(output.splitlines()) if line.startswith("{")))
        if state == expected:
            command(qemu, "/usr/local/etc/rc.d/sdwand.sh service_status")
            mode = "forwarding" if forwarding else "observation"
            print(f"UPDATER_READINESS_CONFIRMED mode={mode} version={version}", flush=True)
            return
        time.sleep(1)
    raise RuntimeError(f"The updater did not confirm appliance readiness: {state}")


def verify_native_menu_file(qemu, archive):
    menu = "/usr/local/share/pfSense/menu/sdwan.xml"
    files = command(qemu, f"tar -tf {archive}").splitlines()
    if menu.lstrip("/") not in {name.strip().lstrip("./") for name in files}:
        command(qemu, f"test ! -e {menu}")
        print("NATIVE_MENU_FILE_ABSENT_FROM_OLDER_PACKAGE", flush=True)
        return
    script = ('require "config.inc"; $path = g_get("ext_menu_path") . "/sdwan.xml"; '
              'echo json_encode(array_column(parse_xml_config_pkg($path, "packagegui")["menu"], "url", "section"));')
    entries = json.loads(command(qemu, f"test -s {menu}\nphp -r {shlex.quote(script)}"))
    assert entries == {"Status": "/sdwan/status.php", "Diagnostics": "/sdwan/diagnostics.php"}, entries
    print("NATIVE_STATUS_AND_DIAGNOSTICS_MENU_FILE_OK", flush=True)


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
    log_event = "Active PF rules confirmed reconciliation of stale forwarding."

    def confirmations():
        return int(command(qemu, f"grep -Fc '{log_event}' /var/log/system.log || :"))

    worker = command(qemu, 'pgrep -f -P "$(cat /var/run/sdwand.pid)" /usr/local/sbin/sdwand.php')
    queue = command(qemu, "pgrep -u 0 -x check_reload_status").splitlines()
    pids = [worker, *queue]
    assert queue and all(re.fullmatch(r"[1-9][0-9]*", pid) for pid in pids), pids
    processes = " ".join(pids)
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh watchdog_status")
    previous_confirmations = confirmations()
    try:
        command(qemu, f"kill -STOP {processes}")
        wait_receipt(qemu, lambda s: not s["snapshot"], 48)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            rules = loaded(qemu)
            if (set(rules) == {"41001", "41003"} and all(line.startswith("block ") for line in rules.values())
                    and confirmations() > previous_confirmations):
                break
            time.sleep(1)
        else:
            diagnostics(qemu)
            raise RuntimeError("The watchdog did not confirm and load the expected PF blocks after expiry")
        command(qemu, "test -s /var/run/sdwan-observer.json")
        tcp_pair("stale observation", (None, None))
        management("stale observation", certificate)
    finally:
        command(qemu, f"kill -CONT {processes}")
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
    targets = {"erp": ERP, "backup": BACKUP, "native_control": "192.0.2.166"}
    with ExitStack() as sessions:
        sessions.callback(fault)
        fault(f'iifname "sw-wire0" ip saddr {A} ip daddr 192.0.2.164 tcp dport 7 drop')
        initial = wait_paths(qemu, "before WAN2 lease change", active)
        tcp_pair("before WAN2 lease change", (B, A))
        sockets = {name: held_connection(target, sessions) for name, target in targets.items()}
        for name, child in sockets.items():
            assert established(child, "before-lease-change") == f"{B if name == 'erp' else A} before-lease-change"
        before = ingress_tcp_states(qemu, targets.values())
        state_ids = {}
        for name, target in targets.items():
            matches = [key for key, entry in before[target].items() if entry["status"] == "ESTABLISHED:ESTABLISHED"]
            assert len(matches) == 1, (name, before[target])
            state_ids[name] = matches[0]
        assert before[ERP][state_ids["erp"]]["next_hop"] == "203.0.113.2@vtnet2", before[ERP]
        assert before[BACKUP][state_ids["backup"]]["next_hop"] == "198.51.100.2@vtnet0", before[BACKUP]

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
        changed = ingress_tcp_states(qemu, targets.values())
        try:
            erp_reply = established(sockets["erp"], "after-lease-change", receive=2)
        except BrokenPipeError:
            with suppress(BrokenPipeError):
                sockets["erp"].stdin.close()
            erp_reply = ""
        assert erp_reply in ("", f"{B} after-lease-change"), erp_reply
        evidence = {name: {
            "id": state_ids[name], "before": before[target][state_ids[name]],
            "after": changed[target].get(state_ids[name]),
        } for name, target in targets.items()}
        print("NATIVE_DHCP_ESTABLISHED_STATE_EVIDENCE " + json.dumps({
            "sessions": evidence, "old_erp_peer_reply": erp_reply,
        }, sort_keys=True), flush=True)
        for name in ("backup", "native_control"):
            assert changed[targets[name]].get(state_ids[name]) == before[targets[name]][state_ids[name]], name
            assert established(sockets[name], "after-lease-change") == f"{A} after-lease-change", name
        print("NATIVE_DHCP_LEASE_NEW_ADDRESS_AND_HOP_APPLIED_IN_PF", flush=True)
        stop(renewed_provider)
        serve_lease(cleanup, B, GATEWAYS["GW_B"][1])
        command(qemu, f"php {LAB}/ce291-guest.php renew_wan2", timeout=90)
        wait_lease(qemu, B, GATEWAYS["GW_B"][1])
        restored = ingress_tcp_states(qemu, targets.values())
        for name in ("backup", "native_control"):
            assert restored[targets[name]].get(state_ids[name]) == before[targets[name]][state_ids[name]], name
            assert established(sockets[name], "after-original-lease") == f"{A} after-original-lease", name
        print("NATIVE_DHCP_BACKUP_AND_UNBOUND_SESSIONS_PRESERVED", flush=True)
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
    installed_since = int(command(qemu, "date +%s"))
    rv = command(qemu, f"pkg add {package}", timeout=180)
    print(rv.splitlines()[-6:], flush=True)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == version
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    print(command(qemu, f"php {LAB}/ce291-guest.php release_manifest {version}"), flush=True)
    verify_updater_readiness(qemu, version, installed_since, forwarding=False)
    verify_native_menu_file(qemu, package)
    print("PACKAGE_INSTALLED_WITH_NATIVE_HOOKS; STOCK_MODE_OBSERVATION", flush=True)

    command(qemu, f"pkg -o DEVELOPER_MODE=yes install -f -l -U -y {rollback}", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == previous_version
    verify_native_menu_file(qemu, rollback)
    command(qemu, f"php {LAB}/ce291-guest.php settings")
    config_hash = "php -r 'require \"config.inc\";echo hash(\"sha256\", serialize(config_get_path(\"installedpackages/sdwan\")));'"
    saved = command(qemu, config_hash)
    installed_since = int(command(qemu, "date +%s"))
    command(qemu, f"pkg add -f {package}", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == version
    assert command(qemu, config_hash) == saved
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    verify_updater_readiness(qemu, version, installed_since, forwarding=False)
    verify_native_menu_file(qemu, package)
    print("NATIVE_UPGRADE_PRESERVES_POLICY_CONFIGURATION", flush=True)
    certificate = management("baseline")
    native_rules = loaded(qemu)
    primary = {"G": "GW_A", "B": "GW_A"}
    assert_rules(native_rules, primary)
    reference = route_and_nat(qemu)
    command(qemu, f"cp -p /etc/inc/filter.inc {LAB}/filter.stock; cp {LAB}/filter*.inc /etc/inc/")
    reboot_with_overlay(qemu)
    assert "INITIAL_BIND_REJECTED_INVALID_PROBE_ROUTE" in command(qemu, f"php {LAB}/ce291-guest.php probe_route_guard")
    tcp_pair("native paths after rejected bind", (A, A))
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    wait_paths(qemu, "baseline", primary)
    verify_updater_readiness(qemu, version, installed_since, forwarding=True)
    history_script = ('require "/usr/local/pkg/sdwan_log.inc"; '
                      'echo json_encode(sdwan_log_recent_policy_events("/var/log/system.log", "ERP"));')
    deadline = time.monotonic() + 30
    while True:
        history = json.loads(command(qemu, f"php -r {shlex.quote(history_script)}")) or []
        if (any(event["type"] == "recommended" for event in history)
                and any(event["type"] == "applied" and "gateway GW_A in group G." in event["detail"]
                        for event in history)):
            break
        assert time.monotonic() < deadline, history
        time.sleep(1)
    print("NATIVE_SYSLOG_POLICY_RECOMMENDATION_AND_PF_CONFIRMATION_OK", flush=True)
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
    request = command(qemu, f"php {LAB}/ce291-guest.php unbind B")
    timestamps = re.findall(r"^WITHDRAWAL_START_NS=([0-9]+)$", request, re.M)
    assert len(timestamps) == 1, request
    started = int(timestamps[0])
    wait_receipt(qemu, lambda state: state["snapshot"] and not state["snapshot"].get("steering")
                 and not state["receipt"] and withdrawal_proven(state, started, ()), 45)
    assert loaded(qemu) == native_rules
    assert route_and_nat(qemu) == reference
    tcp_pair("after final withdrawal", (A, A))
    for stream in rollback_sessions:
        assert established(stream, "after final withdrawal") == f"{A} after final withdrawal"
    print("FINAL_BINDING_RESTORED_NATIVE_RULES_OK", flush=True)
    command(qemu, f"cp -p {LAB}/filter.stock /etc/inc/filter.inc; rm /etc/inc/filter-sdwan.inc")
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart; /etc/rc.filter_configure_sync")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    assert loaded(qemu) == native_rules
    assert route_and_nat(qemu) == reference
    tcp_pair("native rollback", (A, A))
    management("native rollback", certificate)
    # Reinstall the same bytes without rebooting, with the old proof still present.
    command(qemu, f"test -s /var/run/sdwan-filter-boot.json; cp {LAB}/filter*.inc /etc/inc/")
    assert "NATIVE_WARM_BIND_REFUSED_BEFORE_OVERLAY_BOOT" in command(
        qemu, f"php {LAB}/ce291-guest.php refuse_warm_bind"
    )
    print("NATIVE_SAME_OVERLAY_REINSTALL_REQUIRES_REBOOT", flush=True)
    command(qemu, f"cp -p {LAB}/filter.stock /etc/inc/filter.inc; rm /etc/inc/filter-sdwan.inc")
    command(qemu, f"pkg -o DEVELOPER_MODE=yes install -f -l -U -y {rollback}", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == previous_version
    verify_native_menu_file(qemu, rollback)
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    tcp_pair("package rollback", (A, A))
    for stream in rollback_sessions:
        assert established(stream, "after rollback") == f"{A} after rollback"
    print("NATIVE_AND_PACKAGE_ROLLBACK_OK", flush=True)


def install_candidate(qemu):
    package = f"{LAB}/candidate.pkg"
    command(qemu, f'test "$(sha256 -q {package})" = "$(cat {LAB}/candidate.sha256)"')
    version = command(qemu, f"pkg query -F {package} '%v'")
    command(qemu, f"pkg add {package}", timeout=180)
    command(qemu, f"php {LAB}/ce291-guest.php settings")
    stock_hash = command(qemu, "sha256 -q /etc/inc/filter.inc")
    command(qemu, f"cp {LAB}/filter*.inc /etc/inc/; /usr/local/etc/rc.d/sdwand.sh restart")
    return version, stock_hash


def install_bound_candidate(qemu):
    version, stock_hash = install_candidate(qemu)
    reboot_with_overlay(qemu)
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    return version, stock_hash


def path_checks(qemu, _cleanup, _provider):
    install_bound_candidate(qemu)
    primary = {"G": "GW_A", "B": "GW_A"}
    wait_paths(qemu, "before focused path checks", primary)
    certificate = management("before focused path checks")
    verify_expired_sample(qemu, primary, certificate)
    same_target_probes(qemu)
    print("CE_PATH_CHECKS_OK", flush=True)


def fleet_pilot(qemu, _cleanup, _provider):
    install_candidate(qemu)
    command(qemu, f"php {LAB}/ce291-guest.php fleet_pilot_group")
    reboot_with_overlay(qemu)
    command(qemu, f"php {LAB}/ce291-guest.php bind")
    primary = {"G": "GW_A", "B": "GW_A"}
    wait_paths(qemu, "before fleet policy", primary)
    certificate = management("before fleet policy")
    reference = route_and_nat(qemu)
    site = f"php {LAB}/fleet-site.php"
    command(qemu, f"{site} enroll pilot")

    def report():
        return json.loads(command(qemu, f"{site} status"))

    controller = SCRIPT.parents[2] / "tools/fleet-controller.py"
    with tempfile.TemporaryDirectory(prefix="sdwan-fleet-") as folder:
        store = Path(folder) / "controller"

        def manage(*args):
            return json.loads(run(sys.executable, controller, store, *args, capture_output=True).stdout)

        manage("enroll", "pilot")
        before = report()
        bundle = manage("publish", "pilot", "1", before["config_sha256"], "ERP", "lab", "balance")
        manifest = Path(bundle["path"]).read_text(encoding="utf-8")
        command(qemu, f"printf %s {shlex.quote(manifest)} > {LAB}/fleet-policy.json")
        command(qemu, f"{site} apply {LAB}/fleet-policy.json {bundle['sha256']}")
        deadline = time.monotonic() + 135
        while time.monotonic() < deadline:
            applied = report()
            paths = {item["policy"]: item for item in applied["paths"]}
            if (applied["revision"] == 1 and paths["ERP"]["pf"] == "applied" and
                    set(paths["ERP"]["gateways"]) == {"GW_A", "GW_B"} and
                    paths["Backup"]["pf"] == "applied" and paths["Backup"]["gateways"] == ["GW_A"]):
                break
            time.sleep(1)
        else:
            raise AssertionError(f"Fleet revision did not reach PF: {applied}")
        report_path = Path(folder) / "pilot.json"
        report_path.write_text(json.dumps(applied), encoding="utf-8")
        manage("report", "pilot", report_path)
        assert manage("inventory") == [{"site": "pilot", "report": applied}]
        print(f"FLEET_CONTROLLER_CONFIRMED_PF {json.dumps(applied)}", flush=True)

    # The controller directory is gone and no appliance route depends on it.
    assert not store.exists()
    assert report()["revision"] == 1
    for target, expected in [(ERP, {A, B}), (BACKUP, {A})]:
        peers = set()
        for attempt in range(8):
            payload = f"fleet-offline-{attempt}"
            response = run(*in_ns("sdwan-client", sys.executable, SCRIPT, "flow", target),
                           input=payload + "\n", capture_output=True).stdout.strip().split()
            assert len(response) == 2 and response[1] == payload, response
            peers.add(response[0])
        assert peers == expected, peers
        print(f"FLEET_OFFLINE_PEER_SOURCES {target} {sorted(peers)}", flush=True)
    command(qemu, f"{site} rollback")
    wait_paths(qemu, "fleet rollback", primary)
    assert report()["revision"] == 0
    tcp_pair("fleet rollback", (A, A))
    management("fleet rollback", certificate)
    assert route_and_nat(qemu) == reference
    print("FLEET_PILOT_OFFLINE_AND_ROLLBACK_OK", flush=True)


def recovery(qemu, cleanup, _provider, *, restart, image):
    assert command(qemu, "cat /etc/version") == "2.9.1-RELEASE"
    version, stock_hash = install_bound_candidate(qemu)
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
        command(qemu, f"cp {LAB}/filter*.inc /etc/inc/")
        reboot_with_overlay(qemu)
    else:
        assert mode == "ABI=2", mode
        verify_overlay_boot(qemu)
    wait_paths(qemu, "recovered after OS transaction", primary)
    tcp_pair("recovered after OS transaction", (A, A))
    assert route_and_nat(qemu) == reference

    command(qemu, f"php {LAB}/ce291-guest.php restore_remapped")
    qemu = restart(qemu, model="e1000")
    wait_lease(qemu, B, GATEWAYS["GW_B"][1], "em2")
    verify_overlay_boot(qemu)
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
        scenarios = {"acceptance": acceptance, "paths": path_checks, "recovery": recovery, "fleet-pilot": fleet_pilot}
        if scenario not in scenarios or (scenario == "recovery" and ce_version != "2.9.1"):
            raise SystemExit(f"Unsupported scenario for CE {ce_version}: {scenario}")
        appliance(Path(sys.argv[1]).resolve(), ce_version, scenarios[scenario])
