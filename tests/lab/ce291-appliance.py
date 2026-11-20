#!/usr/bin/env python3
"""Exercise an installed pfSense system on a disconnected QEMU topology."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import socketserver
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
        ("sdwan-peer", "203.0.113.2/30"),
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
    run("ip", "-n", "sdwan-client", "route", "add", "default", "via", "192.0.2.1")
    for n in range(162, 168):
        run("ip", "-n", "sdwan-peer", "addr", "add", f"192.0.2.{n}/32", "dev", "lo")
    run(*in_ns("sdwan-peer", "nft", "-f", "-"), input=
        "table inet test {\n chain input {\n  type filter hook input priority filter; policy accept;\n }\n}\n")
    server = subprocess.Popen(in_ns("sdwan-peer", sys.executable, SCRIPT, "serve"),
                              stdout=subprocess.PIPE, text=True)
    cleanup.callback(stop, server)
    cleanup.callback(server.stdout.close)
    if not select.select([server.stdout], [], [], 4)[0] or server.stdout.readline().strip() != "ready":
        raise RuntimeError("The isolated peer failed to start")
    return net_args


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
    qemu.sendline("echo __SDWAN_SHELL__")
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


def wait_paths(qemu, label, expected, wait_ack=False):
    deadline = time.monotonic() + 135
    seen = set()
    while time.monotonic() < deadline:
        raw = command(qemu, f"php {LAB}/ce291-guest.php observations")
        parsed = json.loads(next(line for line in reversed(raw.splitlines()) if line.startswith("{")))
        snapshot, receipt = parsed["snapshot"] or {}, parsed["receipt"]
        if receipt and receipt["accepted"]:
            seen.add(receipt["decision"])
        steering = {name: row["gateway"] for name, row in snapshot.get("steering", {}).items()}
        verified = {name: ("blocked" if value is None else "applied") for name, value in expected.items()}
        if steering == expected and snapshot.get("forwarding_check") == verified:
            if wait_ack:
                assert snapshot["forwarding_id"] in seen, (label, "missing native acknowledgement", seen)
            rules = loaded(qemu)
            assert_rules(rules, expected)
            for line in rules.values():
                print(f"{label} PF {line}", flush=True)
            return snapshot
        time.sleep(1)
    raise RuntimeError(f"{label} did not converge: last observer response {raw}")


def loaded(qemu):
    raw = command(qemu, "pfctl -sr 2>/dev/null | awk '/ridentifier (41001|41003)$/ '")
    return {line.split()[-1]: line for line in raw.splitlines() if re.search(r"ridentifier (41001|41003)$", line)}


def assert_rules(rules, choices):
    assert set(rules) == {"41001", "41003"}, rules
    for group, tracker in (("G", "41001"), ("B", "41003")):
        wanted = choices[group]
        line = rules[tracker]
        if wanted is None:
            assert line.startswith("block "), line
        else:
            device, hop = GATEWAYS[wanted]
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


def acceptance(qemu, cleanup):
    rv = command(qemu, f"pkg add {LAB}/pfSense-pkg-SDWAN-0.4.28.pkg", timeout=180)
    print(rv.splitlines()[-6:], flush=True)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.28"
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    command(qemu, f"php {LAB}/ce291-guest.php settings")
    print("PACKAGE_INSTALLED_WITH_NATIVE_HOOKS; STOCK_MODE_OBSERVATION", flush=True)

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
    fault()
    wait_paths(qemu, "WANs recovered", primary)
    tcp_pair("WANs recovered", (A, A))
    assert route_and_nat(qemu) == reference

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

    command(qemu, f"php {LAB}/ce291-guest.php unbind")
    command(qemu, f"cp -p {LAB}/filter.stock /etc/inc/filter.inc; rm /etc/inc/filter-sdwan.inc")
    command(qemu, "/usr/local/etc/rc.d/sdwand.sh restart; /etc/rc.filter_configure_sync")
    assert "ABI=0" in command(qemu, f"php {LAB}/ce291-guest.php mode")
    assert loaded(qemu) == native_rules
    assert route_and_nat(qemu) == reference
    tcp_pair("native rollback", (A, A))
    command(qemu, f"pkg add -f {LAB}/pfSense-pkg-SDWAN-0.4.27.pkg", timeout=180)
    assert command(qemu, "pkg query '%v' pfSense-pkg-SDWAN") == "0.4.27"
    command(qemu, "pkg check -s pfSense-pkg-SDWAN; /usr/local/etc/rc.d/sdwand.sh status")
    tcp_pair("package rollback", (A, A))
    print("NATIVE_AND_PACKAGE_ROLLBACK_OK", flush=True)


def appliance(image):
    assert os.geteuid() == 0 and Path(image).is_file()
    with ExitStack() as cleanup:
        nets = wire(cleanup)
        log = cleanup.enter_context(open("ce291-console.log", "w", encoding="utf-8"))
        qemu = pexpect.spawn("qemu-system-x86_64", [
            "-machine", "q35,accel=kvm:tcg", "-m", "3072", "-smp", "2",
            "-drive", f"file={image},format=raw,if=virtio", "-display", "none",
            "-serial", "stdio", "-monitor", "none", *nets,
        ], encoding="utf-8", codec_errors="replace", timeout=120)
        cleanup.callback(stop_vm, qemu)
        qemu.logfile_read = log
        first_boot(qemu)
        acceptance(qemu, cleanup)
        print("CE_291_TWO_WAN_APPLIANCE_ACCEPTED", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        with socketserver.UDPServer(("198.51.100.2", 53), DnsEcho) as dns:
            with socketserver.ThreadingTCPServer(("0.0.0.0", 7), Echo) as server:
                threading.Thread(target=dns.serve_forever, daemon=True).start()
                print("ready", flush=True)
                server.serve_forever()
    elif sys.argv[1] in ("flow", "held"):
        client(sys.argv[2], held=sys.argv[1] == "held")
    else:
        appliance(Path(sys.argv[1]).resolve())
