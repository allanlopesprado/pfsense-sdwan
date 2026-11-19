#!/usr/bin/env python3
"""Exercise real DHCP leases and PPPoE sessions in disposable namespaces."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

from ikev2.run import inside, run, stop_process, wait_for

FIRST = ("192.0.2.10", "192.0.2.1")
SECOND = ("198.51.100.10", "198.51.100.1")
ROOT = Path(__file__).resolve().parent


def launch(stack, work, name, node, *command):
    log = stack.enter_context((work / (name + ".log")).open("w"))
    child = subprocess.Popen(inside(node, *command), stdout=log, stderr=log)
    stack.callback(stop_process, child, signal.SIGTERM)
    return child


def setup(stack):
    client, server = ("access" + side + str(os.getpid()) for side in ("client", "server"))
    for node in (client, server):
        run(["ip", "netns", "add", node])
        stack.callback(run, ["ip", "netns", "del", node], check=False)
        run(["ip", "-n", node, "link", "set", "lo", "up"])
    run(["ip", "-n", client, "link", "add", "access0", "type", "veth", "peer", "name", "access0", "netns", server])
    for node in (client, server):
        run(["ip", "-n", node, "link", "set", "access0", "up"])
    return client, server


def addresses(node, device):
    query = run(["ip", "-n", node, "-j", "-4", "addr", "show", "dev", device], check=False)
    if query.returncode:
        return []
    return [entry for iface in json.loads(query.stdout) for entry in iface["addr_info"]]


def prove(node, device, expected, phase):
    source, gateway = expected
    if not any(addr["local"] == source for addr in addresses(node, device)):
        raise RuntimeError("The negotiated address was not configured")
    route = json.loads(run(["ip", "-n", node, "-j", "-4", "route", "get", gateway]).stdout)[0]
    if (route["dev"], route.get("prefsrc")) != (device, source):
        raise RuntimeError(f"Unexpected live route: {route}")
    run(inside(node, "ping", "-n", "-c", "2", "-W", "1", gateway))
    print(f"ok - {phase}: {source} reached its next hop {gateway} through {device}")
    return route["prefsrc"], route["dst"]


def dhcp(work, stack, client, server):
    for node in (client, server):
        run(inside(node, "ethtool", "-K", "access0", "tx", "off"))
    events = work / "lease.log"
    hook = work / "dhcp-hook"
    hook.write_text(r"""#!/bin/sh
set -eu
case "$1" in
    bound|renew)
        ip -4 addr flush dev "$interface" scope global
        ip addr add "$ip/24" dev "$interface"
        set -- $router
        ip route replace default via "$1" dev "$interface"
        printf '%s %s\n' "$ip" "$1" >> "$SDWAN_LEASE_EVENTS"
        ;;
    deconfig)
        ip -4 addr flush dev "$interface" scope global
        ip route del default dev "$interface" 2>/dev/null || :
        ;;
esac
""")
    hook.chmod(0o700)

    def offer(label, lease):
        ip, gateway = lease
        run(["ip", "-n", server, "addr", "replace", gateway + "/24", "dev", "access0"])
        return launch(stack, work, label, server, "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null",
                      "--port=0", "--interface=access0", "--bind-interfaces", "--log-dhcp", "--log-facility=-",
                      "--dhcp-broadcast", "--dhcp-authoritative", f"--dhcp-range={ip},{ip},255.255.255.0,2m",
                      f"--dhcp-option=3,{gateway}", f"--dhcp-leasefile={work / (label + '.leases')}",
                      f"--pid-file={work / (label + '.pid')}", "--user=root")

    def observed(lease):
        if not events.exists():
            return 0
        return events.read_text().splitlines().count(" ".join(lease))

    old_server = offer("dhcp-a", FIRST)
    agent = launch(stack, work, "udhcpc", client, "env", f"SDWAN_LEASE_EVENTS={events}", "busybox", "udhcpc",
                   "-f", "-i", "access0", "-s", str(hook), "-p", str(work / "udhcpc.pid"), "-B", "-T", "1", "-t", "4")
    wait_for("first DHCP ACK", lambda: observed(FIRST), 15)
    old = prove(client, "access0", FIRST, "DHCP initial lease")
    agent.send_signal(signal.SIGUSR1)
    wait_for("renewal with unchanged lease", lambda: observed(FIRST) >= 2, 12)
    prove(client, "access0", FIRST, "DHCP live renewal")

    agent.send_signal(signal.SIGUSR2)
    wait_for("release of DHCP address", lambda: not addresses(client, "access0"), 10)
    stop_process(old_server, signal.SIGTERM)
    run(["ip", "-n", server, "addr", "del", FIRST[1] + "/24", "dev", "access0"])
    offer("dhcp-b", SECOND)
    agent.send_signal(signal.SIGUSR1)
    wait_for("DHCP ACK on new subnet", lambda: observed(SECOND), 15)
    new = prove(client, "access0", SECOND, "DHCP redial with a different address and gateway")
    default = json.loads(run(["ip", "-n", client, "-j", "route", "show", "default"]).stdout)
    if len(default) != 1 or default[0]["gateway"] != SECOND[1] or observed(SECOND) != 1:
        raise RuntimeError("The new DHCP gateway is not the single active default")
    if any(addr["local"] == FIRST[0] for addr in addresses(client, "access0")):
        raise RuntimeError("The obsolete lease was retained on the interface")
    return "access0", old, new


def pppoe(work, stack, client, server):
    options = work / "ppp-options"
    options.write_text("noauth\nnobsdcomp\nnodeflate\nlcp-echo-interval 1\nlcp-echo-failure 2\n")
    device = "pppwan"
    pairs = []
    for label, expected in (("a", FIRST), ("b", SECOND)):
        source, gateway = expected
        concentrator = launch(stack, work, "pppoe-server-" + label, server, "pppoe-server", "-F", "-I", "access0",
                              "-L", gateway, "-R", source, "-N", "1", "-O", str(options), "-C", "sdwan-lab")
        session = launch(stack, work, "pppd-" + label, client, "pppd", "nodetach", "noauth", "noipdefault",
                         "plugin", "pppoe.so", "nic-access0", "ifname", device, "mtu", "1492", "mru", "1492",
                         "ip-up-script", "/bin/true", "ip-down-script", "/bin/true",
                         "lcp-echo-interval", "1", "lcp-echo-failure", "2", "debug")
        wait_for("PPPoE discovery and IPCP", lambda: any(x["local"] == source
                                                        for x in addresses(client, device)), 23)
        pairs.append(prove(client, device, expected, f"PPPoE session {label}"))
        if label == "a":
            run(["ip", "-n", client, "link", "set", "access0", "down"])
            wait_for("loss of PPPoE session after link outage", lambda: not addresses(client, device), 12)
            stop_process(session, signal.SIGTERM)
            stop_process(concentrator, signal.SIGTERM)
            run(["ip", "-n", client, "link", "set", "access0", "up"])
    return device, *pairs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol", choices=["dhcp", "pppoe"])
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="sdwan-access-") as tmp:
        work = Path(tmp)
        try:
            with ExitStack() as stack:
                client, server = setup(stack)
                test = dhcp if args.protocol == "dhcp" else pppoe
                device, old, new = test(work, stack, client, server)
                result = run(["php", str(ROOT / "check-dynamic-monitor.php"), device, *old, *new])
                print(result.stdout.strip())
        except Exception:
            for path in sorted(work.glob("*.log")):
                print(path.name, path.read_text()[-4000:])
            raise


if __name__ == "__main__":
    main()
