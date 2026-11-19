#!/usr/bin/env python3
"""Obtain an IPv6 prefix, announce it on a LAN, then renegotiate and renumber."""

from contextlib import ExitStack
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

from ikev2.run import inside, run, stop_process, wait_for

WAN = "2001:db8:1::"
DESTINATION = "2001:db8:ff::10"
POOLS = ("2001:db8:100::/56", "2001:db8:200::/56")


def launch(stack, work, node, name, *args):
    log = stack.enter_context((work / (name + ".log")).open("w"))
    child = subprocess.Popen(inside(node, *args), stdout=log, stderr=log)
    stack.callback(stop_process, child, signal.SIGTERM)
    return child


def own_prefix(node, device, prefix):
    result = run(["ip", "-n", node, "-j", "-6", "addr", "show", "dev", device])
    return any(ip_address(item["local"]) in prefix and not item.get("tentative", False)
               for iface in json.loads(result.stdout) for item in iface["addr_info"])


def exercise(work, stack):
    upstream, router, client = [f"pd-{role}-{os.getpid()}" for role in ("isp", "router", "lan")]
    for node in (upstream, router, client):
        run(["ip", "netns", "add", node])
        stack.callback(run, ["ip", "netns", "del", node], check=False)
        run(["ip", "-n", node, "link", "set", "lo", "up"])
        run(inside(node, "sysctl", "-qw", "net.ipv6.conf.default.accept_dad=0"))
    for side_a, dev_a, side_b, dev_b in ((upstream, "wan0", router, "wan0"), (router, "lan0", client, "lan0")):
        run(["ip", "-n", side_a, "link", "add", dev_a, "type", "veth", "peer", "name", dev_b, "netns", side_b])
        for node, dev in ((side_a, dev_a), (side_b, dev_b)):
            run(["ip", "-n", node, "link", "set", dev, "up"])
    run(inside(router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"))
    run(inside(client, "sysctl", "-qw", "net.ipv6.conf.lan0.accept_ra=2", "net.ipv6.conf.lan0.autoconf=1"))
    run(["ip", "-n", upstream, "-6", "addr", "add", WAN + "1/64", "dev", "wan0"])
    run(["ip", "-n", router, "-6", "addr", "add", WAN + "2/64", "dev", "wan0"])
    run(["ip", "-n", upstream, "-6", "addr", "add", DESTINATION + "/128", "dev", "lo"])
    run(["ip", "-n", router, "-6", "route", "add", "default", "via", WAN + "1", "dev", "wan0"])
    old_lan = None
    duid = ""
    token = work.name
    for path in ("/run/kea", "/var/lib/kea", "/var/lib/dhcp"):
        Path(path).mkdir(exist_ok=True)
    for index, subnet in enumerate(POOLS):
        prefix = ip_network(subnet)
        # Match the installed profiles without sharing the host's service files.
        lease = Path(f"/var/lib/dhcp/dhclient6.{token}-{index}.leases")
        pid = Path(f"/run/dhclient6.{token}.pid")
        for artifact in (lease, lease.with_name(lease.name + "~"), pid):
            stack.callback(artifact.unlink, missing_ok=True)
        conf = work / f"kea-{index}.json"
        runtime = work / f"kea-{index}-run"
        data = work / f"kea-{index}-data"
        runtime.mkdir()
        data.mkdir()
        if duid:
            lease.write_text(duid + "\n")
        conf.write_text(json.dumps({"Dhcp6": {
            "interfaces-config": {"interfaces": ["wan0"]},
            "lease-database": {"type": "memfile", "persist": False},
            "renew-timer": 60, "rebind-timer": 90, "preferred-lifetime": 120, "valid-lifetime": 180,
            "subnet6": [{"id": 1, "interface": "wan0", "subnet": WAN + "/64",
                         "pd-pools": [{"prefix": str(prefix.network_address),
                                       "prefix-len": prefix.prefixlen, "delegated-len": prefix.prefixlen}]}],
        }}))
        private = ('mount --bind "$1" /etc/kea/kea-dhcp6.conf && mount --bind "$2" /run/kea && '
                   'mount --bind "$3" /var/lib/kea && exec kea-dhcp6 -c /etc/kea/kea-dhcp6.conf')
        kea = launch(stack, work, upstream, f"kea-{index}", "unshare", "--mount", "--propagation", "private",
                     "sh", "-ec", private, "kea-lab", str(conf), str(runtime), str(data))
        request = ["dhclient", "-6", "-P", "-v", "-lf", str(lease), "-pf", str(pid), "-sf", "/bin/true"]
        agent = launch(stack, work, router, f"dhclient-{index}", *request, "-d", "wan0")

        def granted():
            if not lease.exists():
                return None
            for issued in re.findall(r"ia-prefix\s+([a-f0-9:/]+)\s*\{", lease.read_text(), re.I):
                parsed = ip_network(issued)
                if parsed == prefix:
                    return parsed
            return None

        delegated = wait_for("delegated prefix " + subnet, granted, 24)
        lan = next(delegated.subnets(new_prefix=64))
        if old_lan:
            wait_for("old SLAAC prefix to expire", lambda: not own_prefix(client, "lan0", old_lan), 22)
        run(["ip", "-n", upstream, "-6", "route", "add", str(delegated), "via", WAN + "2", "dev", "wan0"])
        lan_addr = f"{lan.network_address + 1}/{lan.prefixlen}"
        run(["ip", "-n", router, "-6", "addr", "add", lan_addr, "dev", "lan0"])
        ra = work / f"radvd-{index}.conf"
        ra.write_text(f"""interface lan0 {{
AdvSendAdvert on;
MinRtrAdvInterval 3;
MaxRtrAdvInterval 4;
AdvDefaultLifetime 12;
prefix {lan} {{
AdvOnLink on;
AdvAutonomous on;
AdvValidLifetime 12;
AdvPreferredLifetime 8;
}};
}};
""")
        advertiser = launch(stack, work, router, f"radvd-{index}", "radvd", "-n", "-m", "stderr",
                            "-C", str(ra), "-p", str(work / "radvd.pid"))
        wait_for("LAN address from Router Advertisement", lambda: own_prefix(client, "lan0", lan), 14)
        route = json.loads(run(["ip", "-n", client, "-j", "-6", "route", "get", DESTINATION]).stdout)[0]
        if route["dev"] != "lan0" or not route.get("gateway", "").startswith("fe80:") or \
                ip_address(route["prefsrc"]) not in lan:
            raise RuntimeError(f"IPv6 client did not use the advertised delegation: {route}")
        run(inside(client, "ping", "-6", "-n", "-c", "2", "-W", "1", DESTINATION))
        print(f"ok - DHCPv6 delegated {delegated}, RA assigned {lan} and the LAN client reached the upstream peer")
        if index == 0:
            stop_process(advertiser, signal.SIGTERM)
            stop_process(agent, signal.SIGTERM)
            stop_process(kea, signal.SIGTERM)
            duid = next(line for line in lease.read_text().splitlines() if line.startswith("default-duid "))
            run(["ip", "-n", upstream, "-6", "route", "del", str(delegated)])
            run(["ip", "-n", router, "-6", "addr", "del", lan_addr, "dev", "lan0"])
            lost = run(inside(client, "ping", "-6", "-n", "-c", "1", "-W", "1", DESTINATION), check=False)
            if lost.returncode == 0:
                raise RuntimeError("Obsolete IPv6 route still reached the destination after withdrawal")
            old_lan = lan


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="sdwan-ipv6-pd-") as tmp:
        work = Path(tmp)
        try:
            with ExitStack() as stack:
                exercise(work, stack)
        except Exception:
            for path in sorted(work.glob("*.log")):
                print(path.name, path.read_text()[-3000:])
            raise
