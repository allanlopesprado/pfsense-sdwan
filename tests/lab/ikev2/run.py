#!/usr/bin/env python3
"""Two isolated strongSwan peers and a passive one- to three-link transit network."""

import argparse
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

CHARON = "/usr/lib/ipsec/charon"
os.environ["LC_ALL"] = "C"


def run(args, *, data=None, check=True, timeout=20):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args)} returned {result.returncode}: {result.stderr.strip()} {result.stdout.strip()}")
    return result


def wait_for(label, fn, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {label}")


@dataclass(frozen=True)
class PathPair:
    name: str
    reqid: int
    outer: tuple
    inner: tuple


PATHS = (
    PathPair("a", 101, ("192.0.2.1", "192.0.2.2"), ("10.241.1.1", "10.241.1.2")),
    PathPair("b", 102, ("198.51.100.1", "198.51.100.2"), ("10.241.2.1", "10.241.2.2")),
    PathPair("c", 103, ("203.0.113.1", "203.0.113.2"), ("10.241.3.1", "10.241.3.2")),
)


def inside(ns, *args):
    return ["ip", "netns", "exec", ns, *args]


def create_network(stack, nodes, wire, paths, shared_selectors=False):
    for name in [*nodes, wire]:
        run(["ip", "netns", "add", name])
        stack.callback(run, ["ip", "netns", "del", name], check=False)
        run(["ip", "-n", name, "link", "set", "lo", "up"])
    for path in paths:
        switch = "br" + path.name
        run(["ip", "-n", wire, "link", "add", switch, "type", "bridge"])
        run(["ip", "-n", wire, "link", "set", switch, "up"])
        for idx, ns in enumerate(nodes):
            end, tap = "wan" + path.name, f"tap{path.name}{idx}"
            run(["ip", "-n", ns, "link", "add", end, "type", "veth", "peer", "name", tap, "netns", wire])
            run(["ip", "-n", wire, "link", "set", tap, "master", switch])
            run(["ip", "-n", wire, "link", "set", tap, "up"])
            run(["ip", "-n", ns, "addr", "add", path.outer[idx] + "/30", "dev", end])
            run(["ip", "-n", ns, "link", "set", end, "up"])
            if shared_selectors:
                overlay = "xfrm" + path.name
                run(["ip", "-n", ns, "link", "add", overlay, "type", "xfrm", "dev", end, "if_id", str(path.reqid)])
                run(["ip", "-n", ns, "link", "set", overlay, "up"])
                continue
            run(["ip", "-n", ns, "addr", "add", path.inner[idx] + "/32", "dev", "lo"])
            run(["ip", "-n", ns, "route", "add", path.inner[1-idx] + "/32", "via", path.outer[1-idx],
                 "dev", end, "src", path.inner[idx]])
    if shared_selectors:
        for idx, ns in enumerate(nodes):
            run(["ip", "-n", ns, "addr", "add", paths[0].inner[idx] + "/32", "dev", "lo"])


def guard(ns, idx, paths):
    """Persistently refuse access to each protected host without that tunnel."""
    rules = ["table ip ike_lab {"]
    for p in paths:
        rules.append(f"counter clear_{p.name} {{ }}")
    rules.append("chain outbound { type filter hook output priority filter; policy accept;")
    for p in paths:
        flow = f"ip saddr {p.inner[idx]} ip daddr {p.inner[1-idx]}"
        rules += [f"{flow} ipsec out reqid {p.reqid} accept", f"{flow} counter name clear_{p.name} drop"]
    run(inside(ns, "nft", "-f", "-"), data="\n".join([*rules, "}", "}"]) + "\n")


def guard_drops(ns, path):
    counters = json.loads(run(inside(ns, "nft", "-j", "list", "counter", "ip", "ike_lab",
                                     "clear_" + path.name)).stdout)["nftables"]
    return next(item["counter"]["packets"] for item in counters if "counter" in item)


def probe(ns, idx, p, expect=True):
    result = run(inside(ns, "ping", "-n", "-I", p.inner[idx], "-c", "2", "-W", "1",
                        "-w", "4", p.inner[1-idx]), check=False)
    if expect and (result.returncode or "0% packet loss" not in result.stdout or "2 received" not in result.stdout):
        raise RuntimeError(f"Expected both replies on {p.name}: {result.stdout} {result.stderr}")
    if not expect and (result.returncode != 1 or "0 received" not in result.stdout):
        raise RuntimeError(f"Expected zero replies on {p.name}: {result.stdout} {result.stderr}")


def stop_process(process, sig):
    if process.poll() is None:
        process.send_signal(sig)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@contextmanager
def captures(work, wire, stage, paths):
    files = {}
    with ExitStack() as stack:
        for p in paths:
            dev = f"tap{p.name}0"
            name = work / f"{stage}-{dev}.pcap"
            log = work / f"{stage}-{dev}.log"
            err = stack.enter_context(log.open("w"))
            process = subprocess.Popen(inside(wire, "tcpdump", "-p", "-U", "-nn", "-i", dev, "-w", str(name),
                                              "icmp or esp or udp port 500 or udp port 4500"),
                                       stdout=subprocess.DEVNULL, stderr=err)
            stack.callback(stop_process, process, signal.SIGINT)
            wait_for(f"capture {dev}", lambda: "listening on" in log.read_text() and process.poll() is None, 6)
            files[p.name] = name
        yield files
        # Allow the packet socket to deliver its last buffered frame to libpcap.
        time.sleep(1.1)


def packets(pcap, expression):
    output = run(["tcpdump", "-tnnr", str(pcap), expression]).stdout.strip()
    return len(output.splitlines()) if output else 0


def inner_filter(p):
    return f"icmp and host {p.inner[0]} and host {p.inner[1]}"


def no_clear(files, paths):
    for p in paths:
        for filename in files.values():
            if packets(filename, inner_filter(p)):
                raise RuntimeError(f"Plaintext protected ICMP found in {filename.name}")


def esp_packets(files, path, origin, spi):
    match = (f"src {path.outer[origin]} and dst {path.outer[1-origin]} and ip proto 50 "
             f"and ip[((ip[0] & 15) * 4):4] = 0x{spi}")
    return packets(files[path.name], match)


def assert_esp(files, p, sa):
    for idx, spi in enumerate((sa["out_spi"], sa["in_spi"])):
        if esp_packets(files, p, idx, spi) < 2:
            raise RuntimeError(f"Missing expected ESP traffic with SPI {spi} on {p.name}")


def connection(p, idx, shared_selectors):
    local_ts = "0.0.0.0/0" if shared_selectors else f"{p.inner[idx]}/32"
    remote_ts = "0.0.0.0/0" if shared_selectors else f"{p.inner[1-idx]}/32"
    interface_ids = f"if_id_in = {p.reqid}\n                if_id_out = {p.reqid}" if shared_selectors else ""
    return f"""
    path-{p.name} {{
        version = 2
        local_addrs = {p.outer[idx]}
        remote_addrs = {p.outer[1-idx]}
        mobike = no
        proposals = aes128gcm16-prfsha256-ecp256
        local {{
            auth = psk
            id = @peer{idx}-{p.name}.test
        }}
        remote {{
            auth = psk
            id = @peer{1-idx}-{p.name}.test
        }}
        children {{
            data-{p.name} {{
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                {interface_ids}
                reqid = {p.reqid}
                esp_proposals = aes128gcm16-ecp256
                start_action = none
                close_action = none
            }}
        }}
    }}
"""


class Peer:
    def __init__(self, ns, idx, work, keys, stack, paths, shared_selectors=False):
        self.ns = ns
        directory = work / ns
        directory.mkdir(mode=0o700)
        (directory / "run").mkdir()
        confdir = directory / "swanctl"
        confdir.mkdir(mode=0o700)
        secrets_body = []
        for p in paths:
            secrets_body.append(f"""
    ike-{p.name} {{
        id-1 = @peer0-{p.name}.test
        id-2 = @peer1-{p.name}.test
        secret = 0x{keys[p.name]}
    }}
""")
        (confdir / "swanctl.conf").write_text("connections {\n" + "".join(connection(p, idx, shared_selectors) for p in paths)
                                             + "}\nsecrets {\n" + "".join(secrets_body) + "}\n")
        (directory / "strongswan.conf").write_text("""charon {
    install_routes = no
    load_modular = yes
    filelog {
        stdout {
            default = 1
            flush_line = yes
        }
    }
    plugins {
        include /etc/strongswan.d/charon/*.conf
    }
}
""")
        self.log = directory / "daemon.log"
        output = stack.enter_context(self.log.open("w"))
        # Keep distro-provided PID and VICI socket paths private to this process.
        # Binding /run also covers /var/run, a symlink on Ubuntu.
        launch = ('mount --bind "$1/run" /run && mount --bind "$1/strongswan.conf" /etc/strongswan.conf '
                  '&& mount --bind "$1/swanctl" /etc/swanctl && exec /usr/lib/ipsec/charon')
        self.process = subprocess.Popen(inside(ns, "unshare", "--mount", "--propagation", "private",
                                              "sh", "-ec", launch, "ike-lab", str(directory)),
                                       stdout=output, stderr=subprocess.STDOUT)
        stack.callback(stop_process, self.process, signal.SIGTERM)
        wait_for("private VICI socket on " + ns, lambda: (directory / "run/charon.vici").is_socket()
                 and self.process.poll() is None, 12)
        self.control("--load-conns")
        self.control("--load-creds", "--noprompt")

    def control(self, *args):
        return run(["nsenter", "-t", str(self.process.pid), "-m", "-n", "--", "swanctl", *args]).stdout

    def status(self, p):
        output = self.control("--list-sas", "--ike", f"path-{p.name}", "--child", f"data-{p.name}")
        ike = re.search(rf"^path-{p.name}: #\d+, ESTABLISHED, IKEv2, ([0-9a-f]+)_i\*? ([0-9a-f]+)_r", output, re.M)
        child = re.findall(rf"^\s*data-{p.name}: #\d+, reqid {p.reqid}, INSTALLED, TUNNEL, ESP:AES_GCM_16-128", output, re.M)
        directions = re.findall(r"^[ \t]*(in|out)[ \t]+([0-9a-f]+)(?: \([^)]+\))?,[ \t]+(\d+) bytes,", output, re.M)
        if not ike or len(child) != 1 or len(directions) != 2:
            return None
        data = {"ike": ike.groups()}
        for direction, spi, count in directions:
            data[direction + "_spi"] = spi
            data[direction + "_bytes"] = int(count)
        return data if "in_spi" in data and "out_spi" in data else None


def pair_status(peers, path):
    pair = [peer.status(path) for peer in peers]
    if not all(pair):
        return None
    a, b = pair
    if a["ike"] != b["ike"] or a["out_spi"] != b["in_spi"] or a["in_spi"] != b["out_spi"]:
        return None
    return pair


def snapshot(peers, p):
    return wait_for("matching negotiated SPIs on " + p.name, lambda: pair_status(peers, p))


def rekeyed(peers, p, old, mode):
    pair = pair_status(peers, p)
    if pair:
        fields = ("in_spi", "out_spi") if mode == "child" else ("ike",)
        if all(pair[0][key] != old[0][key] for key in fields):
            return pair
    return None


def data_stage(work, wire, peers, paths, stage):
    before = {p.name: snapshot(peers, p) for p in paths}
    with captures(work, wire, stage, paths) as files:
        for p in paths:
            probe(peers[0].ns, 0, p)
            probe(peers[1].ns, 1, p)
    no_clear(files, paths)
    for p in paths:
        after = snapshot(peers, p)
        for old, new in zip(before[p.name], after):
            if any(new[k] <= old[k] for k in ("in_bytes", "out_bytes")):
                raise RuntimeError(f"Negotiated CHILD_SA byte counters did not increase on {p.name}")
        assert_esp(files, p, after[0])
        print(f"ok - {stage}: {p.name} received replies in both directions; ESP SPIs "
              f"{after[0]['in_spi']}/{after[0]['out_spi']}; protected bytes in/out "
              f"{after[0]['in_bytes']}/{after[0]['out_bytes']}", flush=True)


def exercise(work, stack, paths):
    suffix = str(os.getpid())
    nodes = [f"ikeleft{suffix}", f"ikeright{suffix}"]
    wire = "ikewire" + suffix
    create_network(stack, nodes, wire, paths)
    with captures(work, wire, "control", paths) as files:
        for p in paths:
            probe(nodes[0], 0, p)
    for p in paths:
        if packets(files[p.name], inner_filter(p)) < 4:
            raise RuntimeError("Plaintext positive control failed on " + p.name)
    print(f"ok - transit captures detected plaintext controls on all {len(paths)} links", flush=True)
    for idx, ns in enumerate(nodes):
        guard(ns, idx, paths)
    keys = {p.name: secrets.token_hex(32) for p in paths}
    peers = [Peer(ns, idx, work, keys, stack, paths) for idx, ns in enumerate(nodes)]
    with captures(work, wire, "negotiate", paths) as files:
        for p in paths:
            peers[0].control("--initiate", "--child", "data-" + p.name, "--timeout", "10")
            snapshot(peers, p)
    for p in paths:
        for idx in range(2):
            ike = f"src {p.outer[idx]} and dst {p.outer[1-idx]} and udp port 500"
            if packets(files[p.name], ike) == 0:
                raise RuntimeError("No bidirectional IKE exchange recorded on " + p.name)
    data_stage(work, wire, peers, paths, "initial")
    primary, *alternates = paths
    old_a = snapshot(peers, primary)
    unaffected = {p.name: snapshot(peers, p)[0] for p in alternates}
    peers[0].control("--rekey", "--child", "data-a")
    wait_for("new ESP SPIs", lambda: rekeyed(peers, primary, old_a, "child"))
    data_stage(work, wire, peers, paths, "after-child-rekey")
    before_ike = snapshot(peers, primary)
    peers[0].control("--rekey", "--ike", "path-a")
    wait_for("new IKE SPIs", lambda: rekeyed(peers, primary, before_ike, "ike"))
    for p in alternates:
        current = snapshot(peers, p)[0]
        if any(current[key] != unaffected[p.name][key] for key in ("ike", "in_spi", "out_spi")):
            raise RuntimeError("Rekey of A unexpectedly changed association " + p.name)
    data_stage(work, wire, peers, paths, "after-ike-rekey")

    for index, removed in enumerate(paths):
        ike = "path-" + removed.name
        peers[0].control("--terminate", "--ike", ike, "--timeout", "10")
        wait_for("retirement of both peers' IKE and CHILD SAs on " + removed.name,
                 lambda: all(not peer.control("--list-sas", "--ike", ike).strip() for peer in peers))
        before = [guard_drops(ns, removed) for ns in nodes]
        survivors = paths[index + 1:]
        with captures(work, wire, "withdrawn-" + removed.name, paths) as files:
            for idx, ns in enumerate(nodes):
                probe(ns, idx, removed, expect=False)
                # An ordinary underlay flow remains independent of SA changes.
                run(inside(ns, "ping", "-n", "-c", "1", "-W", "1", removed.outer[1-idx]))
            for p in survivors:
                probe(nodes[0], 0, p)
        no_clear(files, paths)
        for p in survivors:
            assert_esp(files, p, snapshot(peers, p)[0])
        if not all(guard_drops(ns, removed) > count for ns, count in zip(nodes, before)):
            raise RuntimeError("Missing no-policy drops at one or both ends")
        print(f"ok - withdrawal of {removed.name}: no cleartext, underlay still reachable, "
              f"remaining ESP paths {[p.name for p in survivors]}", flush=True)

    for p in reversed(paths):
        peers[0].control("--initiate", "--child", "data-" + p.name, "--timeout", "10")
        snapshot(peers, p)
    data_stage(work, wire, peers, paths, "restored")


def exercise_shared_selectors(work, stack):
    nodes = [f"ikeleft{os.getpid()}", f"ikeright{os.getpid()}"]
    wire = f"ikewire{os.getpid()}"
    paths = tuple(replace(p, inner=("10.241.250.1", "10.241.250.2")) for p in PATHS[:2])
    primary, standby = paths
    create_network(stack, nodes, wire, paths, shared_selectors=True)

    def prefer(idx, path, overlay=True):
        prefix = path.inner[1-idx] + "/32"
        via = ["dev", "xfrm" + path.name] if overlay else ["via", path.outer[1-idx], "dev", "wan" + path.name]
        run(["ip", "-n", nodes[idx], "route", "replace", prefix, *via, "src", path.inner[idx]])

    for idx in range(2):
        prefer(idx, primary, overlay=False)
    with captures(work, wire, "shared-cleartext-control", paths) as files:
        probe(nodes[0], 0, primary)
    if packets(files[primary.name], inner_filter(primary)) != 4:
        raise RuntimeError("Could not observe cleartext on the transit capture during the positive control")

    keys = {p.name: secrets.token_hex(32) for p in paths}
    peers = [Peer(ns, idx, work, keys, stack, paths, shared_selectors=True) for idx, ns in enumerate(nodes)]
    negotiated = {}
    for path in paths:
        peers[0].control("--initiate", "--child", f"data-{path.name}", "--timeout", "10")
        negotiated[path.name] = snapshot(peers, path)[0]
        for peer in peers:
            listing = peer.control("--list-sas", "--ike", f"path-{path.name}", "--child", f"data-{path.name}")
            if len(re.findall(r"^\s+(?:local|remote)\s+0\.0\.0\.0/0\s*$", listing, re.M)) != 2:
                raise RuntimeError(f"The {path.name} CHILD_SA did not negotiate both wildcard selectors")
    for ns in nodes:
        if run(["ip", "-n", ns, "route", "show", "default"]).stdout.strip():
            raise RuntimeError("Wildcard selectors unexpectedly installed a default route in the lab")
    print("ok - both tunnels negotiated 0.0.0.0/0 in both directions, with no default route installed", flush=True)

    def verify_paths(stage, outbound, inbound):
        prefer(0, outbound)
        prefer(1, inbound)
        with captures(work, wire, stage, paths) as traces:
            probe(nodes[0], 0, primary)
        no_clear(traces, paths)
        for direction, expected in enumerate((outbound, inbound)):
            key = ("out_spi", "in_spi")[direction]
            for path in paths:
                count = esp_packets(traces, path, direction, negotiated[path.name][key])
                if count != (2 if path == expected else 0):
                    raise RuntimeError(f"{stage}: unexpected ESP count {count} from peer {direction} on {path.name}")
        print(f"ok - {stage}: outbound {outbound.name}, return {inbound.name} (ESP captures on both WANs)", flush=True)

    verify_paths("aligned-primary", primary, primary)
    verify_paths("mismatched-preferences", primary, standby)
    verify_paths("aligned-standby", standby, standby)

    peers[0].control("--terminate", "--ike", "path-b", "--timeout", "10")
    wait_for("retirement of standby on both peers",
             lambda: all(not peer.control("--list-sas", "--ike", "path-b").strip() for peer in peers))
    with captures(work, wire, "shared-no-sa", paths) as files:
        probe(nodes[0], 0, primary, expect=False)
    no_clear(files, paths)
    verify_paths("recovered-primary", primary, primary)
    print("ok - a route through a withdrawn SA dropped protected traffic until both peers returned to A", flush=True)


def exercise_vip_takeover(work, stack):
    path = PATHS[0]
    suffix = str(os.getpid())
    primary, backup, remote, wire = (label + suffix for label in ("ikeprimary", "ikebackup", "ikepeer", "ikewire"))
    create_network(stack, (primary, remote), wire, (path,))
    for index, node in enumerate((primary, remote)):
        guard(node, index, (path,))
    keys = {path.name: secrets.token_hex(32)}
    active = Peer(primary, 0, work, keys, stack, (path,))
    peer = Peer(remote, 1, work, keys, stack, (path,))
    active.control("--initiate", "--child", f"data-{path.name}")
    baseline = snapshot((active, peer), path)
    data_stage(work, wire, (active, peer), (path,), "vip-primary")

    # The standby owns no SAs. Move the test endpoint into its network
    # namespace while leaving the remote peer's original SAs untouched.
    stop_process(active.process, signal.SIGKILL)
    run(["ip", "netns", "add", backup])
    stack.callback(run, ["ip", "netns", "del", backup], check=False)
    run(["ip", "-n", backup, "link", "set", "lo", "up"])
    run(["ip", "-n", primary, "link", "set", "wana", "netns", backup])
    run(["ip", "-n", backup, "addr", "replace", path.outer[0] + "/30", "dev", "wana"])
    run(["ip", "-n", backup, "link", "set", "wana", "up"])
    run(["ip", "-n", backup, "addr", "add", path.inner[0] + "/32", "dev", "lo"])
    run(["ip", "-n", backup, "route", "add", path.inner[1] + "/32", "via", path.outer[1],
         "dev", "wana", "src", path.inner[0]])
    guard(backup, 0, (path,))
    with captures(work, wire, "vip-no-sa", (path,)) as files:
        probe(backup, 0, path, expect=False)
        probe(remote, 1, path, expect=False)
    no_clear(files, (path,))
    if guard_drops(backup, path) == 0:
        raise RuntimeError("The standby did not enforce its protection rule before negotiation")

    takeover = Peer(backup, 0, work, keys, stack, (path,))
    takeover.control("--initiate", "--child", f"data-{path.name}")
    fresh = snapshot((takeover, peer), path)
    if any(fresh[0][field] == baseline[0][field] for field in ("ike", "in_spi", "out_spi")):
        raise RuntimeError("The new owner did not negotiate independent IKE and ESP SAs")
    data_stage(work, wire, (takeover, peer), (path,), "vip-backup")
    print("ok - the same endpoint recovered on a different node with newly negotiated SAs and no protected cleartext", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", type=int, choices=(1, 2, 3), default=2)
    scenarios = parser.add_mutually_exclusive_group()
    scenarios.add_argument("--shared-selectors", action="store_true", help="two tunnels with identical wildcard selectors")
    scenarios.add_argument("--vip-takeover", action="store_true", help="move one endpoint between separate IKE processes")
    settings = parser.parse_args()
    if settings.vip_takeover and settings.paths != 1:
        parser.error("--vip-takeover requires one path")
    if settings.shared_selectors and settings.paths != 2:
        parser.error("--shared-selectors requires exactly two paths")
    if sys.platform != "linux" or os.getuid() != 0:
        raise SystemExit("This test requires root in a disposable Ubuntu VM with network and mount namespaces.")
    if not Path(CHARON).is_file():
        raise SystemExit("Install the Ubuntu strongswan-charon and strongswan-swanctl packages first.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="sdwan-ike-") as directory:
        with ExitStack() as stack:
            try:
                if settings.shared_selectors:
                    exercise_shared_selectors(Path(directory), stack)
                elif settings.vip_takeover:
                    exercise_vip_takeover(Path(directory), stack)
                else:
                    exercise(Path(directory), stack, PATHS[:settings.paths])
            except Exception:
                for output in sorted(Path(directory).glob("*/daemon.log")):
                    print(output.parent.name, "\n", output.read_text()[-5000:], file=sys.stderr)
                raise


if __name__ == "__main__":
    main()
