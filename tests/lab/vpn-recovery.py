#!/usr/bin/env python3
"""Prove OpenVPN and WireGuard recover an application across two isolated links."""

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from ikev2.run import PATHS, create_network, inside, packets, run, stop_process, wait_for

ENDPOINT = "203.0.113.10"
INNER = ("10.247.0.1", "10.247.0.2")
HTTP_PORT = 18080
LINKS = PATHS[:2]


def start(stack, work, node, name, *argv):
    log = stack.enter_context((work / (name + ".log")).open("w"))
    process = subprocess.Popen(inside(node, *argv), stdout=log, stderr=log)
    stack.callback(stop_process, process, signal.SIGTERM)
    return process


def certificate(work, name, purpose):
    key, request, cert = (str(work / (name + suffix)) for suffix in (".key", ".csr", ".crt"))
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
         "-keyout", key, "-out", request])
    extension = work / (name + ".ext")
    extension.write_text(f"extendedKeyUsage={purpose}\nkeyUsage=digitalSignature,keyEncipherment\n")
    run(["openssl", "x509", "-req", "-in", request, "-CA", str(work / "ca.crt"),
         "-CAkey", str(work / "ca.key"), "-CAcreateserial", "-days", "1",
         "-extfile", str(extension), "-out", cert])
    return cert, key


def openvpn(stack, work, nodes):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=isolated-lab",
         "-days", "1", "-keyout", str(work / "ca.key"), "-out", str(work / "ca.crt")])
    for idx, node in enumerate(nodes):
        peer = 1 - idx
        name = ("client", "server")[idx]
        cert, key = certificate(work, name, name + "Auth")
        endpoint = f"tls-server\nlocal {ENDPOINT}\nport 11494\ndh none\nfloat\n" if idx else (
            f"tls-client\nremote {ENDPOINT} 11494\nnobind\nconnect-retry 1 2\nremote-cert-tls server\n")
        config = work / (name + ".conf")
        config.write_text(
            f"dev tun0\ndisable-dco\nproto udp4\ntopology p2p\nifconfig {INNER[idx]} {INNER[peer]}\n"
            f"ca {work / 'ca.crt'}\ncert {cert}\nkey {key}\n"
            "ping 1\nping-restart 4\npersist-key\npersist-tun\ntun-mtu 1350\nverb 3\n" + endpoint
        )
        start(stack, work, node, "openvpn-" + name, "openvpn", "--config", str(config))
    return "tun0", 11494


def wireguard(work, nodes):
    private = []
    public = []
    for idx in range(2):
        key = run(["wg", "genkey"]).stdout
        path = work / f"wg{idx}.key"
        path.write_text(key)
        private.append(path)
        public.append(run(["wg", "pubkey"], data=key).stdout.strip())
    for idx, node in enumerate(nodes):
        run(["ip", "-n", node, "link", "add", "wg0", "type", "wireguard"])
        run(["ip", "-n", node, "addr", "add", INNER[idx] + "/30", "dev", "wg0"])
        peer = 1 - idx
        args = inside(node, "wg", "set", "wg0", "private-key", str(private[idx]), "listen-port", str(51821 - idx),
                      "peer", public[peer], "allowed-ips", INNER[peer] + "/32")
        if idx == 0:
            args += ["endpoint", f"{ENDPOINT}:51820", "persistent-keepalive", "1"]
        run(args)
        run(["ip", "-n", node, "link", "set", "wg0", "mtu", "1350", "up"])
    return "wg0", 51820


@contextmanager
def capture(work, wire, stage, port):
    files = {}
    with ExitStack() as stack:
        for path in LINKS:
            dev = f"tap{path.name}0"
            pcap = work / f"{stage}-{dev}.pcap"
            name = f"{stage}-{dev}"
            process = start(stack, work, wire, name, "tcpdump", "-p", "-U", "-nn", "-i", dev,
                            "-w", str(pcap), f"udp port {port} or tcp port {HTTP_PORT}")
            wait_for(f"capture on {dev}", lambda: process.poll() is None and
                     "listening on" in (work / (name + ".log")).read_text(), 7)
            # Override the ordinary daemon cleanup so libpcap flushes cleanly.
            stack.callback(stop_process, process, signal.SIGINT)
            files[path.name] = pcap
        yield files
        time.sleep(0.4)


def verify_trace(files, active, port):
    for pcap in files.values():
        if packets(pcap, f"tcp port {HTTP_PORT} and (host {INNER[0]} or host {INNER[1]})"):
            raise RuntimeError(f"Protected HTTP in clear on {pcap.name}")
        drops = pcap.with_suffix(".log").read_text()
        if not re.search(r"^0 packets dropped by kernel", drops, re.M):
            raise RuntimeError(f"Capture could not certify packet counts: {drops}")
    if active is None:
        return
    path = files[active.name]
    local = active.outer[0]
    if not packets(path, f"udp dst port {port} and src host {local} and dst host {ENDPOINT}"):
        raise RuntimeError(f"No encrypted outer request on {active.name}")
    if not packets(path, f"udp src port {port} and src host {ENDPOINT} and dst host {local}"):
        raise RuntimeError(f"No encrypted outer response on {active.name}")


def request(node, address, digest):
    script = ("from urllib.request import urlopen; import hashlib,sys; "
              "print(hashlib.sha256(urlopen(sys.argv[1],timeout=1).read()).hexdigest())")
    url = f"http://{address}:{HTTP_PORT}/payload"
    result = run(inside(node, "python3", "-c", script, url), check=False, timeout=4)
    return result.returncode == 0 and result.stdout.strip() == digest


def exercise(args, work, stack):
    suffix = str(os.getpid())
    nodes = ["vpnclient" + suffix, "vpnserver" + suffix]
    client, server = nodes
    wire = "vpnswitch" + suffix
    create_network(stack, nodes, wire, LINKS)
    run(["ip", "-n", server, "addr", "add", ENDPOINT + "/32", "dev", "lo"])

    def choose(path):
        run(["ip", "-n", client, "route", "replace", ENDPOINT + "/32", "via", path.outer[1],
             "dev", "wan" + path.name, "src", path.outer[0]])

    def link(path, status):
        run(["ip", "-n", wire, "link", "set", f"tap{path.name}1", status])

    choose(LINKS[0])
    device, port = (openvpn(stack, work, nodes) if args.protocol == "openvpn"
                    else wireguard(work, nodes))
    content = work / "http"
    content.mkdir()
    payload = os.urandom(65536)
    (content / "payload").write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    for idx, node in enumerate(nodes):
        wait_for("tunnel interface on " + node,
                 lambda: INNER[idx] in run(["ip", "-n", node, "-4", "addr", "show", "dev", device],
                                            check=False).stdout, 22)
        start(stack, work, node, f"http-{idx}", "python3", "-m", "http.server", str(HTTP_PORT),
              "--bind", INNER[idx], "--directory", str(content))

    def establish(path, stage):
        start_time = time.monotonic()
        with capture(work, wire, stage, port) as files:
            wait_for("first verified TCP transfer", lambda: request(client, INNER[1], digest), 24)
            elapsed = time.monotonic() - start_time
            wait_for("verified reverse TCP transfer", lambda: request(server, INNER[0], digest), 10)
        verify_trace(files, path, port)
        print(f"ok - {args.protocol} {stage}: WAN {path.name}, 64 KiB in both directions, "
              f"first response verified in {elapsed:.2f}s including capture setup")

    establish(LINKS[0], "initial")
    link(LINKS[0], "down")
    with capture(work, wire, "no-link", port) as files:
        if request(client, INNER[1], digest) or request(server, INNER[0], digest):
            raise RuntimeError("Application unexpectedly reached an offline peer")
    verify_trace(files, None, port)
    choose(LINKS[1])
    establish(LINKS[1], "failover")
    if args.protocol == "wireguard":
        remote = run(inside(server, "wg", "show", device, "endpoints")).stdout
        if (LINKS[1].outer[0] + ":") not in remote:
            raise RuntimeError("Remote WireGuard peer did not learn the authenticated endpoint on WAN B")
    link(LINKS[0], "up")
    link(LINKS[1], "down")
    choose(LINKS[0])
    establish(LINKS[0], "failback")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol", choices=["openvpn", "wireguard"])
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="sdwan-vpn-") as tmp:
        work = Path(tmp)
        try:
            with ExitStack() as stack:
                exercise(args, work, stack)
        except Exception:
            for path in sorted(work.glob("openvpn-*.log")):
                print(path.name, path.read_text()[-4000:])
            raise


if __name__ == "__main__":
    main()
