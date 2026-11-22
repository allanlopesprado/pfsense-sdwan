#!/usr/bin/env python3
"""Verify DNS and HTTPS for one target IP through both appliance WANs."""
import argparse
import importlib.util
import json
import time
from pathlib import Path


TARGET = "192.0.2.168"
NO_PATH = "No matching host route or source"
PROTOCOLS = {"dns": "udp dport 53", "https": "tcp dport 443 tcp flags & (syn | ack) == syn"}
PATH_CHECKS = ("dns", "dns_aaaa", "https")
MONITOR = {"GW_A": ("sw-wire0", "a"), "GW_B": ("sw-wire2", "b")}
NATIVE_PATHS = {"G": "GW_A", "B": "GW_A"}


def load_benchmark():
    path = Path(__file__).with_name("ce-ab-benchmark.py")
    spec = importlib.util.spec_from_file_location("ce_benchmark", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_counters(ce):
    rules = []
    for (interface, suffix), source in zip(MONITOR.values(), (ce.A, ce.B)):
        for protocol, match in PROTOCOLS.items():
            prefix = f'add rule inet test evidence iifname "{interface}" ip daddr {TARGET} {match}'
            rules.append(f'{prefix} counter comment "shared-{protocol}-{suffix}-total"')
            rules.append(f'{prefix} ip saddr {source} counter comment "shared-{protocol}-{suffix}-expected"')
            if suffix == "b":
                renewed = ce.WAN2_RENEWED[0]
                rules.append(f'{prefix} ip saddr {renewed} counter comment "shared-{protocol}-b-renewed"')
    ce.run(*ce.in_ns("sdwan-peer", "nft", "-f", "-"), input="\n".join(rules) + "\n")


def configure_route(ce, qemu, table, device, hop):
    ce.command(qemu, f"route -n add -host {hop} -iface {device} -fib {table}")
    ce.command(qemu, f"route -n add -host {TARGET} {hop} -fib {table}")


def configure_routes(ce, qemu):
    for table, (device, hop) in enumerate(ce.GATEWAYS.values(), 1):
        configure_route(ce, qemu, table, device, hop)


def remove_route(ce, qemu, table, hop):
    ce.command(qemu, f"route -n delete -host {TARGET} -fib {table} >/dev/null 2>&1 || :")
    ce.command(qemu, f"route -n delete -host {hop} -fib {table} >/dev/null 2>&1 || :")


def remove_routes(ce, qemu):
    for table, (_, hop) in enumerate(ce.GATEWAYS.values(), 1):
        remove_route(ce, qemu, table, hop)


def assert_native_routing(ce, qemu, expected, *, settle_seconds=0):
    deadline = time.monotonic() + settle_seconds
    while True:
        current = ce.route_and_nat(qemu)
        if current == expected:
            return
        # The lease address and next hop can appear before WAN NAT is rebuilt.
        assert current[0] == expected[0] and time.monotonic() < deadline, (current, expected)
        time.sleep(1)


def measure(ce, qemu, protocol, expected, expected_sends, *, mode="normal", renewed=False):
    name = protocol.split("_", 1)[0]
    wan2_source = "renewed" if renewed else "expected"
    labels = [f"shared-{name}-a-total", f"shared-{name}-a-expected",
              f"shared-{name}-b-total", f"shared-{name}-b-{wan2_source}"]
    before = [ce.evidence_count(label) for label in labels]
    response = ce.command(qemu, f"php {ce.LAB}/ce291-guest.php package_fib_probe {mode} {protocol}")
    checks = json.loads(response.splitlines()[-1])
    expected_checks = {gateway: {"probe_primary": result} for gateway, result in zip(MONITOR, expected)}
    assert checks == expected_checks, (protocol, mode, checks, expected_checks)
    deltas = [ce.evidence_count(label) - previous for label, previous in zip(labels, before)]
    totals, with_expected_source = deltas[::2], deltas[1::2]
    assert totals == with_expected_source and [total > 0 for total in totals] == list(expected_sends), (
        protocol, mode, totals, with_expected_source, expected_sends
    )
    print(json.dumps({"protocol": protocol, "mode": mode, "checks": checks, "packets_per_wan": totals}),
          flush=True)


def renew_wan2(ce, qemu, cleanup, provider):
    device, original_hop = ce.GATEWAYS["GW_B"]
    renewed_ip, renewed_hop = ce.WAN2_RENEWED
    ce.stop(provider)
    renewed_provider = ce.serve_lease(cleanup, renewed_ip, renewed_hop)
    try:
        ce.command(qemu, f"php {ce.LAB}/ce291-guest.php renew_wan2", timeout=90)
        ce.wait_lease(qemu, renewed_ip, renewed_hop)
        for protocol in PATH_CHECKS:
            measure(ce, qemu, protocol, ("Passed", NO_PATH), (True, False), renewed=True)
        remove_route(ce, qemu, 2, original_hop)
        configure_route(ce, qemu, 2, device, renewed_hop)
        for protocol in PATH_CHECKS:
            measure(ce, qemu, protocol, ("Passed", "Passed"), (True, True), renewed=True)
    finally:
        remove_route(ce, qemu, 2, renewed_hop)
        ce.stop(renewed_provider)
        ce.serve_lease(cleanup, ce.B, original_hop)
        ce.command(qemu, f"php {ce.LAB}/ce291-guest.php renew_wan2", timeout=90)
        ce.wait_lease(qemu, ce.B, original_hop)
    print("SHARED_TARGET_DNS_HTTPS_DHCP_OK", flush=True)


def exercise(ce, benchmark, qemu, cleanup, provider):
    version, _ = ce.install_bound_candidate(qemu)
    ce.wait_paths(qemu, "before installed package verification", NATIVE_PATHS)
    verification = ce.command(qemu, f"sh {ce.LAB}/verify-appliance.sh {version} --forwarding", timeout=90)
    for group, policy in (("G", "ERP"), ("B", "Backup")):
        assert any(line.startswith(f"Group {group}, policy {policy}, trackers ") and line.endswith(": applied.")
                   for line in verification.splitlines()), verification
    print(verification, flush=True)
    benchmark.setup_probes(ce, qemu, cleanup, shared_host=TARGET)
    install_counters(ce)
    reference = ce.route_and_nat(qemu)
    certificate = ce.management("before shared target tests")
    try:
        configure_routes(ce, qemu)
        for protocol in PATH_CHECKS:
            measure(ce, qemu, protocol, ("Passed", "Passed"), (True, True))
            measure(ce, qemu, protocol, (NO_PATH, NO_PATH), (False, False), mode="reversed")
        measure(ce, qemu, "dns_aaaa_missing", ("DNS check failed", "DNS check failed"), (True, True))
        measure(ce, qemu, "https_expected_marker", ("Passed", "Passed"), (True, True))
        mismatch = "HTTPS response marker mismatch"
        measure(ce, qemu, "https_wrong_marker", (mismatch, mismatch), (True, True))
        measure(ce, qemu, "https_wrong_name", ("HTTPS check failed", "HTTPS check failed"), (True, True))
        ce.command(qemu, f"route -n delete -host {TARGET} -fib 2")
        ce.command(qemu, f"route -n add -host {TARGET} -iface vtnet0 -fib 2")
        for protocol in PATH_CHECKS:
            measure(ce, qemu, protocol, ("Passed", NO_PATH), (True, False))
        device, hop = ce.GATEWAYS["GW_B"]
        remove_route(ce, qemu, 2, hop)
        configure_route(ce, qemu, 2, device, hop)
        for protocol in PATH_CHECKS:
            measure(ce, qemu, protocol, ("Passed", "Passed"), (True, True))
        renew_wan2(ce, qemu, cleanup, provider)
        ce.wait_paths(qemu, "after native DHCP reload", NATIVE_PATHS)
        assert_native_routing(ce, qemu, reference, settle_seconds=30)
    finally:
        remove_routes(ce, qemu)

    # Provisioned lab host routes are ephemeral. A new boot must fail closed
    # until the site restores them. The default table and management stay native.
    configure_routes(ce, qemu)
    qemu.sendline("shutdown -r now")
    ce.console_shell(qemu)
    ce.wait_lease(qemu, ce.B, ce.GATEWAYS["GW_B"][1])
    ce.wait_paths(qemu, "after shared target reboot", NATIVE_PATHS)
    ce.management("after shared target reboot", certificate)
    for protocol in PATH_CHECKS:
        measure(ce, qemu, protocol, (NO_PATH, NO_PATH), (False, False))
    assert_native_routing(ce, qemu, reference, settle_seconds=30)
    try:
        configure_routes(ce, qemu)
        for protocol in PATH_CHECKS:
            measure(ce, qemu, protocol, ("Passed", "Passed"), (True, True))
        assert_native_routing(ce, qemu, reference)
    finally:
        remove_routes(ce, qemu)
    print("SHARED_TARGET_DNS_HTTPS_REBOOT_OK", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("ce_version", choices=("2.9.1", "2.9.2"))
    args = parser.parse_args()
    benchmark = load_benchmark()
    ce = benchmark.appliance_module()

    def scenario(qemu, cleanup, provider):
        exercise(ce, benchmark, qemu, cleanup, provider)

    ce.appliance(args.image.resolve(), args.ce_version, scenario=scenario)


if __name__ == "__main__":
    main()
