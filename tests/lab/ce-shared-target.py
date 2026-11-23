#!/usr/bin/env python3
"""Verify DNS and HTTPS for one target IP through both appliance WANs."""
import argparse
import importlib.util
import json
import re
import sys
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


def activation_mismatch_evidence(ce, qemu, worker):
    details = ce.command(qemu, f"""printf '%s\\n' 'Active PF trackers and native generation'
pfctl -P -sr 2>/dev/null | grep -E 'ridentifier (41001|41003)$|descr=Default deny rule IPv[46]' | head -12
printf '%s\\n' 'Observer and reload processes'
ps -ax -o pid= -o ppid= -o stat= -o command= | awk '$1 == {int(worker)} || $0 ~ /sdwand\\.php|check_reload_status/' | head -12
for entry in sdwan-observer.json sdwan-observer.json.forwarded sdwan-filter-commit.json sdwan-expiry.heartbeat; do
    printf '%s\\n' "$entry"
    if [ -r "/var/run/$entry" ]; then head -c 4096 "/var/run/$entry"; printf '\\n'; else printf '%s\\n' absent; fi
done
printf '%s\\n' 'Bindings read from persisted configuration'
/usr/local/bin/php -r '
    $xml = simplexml_load_file("/cf/conf/config.xml", "SimpleXMLElement", LIBXML_NONET);
    if ($xml === false) {{ exit(1); }}
    $rows = [];
    foreach ($xml->gateways->sdwan_bindings->item ?? [] as $binding) {{
        $trackers = [];
        foreach ($binding->trackers->item ?? [] as $tracker) {{ $trackers[] = (string)$tracker; }}
        $rows[] = ["group" => (string)$binding->group, "policy" => (string)$binding->policy,
            "trackers" => $trackers, "rules_revision" => (string)$binding->rules_revision,
            "policy_revision" => (string)$binding->policy_revision];
    }}
    echo json_encode(["time" => time(), "monotonic_ns" => hrtime(true), "bindings" => $rows], JSON_THROW_ON_ERROR), PHP_EOL;
' || printf '%s\\n' 'Unable to read acceptance bindings'
printf '%s\\n' 'PF counters and matching ERP states'
pfctl -P -vvsr 2>/dev/null | grep -A2 -E 'on vtnet1|ridentifier 41001$' | head -90
pfctl -vvss 2>/dev/null | grep -A3 -F '192.0.2.162:7' | head -35
if [ -r /var/log/system.log ]; then
    printf '%s\\n' 'Recent SD-WAN and native reload messages'
    tail -n 100 /var/log/system.log | grep -Ei 'SD-WAN|filter reload|check_reload_status' | tail -15
fi""", timeout=15)
    print(details, flush=True)


def verify_activation_guard(ce, qemu):
    native = ce.loaded(qemu)
    ce.assert_rules(native, NATIVE_PATHS)
    certificate = ce.management("before activating ERP binding")
    routing = ce.route_and_nat(qemu)
    worker = ce.worker_pid(qemu)
    deadline = time.monotonic() + 45
    while True:
        snapshot = ce.observations(qemu)["snapshot"] or {}
        if (snapshot.get("observer", {}).get("pid") == int(worker)
                and snapshot.get("policies", {}).get("ERP", {}).get("selected") == "a"):
            break
        assert time.monotonic() < deadline, snapshot
        time.sleep(1)
    assert not snapshot.get("steering"), snapshot
    ce.tcp_pair("ERP and backup before activation", (ce.A, ce.A))

    ce.command(qemu, f"kill -STOP {worker}")
    try:
        ce.command(qemu, f"php {ce.LAB}/ce291-guest.php bind G; /etc/rc.filter_configure_sync")
        loaded = ce.loaded(qemu)
        ce.assert_rules(loaded, {"G": None, "B": "GW_A"})
        assert loaded["41003"] == native["41003"], (loaded, native)
        print(f"ERP awaiting its first observation PF {loaded['41001']}", flush=True)
        try:
            ce.tcp_pair("only the new ERP binding is guarded", (None, ce.A))
        except AssertionError:
            print("PF after mismatched activation traffic", flush=True)
            try:
                activation_mismatch_evidence(ce, qemu, worker)
            except Exception as error:
                print(f"Could not collect all activation evidence: {type(error).__name__}", flush=True)
            raise
        ce.management("waiting for first bound observation", certificate)
        assert_native_routing(ce, qemu, routing)
    finally:
        ce.command(qemu, f"kill -CONT {worker}")

    resumed = ce.wait_paths(qemu, "ERP applied after first bound observation", {"G": "GW_A"},
                            native_choices={"B": "GW_A"})
    assert resumed["snapshot"]["observer"]["pid"] == int(worker), resumed
    ce.tcp_pair("ERP and backup after verified activation", (ce.A, ce.A))
    ce.management("after ERP binding is applied", certificate)
    assert_native_routing(ce, qemu, routing)
    print("CE_ERP_ACTIVATION_GUARD_OK", flush=True)


def verify_interface_traffic(ce, qemu, active):
    def read_counters():
        response = ce.command(qemu, """php <<'PHP'
<?php
require_once('config.inc');
require_once('interfaces.inc');
define('SDWAN_GUI', true);
require '/usr/local/www/sdwan/ui.inc.php';
if (!function_exists('get_real_interface') || !function_exists('pfSense_get_interface_stats')) {
    throw new RuntimeException('Native interface lookup or statistics API missing in the guest CLI');
}
$settings = sdwan_get_config();
$policy = array_column($settings['policies'], null, 'name')['ERP'];
$members = array_column($settings['members'], null, 'name');
$sample = sdwan_ui_traffic_sample($policy, $members, sdwan_gateways(), sdwan_config_revision($settings));
if (!(array)$sample['interfaces']) {
    $native = [];
    foreach (['wan', 'opt1'] as $interface) {
        $device = get_real_interface($interface, 'inet', false, true);
        $stats = is_string($device) ? pfSense_get_interface_stats($device) : null;
        $native[$interface] = ['device' => $device, 'inbytes' => $stats['inbytes'] ?? null,
            'outbytes' => $stats['outbytes'] ?? null];
    }
    throw new RuntimeException('Collector returned no counters. Native API: ' . json_encode($native, JSON_THROW_ON_ERROR));
}
echo json_encode($sample, JSON_THROW_ON_ERROR), PHP_EOL;
PHP""")
        sample = json.loads(response.splitlines()[-1])
        assert sample["revision"] == active["snapshot"]["config_revision"], sample
        assert set(sample["interfaces"]) == {path[0] for path in ce.GATEWAYS.values()}, sample
        for row in sample["interfaces"].values():
            assert set(row) == {"at_ns", "inbytes", "outbytes"}, row
            assert all(isinstance(value, str) and value.isascii() and value.isdecimal()
                       for value in row.values()), row
        return sample["interfaces"]

    before = read_counters()
    for (_, hop), source in zip(ce.GATEWAYS.values(), (ce.A, ce.B)):
        ce.command(qemu, f"ping -n -c 2 -s 1000 -S {source} {hop}", timeout=12)
    after = read_counters()
    for interface in before:
        changes = {field: int(after[interface][field]) - int(before[interface][field])
                   for field in before[interface]}
        assert changes["at_ns"] > 0 and changes["inbytes"] >= 2000 and changes["outbytes"] >= 2000, changes
        print(f"Read-only native counters {interface}: {changes}", flush=True)
    assert ce.observations(qemu)["receipt"] == active["receipt"]
    ce.assert_rules(ce.loaded(qemu), NATIVE_PATHS)
    print("CE_NATIVE_INTERFACE_COUNTERS_OK", flush=True)


def verify_readiness_policy(ce, qemu, unready_source, hostname):
    script = f"{ce.LAB}/shared-readiness.php"
    ce.command(qemu, f"""umask 077
cat >{script} <<'PHP'
<?php
require_once 'config.inc';
require_once '/usr/local/pkg/sdwan.inc';
$current = sdwan_get_config();
$backup = __DIR__ . '/shared-readiness-original.json';
if (($argv[1] ?? '') === 'restore') {{
    $candidate = json_decode(file_get_contents($backup), true, 32, JSON_THROW_ON_ERROR);
}} else {{
    if (file_put_contents($backup, json_encode($current, JSON_THROW_ON_ERROR)) === false) {{
        throw new RuntimeException('Could not save the lab settings');
    }}
    $candidate = $current;
    $tables = ['GW_A' => 1, 'GW_B' => 2];
    foreach ($candidate['members'] as &$member) {{
        $member['probe_primary'] = 'fib=' . $tables[$member['gateway']] . ' https://{hostname}/healthz {TARGET} expect=ok';
        unset($member['probe_secondary']);
    }}
    unset($member);
    foreach ($candidate['policies'] as &$policy) {{
        $policy['primary_check'] = $policy['name'] === 'ERP' ? 'required' : 'ignored';
        $policy['secondary_check'] = 'ignored';
    }}
    unset($policy);
}}
$errors = sdwan_save_config($candidate, sdwan_config_revision($current), true);
if ($errors) {{
    throw new RuntimeException(implode('; ', $errors));
}}
PHP
php {script}""")

    def check(label, routes, sources, checks):
        snapshot = ce.wait_paths(qemu, label, routes)["snapshot"]
        result = [(snapshot["members"][name]["status"], snapshot["members"][name]["checks"]["probe_primary"])
                  for name in ("a", "b")]
        assert result == [("online", status) for status in checks], (label, result)
        print(f"{label}: {result!r}", flush=True)
        ce.tcp_pair(label, sources)

    try:
        check("both readiness markers match", NATIVE_PATHS, (ce.A, ce.A), ("Passed", "Passed"))
        unready_source.write_text(ce.A, encoding="ascii")
        check("HTTP 200 with wrong marker on WAN1", {"G": "GW_B", "B": "GW_A"}, (ce.B, ce.A),
              ("HTTPS response marker mismatch", "Passed"))
        unready_source.unlink()
        check("WAN1 readiness restored", NATIVE_PATHS, (ce.A, ce.A), ("Passed", "Passed"))
    finally:
        unready_source.unlink(missing_ok=True)
        ce.command(qemu, f"php {script} restore")
    ce.wait_paths(qemu, "original policies restored", NATIVE_PATHS)
    ce.tcp_pair("original policies restored", (ce.A, ce.A))


def verify_erp_host_alias(ce, qemu):
    guest = f"php {ce.LAB}/ce291-guest.php"
    result = ce.command(qemu, f"{guest} unbind G")
    withdrawal = re.findall(r"^WITHDRAWAL_START_NS=(\d+)$", result, re.MULTILINE)
    assert len(withdrawal) == 1, result
    ce.wait_paths(qemu, "before approving the alias", {"B": "GW_A"}, native_choices={"G": "GW_A"},
                  withdrawal_after=int(withdrawal[0]))
    ce.command(qemu, f"{guest} erp_host_alias; {guest} bind G")
    ce.wait_paths(qemu, "native host alias approved", NATIVE_PATHS)

    table = "SDWAN_LAB_ERP"
    extra = "192.0.2.169"

    def members():
        return set(ce.command(qemu, f"pfctl -t {table} -T show").split())

    def extra_flow(expected, label):
        result = ce.run(*ce.in_ns("sdwan-client", sys.executable, ce.SCRIPT, "flow", extra),
                        input=label + "\n", capture_output=True)
        assert result.stdout.strip() == f"{expected} {label}", result.stdout
        print(f"{label}: {extra} replied from {expected}", flush=True)

    assert members() == {ce.ERP}
    backup = ce.loaded(qemu)["41003"]
    try:
        ce.fault(f'iifname "sw-wire0" ip saddr {ce.A} ip daddr 192.0.2.164 tcp dport 7 drop')
        active = {"G": "GW_B", "B": "GW_A"}
        before = ce.wait_paths(qemu, "alias ERP failover", active)
        rules = ce.command(qemu, "pfctl -P -sr 2>/dev/null | awk '/ridentifier (41001|41002)$/'").splitlines()
        assert len(rules) == 2 and rules[0].startswith("pass ") and rules[1].startswith("block "), rules
        assert all(re.search(rf"\bto <{table}(?::[0-9]+)?> port = 7\b", rule) for rule in rules), rules
        assert ce.loaded(qemu)["41003"] == backup
        ce.tcp_pair("alias ERP failover", (ce.B, ce.A))
        extra_flow(ce.A, "before refreshing the host table")
        ce.command(qemu, f"pfctl -t {table} -T add {extra}")
        assert members() == {ce.ERP, extra}
        extra_flow(ce.B, "after refreshing the host table")
        after = ce.wait_paths(qemu, "confirmed alias after native table refresh", active)
        assert after["signature"] == before["signature"], (before, after)
        assert members() == {ce.ERP, extra}
        ce.tcp_pair("existing alias destination and backup after table refresh", (ce.B, ce.A))
    finally:
        ce.fault()
    print("NATIVE_HOST_ALIAS_TABLE_AND_REFRESH_STEERING_OK", flush=True)


def exercise(ce, benchmark, qemu, cleanup, provider):
    version, _ = ce.install_bound_candidate(qemu)
    active = ce.wait_paths(qemu, "before installed package verification", NATIVE_PATHS)
    verify_interface_traffic(ce, qemu, active)
    verification = ce.command(qemu, f"sh {ce.LAB}/verify-appliance.sh {version} --forwarding", timeout=90)
    for group, policy in (("G", "ERP"), ("B", "Backup")):
        assert any(line.startswith(f"Group {group}, policy {policy}, trackers ") and line.endswith(": applied.")
                   for line in verification.splitlines()), verification
    print(verification, flush=True)
    unready_source = benchmark.setup_probes(ce, qemu, cleanup, shared_host=TARGET)
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
        measure(ce, qemu, "https_large", ("Passed", "Passed"), (True, True))
        measure(ce, qemu, "https_large_marker", (mismatch, mismatch), (True, True))
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
        print("SHARED_TARGET_DNS_HTTPS_REBOOT_OK", flush=True)
        verify_readiness_policy(ce, qemu, unready_source, benchmark.TLS_NAME)
        assert_native_routing(ce, qemu, reference)
    finally:
        remove_routes(ce, qemu)
    verify_erp_host_alias(ce, qemu)
    assert_native_routing(ce, qemu, reference)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("ce_version", choices=("2.9.1", "2.9.2"))
    parser.add_argument("--activation-guard", action="store_true",
                        help="isolate first binding activation with the observer suspended")
    args = parser.parse_args()
    benchmark = load_benchmark()
    ce = benchmark.appliance_module()

    def scenario(qemu, cleanup, provider):
        if args.activation_guard:
            ce.install_candidate(qemu)
            verify_activation_guard(ce, qemu)
        else:
            exercise(ce, benchmark, qemu, cleanup, provider)

    ce.appliance(args.image.resolve(), args.ce_version, scenario=scenario)
    if not args.activation_guard:
        print(f"CE_{args.ce_version.replace('.', '')}_READINESS_OK", flush=True)


if __name__ == "__main__":
    main()
