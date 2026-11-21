#!/usr/bin/env python3
"""Compile PF rules for every availability combination on two or three paths."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from daemon_integration import ROOT, PKG, answer, fixture, stage


def extract(source, name):
    # Standalone native functions close at column zero in the pinned CE source.
    pattern = rf"^function {re.escape(name)}\(.*?\n\}}(?=\n)"
    matches = re.findall(pattern, source, re.M | re.S)
    if len(matches) != 1:
        raise ValueError(f"Expected one standalone upstream function: {name}")
    return matches[0]


def render_harness(work, core):
    stage(work)
    relative = Path("src/etc/inc/filter.inc")
    target = work / relative
    target.parent.mkdir(parents=True)
    shutil.copyfile(core / relative, target)
    original = target.read_text()
    subprocess.run(["git", "apply", str(ROOT / "core/filter-sdwan.patch")], cwd=work, check=True)
    patched = target.read_text()
    methods = ["filter_generate_gateways", "array_from_filter_lines", "filter_generate_address",
               "filter_generate_port", "filter_generate_user_rule"]
    renderer = [extract(patched, method) for method in methods]
    renderer.append(extract(original, "filter_generate_user_rule").replace(
        "function filter_generate_user_rule(", "function lab_stock_user_rule(", 1))
    renderer.append(extract((core / "src/etc/inc/globals.inc").read_text(), "get_ipprotocols"))
    (work / "native-renderer.inc").write_text("<?php\n" + "\n".join(renderer))
    for name in ("sdwan_preflight.inc", "sdwan_steering.inc"):
        shutil.copyfile(PKG / name, work / name)
    provider = "/usr/local/pkg/sdwan_steering.inc"
    for source, dest in [(ROOT / "core/filter-sdwan.inc", work / "filter-sdwan.inc"),
                         (work / "sdwand.php", work / "sdwand.php")]:
        content = source.read_text()
        assert content.count(provider) == 1, source
        dest.write_text(content.replace(provider, str(work / "sdwan_steering.inc")))
    # Only the daemon's external native reload request is replaced.
    (work / "filter.inc").write_text(
        "<?php require_once(__DIR__.'/filter-sdwan.inc'); function is_platform_booting() { return true; }")
    (work / "Net").mkdir()
    # Stand in for PEAR's numeric address validation for the literal fixtures.
    (work / "Net/IPv6.php").write_text(
        "<?php class Net_IPv6 { static function checkIPv6($ip) { "
        "return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false; } }")


def test_config(work, family, links, vti):
    config = fixture(work)
    if links == 3:
        config["gateways/gateway_item"].append({"name": "GW_C", "interface": "opt3"})
        config["interfaces"]["opt3"] = {"enable": ""}
        config["processes"]["GW_C"] = {"socket": str(work / "GW_C.sock")}
        policy_config = config["installedpackages/sdwan"]
        policy_config["members"]["item"].append({"name": "c", "gateway": "GW_C", "cost": "30"})
        policy_config["policies"]["item"][0]["members"]["item"].append("c")
    if family == "inet6":
        client, target, other = "2001:db8:10::11", "2001:db8:40::162", "2001:db8:40::164"
        uplinks = [("2001:db8:20::1", "2001:db8:20::2"), ("fe80::1", "fe80::2"),
                   ("2001:db8:50::1", "2001:db8:50::2")]
    else:
        client, target, other = "192.0.2.11", "192.0.2.162", "192.0.2.164"
        uplinks = [("198.51.100.1", "198.51.100.2"), ("203.0.113.1", "203.0.113.2"),
                   ("192.0.2.129", "192.0.2.130")]
    rule = {"tracker": "41001", "type": "pass", "ipprotocol": family, "interface": "lan", "protocol": "tcp",
            "source": {"address": client}, "destination": {"address": target, "port": "7"},
            "gateway": "G", "descr": "path-a"}
    guard = dict(rule, type="block", tracker="41002", descr="native-guard")
    del guard["gateway"]
    second = dict(rule, tracker="41003", destination={"address": other, "port": "7"})
    second_guard = dict(guard, tracker="41004", destination=second["destination"])
    group_members = [f"{gw['name']}|{tier}|" for tier, gw in enumerate(config["gateways/gateway_item"], 1)]
    config.update({"filter/rule": [rule, guard, second, second_guard],
                   "gateways/gateway_group": [{"name": "G", "item": group_members}],
                   "fixture_sources": {}, "fixture_devices": {}, "reload_gateways": {}})
    config["interfaces"]["lan"] = {"enable": "", "if": "lablan"}
    devices = ("ipsec10", "ipsec20", "ipsec30") if vti else ("labwana", "labwanb", "labwanc")
    if vti:
        config.update({"ipsec/filtermode": "if_ipsec", "ipsec/phase1": [], "ipsec/phase2": []})
    for index, (gw, (source, hop), device) in enumerate(zip(config["gateways/gateway_item"], uplinks, devices), 1):
        interface, name = gw["interface"], gw["name"]
        if vti:
            transport = f"opt{index + 10}"
            config["interfaces"][transport] = {"enable": "", "if": f"wan{index}"}
            config["ipsec/phase1"].append({"ikeid": str(index), "interface": transport, "iketype": "ikev2",
                                           "remote-gateway": f"198.18.{index}.2"})
            config["ipsec/phase2"].append({"ikeid": str(index), "reqid": device[5:], "mode": "vti"})
        gw["gateway"] = hop
        config["interfaces"][interface]["if"] = device
        config["fixture_devices"][interface] = device
        config["fixture_sources"][device] = source
        scope = "%" + device if hop.startswith("fe80:") else ""
        config["processes"][name].update(targetip=hop + scope, srcip=source + scope)
        config["reload_gateways"][name] = {"interface": device, "ipprotocol": family, "address": hop, "online": True}
    return config


def run(php, core, output, replay, family, links, vti=False):
    with tempfile.TemporaryDirectory(prefix="sdwan-render-", dir="/tmp") as tmp, ExitStack() as stack:
        work = Path(tmp)
        render_harness(work, core)
        if replay:
            # A restricted host may forbid AF_UNIX. Replace the transport only;
            # the production parser, worker, publisher and filter hook still run.
            daemon = work / "sdwand.php"
            call = "@stream_socket_client('unix://' . $process['socket'], $errno, $error, 0.25)"
            code = daemon.read_text()
            assert code.count(call) == 1
            daemon.write_text(code.replace(call, "fopen($process['socket'], 'rb')"))
        config = test_config(work, family, links, vti)
        bound_rule = config["filter/rule"][0]
        scoped_flow = f'{family} proto tcp from {bound_rule["source"]["address"]} to {bound_rule["destination"]["address"]} port 7'
        settings = work / "fixture.json"
        snapshot = work / "snapshot.json"
        def execute(*args):
            result = subprocess.run([php, "-d", f"include_path={work}", *args], capture_output=True, text=True, timeout=15)
            if result.returncode or result.stderr:
                raise RuntimeError(f"PHP failed ({result.returncode}): {result.stderr}{result.stdout}")
            return result.stdout.strip()
        def compile_rule(operation="render"):
            settings.write_text(json.dumps(config))
            return execute(str(ROOT / "tests/fixtures/native_filter.php"), str(work), str(core), operation)
        preview = json.loads(compile_rule("preview"))
        assert not preview["errors"], preview
        binding = preview["binding"]
        binding["group"] = [binding["group"]]  # pfSense config.xml always lists <group>.
        for key in ("trackers", "gateways"):
            binding[key] = {"item": binding[key]}
        config["gateways/sdwan_bindings"] = {"item": [binding]}
        config["gateways/sdwan_bindings/item"] = [binding]

        sockets = {}
        if not replay:
            for name, process in config["processes"].items():
                listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                listener.settimeout(4)
                listener.bind(process["socket"])
                listener.listen(1)
                sockets[name] = listener

        def observe(losses, label):
            config["filter/rule"][0]["descr"] = label
            settings.write_text(json.dumps(config))
            with ThreadPoolExecutor(max_workers=links) as pool:
                events = []
                for name, loss in zip(config["processes"], losses):
                    frame = f"{name} 10000 1000 {loss}"
                    if replay:
                        Path(config["processes"][name]["socket"]).write_text(frame + "\n")
                    else:
                        events.append(pool.submit(answer, sockets[name], frame))
                execute(str(work / "sdwand.php"), "--once")
                for event in events:
                    event.result()
            return compile_rule()

        def next_hop(choice):
            route = config["reload_gateways"][choice]
            device, address = route["interface"], route["address"]
            if address.startswith("fe80:"):
                address += "%" + device
            return f"{device} {address}"

        rules = {}
        gateway_names = list(config["processes"])
        # Start each combination independently so availability assertions do
        # not depend on the separate recovery hysteresis timer.
        for mask in range(1 << links):
            snapshot.unlink(missing_ok=True)
            losses = [0 if mask & (1 << index) else 100 for index in range(links)]
            choice = next((name for name, loss in zip(gateway_names, losses) if loss == 0), None)
            label = f"path-{choice[-1].lower()}" if choice else "no-member"
            line = observe(losses, label)
            published = json.loads(snapshot.read_text())
            assert published["steering"]["G"]["gateway"] == choice, published
            normalized = " ".join(line.split())
            expected = "pass in quick" if choice else "block in quick"
            assert normalized.startswith(expected + " on $LABLAN "), line
            for field in (scoped_flow, "ridentifier 41001",
                          'label "id=41001"', 'label "tags=user_rule"', f'label "descr={label}"'):
                assert field in normalized, line
            assert "\n" not in line and "$GW" not in line, line
            if choice:
                assert f"route-to ({next_hop(choice)})" in normalized and "keep state" in normalized, line
                tier = gateway_names.index(choice) + 1
                assert f'label "gw={tier}:G"' in normalized, line
                if choice in ("GW_A", "GW_B"):
                    shutil.copy(snapshot, work / f"sample-{choice[-1].lower()}.json")
            else:
                assert "route-to" not in line and "keep state" not in line and "flags any" in line, line
            rules[label] = line
        assert compile_rule("control") == "unchanged"
        transport = "file replay" if replay else "AF_UNIX"
        path_type = "IPsec VTI" if vti else "direct WAN"
        print(f"ok - {family}, {links} {path_type} links: observer ({transport}) and native PF renderer "
              f"agreed across all {1 << links} availability combinations")

        if family == "inet" and links == 2 and not vti:
            # Compile the weighted pool and both degraded shapes using the same
            # observer and native renderer as the single-gateway controls.
            legacy = deepcopy(config)
            policy = config["installedpackages/sdwan"]["policies"]["item"][0]
            policy["strategy"] = "balance"
            config["gateways/gateway_group"][0]["item"] = ["GW_A|1|", "GW_B|1|"]
            config["gateways/gateway_item"][1]["weight"] = "2"
            config["reload_gateways"]["GW_B"]["weight"] = "2"
            result = json.loads(compile_rule("preview"))
            assert not result["errors"], result
            weighted = result["binding"]
            weighted["group"] = [weighted["group"]]
            for key in ("trackers", "gateways"):
                weighted[key] = {"item": weighted[key]}
            config["gateways/sdwan_bindings"] = {"item": [weighted]}
            config["gateways/sdwan_bindings/item"] = [weighted]
            for losses, label, expected in (
                ([0, 0], "weighted-pool", ["GW_A", "GW_B"]),
                ([100, 0], "weighted-backup", ["GW_B"]),
                ([100, 100], "weighted-blocked", []),
            ):
                line = observe(losses, label)
                state = json.loads(snapshot.read_text())["steering"]["G"]
                assert state["pool"] == expected, state
                if len(expected) > 1:
                    assert line.count(next_hop("GW_A")) == 2 and line.count(next_hop("GW_B")) == 4, line
                    assert "round-robin" in line and "sticky-address" not in line, line
                elif expected:
                    assert "round-robin" not in line and f"route-to ({next_hop(expected[0])})" in line, line
                else:
                    assert line.startswith("block") and "route-to" not in line, line
                rules[label] = line
            config.setdefault("system", {})["lb_use_sticky"] = ""
            sticky_pool = observe([0, 0], "weighted-sticky-pool")
            assert "round-robin sticky-address" in sticky_pool, sticky_pool
            sticky_backup = observe([100, 0], "weighted-sticky-backup")
            assert "sticky-address" not in sticky_backup and f'route-to ({next_hop("GW_B")})' in sticky_backup, sticky_backup
            config = legacy
            print("ok - weighted members, sticky option, one eligible next hop, and an empty SLA set reached the native filter compiler")

        def denied(reason):
            line = " ".join(compile_rule().split())
            assert line.startswith("block in quick") and "route-to" not in line, (reason, line)
        shutil.copy(work / "sample-a.json", snapshot)
        first, same_cycle, next_cycle = json.loads(compile_rule("freeze"))
        assert "41001" in first and "41003" in same_cycle
        assert all(next_hop("GW_A") in line for line in (first, same_cycle))
        assert next_hop("GW_B") in next_cycle
        old = json.loads(snapshot.read_text())
        old["generated_at"] -= 300
        snapshot.write_text(json.dumps(old))
        denied("stale telemetry")
        shutil.copy(work / "sample-a.json", snapshot)
        stable = deepcopy(config)
        config["filter/rule"][0]["source"] = {"any": ""}
        denied("edited native match")
        config = deepcopy(stable)
        config["filter/rule"].pop(1)
        denied("removed adjacent guard")
        config = deepcopy(stable)
        config["gateways/gateway_group"] = []
        config["filter/rule"][0].pop("gateway")
        denied("deleted native group cleared rule gateway")
        config = deepcopy(stable)
        config["reload_gateways"]["GW_A"]["online"] = False
        denied("native gateway down after sample")
        config = deepcopy(stable)
        config["reload_gateways"]["GW_A"]["address"] = "ff02::1" if family == "inet6" else "224.0.0.1"
        denied("non-unicast next hop")
        config = deepcopy(stable)
        if vti:
            config["ipsec/phase1"][1]["interface"] = config["ipsec/phase1"][0]["interface"]
            denied("VTI transports now share a link")
            config = deepcopy(stable)
            config["ipsec/phase2"][0]["disabled"] = ""
            denied("VTI no longer configured")
            config = deepcopy(stable)
        config["gateways/sdwan_bindings/item"].append(binding)
        denied("duplicate tracker binding")
        config = deepcopy(stable)
        (work / "sdwan_steering.inc").rename(work / "detached-provider.inc")
        denied("removed package provider")
        config["gateways/sdwan_bindings"] = {"item": []}
        config["gateways/sdwan_bindings/item"] = []
        assert "$GWG" in compile_rule("rollback")
        print("ok - one decision per reload; stale samples, native drift, missing guard/provider and duplicate bindings block")
        if output:
            output.mkdir(parents=True, exist_ok=True)
            for label, line in rules.items():
                prefix = ("triple-" if links == 3 else "") + ("ipv6-" if family == "inet6" else "")
                (output / f"{prefix}{label}.pf").write_text(line + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--emit-dir", type=Path)
    parser.add_argument("--family", choices=("inet", "inet6", "both"), default="both")
    parser.add_argument("--links", choices=("2", "3", "both"), default="both")
    parser.add_argument("--replay-lines", action="store_true", help="read dpinger frames from files for hosts that prohibit Unix sockets")
    args = parser.parse_args()
    families = ("inet", "inet6") if args.family == "both" else (args.family,)
    link_counts = (2, 3) if args.links == "both" else (int(args.links),)
    for family in families:
        for links in link_counts:
            run(args.php, args.core.resolve(), args.emit_dir, args.replay_lines, family, links)
            run(args.php, args.core.resolve(), None, args.replay_lines, family, links, vti=True)
