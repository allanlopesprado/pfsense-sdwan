#!/usr/bin/env python3
"""Compile the lab's three pf rules from real dpinger socket samples and a patched pfSense checkout."""
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
    (work / "Net/IPv6.php").touch()  # The IPv4 lab does not use PEAR IPv6.


def test_config(work):
    config = fixture(work)
    rule = {"tracker": "41001", "type": "pass", "ipprotocol": "inet", "interface": "lan", "protocol": "tcp",
            "source": {"address": "192.0.2.11"}, "destination": {"address": "192.0.2.162", "port": "7"},
            "gateway": "G", "descr": "path-a"}
    guard = dict(rule, type="block", tracker="41002", descr="native-guard")
    del guard["gateway"]
    second = dict(rule, tracker="41003", destination={"address": "192.0.2.164", "port": "7"})
    second_guard = dict(guard, tracker="41004", destination=second["destination"])
    config.update({"filter/rule": [rule, guard, second, second_guard],
                   "gateways/gateway_group": [{"name": "G", "item": ["GW_A|1|", "GW_B|2|"]}],
                   "fixture_sources": {}, "fixture_devices": {}, "reload_gateways": {}})
    config["interfaces"]["lan"] = {"enable": "", "if": "lablan"}
    for gw, network, device in zip(config["gateways/gateway_item"], ("198.51.100", "203.0.113"), ("labwana", "labwanb")):
        interface, name = gw["interface"], gw["name"]
        gw["gateway"] = network + ".2"
        config["interfaces"][interface]["if"] = device
        config["fixture_devices"][interface] = device
        config["fixture_sources"][device] = network + ".1"
        config["processes"][name].update(targetip=gw["gateway"], srcip=network + ".1")
        config["reload_gateways"][name] = {"interface": device, "ipprotocol": "inet", "address": gw["gateway"], "online": True}
    return config


def run(php, core, output, replay):
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
        config = test_config(work)
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
            with ThreadPoolExecutor(max_workers=2) as pool:
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

        rules = {}
        for label, choice, losses in [("path-a", "GW_A", (0, 0)), ("path-b", "GW_B", (100, 0)),
                                      ("no-member", None, (100, 100))]:
            line = observe(losses, label)
            published = json.loads(snapshot.read_text())
            assert published["steering"]["G"]["gateway"] == choice, published
            normalized = " ".join(line.split())
            expected = "pass in quick" if choice else "block in quick"
            assert normalized.startswith(expected + " on $LABLAN "), line
            for field in ("inet proto tcp from 192.0.2.11 to 192.0.2.162 port 7", "ridentifier 41001",
                          'label "id=41001"', 'label "tags=user_rule"', f'label "descr={label}"'):
                assert field in normalized, line
            assert "\n" not in line and "$GW" not in line, line
            if choice:
                route = config["reload_gateways"][choice]
                assert f"route-to ({route['interface']} {route['address']})" in normalized and "keep state" in normalized, line
                tier = 1 if choice == "GW_A" else 2
                assert f'label "gw={tier}:G"' in normalized, line
                shutil.copy(snapshot, work / ("sample-a.json" if choice == "GW_A" else "sample-b.json"))
            else:
                assert "route-to" not in line and "keep state" not in line and "flags any" in line, line
            rules[label] = line
        assert compile_rule("control") == "unchanged"
        transport = "file replay" if replay else "AF_UNIX"
        print(f"ok - --once observations ({transport}) and upstream PF renderer selected A, failed to B, then denied without a path")

        def denied(reason):
            line = " ".join(compile_rule().split())
            assert line.startswith("block in quick") and "route-to" not in line, (reason, line)
        shutil.copy(work / "sample-a.json", snapshot)
        first, same_cycle, next_cycle = json.loads(compile_rule("freeze"))
        assert "41001" in first and "41003" in same_cycle
        assert all("labwana 198.51.100.2" in line for line in (first, same_cycle))
        assert "labwanb 203.0.113.2" in next_cycle
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
        config["reload_gateways"]["GW_A"]["address"] = "224.0.0.1"
        denied("non-unicast next hop")
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
                (output / f"{label}.pf").write_text(line + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--emit-dir", type=Path)
    parser.add_argument("--replay-lines", action="store_true", help="read dpinger frames from files for hosts that prohibit Unix sockets")
    args = parser.parse_args()
    run(args.php, args.core.resolve(), args.emit_dir, args.replay_lines)
