#!/usr/bin/env python3
"""Run the real --once entry point with two Unix dpinger fixture sockets."""
import argparse
import errno
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import fcntl
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "files/usr/local/pkg"


def php(binary, *args):
    result = subprocess.run([binary, "-n", *args], text=True,
                            capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"PHP failed ({result.returncode}): {result.stderr}{result.stdout}")
    return result.stdout


def fixture(sandbox):
    gateway_ips = {"GW_A": "192.0.2.1", "GW_B": "198.51.100.1"}
    source_ips = {"GW_A": "192.0.2.100", "GW_B": "198.51.100.100"}
    gateways = [
        {"name": name, "gateway": ip, "interface": f"opt{i}"}
        for i, (name, ip) in enumerate(gateway_ips.items(), start=1)
    ]
    return {
        "installedpackages/sdwan": {
            "version": "1",
            "members": {"item": [{"name": "a", "gateway": "GW_A", "cost": "10"},
                                 {"name": "b", "gateway": "GW_B", "cost": "20"}]},
            "slas": {"item": [{"name": "voice", "latency_ms": "100", "loss_pct": "1"}]},
            "policies": {"item": [{"name": "calls", "sla": "voice",
                                   "strategy": "cost", "members": {"item": ["a", "b"]}}]},
        },
        "interfaces": {gw["interface"]: {"enable": ""} for gw in gateways},
        "gateways/gateway_item": gateways,
        "fixture_sources": {gw["interface"]: source_ips[gw["name"]] for gw in gateways},
        # Representative unrelated state. The observer may read the firewall
        # configuration but must leave the entire backing document intact.
        "nat": {"outbound": {"mode": "hybrid"}},
        "ipsec": {"phase2": [{"mode": "vti"}]},
        "filter": {"rule": [{"type": "pass", "interface": "lan"}]},
        "processes": {
            name: {"socket": str(sandbox / f"{name}.sock"), "targetip": ip, "srcip": source_ips[name]}
            for name, ip in gateway_ips.items()
        },
    }


def answer(listener, sample):
    connection, _ = listener.accept()
    with connection:
        connection.sendall((sample + "\n").encode("ascii"))


def stage(sandbox):
    # Only replace absolute installation paths. Keep the actual daemon and
    # snapshot read/write logic so this exercises the shipped CLI entry point.
    daemon = (ROOT / "files/usr/local/sbin/sdwand.php").read_text()
    for name in ("sdwan.inc", "sdwan_engine.inc", "sdwan_log.inc"):
        installed = f"/usr/local/pkg/{name}"
        assert daemon.count(installed) == 1, f"Unknown daemon layout: {installed}"
        daemon = daemon.replace(installed, str(sandbox / name))
    (sandbox / "sdwand.php").write_text(daemon)
    shutil.copy(PKG / "sdwan.inc", sandbox)
    shutil.copy(PKG / "sdwan_log.inc", sandbox)
    engine = (PKG / "sdwan_engine.inc").read_text()
    runtime = "/var/run/sdwan-observer.json"
    assert engine.count(runtime) == 1, "Unknown snapshot path"
    (sandbox / "sdwan_engine.inc").write_text(engine.replace(runtime, str(sandbox / "snapshot.json")))
    for name in ("config.inc", "gwlb.inc"):
        shutil.copy(ROOT / "tests/fixtures" / name, sandbox)
    (sandbox / "fixture.json").write_text(json.dumps(fixture(sandbox)))


def run(binary, require_unix):
    # Some WASM builds advertise unix in stream_get_transports() but cannot
    # reach sockets in the host filesystem. CI requires the native test.
    capability = php(binary, "-r", "echo json_encode([php_uname('m'), stream_get_transports()]);")
    arch, transports = json.loads(capability)
    if arch.startswith("wasm") or "unix" not in transports:
        if require_unix:
            raise RuntimeError("Integration requires native PHP with AF_UNIX streams")
        print("skip - daemon integration requires native PHP with AF_UNIX streams")
        return

    with tempfile.TemporaryDirectory(prefix="sdwan-", dir="/tmp") as temporary, ExitStack() as stack:
        sandbox = Path(temporary)
        stage(sandbox)
        snapshot = sandbox / "snapshot.json"
        config_path = sandbox / "fixture.json"
        original_config = config_path.read_bytes()
        read = f"require {json.dumps(str(sandbox / 'sdwan_engine.inc'))}; echo json_encode(sdwan_read_snapshot());"

        # Exercise the actual CLI even in environments which prohibit socket().
        offline_config = json.loads(original_config)
        offline_config["processes"] = {}
        config_path.write_text(json.dumps(offline_config))
        php(binary, "-d", f"include_path={sandbox}", str(sandbox / "sdwand.php"), "--once")
        offline = json.loads(snapshot.read_text())
        assert offline["policies"]["calls"]["selected"] is None
        assert json.loads(php(binary, "-r", read)) == offline

        def expect_failure(message):
            last_snapshot = snapshot.read_bytes()
            try:
                php(binary, "-d", f"include_path={sandbox}", str(sandbox / "sdwand.php"), "--once")
            except RuntimeError as exc:
                assert "PHP failed (1)" in str(exc) and message in str(exc), str(exc)
            else:
                raise AssertionError(f"The worker should have rejected: {message}")
            assert snapshot.read_bytes() == last_snapshot

        with (sandbox / "snapshot.json.lock").open() as held_lock:
            fcntl.flock(held_lock, fcntl.LOCK_EX)
            expect_failure("Another observation is running")
        invalid_config = json.loads(config_path.read_text())
        invalid_config["installedpackages/sdwan"]["version"] = "future"
        config_path.write_text(json.dumps(invalid_config))
        expect_failure("Unsupported SD-WAN configuration format")
        config_path.write_text(json.dumps(offline_config))
        php(binary, "-d", f"include_path={sandbox}", str(sandbox / "sdwand.php"), "--once")
        assert json.loads(snapshot.read_text())["config_revision"] == offline["config_revision"]
        print("ok - a concurrent worker or unreadable schema preserves the last snapshot, and retry succeeds")

        offline["generated_at"] -= 300
        snapshot.write_text(json.dumps(offline))
        assert json.loads(php(binary, "-r", read)) is None
        print("ok - --once publishes an unavailable gateway and expires the stale snapshot")
        now = int(time.time())
        for label, broken in [
            ("truncated JSON", '{"members":'),
            ("future sample", json.dumps(dict(offline, generated_at=now + 3600))),
            ("malformed policy", json.dumps(dict(offline, generated_at=now, policies={"calls": "partial"}))),
            ("malformed member", json.dumps(dict(offline, generated_at=now, members={"a": []}))),
            ("invalid revision", json.dumps(dict(offline, generated_at=now, config_revision="other"))),
        ]:
            snapshot.write_text(broken)
            assert json.loads(php(binary, "-r", read)) is None, label
        print("ok - rejects malformed, truncated, and future observations")
        config_path.write_bytes(original_config)

        gateways = fixture(sandbox)["processes"]
        listeners = {}
        for name, gateway in gateways.items():
            try:
                listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                listener.settimeout(5)
                listener.bind(gateway["socket"])
            except OSError as exc:
                if require_unix or exc.errno not in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT):
                    raise
                print(f"skip - host Unix socket listener unavailable ({exc.strerror})")
                return
            listener.listen()
            listeners[name] = listener
        workers = stack.enter_context(ThreadPoolExecutor(max_workers=2))

        def observe(configuration, samples):
            config_path.write_text(json.dumps(configuration))
            expected_bytes = config_path.read_bytes()
            responders = [workers.submit(answer, listeners[name], sample)
                          for name, sample in samples.items()]
            php(binary, "-d", f"include_path={sandbox}", str(sandbox / "sdwand.php"), "--once")
            for job in responders:
                job.result()
            assert config_path.read_bytes() == expected_bytes
            return json.loads(snapshot.read_text())

        baseline = fixture(sandbox)
        healthy = {"GW_A": "GW_A 20000 1000 0", "GW_B": "GW_B 10000 2000 0"}
        first = observe(baseline, healthy)
        assert first["policies"]["calls"]["selected"] == "a"
        assert first["members"]["a"]["rtt_ms"] == 20
        assert first["members"]["b"]["rttsd_ms"] == 2
        assert len(first["config_revision"]) == len(first["gateway_inventory_revision"]) == 64
        assert json.loads(php(binary, "-r", read)) == first
        print("ok - --once publishes fresh decisions from two Unix sockets")

        with snapshot.open() as old_inode:
            old_number = snapshot.stat().st_ino
            second = observe(baseline, dict(healthy, GW_A="GW_A 20000 1000 3"))
            assert second["policies"]["calls"]["selected"] == "b"
            assert second["members"]["a"]["loss_pct"] == 3
            assert second["config_revision"] == first["config_revision"]
            assert snapshot.stat().st_ino != old_number
            assert json.load(old_inode) == first
        assert list(sandbox.glob(".sdwan-*")) == []
        assert config_path.read_bytes() == original_config
        print("ok - degradation changes recommendation and atomically replaces the snapshot")

        current = ("require 'sdwan.inc'; require 'sdwan_engine.inc'; "
                   "echo json_encode(sdwan_current_snapshot(sdwan_get_config(), sdwan_gateways()));")
        def current_snapshot():
            return json.loads(php(binary, "-d", f"include_path={sandbox}", "-r", current))

        assert current_snapshot() == second
        primary, secondary = baseline["gateways/gateway_item"]
        changed_gateways = [
            {"name": "Renamed"}, {"disabled": ""}, {"monitor_disable": ""}, {"action_disable": ""},
            {"force_down": ""}, {"monitor": "192.0.2.55"}, {"gateway": "dynamic"},
            {"gateway": "2001:db8::1"}, {"latencyhigh": "400"}, {"time_period": "75000"},
        ]
        edits = [{"gateways/gateway_item": [primary | fields, secondary]} for fields in changed_gateways]
        edits.extend([
            {"gateways/gateway_item": [secondary]},
            {"interfaces": {key: value for key, value in baseline["interfaces"].items() if key != primary["interface"]}},
            {"interfaces": baseline["interfaces"] | {primary["interface"]: {"enable": "", "if": "new_device"}}},
            {"system/dpinger_dont_add_static_routes": ""},
        ])
        for edit in edits:
            config_path.write_text(json.dumps(baseline | edit))
            assert current_snapshot() is None, edit
        unrelated = dict(baseline["gateways/gateway_item"][0], name="Unrelated", monitor="192.0.2.123")
        config_path.write_text(json.dumps(baseline | {"gateways/gateway_item": baseline["gateways/gateway_item"] + [unrelated]}))
        assert current_snapshot() == second
        print("ok - native monitoring changes invalidate pending results; unrelated gateways do not")

        for case, expected_status in [("missing interface", "unknown"),
                                      ("changed monitor address", "unknown"),
                                      ("changed source address", "unknown"),
                                      ("monitor_disable", "unknown"), ("force_down", "down")]:
            configuration = fixture(sandbox)
            if case == "missing interface":
                del configuration["interfaces"]["opt1"]
            elif case == "changed monitor address":
                configuration["processes"]["GW_A"]["targetip"] = "192.0.2.23"
            elif case == "changed source address":
                configuration["processes"]["GW_A"]["srcip"] = "192.0.2.252"
            else:
                configuration["gateways/gateway_item"][0][case] = ""
            observed = observe(configuration, {"GW_B": healthy["GW_B"]})
            assert observed["policies"]["calls"]["selected"] == "b", case
            assert observed["members"]["a"]["status"] == expected_status, case
        print("ok - missing, retargeted, disabled and forced-down gateways cannot win")

        changed = fixture(sandbox)
        changed["gateways/gateway_item"][0].update(latencylow="10", latencyhigh="15")
        high_delay = observe(changed, healthy)
        assert high_delay["members"]["a"]["status"] == "down"
        assert high_delay["policies"]["calls"]["selected"] == "b"
        changed["gateways/gateway_item"][0]["action_disable"] = ""
        action_disabled = observe(changed, healthy)
        assert action_disabled["members"]["a"]["status"] == "degraded"
        assert action_disabled["policies"]["calls"]["selected"] == "a"
        assert action_disabled["gateway_inventory_revision"] != high_delay["gateway_inventory_revision"]
        print("ok - native alarm action changes eligibility while SD-WAN SLA still applies")

        for sample in ("GW_A 0 0 0", "OTHER 20000 1000 0"):
            observed = observe(baseline, dict(healthy, GW_A=sample))
            assert observed["members"]["a"]["status"] == "unknown", sample
            assert observed["policies"]["calls"]["selected"] == "b", sample
        outage = observe(baseline, {"GW_A": "GW_A 0 0 100", "GW_B": "GW_B 0 0 100"})
        assert outage["policies"]["calls"]["selected"] is None
        assert all(member["status"] == "down" for member in outage["members"].values())
        print("ok - monitor start-up, wrong socket identity and complete loss fail closed")

        without_members = fixture(sandbox)
        del without_members["installedpackages/sdwan"]
        native = observe(without_members, healthy)
        assert native["members"] == native["policies"] == []
        assert native["gateways"]["GW_A"]["rtt_ms"] == 20
        assert native["gateways"]["GW_B"]["loss_pct"] == 0
        assert len(native["gateway_inventory_revision"]) == 64
        assert json.loads(php(binary, "-r", read)) == native
        print("ok - native gateways publish real measurements before SD-WAN members exist")

        second["generated_at"] -= 300
        snapshot.write_text(json.dumps(second))
        assert json.loads(php(binary, "-r", read)) is None
        print("ok - the snapshot reader rejects an expired observation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default="php")
    parser.add_argument("--require-unix", action="store_true")
    options = parser.parse_args()
    run(options.php, options.require_unix)
