#!/usr/bin/env python3
"""Run the real --once entry point with two Unix dpinger fixture sockets."""
import argparse
import errno
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
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
        "processes": {
            name: {"socket": str(sandbox / f"{name}.sock"), "targetip": ip}
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
    for name in ("sdwan.inc", "sdwan_engine.inc"):
        installed = f"/usr/local/pkg/{name}"
        assert daemon.count(installed) == 1, f"Unknown daemon layout: {installed}"
        daemon = daemon.replace(installed, str(sandbox / name))
    (sandbox / "sdwand.php").write_text(daemon)
    shutil.copy(PKG / "sdwan.inc", sandbox)
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

        def observe(first_loss):
            responders = [
                workers.submit(answer, listeners["GW_A"], f"GW_A 20000 1000 {first_loss}"),
                workers.submit(answer, listeners["GW_B"], "GW_B 10000 2000 0"),
            ]
            php(binary, "-d", f"include_path={sandbox}", str(sandbox / "sdwand.php"), "--once")
            for job in responders:
                job.result()
            return json.loads(snapshot.read_text())

        first = observe(0)
        assert first["policies"]["calls"]["selected"] == "a"
        assert first["members"]["a"]["rtt_ms"] == 20
        assert first["members"]["b"]["rttsd_ms"] == 2
        assert len(first["config_revision"]) == 64
        assert json.loads(php(binary, "-r", read)) == first
        print("ok - --once publishes fresh decisions from two Unix sockets")

        with snapshot.open() as old_inode:
            old_number = snapshot.stat().st_ino
            second = observe(3)
            assert second["policies"]["calls"]["selected"] == "b"
            assert second["members"]["a"]["loss_pct"] == 3
            assert second["config_revision"] == first["config_revision"]
            assert snapshot.stat().st_ino != old_number
            assert json.load(old_inode) == first
        assert list(sandbox.glob(".sdwan-*")) == []
        assert config_path.read_bytes() == original_config
        print("ok - degradation changes recommendation and atomically replaces the snapshot")

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
