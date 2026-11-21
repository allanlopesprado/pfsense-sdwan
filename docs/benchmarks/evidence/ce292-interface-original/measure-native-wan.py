"""Measure WAN interruptions only in the previously prepared two-WAN CE VM."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from threading import Lock
import time


SCENARIO = "/root/sdwan-lab-media/native-scenario.php"
SERVICE = "/usr/local/etc/rc.d/sdwand.sh"
LAN_TRACKER = "ridentifier 771292101"
lock = Lock()


def cmd(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=10)


def emit(kind, **row):
    with lock:
        print("CEAB " + json.dumps(dict(kind=kind, at_ns=time.monotonic_ns(), **row)), flush=True)


def proof():
    result = cmd("/usr/local/bin/php", "-f", SCENARIO, "--", "proof")
    return json.loads(result.stdout)


def route_sample():
    rule = next((line for line in cmd("/sbin/pfctl", "-sr").stdout.splitlines()
                 if LAN_TRACKER in line), "")
    path = re.search(r"route-to \((\S+) (\S+)\)", rule)
    return {
        "path": path.group(1) if path else ("block" if rule.startswith("block") else "unrouted"),
        "next_hop": path.group(2) if path else None,
        "rule": rule,
    }


def ping_sample(name, source, gateway):
    started = time.monotonic_ns()
    result = cmd("/sbin/ping", "-n", "-c", "1", "-W", "650", "-S", source, gateway, check=False)
    match = re.search(r"time[=<]([\d.]+) ms", result.stdout)
    emit("sample", flow=name, started_ns=started, success=result.returncode == 0,
         rtt_ms=float(match.group(1)) if match else None, returncode=result.returncode)


def observe():
    started = time.monotonic_ns()
    emit("sample", flow="pf", started_ns=started, **route_sample())


def block(duration):
    stop = time.monotonic() + duration
    with ThreadPoolExecutor(3) as workers:
        while time.monotonic() < stop:
            next_tick = time.monotonic() + 1
            samples = (
                workers.submit(observe),
                workers.submit(ping_sample, "wan1", "198.18.10.10", "198.18.10.2"),
                workers.submit(ping_sample, "wan2", "198.18.20.10", "198.18.20.2"),
            )
            for sample in samples:
                sample.result()
            time.sleep(max(0, next_tick - time.monotonic()))


def phase(name, seconds, interface=None, state=None):
    started = time.monotonic_ns()
    if interface:
        cmd("/sbin/ifconfig", interface, state)
    emit("phase", name=name, requested_ns=started, window_s=seconds)
    block(seconds)


def configure(mode):
    if mode == "native":
        cmd("/usr/local/bin/php", "-f", SCENARIO, "--", "unbind")
        cmd(SERVICE, "stop")
    else:
        if cmd(SERVICE, "status", check=False).returncode:
            cmd(SERVICE, "start", check=False)
            cmd(SERVICE, "status")
        if proof()["binding"] == "absent":
            cmd("/usr/local/bin/php", "-f", SCENARIO, "--", "bind")
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        state = proof()
        expected = (state["binding"] == "absent" if mode == "native"
                    else state["binding"] == "present" and state["pf"] == "applied")
        if expected and route_sample()["path"] == "em0":
            return
        time.sleep(1)
    raise RuntimeError(f"{mode} did not converge on WAN1 before the trial")


def run(modes):
    if (os.geteuid() or socket.gethostname().split(".")[0] != "sdwan-ce292-lab"
            or cmd("kenv", "-q", "smbios.system.maker").stdout.strip() != "QEMU"
            or not Path("/dev/gpt/pfsensece292lab").exists() or proof()["binding"] != "present"):
        raise RuntimeError("Requires the isolated bound CE lab")
    try:
        for mode in modes:
            configure(mode)
            emit("mode", mode=mode)
            phase("baseline", 6)
            phase("wan1_down", 55, "em0", "down")
            phase("both_down", 12, "em2", "down")
            phase("wan2_restored", 40, "em2", "up")
            phase("wan1_restored", 64, "em0", "up")
            emit("end", mode=mode)
    finally:
        for interface in ("em0", "em2"):
            cmd("/sbin/ifconfig", interface, "up")
        cmd(SERVICE, "start", check=False)
        if proof()["binding"] == "absent":
            cmd("/usr/local/bin/php", "-f", SCENARIO, "--", "bind")
        emit("cleanup", binding=proof()["binding"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("both", "native", "sdwan"), default="both")
    mode = parser.parse_args().mode
    run(("native", "sdwan") if mode == "both" else (mode,))
