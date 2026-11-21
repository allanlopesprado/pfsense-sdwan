"""Compare matched native and SD-WAN priorities in the disposable CE 2.9.2 lab."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time


SCENARIO = "/root/sdwan-lab-media/native-scenario.php"
SERVICE = "/usr/local/etc/rc.d/sdwand.sh"
PHP = "/usr/local/bin/php"
HELPER = Path(__file__).with_name("retune.php")
GATEWAYS = {"wan1": ("198.18.10.10", "198.18.10.2"), "wan2": ("198.18.20.10", "198.18.20.2")}
PF_TRACKER = "ridentifier 771292101"
GUARD_TRACKER = "ridentifier 771292102"


def cmd(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=20)


def emit(kind, **item):
    print("AB040305 " + json.dumps(dict(kind=kind, at_ns=time.monotonic_ns(), **item)), flush=True)


def inspect():
    return json.loads(cmd(PHP, "-f", str(HELPER), "--", "inspect").stdout)


def native_rule():
    rules = cmd("/sbin/pfctl", "-sr").stdout.splitlines()
    primary = next((line for line in rules if line.endswith(PF_TRACKER)), "")
    guard = next((line for line in rules if line.endswith(GUARD_TRACKER)), "")
    match = re.search(r"route-to \((\S+) (\S+)\)", primary)
    if match:
        return dict(path=match.group(1), next_hop=match.group(2), rule=primary, guard=guard)
    if primary.startswith("block") or (not primary and guard.startswith("block")):
        return dict(path="block", next_hop=None, rule=primary, guard=guard)
    return dict(path="unrouted", next_hop=None, rule=primary, guard=guard)


def ping(flow, source, gateway):
    started = time.monotonic_ns()
    result = cmd("/sbin/ping", "-n", "-c", "1", "-W", "650", "-S", source, gateway, check=False)
    match = re.search(r"time[=<]([\d.]+) ms", result.stdout)
    return dict(flow=flow, started_ns=started, finished_ns=time.monotonic_ns(), success=result.returncode == 0,
                rtt_ms=float(match.group(1)) if match else None, returncode=result.returncode)


def observe_state(mode):
    started = time.monotonic_ns()
    result = native_rule()
    pf_finished = time.monotonic_ns()
    default = cmd("/sbin/route", "-n", "get", "-inet", "default", check=False).stdout
    default_fields = dict(re.findall(r"^\s*(gateway|interface):\s+(\S+)", default, re.M))
    telemetry = inspect() if mode == "sdwan" else None
    return dict(flow="pf", started_ns=started, pf_finished_ns=pf_finished, **result,
                default=default_fields, telemetry=telemetry)


def phase(mode, name, expected, expected_pings, minimum, maximum, change=None):
    requested = time.monotonic_ns()
    if change:
        cmd("/sbin/ifconfig", *change)
    event = time.monotonic_ns()
    emit("phase", mode=mode, phase=name, requested_ns=requested, event_ns=event, expected=expected,
         expected_pings=expected_pings, min_s=minimum, max_s=maximum, change=change)
    stop = event + maximum * 10**9
    streak = 0
    first = None
    confirmed = None
    streak_started = None
    samples = 0
    with ThreadPoolExecutor(max_workers=3) as workers:
        while time.monotonic_ns() < stop:
            next_tick = time.monotonic() + 1
            pf_future = workers.submit(observe_state, mode)
            pings = [workers.submit(ping, flow, *addresses) for flow, addresses in GATEWAYS.items()]
            pf_result = pf_future.result()
            ping_results = [future.result() for future in pings]
            samples += 1
            emit("sample", mode=mode, phase=name, **pf_result)
            for result in ping_results:
                emit("sample", mode=mode, phase=name, **result)
            matches = pf_result["path"] == expected
            confirms_physical = [result["success"] for result in ping_results] == expected_pings
            observed = pf_result["pf_finished_ns"]
            if matches and first is None:
                first = observed
            if matches and confirms_physical:
                if streak == 0:
                    streak_started = observed
                streak += 1
                if streak >= 3:
                    confirmed = observed if confirmed is None else confirmed
                    if time.monotonic_ns() >= event + minimum * 10**9:
                        break
            else:
                streak = 0
                if confirmed is None:
                    streak_started = None
            time.sleep(max(0, next_tick - time.monotonic()))
    emit("outcome", mode=mode, phase=name, samples=samples, first_ms=millis(first, event),
         streak_start_ms=millis(streak_started, event), three_ms=millis(confirmed, event),
         last_streak=streak, window_ms=millis(time.monotonic_ns(), event))


def millis(value, event):
    return None if value is None else round((value - event) / 1e6, 3)


def service_running():
    return cmd(SERVICE, "status", check=False).returncode == 0


def prepare(mode):
    if mode == "native":
        if inspect()["binding"] == "present":
            cmd(PHP, "-f", SCENARIO, "--", "unbind")
        if service_running():
            cmd(SERVICE, "stop")
    else:
        if not service_running():
            cmd(SERVICE, "start")
        if inspect()["binding"] == "absent":
            cmd(PHP, "-f", SCENARIO, "--", "bind")
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        status = inspect()
        if mode == "native":
            ready = status["binding"] == "absent" and not service_running()
        else:
            reasons = status["candidates"] or {}
            ready = (status["pf"] == "applied" and status["gateway"] == "LAB_WAN2" and
                     reasons.get("lab_a") == "Eligible" and reasons.get("lab_b") == "Eligible")
        if ready and native_rule()["path"] == "em2":
            emit("ready", mode=mode, state=status)
            return
        time.sleep(1)
    raise RuntimeError(f"{mode} never reached matched starting condition: {inspect()}")


def run(modes):
    if (os.geteuid() or socket.gethostname().split(".")[0] != "sdwan-ce292-lab"
            or cmd("kenv", "-q", "smbios.system.maker").stdout.strip() != "QEMU"
            or not Path("/dev/gpt/pfsensece292lab").exists()):
        raise RuntimeError("Requires the disposable QEMU CE lab.")
    pkg = cmd("/usr/local/sbin/pkg-static", "query", "%v", "pfSense-pkg-SDWAN").stdout.strip()
    if pkg != "0.4.28":
        raise RuntimeError(f"Unexpected package version {pkg}")
    emit("environment", ce=Path("/etc/version").read_text().strip(),
         kernel=cmd("/usr/bin/uname", "-a").stdout.strip(), package=pkg,
         adapter_sha256=cmd("/sbin/sha256", "-q", "/etc/inc/filter-sdwan.inc").stdout.strip())
    try:
        for mode in modes:
            prepare(mode)
            phase(mode, "baseline", "em2", [True, True], 8, 22)
            phase(mode, "wan1_down_nonpreferred", "em2", [False, True], 12, 32, ("em0", "down"))
            phase(mode, "wan1_recovered", "em2", [True, True], 22, 45, ("em0", "up"))
            phase(mode, "wan2_down_preferred", "em0", [True, False], 10, 100, ("em2", "down"))
            phase(mode, "both_down", "block", [False, False], 10, 100, ("em0", "down"))
            phase(mode, "wan1_only_recovered", "em0", [True, False], 10, 120, ("em0", "up"))
            phase(mode, "wan2_recovered", "em2", [True, True], 10, 150, ("em2", "up"))
            emit("mode_complete", mode=mode, state=inspect())
    finally:
        for interface in ("em0", "em2"):
            cmd("/sbin/ifconfig", interface, "up", check=False)
        if not service_running():
            cmd(SERVICE, "start", check=False)
        if inspect()["binding"] == "absent":
            cmd(PHP, "-f", SCENARIO, "--", "bind", check=False)
        emit("run_complete", state=inspect(), rule=native_rule())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("both", "native", "sdwan"), default="both")
    mode = parser.parse_args().mode
    run(("native", "sdwan") if mode == "both" else (mode,))
