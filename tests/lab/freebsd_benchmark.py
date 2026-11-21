"""Compare native and SD-WAN forwarding on the same isolated FreeBSD PF topology."""
import csv
import hashlib
import json
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


BASELINE_SECONDS = 5
FAULT_SECONDS = 12
RECOVERY_SECONDS = 38
CLIENT_INTERVAL = 0.25
CLIENT_TIMEOUT = 0.20
OBSERVER_INTERVAL = 1.0
PAIR_COUNT = 3
SCENARIO = "erp_wan1"
EVENT_FIELDS = ("run", "mode", "scenario", "name", "time_ns", "detail")


def capture(node, *args):
    return subprocess.check_output(["jexec", node, *args], text=True, timeout=10)


def wait_until(deadline_ns):
    time.sleep(max(0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000))


def route_path(output):
    return [line.strip() for line in output.splitlines() if line.strip().startswith(("gateway:", "interface:"))]


def decision(snapshot):
    steering = snapshot.get("steering", {}).get("G", {})
    return steering.get("revision"), steering.get("gateway")


def gateway_sample(path, gateway):
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(0.25)
            connection.connect(path)
            with connection.makefile("rb") as stream:
                raw = stream.readline(512).decode("ascii").strip()
        name, rtt, deviation, loss = raw.split()
        if name != gateway:
            raise ValueError("monitor identifier mismatch")
        rtt, deviation, loss = int(rtt), int(deviation), int(loss)
        if min(rtt, deviation, loss) < 0 or loss > 100 or rtt == deviation == loss == 0:
            raise ValueError(f"monitor has no valid sample: {raw}")
        return {"gateway": name, "rtt_us": rtt, "rttsd_us": deviation, "loss_pct": loss, "raw": raw}
    except (OSError, ValueError) as error:
        return {"gateway": gateway, "error": str(error)}


def pf_evidence(output, run, generation, firewall, routes):
    rules = capture(firewall, "pfctl", "-sr")
    expected = [rule for rule in rules.splitlines() if re.search(r"\bridentifier 41001\b", rule)]
    if len(expected) != 1:
        raise AssertionError(f"Expected one ERP tracker in PF, found {expected}")
    rule = expected[0]
    if rule.startswith("block "):
        gateway, egress, next_hop = None, "blocked", None
    else:
        paths = [(name, hop) for name, hop in routes.items()
                 if re.search(rf"\broute-to\s+\([^)]*\b{re.escape(hop)}\b[^)]*\)", rule)]
        if len(paths) != 1:
            raise AssertionError(f"The ERP tracker did not load a single known next hop: {rule}")
        gateway, next_hop = paths[0]
        egress = "WAN1" if gateway == "GW_A" else "WAN2"
    artifact = f"pf-{run:02d}-{generation:02d}.txt"
    (output / artifact).write_text(rules, encoding="utf-8")
    nat = capture(firewall, "pfctl", "-sn")
    return {"gateway": gateway, "egress": egress, "next_hop": next_hop, "rule": rule,
            "artifact": artifact, "nat_sha256": hashlib.sha256(nat.encode()).hexdigest()}


def validate_run(rows, events, samples, mode, source_a, source_b):
    required = {event for event in ("start", "fault_requested", "fault_applied",
                                   "recovery_requested", "recovery_applied", "end")
                if event not in events}
    if required:
        raise AssertionError(f"Missing timing events: {sorted(required)}")
    fault, recovery = events["fault_applied"], events["recovery_applied"]

    def successful(flow, after, before):
        return [row for row in rows if row["flow"] == flow and row["status"] == "ok"
                and after <= int(row["started_ns"]) and int(row["ended_ns"]) < before]

    initial = successful("erp", events["start"], events["fault_requested"])
    if not initial or any(row["peer_source"] != source_a for row in initial):
        raise AssertionError("ERP baseline did not use WAN1")
    # Exclude requests overlapping the commands that change the peer rules.
    stable_fault_end = events["recovery_requested"]
    fault_successes = successful("erp", fault, stable_fault_end)
    if mode == "native":
        if fault_successes:
            raise AssertionError("The native gateway group steered an ERP-only outage away from WAN1")
    elif len(fault_successes) < 3 or any(row["peer_source"] != source_b for row in fault_successes):
        raise AssertionError("SD-WAN did not return three valid ERP responses through WAN2 during the outage")
    for flow in ("backup", "dns"):
        control = successful(flow, fault, stable_fault_end)
        if len(control) < 3 or (flow == "backup" and any(row["peer_source"] != source_a for row in control)):
            raise AssertionError(f"{flow} did not remain available during the ERP-only outage")
    restored = successful("erp", recovery, events["end"])
    if len([row for row in restored if row["peer_source"] == source_a]) < 3:
        raise AssertionError("ERP did not return to WAN1 by the end of the recovery window")
    for gateway in ("GW_A", "GW_B"):
        healthy = [value for timestamp, value in samples if fault <= timestamp < stable_fault_end
                   and value["gateway"] == gateway and value.get("loss_pct", 100) < 20]
        if len(healthy) < 3:
            raise AssertionError(f"Expected real dpinger samples with low loss on {gateway} during ERP loss")


def run_benchmark(output, work, config, binding, client, firewall, peer, remote_a,
                  load_policy, set_service_loss, check_dns):
    output.mkdir(parents=True, exist_ok=True)
    if (output / "metadata.json").exists() or any(output.glob("transactions*.csv")) or (output / "events.csv").exists():
        raise ValueError(f"Choose an output directory without an earlier benchmark: {output}")
    config_path = work / "fixture.json"
    snapshot_path = work / "snapshot.json"
    source_a, source_b = (config["fixture_sources"][name] for name in ("opt1", "opt2"))
    routes = {name: config["reload_gateways"][name]["address"] for name in ("GW_A", "GW_B")}
    metadata = {
        "scenario": SCENARIO,
        "host": platform.platform(),
        "baseline_seconds": BASELINE_SECONDS,
        "fault_seconds": FAULT_SECONDS,
        "recovery_seconds": RECOVERY_SECONDS,
        "client_interval_ms": int(CLIENT_INTERVAL * 1000),
        "client_timeout_ms": int(CLIENT_TIMEOUT * 1000),
        "observer_interval_ms": int(OBSERVER_INTERVAL * 1000),
        "pair_count": PAIR_COUNT,
        "sources": {"WAN1": source_a, "WAN2": source_b},
        "next_hops": routes,
        "method": {
            "native": "Pinned pfSense rule compiler without a binding. Both gateways remain healthy.",
            "sdwan": "Real package observer --once, polled by the lab. A new decision loads the compiled rule in FreeBSD PF.",
            "client": "Independent TCP, persistent TCP, backup TCP and DNS probes use the same destinations and cadence in both modes.",
            "fault": "Peer PF drops the ERP TCP service and its standby probe on WAN1 only.",
        },
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    def observe():
        capture(firewall, "/usr/local/bin/php", "-n", "-d", "extension=filter",
                "-d", f"include_path={work}", str(work / "sdwand.php"), "--once")
        return json.loads(snapshot_path.read_text())

    nat_before = capture(firewall, "pfctl", "-sn")
    route_before = route_path(capture(firewall, "route", "-n", "get", "default"))
    all_rows = []
    with (output / "events.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=EVENT_FIELDS)
        writer.writeheader()
        stream.flush()
        lock = threading.Lock()
        completed = 0
        for pair in range(1, PAIR_COUNT + 1):
            modes = ("native", "sdwan") if pair % 2 else ("sdwan", "native")
            for mode in modes:
                completed += 1
                run = completed
                times = {}
                gateway_samples = []

                def event(name, time_ns=None, **detail):
                    timestamp = time.monotonic_ns() if time_ns is None else time_ns
                    with lock:
                        times[name] = timestamp
                        writer.writerow({"run": run, "mode": mode, "scenario": SCENARIO,
                                         "name": name, "time_ns": timestamp,
                                         "detail": json.dumps(detail, separators=(",", ":"))})
                        stream.flush()
                    return timestamp

                set_service_loss()
                capture(firewall, "pfctl", "-F", "states")
                snapshot_path.unlink(missing_ok=True)
                if mode == "sdwan":
                    config["gateways/sdwan_bindings"] = {"item": [binding]}
                    config["gateways/sdwan_bindings/item"] = [binding]
                else:
                    config.pop("gateways/sdwan_bindings", None)
                    config.pop("gateways/sdwan_bindings/item", None)
                config_path.write_text(json.dumps(config))

                last = decision(observe()) if mode == "sdwan" else None
                generation = 1
                loaded_at = load_policy(verify_native=(mode == "native"))
                event("pf_loaded", loaded_at, **pf_evidence(output, run, generation, firewall, routes))
                check_dns()
                ready = work / f"benchmark-ready-{run}"
                run_csv = output / f"transactions-{run:02d}.csv"
                duration = BASELINE_SECONDS + FAULT_SECONDS + RECOVERY_SECONDS
                client_script = Path(__file__).with_name("benchmark_client.py").resolve()
                client_process = subprocess.Popen(["jexec", client, sys.executable, str(client_script), str(run_csv),
                    "--duration", str(duration), "--interval", str(CLIENT_INTERVAL), "--timeout", str(CLIENT_TIMEOUT),
                    "--run", str(run), "--mode", mode, "--scenario", SCENARIO, "--ready-file", str(ready)])
                stop = threading.Event()

                def monitor():
                    nonlocal last, generation
                    next_poll = time.monotonic_ns()
                    interval = int(OBSERVER_INTERVAL * 1_000_000_000)
                    while not stop.is_set():
                        for name in routes:
                            sample = gateway_sample(config["processes"][name]["socket"], name)
                            gateway_samples.append((event("gateway_sample", **sample), sample))
                        if mode == "sdwan":
                            snapshot = observe()
                            current = decision(snapshot)
                            event("snapshot", gateway=current[1], policy_selected=snapshot["policies"]["calls"]["selected"],
                                  members={key: snapshot["members"][key] for key in ("a", "b")})
                            if current != last:
                                generation += 1
                                loaded = load_policy()
                                event("pf_loaded", loaded, **pf_evidence(output, run, generation, firewall, routes))
                                last = current
                        next_poll += interval
                        # Preserve the measurement schedule without launching overlapping observers.
                        now = time.monotonic_ns()
                        if next_poll < now:
                            event("observer_interval_overrun", elapsed_ms=(now - next_poll) / 1_000_000)
                            next_poll += ((now - next_poll) // interval + 1) * interval
                        stop.wait(max(0, (next_poll - time.monotonic_ns()) / 1_000_000_000))

                try:
                    for _ in range(150):
                        if ready.exists() or client_process.poll() is not None:
                            break
                        time.sleep(0.05)
                    if not ready.exists() or client_process.poll() is not None:
                        raise RuntimeError(f"Benchmark client did not become ready on run {run}")
                    start = int(ready.read_text().strip())
                    event("start", start, pair=pair, wan1_source=source_a, wan2_source=source_b,
                          interval_ms=metadata["client_interval_ms"], timeout_ms=metadata["client_timeout_ms"])
                    print(f"benchmark run {run}/{PAIR_COUNT * 2}: pair {pair}, {mode}", flush=True)
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        observer = pool.submit(monitor)
                        try:
                            wait_until(start + BASELINE_SECONDS * 1_000_000_000)
                            event("fault_requested", interface=remote_a)
                            set_service_loss(remote_a)
                            fault = event("fault_applied", interface=remote_a)
                            wait_until(fault + (FAULT_SECONDS - 1) * 1_000_000_000)
                            peer_artifact = f"peer-{run:02d}-during-fault.txt"
                            peer_rules = capture(peer, "pfctl", "-vvsr")
                            (output / peer_artifact).write_text(peer_rules, encoding="utf-8")
                            event("peer_pf_counters", artifact=peer_artifact)
                            wait_until(fault + FAULT_SECONDS * 1_000_000_000)
                            event("recovery_requested", interface=remote_a)
                            set_service_loss()
                            event("recovery_applied", interface=remote_a)
                            if client_process.wait(timeout=RECOVERY_SECONDS + 10) != 0:
                                raise RuntimeError(f"Benchmark client failed on run {run}")
                        finally:
                            stop.set()
                            observer.result(timeout=15)
                    event("end")
                finally:
                    if client_process.poll() is None:
                        client_process.kill()
                        client_process.wait(timeout=3)
                    set_service_loss()
                with run_csv.open(newline="", encoding="utf-8") as file:
                    rows = list(csv.DictReader(file))
                if not rows:
                    raise AssertionError(f"No benchmark transactions on run {run}")
                all_rows.extend(rows)
                # Keep the aggregated raw data available even after an assertion failure.
                with (output / "transactions.csv").open("w", newline="", encoding="utf-8") as merged:
                    raw_writer = csv.DictWriter(merged, fieldnames=list(rows[0]))
                    raw_writer.writeheader()
                    raw_writer.writerows(all_rows)
                validate_run(rows, times, gateway_samples, mode, source_a, source_b)
    if nat_before != capture(firewall, "pfctl", "-sn") or route_before != route_path(
            capture(firewall, "route", "-n", "get", "default")):
        raise AssertionError("ERP benchmark altered NAT or the system default route")
    print("ok - both modes preserved NAT and the system default route", flush=True)
