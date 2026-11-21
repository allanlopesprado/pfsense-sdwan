"""Extract synthetic CE 2.9.2 retune evidence and produce reusable CSV files."""

import argparse
from collections import Counter, defaultdict
import csv
import json
import math
from pathlib import Path
from statistics import median


PREFIX = "AB040305 "


def collect(path):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(PREFIX):
            events.append(json.loads(line[len(PREFIX):]))
        elif line.startswith("{") and path.suffix == ".jsonl":
            events.append(json.loads(line))
    return events


def write_csv(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def p95(values):
    return sorted(values)[math.ceil(len(values) * 0.95) - 1] if values else None


def convergence(phase, snapshots, wan1, wan2):
    start = phase["event_ns"]
    expected = phase["expected"]
    path_seen = next((row["pf_finished_ns"] for row in snapshots if row["path"] == expected), None)
    first = None
    confirmed = None
    final_streak = 0
    post_confirmation_deviations = 0
    for rule, ping1, ping2 in zip(snapshots, wan1, wan2):
        if rule["path"] != expected or [ping1["success"], ping2["success"]] != phase["expected_pings"]:
            final_streak = 0
            if confirmed is None:
                first = None
            else:
                post_confirmation_deviations += 1
            continue
        sampled = max(rule["pf_finished_ns"], ping1["finished_ns"], ping2["finished_ns"])
        if first is None:
            first = sampled
        final_streak += 1
        if final_streak == 3 and confirmed is None:
            confirmed = sampled

    def relative(value):
        return None if value is None else round((value - start) / 1e6, 3)

    expected_gateway, expected_member = {
        "em0": ("LAB_WAN1", "lab_a"), "em2": ("LAB_WAN2", "lab_b"), "block": (None, None),
    }[expected]
    first_eligibility = next((
        row["at_ns"] for row in snapshots if row["telemetry"] and expected_member and
        (row["telemetry"]["candidates"] or {}).get(expected_member) == "Eligible"
    ), None)
    first_recommendation = next((
        row["at_ns"] for row in snapshots if row["telemetry"] and
        row["telemetry"]["binding"] == "present" and
        row["telemetry"]["generation"] is not None and row["telemetry"]["gateway"] == expected_gateway
    ), None)
    confirmed_receipt = next((
        row["at_ns"] for row in snapshots if row["path"] == expected and
        (row["telemetry"] or {}).get("receipt_confirmed")
    ), None)
    return {
        "first_ms": relative(path_seen), "streak_start_ms": relative(first) if confirmed is not None else None,
        "three_ms": relative(confirmed), "last_streak": final_streak,
        "first_eligibility_ms": relative(first_eligibility),
        "first_recommendation_ms": relative(first_recommendation),
        "first_confirmed_receipt_ms": relative(confirmed_receipt),
        "post_confirmation_deviations": post_confirmation_deviations,
    }


def aggregate(records, folder):
    folder.mkdir(parents=True, exist_ok=True)
    phases = {}
    outcomes = {}
    quality = defaultdict(list)
    rules_by_phase = defaultdict(list)
    pf = []
    pings = []
    raw = folder / "events.jsonl"
    raw.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    for record in records:
        kind = record["kind"]
        if kind in {"phase", "sample", "outcome"}:
            key = record["mode"], record["phase"]
        if kind == "phase":
            phases[key] = record
        elif kind == "outcome":
            outcomes[key] = record
        elif kind == "sample":
            if record["flow"] == "pf":
                pf.append(record)
                rules_by_phase[key].append(record)
            else:
                pings.append(record)
                quality[(*key, record["flow"])].append(record)

    def since(row, field):
        base = phases[row["mode"], row["phase"]]["event_ns"]
        return round((row[field] - base) / 1e6, 3)

    pf_rows = []
    for row in pf:
        telemetry = row["telemetry"] or {}
        pf_rows.append({
            **row, "relative_ms": since(row, "pf_finished_ns"),
            "default_interface": row["default"].get("interface"),
            "default_gateway": row["default"].get("gateway"),
            "recommended": telemetry.get("gateway"), "forwarding_status": telemetry.get("pf"),
            "receipt_confirmed": telemetry.get("receipt_confirmed"),
        })
    write_csv(folder / "pf.csv", pf_rows, (
        "mode", "phase", "relative_ms", "path", "next_hop", "default_interface", "default_gateway",
        "recommended", "forwarding_status", "receipt_confirmed", "rule", "guard",
    ))
    ping_rows = [{**row, "relative_ms": since(row, "finished_ns")} for row in pings]
    write_csv(folder / "ping.csv", ping_rows, (
        "mode", "phase", "flow", "relative_ms", "success", "rtt_ms", "returncode",
    ))
    rows = []
    for key, samples in quality.items():
        times = [sample["rtt_ms"] for sample in samples if sample["rtt_ms"] is not None]
        received = sum(sample["success"] for sample in samples)
        rows.append(dict(
            mode=key[0], phase=key[1], flow=key[2], sent=len(samples), received=received,
            lost=len(samples) - received, loss_pct=round(100 * (len(samples) - received) / len(samples), 3),
            median_ms=round(median(times), 3) if times else None, p95_ms=p95(times),
            max_ms=max(times) if times else None,
        ))
    write_csv(folder / "ping-summary.csv", rows, (
        "mode", "phase", "flow", "sent", "received", "lost", "loss_pct", "median_ms", "p95_ms", "max_ms",
    ))
    observed = defaultdict(Counter)
    default_observed = defaultdict(Counter)
    for row in pf_rows:
        key = row["mode"], row["phase"]
        observed[key][row["path"]] += 1
        default_observed[key][row["default_interface"] or "absent"] += 1
    result = []
    for key, phase in phases.items():
        outcome = outcomes.get(key, {})
        recomputed = convergence(phase, rules_by_phase[key], quality[(*key, "wan1")], quality[(*key, "wan2")])
        result.append({
            **outcome, **recomputed, "mode": key[0], "phase": key[1], "expected": phase["expected"],
            "pf_observations": json.dumps(observed[key], sort_keys=True),
            "default_observations": json.dumps(default_observed[key], sort_keys=True),
            "status": ("incomplete" if not outcome else "right_censored" if recomputed["three_ms"] is None
                       else "confirmed_with_instability" if recomputed["post_confirmation_deviations"]
                       else "confirmed"),
        })
    write_csv(folder / "phases.csv", result, (
        "mode", "phase", "expected", "samples", "first_ms", "streak_start_ms", "three_ms",
        "last_streak", "first_eligibility_ms", "first_recommendation_ms", "first_confirmed_receipt_ms", "post_confirmation_deviations",
        "window_ms", "status", "pf_observations", "default_observations",
    ))
    print(json.dumps({"events": len(records), "phase_outcomes": len(outcomes), "ping_samples": len(pings),
                      "pf_samples": len(pf), "completion_records": sum(r["kind"] == "run_complete" for r in records)},
                     indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial_log", type=Path, help="raw QEMU serial output or exported events.jsonl")
    parser.add_argument("output_folder", type=Path)
    args = parser.parse_args()
    records = collect(args.serial_log)
    if not records:
        raise SystemExit("No benchmark records in serial input")
    aggregate(records, args.output_folder)
