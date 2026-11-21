#!/usr/bin/env python3
"""Summarize the A/B traffic and fault logs without contacting the lab."""
import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
import json
import math
from pathlib import Path
from statistics import median


NS_PER_MS = 1_000_000
STREAK = 3
PHASES = ("baseline", "fault", "recovery")
RUN_FIELDS = ("run", "mode", "scenario")
TRANSACTION_FIELDS = RUN_FIELDS + (
    "flow", "sequence", "planned_ns", "started_ns", "connect_ns", "ended_ns",
    "status", "peer_source",
)
EVENT_FIELDS = RUN_FIELDS + ("name", "time_ns", "detail")


@dataclass(frozen=True)
class Transaction:
    sequence: int
    planned_ns: int
    started_ns: int
    connect_ns: int | None
    ended_ns: int
    status: str
    peer_source: str

    @classmethod
    def from_row(cls, row):
        result = cls(
            *(int(row[field]) for field in ("sequence", "planned_ns", "started_ns")),
            int(row["connect_ns"]) if row["connect_ns"] else None,
            int(row["ended_ns"]),
            row["status"],
            row["peer_source"],
        )
        if result.ended_ns < result.started_ns or (
            result.connect_ns is not None
            and not result.started_ns <= result.connect_ns <= result.ended_ns
        ):
            raise ValueError(f"Invalid transaction timestamps: {row}")
        return result


def rows(path, required):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(required).difference(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns {', '.join(sorted(missing))}")
        for row in reader:
            if any(row[field] is None for field in required):
                raise ValueError(f"{path}:{reader.line_num}: incomplete row")
            yield row


def run_key(row):
    return tuple(row[field] for field in RUN_FIELDS)


def milliseconds(value):
    return round(value / NS_PER_MS, 3)


def distribution(samples):
    ordered = sorted(samples)
    if not ordered:
        return {"n": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}
    return {
        "n": len(ordered),
        "p50_ms": milliseconds(median(ordered)),
        "p95_ms": milliseconds(ordered[math.ceil(0.95 * len(ordered)) - 1]),
        "max_ms": milliseconds(ordered[-1]),
    }


def metrics(samples, crossing):
    statuses = Counter(sample.status for sample in samples)
    successful = [sample for sample in samples if sample.status == "ok"]
    total = len(samples)
    return {
        "attempts": total,
        "ok": len(successful),
        "failed": total - len(successful),
        "failure_pct": round(100 * (total - len(successful)) / total, 2) if total else None,
        "status": dict(sorted(statuses.items())),
        "peer_sources": dict(sorted(Counter(
            sample.peer_source for sample in successful if sample.peer_source
        ).items())),
        "response": distribution(sample.ended_ns - sample.started_ns for sample in successful),
        "handshake": distribution(
            sample.connect_ns - sample.started_ns for sample in successful
            if sample.connect_ns is not None
        ),
        "schedule_delay": distribution(
            max(0, sample.started_ns - sample.planned_ns) for sample in samples
        ),
        "crossed_phase_boundary": crossing,
    }


def sustained(samples, start, end, peer_source=None):
    window = [sample for sample in samples if start <= sample.started_ns < end]
    finished = [sample for sample in window if sample.ended_ns <= end]
    observation = {
        "observation_ms": milliseconds(end - start),
        "started_attempts": len(window),
        "completed_attempts": len(finished),
    }
    streak = []
    for sample in finished:
        if sample.status != "ok" or (peer_source is not None and sample.peer_source != peer_source):
            streak.clear()
            continue
        if streak and sample.sequence != streak[-1].sequence + 1:
            streak.clear()
        streak.append(sample)
        if len(streak) == STREAK:
            return {
                "outcome": "observed",
                "first_reply_ms": milliseconds(streak[0].ended_ns - start),
                "confirmed_ms": milliseconds(max(item.ended_ns for item in streak) - start),
                "first_sequence": streak[0].sequence,
                "peer_source": streak[0].peer_source or None,
                **observation,
            }
    return {
        "outcome": "not_observed" if finished else "no_samples",
        "last_completion_ms": milliseconds(max(item.ended_ns for item in finished) - start)
        if finished else None,
        **observation,
    }


def event_detail(event):
    try:
        result = json.loads(event["detail"])
    except json.JSONDecodeError:
        return {}
    return result if isinstance(result, dict) else {}


def first_event(timeline, start, end, name, match):
    for time_ns, kind, detail in timeline:
        if start <= time_ns < end and kind == name and match(detail):
            return milliseconds(time_ns - start)
    return None


def probe_status(detail, member):
    return detail.get("members", {}).get(member, {}).get("checks", {}).get("probe_primary")


def observed_fault_events(timeline, fault, recovery, end):
    service_errors = {"Timed out", "TCP check failed", "DNS check failed", "HTTPS check failed"}
    return {
        "service_probe_wan1_failed_ms": first_event(
            timeline, fault, recovery, "snapshot",
            lambda detail: probe_status(detail, "a") in service_errors
        ),
        "sdwan_chose_wan2_ms": first_event(
            timeline, fault, recovery, "snapshot", lambda detail: detail.get("gateway") == "GW_B"
        ),
        "pf_wan2_during_fault_ms": first_event(
            timeline, fault, recovery, "pf_loaded", lambda detail: detail.get("egress") == "WAN2"
        ),
        "service_probe_wan1_recovered_ms": first_event(
            timeline, recovery, end, "snapshot",
            lambda detail: probe_status(detail, "a") == "Passed"
        ),
        "pf_wan1_after_repair_ms": first_event(
            timeline, recovery, end, "pf_loaded", lambda detail: detail.get("egress") == "WAN1"
        ),
    }


def phase_before(time_ns, fault, recovery):
    return PHASES[0 if time_ns < fault else 1 if time_ns < recovery else 2]


def summarize_gateways(timeline, fault, recovery):
    groups = defaultdict(list)
    for time_ns, kind, detail in timeline:
        if kind == "gateway_sample" and detail.get("gateway"):
            groups[phase_before(time_ns, fault, recovery), detail["gateway"]].append(detail)
    output = []
    for (phase, gateway), samples in sorted(
        groups.items(), key=lambda item: (PHASES.index(item[0][0]), item[0][1])
    ):
        latency = {field: distribution(
            1_000 * float(sample[field]) for sample in samples if sample.get(field) is not None
        ) for field in ("rtt_us", "rttsd_us")}
        losses = [float(sample["loss_pct"]) for sample in samples if sample.get("loss_pct") is not None]
        output.append({
            "phase": phase, "gateway": gateway, "samples": len(samples),
            "rtt": latency["rtt_us"], "reported_rttsd": latency["rttsd_us"],
            "loss_p50_pct": round(median(losses), 3) if losses else None,
            "loss_max_pct": max(losses, default=None),
        })
    return output


def analyze(directory):
    events = defaultdict(list)
    for event in rows(directory / "events.csv", EVENT_FIELDS):
        events[run_key(event)].append(event)

    runs = defaultdict(lambda: defaultdict(list))
    for row in rows(directory / "transactions.csv", TRANSACTION_FIELDS):
        runs[run_key(row)][row["flow"]].append(Transaction.from_row(row))
    if not runs:
        raise ValueError("No transaction samples")
    if events.keys() != runs.keys():
        raise ValueError(f"Inconsistent run keys. Missing events: {runs.keys() - events.keys()}; "
                         f"missing traffic: {events.keys() - runs.keys()}")

    aggregate = defaultdict(list)
    runs_report = []
    for key, flows in sorted(runs.items()):
        run, mode, scenario = key
        timeline = events[key]
        times = {}
        for name in ("start", "fault_applied", "recovery_applied", "end"):
            matches = [int(event["time_ns"]) for event in timeline if event["name"] == name]
            if len(matches) != 1:
                raise ValueError(f"{key}: expected one {name} event, got {len(matches)}")
            times[name] = matches[0]
        start, fault, recovery, end = times.values()
        if not start <= fault < recovery < end:
            raise ValueError(f"{key}: invalid phase event ordering")
        event_samples = sorted(
            ((int(event["time_ns"]), event["name"], event_detail(event)) for event in timeline),
            key=lambda item: item[0],
        )
        settings = event_detail(next(event for event in timeline if event["name"] == "start"))
        primary = settings.get("wan1_source", "198.51.100.1")
        standby = settings.get("wan2_source", "203.0.113.1")
        phase_metrics = []
        sequence_gaps = {}
        for flow, samples in sorted(flows.items()):
            samples.sort(key=lambda sample: sample.sequence)
            numbers = [sample.sequence for sample in samples]
            if len(numbers) != len(set(numbers)):
                raise ValueError(f"{key}/{flow}: duplicate sequence numbers")
            sequence_gaps[flow] = numbers[-1] - numbers[0] + 1 - len(numbers)

            for phase, first, limit in zip(PHASES, (None, fault, recovery), (fault, recovery, None)):
                values = [sample for sample in samples
                          if (first is None or sample.started_ns >= first)
                          and (limit is None or sample.started_ns < limit)]
                crossed = sum(sample.ended_ns >= limit for sample in values) if limit is not None else 0
                phase_metrics.append({"phase": phase, "flow": flow, **metrics(values, crossed)})
                aggregate[scenario, mode, phase, flow].append((values, crossed))

        erp = flows.get("erp", [])
        while_faulted = [sample for sample in erp
                         if fault <= sample.started_ns and sample.ended_ns < recovery]
        before_repair = while_faulted[-STREAK:]
        wan2_seen = any(sample.status == "ok" and sample.peer_source == standby
                        for sample in while_faulted)
        health_at_repair = (len(before_repair) == STREAK
                            and before_repair[-1].sequence - before_repair[0].sequence == STREAK - 1
                            and all(sample.status == "ok" for sample in before_repair))
        runs_report.append({
            "run": run,
            "mode": mode,
            "scenario": scenario,
            "fault_window_ms": milliseconds(recovery - fault),
            "recovery_window_ms": milliseconds(end - recovery),
            "settings": settings,
            "sequence_gaps": sequence_gaps,
            "observed_event_ms": observed_fault_events(event_samples, fault, recovery, end),
            "gateway_samples": summarize_gateways(event_samples, fault, recovery),
            "flow_after_repair": {flow: sustained(samples, recovery, end)
                                  for flow, samples in flows.items()},
            "wan1_source": primary,
            "wan2_source": standby,
            "erp_wan2_during_fault": sustained(erp, fault, recovery, standby),
            "erp_service_after_repair": sustained(erp, recovery, end),
            "erp_wan1_after_repair": sustained(erp, recovery, end, primary),
            "erp_serving_before_repair": health_at_repair,
            "erp_received_by_wan2_during_fault": wan2_seen,
            "flows": phase_metrics,
        })

    aggregates = []
    for (scenario, mode, phase, flow), parts in sorted(
        aggregate.items(), key=lambda item: (item[0][:2], PHASES.index(item[0][2]), item[0][3])
    ):
        aggregates.append({
            "scenario": scenario, "mode": mode, "phase": phase, "flow": flow,
            "runs": len(parts),
            **metrics([sample for samples, _ in parts for sample in samples],
                      sum(crossing for _, crossing in parts)),
        })
    return {"steady_success_count": STREAK, "runs": runs_report, "aggregate": aggregates}


def latency_text(result):
    if not result["n"]:
        return "—"
    return " / ".join(f"{result[field]:.3f}" for field in ("p50_ms", "p95_ms", "max_ms"))


def milestone_text(result):
    if result["outcome"] == "no_samples":
        return "no completed attempts"
    if result["outcome"] != "observed":
        return (f"not observed in {result['observation_ms'] / 1000:.3f} s "
                f"({result['completed_attempts']} completed attempts)")
    return f"{result['first_reply_ms'] / 1000:.3f} / {result['confirmed_ms'] / 1000:.3f} s"


def table(report, with_runs):
    key = "aggregate" if with_runs else "flows"
    fields = "| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |"
    header = ("| Scenario | Mode | Runs " if with_runs else "") + fields
    dash = "| --- | --- | ---: " if with_runs else ""
    divider = dash + "| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |"
    output = [header, divider]
    for row in report[key]:
        outcome = row["status"]
        identities = " — ".join(f"{source} × {count}" for source, count in row["peer_sources"].items())
        values = [
            row["phase"], row["flow"], f"{row['ok']} / {row['attempts']}",
            f"{row['failure_pct']:.2f}%" if row["failure_pct"] is not None else "—",
            str(outcome.get("timeout", 0)),
            (f"{latency_text(row['response'])} ({row['response']['n']})"),
            (f"{latency_text(row['handshake'])} ({row['handshake']['n']})"),
            identities or "—", str(row["crossed_phase_boundary"]),
        ]
        if with_runs:
            values = [row["scenario"], row["mode"], str(row["runs"]), *values]
        output.append("| " + " | ".join(values) + " |")
    return output


def render_markdown(report):
    output = [
        "# SD-WAN A/B benchmark",
        "",
        "Convergence requires three consecutive successful attempts. Times are from the",
        "actual fault or repair event to the first reply in that streak and to confirmation",
        "of the entire streak. A missing streak is reported with its observation window.",
        "Failures include all recorded statuses other than OK. Response and connection",
        "latencies include successful requests only. P95 uses the nearest rank.",
        "A boundary-crossing request is attributed to the phase where it started.",
        "",
        "## ERP recovery by run",
        "",
        "| Run | Scenario | Mode | WAN2 during fault | Service after repair | WAN1 after repair | Last 3 completed before repair succeeded |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for run in report["runs"]:
        values = [run["run"], run["scenario"], run["mode"], *(
            milestone_text(run[field]) for field in (
                "erp_wan2_during_fault", "erp_service_after_repair", "erp_wan1_after_repair"
            )
        ), "yes" if run["erp_serving_before_repair"] else "no"]
        output.append("| " + " | ".join(values) + " |")

    output.extend(("", "## Pooled traffic measurements", "", *table(report, with_runs=True)))
    for run in report["runs"]:
        output.extend((
            "", f"## Run {run['run']} · {run['mode']} · {run['scenario']}", "",
            f"Fault window {run['fault_window_ms'] / 1000:.3f} s. "
            f"Recovery window {run['recovery_window_ms'] / 1000:.3f} s.",
        ))
        missing = [f"{flow} {count}" for flow, count in run["sequence_gaps"].items() if count]
        if missing:
            output.append("Missing sequence numbers: " + ", ".join(missing) + ".")
        output.extend(("", *table(run, with_runs=False)))
        output.extend(("", "| Time relative to fault or repair | Seconds |", "| --- | ---: |"))
        labels = {
            "service_probe_wan1_failed_ms": "WAN1 service probe failed",
            "sdwan_chose_wan2_ms": "SD-WAN selected WAN2",
            "pf_wan2_during_fault_ms": "PF loaded and confirmed WAN2",
            "service_probe_wan1_recovered_ms": "WAN1 service probe recovered",
            "pf_wan1_after_repair_ms": "PF loaded and confirmed WAN1 after repair",
        }
        for key, label in labels.items():
            elapsed = run["observed_event_ms"][key]
            value = f"{elapsed / 1000:.3f}" if elapsed is not None else "—"
            output.append(f"| {label} | {value} |")
        for flow, result in sorted(run["flow_after_repair"].items()):
            output.append(f"| {flow} first sustained replies after repair | {milestone_text(result)} |")
        if run["gateway_samples"]:
            output.extend((
                "", "| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | "
                "RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |",
                "| --- | --- | ---: | --- | --- | --- |",
            ))
            for value in run["gateway_samples"]:
                loss = "—" if value["loss_p50_pct"] is None else (
                    f"{value['loss_p50_pct']:g} / {value['loss_max_pct']:g}"
                )
                output.append(
                    f"| {value['phase']} | {value['gateway']} | {value['samples']} | "
                    f"{latency_text(value['rtt'])} | {latency_text(value['reported_rttsd'])} | {loss} |"
                )
    return "\n".join(output) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="directory with transactions.csv and events.csv")
    parser.add_argument("--out", type=Path, help="output directory, defaults to the input directory")
    args = parser.parse_args()
    try:
        report = analyze(args.input)
        output = args.out or args.input
        output.mkdir(parents=True, exist_ok=True)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (output / "report.md").write_text(render_markdown(report), encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
