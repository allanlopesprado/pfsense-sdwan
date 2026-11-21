"""Summarize ICMP and PF evidence from the isolated CE 2.9.2 WAN experiment."""

import argparse
from collections import Counter
import csv
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
import statistics


MARKER = re.compile(r"CEAB (?=\{)")
EXPECTED = {
    "baseline": "em0",
    "wan1_down": "em2",
    "both_down": "block",
    "wan2_restored": "em2",
    "wan1_restored": "em0",
}
MODES = ("native", "sdwan")
GATEWAYS = ("wan1", "wan2")
PF_TARGETS = ("em0", "em2", "block", "unrouted")
ICMP_CHANGES = {
    ("wan1_down", "wan1"): False,
    ("both_down", "wan2"): False,
    ("wan2_restored", "wan2"): True,
    ("wan1_restored", "wan1"): True,
}
NS_PER_MS = 1_000_000


@dataclass
class Phase:
    mode: str
    name: str
    requested_ns: int
    applied_ns: int
    window_s: float
    end_ns: int | None = None
    samples: list = field(default_factory=list)


def records_from_log(path):
    decoder = json.JSONDecoder()
    records = []
    lines = path.read_bytes().decode("utf-8", errors="replace").splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = MARKER.search(line)
        if match is None:
            continue
        # The terminal can leave non-JSON bytes after a record. Keep a
        # verbatim copy of the measurement prefix and the JSON itself.
        try:
            record, length = decoder.raw_decode(line[match.end():])
        except json.JSONDecodeError as error:
            if index == len(lines) - 1 and not line.endswith(("\r", "\n")):
                break
            raise ValueError(f"Malformed CEAB record: {line[match.start():]}") from error
        records.append((line[match.start():match.end() + length], record))
    starts = [index for index, (_, record) in enumerate(records)
              if record.get("kind") == "mode" and record.get("mode") == "native"]
    if not starts:
        raise ValueError("No CEAB native comparison start found")
    return records[starts[-1]:]


def parse_phases(records):
    phases = []
    mode = None
    active = None
    modes_ended = set()
    cleanup_binding = None
    for _, row in records:
        kind = row["kind"]
        if kind == "mode":
            mode = row["mode"]
            if mode not in MODES:
                raise ValueError(f"Invalid benchmark mode {mode!r}")
            active = None
            cleanup_binding = None
        elif kind == "phase":
            if active is not None:
                active.end_ns = row["requested_ns"]
            active = Phase(mode, row["name"], row["requested_ns"], row["at_ns"], row["window_s"])
            phases.append(active)
        elif kind == "sample":
            if active is None:
                raise ValueError("CEAB sample appeared outside a phase")
            if row["started_ns"] < active.applied_ns or row["at_ns"] < row["started_ns"]:
                raise ValueError("CEAB sample timestamps are inconsistent")
            active.samples.append(row)
        elif kind == "end":
            if row["mode"] != mode or active is None:
                raise ValueError("CEAB end does not match the current mode")
            active.end_ns = row["at_ns"]
            modes_ended.add(mode)
            active = None
        elif kind == "cleanup":
            cleanup_binding = row.get("binding")
    return phases, modes_ended, cleanup_binding


def milliseconds(end_ns, start_ns):
    return round((end_ns - start_ns) / NS_PER_MS, 3)


def elapsed(phase):
    end_ns = phase.end_ns
    if end_ns is None:
        end_ns = max((row["at_ns"] for row in phase.samples), default=phase.applied_ns)
    return milliseconds(end_ns, phase.applied_ns)


def first_streak(samples, matched, consecutive):
    streak = 0
    for row in samples:
        streak = streak + 1 if matched(row) else 0
        if streak == consecutive:
            return row
    return None


def timing(first, stable, phase):
    return {
        "first_after_applied_ms": milliseconds(first["at_ns"], phase.applied_ns) if first else None,
        "first_after_request_ms": milliseconds(first["at_ns"], phase.requested_ns) if first else None,
        "stable_after_applied_ms": milliseconds(stable["at_ns"], phase.applied_ns) if stable else None,
        "stable_after_request_ms": milliseconds(stable["at_ns"], phase.requested_ns) if stable else None,
    }


def observation(first, stable, samples):
    if not samples:
        return "no_samples"
    if not first:
        return "right_censored"
    return "stable" if stable else "first_only"


def ping_summary(phase, flow, consecutive):
    samples = sorted((row for row in phase.samples if row["flow"] == flow), key=lambda row: row["at_ns"])
    successes = [row for row in samples if row["success"]]
    rtts = sorted(row["rtt_ms"] for row in successes if row["rtt_ms"] is not None)
    sent = len(samples)
    lost = sent - len(successes)
    codes = Counter(row["returncode"] for row in samples)
    stable = first_streak(samples, lambda row: row["success"], consecutive)
    first = successes[0] if successes else None
    first_loss = next((row for row in samples if not row["success"]), None)
    stable_loss = first_streak(samples, lambda row: not row["success"], consecutive)
    return {
        "mode": phase.mode, "phase": phase.name, "flow": flow,
        "window_ms": elapsed(phase), "window_complete": phase.end_ns is not None,
        "sent": sent, "received": len(successes), "lost": lost,
        "loss_pct": round(100 * lost / sent, 3) if sent else None,
        "rtt_samples": len(rtts), "success_without_rtt": len(successes) - len(rtts),
        "rtt_min_ms": rtts[0] if rtts else None,
        "rtt_median_ms": round(statistics.median(rtts), 3) if rtts else None,
        "rtt_p95_ms": rtts[math.ceil(0.95 * len(rtts)) - 1] if rtts else None,
        "rtt_max_ms": rtts[-1] if rtts else None,
        "returncodes": json.dumps(dict(sorted(codes.items())), separators=(",", ":")),
        "status": observation(first, stable, samples),
        "loss_status": observation(first_loss, stable_loss, samples),
        **timing(first, stable, phase),
        **{f"loss_{key}": value for key, value in timing(first_loss, stable_loss, phase).items()},
    }


def pf_summary(phase, target, consecutive):
    samples = sorted((row for row in phase.samples if row["flow"] == "pf"), key=lambda row: row["at_ns"])
    matches = [row for row in samples if row["path"] == target]
    first = matches[0] if matches else None
    stable = first_streak(samples, lambda row: row["path"] == target, consecutive)
    prior_difference = first is not None and any(
        row["at_ns"] < first["at_ns"] and row["path"] != target for row in samples
    )
    return {
        "mode": phase.mode, "phase": phase.name, "target": target,
        "expected": target == EXPECTED.get(phase.name),
        "requested_ns": phase.requested_ns, "applied_ns": phase.applied_ns,
        "ifconfig_ms": milliseconds(phase.applied_ns, phase.requested_ns),
        "window_ms": elapsed(phase), "window_complete": phase.end_ns is not None,
        "samples": len(samples), "target_samples": len(matches),
        "first_sample_already_on_target": bool(samples and samples[0]["path"] == target),
        "preceded_by_different_sample": prior_difference,
        "final_path": samples[-1]["path"] if samples else None,
        "samples_off_target_after_stable": (
            sum(row["at_ns"] > stable["at_ns"] and row["path"] != target for row in samples)
            if stable else None
        ),
        "status": observation(first, stable, samples),
        **timing(first, stable, phase),
        "first_next_hop": first.get("next_hop") if first else None,
        "first_rule": first.get("rule") if first else None,
    }


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=tuple(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def display(value):
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def markdown(complete, consecutive, cleanup_binding, pings, pf):
    lines = [
        "# Comparativo de WAN no pfSense CE 2.9.2 isolado",
        "",
        f"Coleta {'completa' if complete else 'incompleta'}. Estado do vínculo após a limpeza "
        f"\u0060{cleanup_binding or 'sem evidência'}\u0060.",
        "",
        "Os pings foram originados pelo firewall, com endereço de origem fixo, para o gateway "
        "de cada WAN. As medições de RTT se referem ao gateway dentro do QEMU. O destino "
        "de aplicação, a experiência do cliente LAN e os tempos de produção têm ensaios próprios.",
        "",
        f"Na tabela de PF, a primeira medida indica a primeira amostra na rota esperada. "
        f"A confirmação exige {consecutive} amostras consecutivas observadas no mesmo caminho. "
        "A coluna de desvios posteriores registra quando essa sequência foi interrompida. "
        "A resolução é a cadência de coleta, cerca de um segundo mais os atrasos de execução. "
        "Um caminho já presente no primeiro poll não tem instante de transição medido.",
        "",
        "Os tempos das tabelas partem do término do comando da fase. O CSV também registra o "
        "intervalo desde a solicitação. A ausência de evento dentro da janela é censura à direita.",
        "",
        "## ICMP nos gateways",
        "",
        "| Modo | Fase | Gateway | Enviados | Recebidos | Perdidos | Perda % | RTT mediana ms | RTT p95 ms | RTT máximo ms |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    fields = ("mode", "phase", "flow", "sent", "received", "lost", "loss_pct",
              "rtt_median_ms", "rtt_p95_ms", "rtt_max_ms")
    for row in pings:
        lines.append("| " + " | ".join(display(row[key]) for key in fields) + " |")
    lines += [
        "",
        "O p95 usa o posto mais próximo, e o cálculo de RTT usa somente respostas com valor de RTT.",
        "",
        f"| Modo | Fase | Gateway | Evento esperado | Primeiro ms | {consecutive}ª consecutiva ms | Estado |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in pings:
        key = (row["phase"], row["flow"])
        if key in ICMP_CHANGES:
            success_expected = ICMP_CHANGES[key]
            prefix = "" if success_expected else "loss_"
            state = "Resposta" if success_expected else "Ausência de resposta"
            values = (row["mode"], row["phase"], row["flow"], state,
                      row[prefix + "first_after_applied_ms"], row[prefix + "stable_after_applied_ms"],
                      row[prefix + "status"])
            lines.append("| " + " | ".join(display(value) for value in values) + " |")
    lines += [
        "",
        "## Regra carregada no PF",
        "",
        f"| Modo | Fase | Caminho esperado | Observações | Amostras no caminho | Primeiro ms | {consecutive}ª consecutiva ms | Desvios posteriores | Última rota | Estado |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    fields = ("mode", "phase", "target", "samples", "target_samples", "first_after_applied_ms",
              "stable_after_applied_ms", "samples_off_target_after_stable", "final_path", "status")
    for row in pf:
        if row["expected"]:
            lines.append("| " + " | ".join(display(row[key]) for key in fields) + " |")
    lines += [
        "",
        "O CSV de PF inclui os outros caminhos observados, o próximo salto e a regra original do "
        "tracker. A saída bruta recortada preserva os eventos e amostras do console.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial_log", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--stable-samples", type=int, default=3)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    if args.stable_samples < 1:
        parser.error("--stable-samples must be positive")
    records = records_from_log(args.serial_log)
    phases, modes_ended, cleanup_binding = parse_phases(records)
    actual = [(phase.mode, phase.name) for phase in phases]
    expected = [(mode, phase) for mode in MODES for phase in EXPECTED]
    complete = (
        actual == expected and modes_ended == set(MODES) and cleanup_binding == "present"
        and all({row["flow"] for row in phase.samples} >= {"pf", *GATEWAYS} for phase in phases)
    )
    pings = [ping_summary(phase, flow, args.stable_samples) for phase in phases for flow in GATEWAYS]
    pf = [pf_summary(phase, target, args.stable_samples) for phase in phases for target in PF_TARGETS]
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "native-wan-raw.log").open("w", encoding="utf-8", newline="\n") as stream:
        stream.writelines(raw + "\n" for raw, _ in records)
    write_csv(args.output / "native-wan-ping.csv", pings)
    write_csv(args.output / "native-wan-pf.csv", pf)
    (args.output / "native-wan-summary.md").write_text(
        markdown(complete, args.stable_samples, cleanup_binding, pings, pf), encoding="utf-8"
    )
    print(f"{len(records)} CEAB records, {len(phases)} phases, complete={complete}")
    if args.require_complete and not complete:
        parser.exit(2, "CEAB comparison incomplete; partial artifacts were preserved.\n")


if __name__ == "__main__":
    main()
