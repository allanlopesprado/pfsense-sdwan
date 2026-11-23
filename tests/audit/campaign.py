"""Run a bounded set of divergence audit seeds and preserve each report."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


AUDIT = Path(__file__).with_name("run.py")
OUTCOMES = ("passed", "known", "resolved", "unexpected")


def run_seed(seed, directory, php, revision):
    record = {"seed": seed, "directory": directory.name}
    process = None
    try:
        directory.mkdir()
        process = subprocess.run(
            [sys.executable, "-B", str(AUDIT), "--seed", str(seed), "--php", php, "--output", str(directory)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False,
        )
        record["exit_code"] = process.returncode
        report = json.loads((directory / "audit.json").read_text(encoding="utf-8"))
        if report["seed"] != seed or report["revision"] != revision:
            raise ValueError("The report seed or revision differs from the requested audit.")
        counts = {name: report["counts"][name] for name in OUTCOMES}
        if any(type(count) is not int or count < 0 for count in counts.values()):
            raise ValueError("The report has invalid outcome counts.")
        record["counts"] = counts
        if process.returncode != int(counts["unexpected"] > 0):
            raise ValueError("The exit code disagrees with the report.")
        digest = next((item.get("input_sha256") for item in report["processes"]
                       if item["driver"] == "transitions.php"), None)
        if isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest):
            record["input_sha256"] = digest
        elif not counts["unexpected"]:
            raise ValueError("The report has no fingerprint for generated transition inputs.")
        if "follow_up" in report:
            record["follow_up"] = report["follow_up"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        record["error"] = str(error)
        if process is not None and process.stderr:
            record["runner_error"] = process.stderr[-1200:].decode("utf-8", errors="replace")
    return record


def markdown(campaign):
    lines = [
        "# SD-WAN audit campaign",
        "",
        f"Revision `{campaign['revision']}`. {len(campaign['rounds'])} rounds, "
        f"{campaign['failed_rounds']} failed, {campaign['distinct_transition_inputs']} distinct transition inputs.",
        "",
        "| Seed | Passed | Known | Resolved | Unexpected | Input SHA-256 prefix | Status |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for record in campaign["rounds"]:
        counts = " | ".join(str(record.get("counts", {}).get(name, "—")) for name in OUTCOMES)
        digest = record.get("input_sha256", "—")[:12]
        status = "error" if "error" in record else "failed" if record["counts"]["unexpected"] else "passed"
        lines.append(f"| {record['seed']} | {counts} | `{digest}` | {status} |")
    counts = " | ".join(str(campaign["counts"][name]) for name in OUTCOMES)
    lines.append(f"| Total | {counts} | | |")
    lines.extend(["", "Full reports and follow-up results are in the per-seed artifact directories."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-seed", type=int, required=True)
    parser.add_argument("--rounds", type=int, choices=range(1, 17), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--php", default=os.environ.get("PHP_BIN", "php"))
    args = parser.parse_args()
    if args.start_seed < 0 or args.start_seed + 2 * args.rounds - 1 > sys.maxsize:
        parser.error("seeds and their follow-up seeds must be nonnegative platform integers")
    args.output.mkdir(parents=True, exist_ok=True)
    revision = os.environ.get("GITHUB_SHA", "local")
    rounds = []
    distinct_inputs = set()
    counts = dict.fromkeys(OUTCOMES, 0)
    failed = 0
    for seed in range(args.start_seed, args.start_seed + 2 * args.rounds, 2):
        record = run_seed(seed, args.output / f"seed-{seed}", args.php, revision)
        digest = record.get("input_sha256")
        if digest is not None:
            if digest in distinct_inputs:
                record["error"] = "Duplicate fingerprint for generated transition inputs."
            distinct_inputs.add(digest)
        for name, count in record.get("counts", {}).items():
            counts[name] += count
        failed += int("error" in record or record["counts"]["unexpected"] > 0)
        rounds.append(record)

    campaign = {"revision": revision, "counts": counts, "failed_rounds": failed,
                "distinct_transition_inputs": len(distinct_inputs), "rounds": rounds}
    (args.output / "campaign.json").write_text(json.dumps(campaign, indent=2) + "\n", encoding="utf-8")
    (args.output / "campaign.md").write_text(markdown(campaign), encoding="utf-8")
    print(f"rounds={len(rounds)} distinct_inputs={len(distinct_inputs)} failed_rounds={failed}")
    return int(failed > 0)


if __name__ == "__main__":
    sys.exit(main())
