"""Run the offline divergence audit and retain the expected and observed values."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
DRIVERS = ("forwarding.php", "decision.php", "dynamic-route.php", "transitions.php", "lifecycle.py", "webui.py")
ID = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+")


def read_cases(driver, environment, php):
    path = ROOT / "tests" / "audit" / driver
    command = [php, str(path)] if path.suffix == ".php" else [sys.executable, "-B", str(path)]
    completed = subprocess.run(
        command, cwd=ROOT, env=environment, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30, check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(f"exit {completed.returncode}\n{detail[-1600:]}")
    cases = json.loads(completed.stdout)
    if not isinstance(cases, list) or not cases:
        raise ValueError("The driver must return a nonempty array of observations.")
    for case in cases:
        if (not isinstance(case, dict) or not isinstance(case.get("id"), str) or
                not ID.fullmatch(case["id"]) or "expected" not in case or "observed" not in case):
            raise ValueError("The driver returned an invalid observation.")
        for field in ("expected", "observed", "known_observed"):
            if field in case and not isinstance(case[field], (str, int, float, bool, type(None))):
                raise ValueError(f"{case['id']} has a non-scalar {field}.")
    return cases


def same(expected, observed):
    return type(expected) is type(observed) and expected == observed


def outcome(case):
    if same(case["expected"], case["observed"]):
        return "resolved" if "known_observed" in case else "passed"
    if "known_observed" in case and same(case["known_observed"], case["observed"]):
        return "known"
    return "unexpected"


def summary(report):
    counts = report["counts"]
    lines = [
        "# SD-WAN divergence audit",
        "",
        f"Seed `{report['seed']}` · Revision `{report['revision']}`",
        "",
        f"{counts['passed']} passed, {counts['known']} known discrepancies, "
        f"{counts['resolved']} resolved, {counts['unexpected']} unexpected.",
        "",
        "| Case | Expected | Observed | Result |",
        "| --- | --- | --- | --- |",
    ]
    for case in report["cases"]:
        values = [json.dumps(case[field], ensure_ascii=True).replace("|", "\\|").replace("`", "'")
                  for field in ("expected", "observed")]
        lines.append(f"| `{case['id']}` | `{values[0]}` | `{values[1]}` | {case['outcome']} |")
    if "follow_up" in report:
        follow_up = report["follow_up"]
        lines += [
            "",
            f"The follow-up used seed `{follow_up['seed']}` and had "
            f"{follow_up['counts']['unexpected']} unexpected results.",
            "Find the second report in the artifact's `follow-up/` directory.",
        ]
    return "\n".join(lines) + "\n"


def audit(php, seed):
    environment = dict(os.environ, PHP_BIN=php, SDWAN_AUDIT_SEED=str(seed))
    results = []
    seen = set()
    for driver in DRIVERS:
        try:
            cases = read_cases(driver, environment, php)
            identifiers = {case["id"] for case in cases}
            if len(identifiers) != len(cases) or identifiers & seen:
                raise ValueError("Duplicate observation identifiers.")
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            results.append({
                "id": f"{Path(driver).stem}.driver",
                "expected": "completed",
                "observed": "failed",
                "outcome": "unexpected",
                "detail": str(error),
            })
            continue
        seen.update(identifiers)
        results.extend({**case, "outcome": outcome(case)} for case in cases)

    occurrences = Counter(case["outcome"] for case in results)
    counts = {name: occurrences[name] for name in ("passed", "known", "resolved", "unexpected")}
    return {"seed": seed, "revision": os.environ.get("GITHUB_SHA", "local"), "counts": counts, "cases": results}


def save_report(report, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / "audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "audit.md").write_text(summary(report), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--php", default=os.environ.get("PHP_BIN", "php"))
    parser.add_argument("--seed", type=int, default=172831)
    args = parser.parse_args()
    report = audit(args.php, args.seed)
    failed = report["counts"]["unexpected"] > 0
    save_report(report, args.output)
    if failed:
        follow_up = audit(args.php, args.seed + 1)
        save_report(follow_up, args.output / "follow-up")
        report["follow_up"] = {key: follow_up[key] for key in ("seed", "counts")}
        save_report(report, args.output)
    print(" ".join(f"{name}={count}" for name, count in report["counts"].items()))
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
