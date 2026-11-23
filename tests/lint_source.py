#!/usr/bin/env python3
"""Lint tracked PHP, shell and XML source with compact failure reporting."""

import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
HOOKS = {"files/pkg-install.in", "files/pkg-deinstall.in"}
HISTORICAL = "docs/benchmarks/evidence/ce292-interface-original/native-cycle.sh"


def main():
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    counts = {}
    failures = 0
    for path in (os.fsdecode(raw) for raw in paths if raw):
        if path.startswith("dist/"):
            continue
        if path.startswith(".github/workflows/"):
            for number, line in enumerate((ROOT / path).read_text(encoding="utf-8").splitlines(), 1):
                use = re.match(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)", line)
                if use and not use[1].startswith("./") and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", use[1]):
                    print(f"{path}:{number}: external Actions must use a full commit SHA", file=sys.stderr)
                    failures += 1
        extension = Path(path).suffix
        if extension in (".php", ".inc"):
            commands = [[sys.argv[1], "-l"]]
        elif extension == ".xml":
            commands = [["xmllint", "--noout", "--nonet"]]
        elif extension == ".sh" or path in HOOKS:
            shellcheck = ["shellcheck", "--format=gcc"]
            if path == HISTORICAL:
                # Preserve the exact source used to record the original appliance evidence.
                shellcheck += ["--exclude=SC2009,SC2015,SC2016,SC3013"]
            commands = [["sh", "-n"], shellcheck]
        else:
            continue
        for command in commands:
            tool = Path(command[0]).name
            counts[tool] = counts.get(tool, 0) + 1
            try:
                result = subprocess.run(command + [path], cwd=ROOT, capture_output=True, check=False)
            except FileNotFoundError:
                sys.exit(f"Required lint tool missing: {tool}")
            if result.returncode:
                failures += 1
                output = (result.stdout + result.stderr).decode(errors="replace")
                print(f"{tool}: {path}\n" + "\n".join(output.splitlines()[:10]), file=sys.stderr)
    print("lint: " + ", ".join(f"{tool}={count}" for tool, count in counts.items()) +
          f"; {failures} failures", flush=True)
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
