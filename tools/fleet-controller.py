#!/usr/bin/env python3
"""Store versioned pilot policies and imported PF evidence on the NOC host."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


def json_file(path, limit=32768):
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Report exceeds the size limit.")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return value


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def store_report(path, report):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".report-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(encode(report))
            handle.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def run(args):
    args.root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.command == "inventory":
        sites = []
        for site in sorted(args.root.iterdir()):
            if site.is_symlink() or not site.is_dir() or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", site.name):
                continue
            report = site / "report.json"
            sites.append({"site": site.name, "report": json_file(report) if report.is_file() else None})
        return sites

    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", args.site):
        raise ValueError("Invalid site identifier.")
    site = args.root / args.site
    if args.command == "enroll":
        site.mkdir(mode=0o700)
        return {"site": args.site}
    if site.is_symlink() or not site.is_dir():
        raise ValueError("Enroll this site before recording evidence or publishing.")

    if args.command == "report":
        report = json_file(args.path)
        if (report.get("schema") != 1 or report.get("site") != args.site or
                type(report.get("observed_at")) is not int or type(report.get("revision")) is not int or
                not isinstance(report.get("paths"), list) or not isinstance(report.get("config_sha256"), str) or
                not re.fullmatch(r"[a-f0-9]{64}", report["config_sha256"])):
            raise ValueError("Invalid or mismatched appliance report.")
        previous = site / "report.json"
        if previous.is_file() and json_file(previous)["observed_at"] > report["observed_at"]:
            raise ValueError("A more recent report is already recorded.")
        store_report(previous, report)
        return {"site": args.site, "report": str(previous)}

    if (not 1 <= args.revision <= 2147483647 or
            not re.fullmatch(r"[a-f0-9]{64}", args.expected_config) or
            any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", name) for name in (args.policy, args.sla))):
        raise ValueError("Invalid policy, SLA, revision or configuration fingerprint.")
    path = site / f"revision-{args.revision}.json"
    payload = encode({"schema": 1, "site": args.site, "revision": args.revision,
                      "expected_config": args.expected_config, "policy": args.policy,
                      "sla": args.sla, "strategy": args.strategy})
    with path.open("xb") as output:
        output.write(payload)
    return {"site": args.site, "path": str(path), "sha256": hashlib.sha256(payload).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inventory")
    commands.add_parser("enroll").add_argument("site")
    report = commands.add_parser("report")
    report.add_argument("site")
    report.add_argument("path", type=Path)
    publish = commands.add_parser("publish")
    publish.add_argument("site")
    publish.add_argument("revision", type=int)
    publish.add_argument("expected_config")
    publish.add_argument("policy")
    publish.add_argument("sla")
    publish.add_argument("strategy", choices=("cost", "latency", "balance"))
    try:
        os.umask(0o077)
        print(encode(run(parser.parse_args())).decode(), end="")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
