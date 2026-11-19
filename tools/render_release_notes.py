#!/usr/bin/env python3
"""Render release notes and refuse to publish an older or reused package version."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VERSION = r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})"


def previous_release(version, tags):
    match = re.fullmatch(VERSION, version)
    if not match:
        raise ValueError(f"Invalid package version: {version}")
    current = tuple(map(int, match.groups()))
    published = []
    for tag in tags:
        match = re.fullmatch("v" + VERSION, tag.strip())
        if match:
            published.append(tuple(map(int, match.groups())))
    if not published:
        return None
    highest = max(published)
    if current <= highest:
        highest_version = ".".join(map(str, highest))
        raise ValueError(f"v{version} must be newer than published v{highest_version}")
    return "v" + ".".join(map(str, highest))


def render_release(index, changes, repository, tags, run_id=None):
    version = index["version"]
    previous = previous_release(version, tags)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected GitHub repository in owner/name format")
    maturity = index["maturity"]
    if maturity not in ("experimental", "stable") or index["package"] != "pfSense-pkg-SDWAN" or not re.fullmatch(r"[a-f0-9]{64}", index["sha256"]):
        raise ValueError("Invalid version index for release notes")
    if not changes.strip():
        raise ValueError("Release notes are empty")

    tag = f"v{version}"
    repo_url = f"https://github.com/{repository}"
    assets = f"{repo_url}/releases/download/{tag}"
    package = f"{index['package']}-{version}.pkg"
    install = f"{repo_url}/blob/{tag}/README.md#install-from-diagnostics--command-prompt"
    evidence = [
        f"[GitHub Actions]({repo_url}/actions/runs/{run_id})" if run_id else
        f"[GitHub Actions]({repo_url}/actions/workflows/checks.yml)",
        f"[SHA-256]({assets}/{package}.sha256)",
    ]
    if previous:
        evidence.append(f"[Compare {previous} with {tag}]({repo_url}/compare/{previous}...{tag})")

    return "\n".join([
        f"{maturity.capitalize()} package for **pfSense CE 2.9.1** on amd64.",
        "",
        "## What changed",
        "",
        changes.strip(),
        "",
        "## Install or upgrade",
        "",
        f"[Download {package}]({assets}/{package}) · [Installation instructions]({install})",
        "",
        "To upgrade from the WebGUI, open **Services → SD-WAN → Updates**, click **Check GitHub**, and select **Upgrade to …**.",
        "",
        "## Screenshots",
        "",
        f"[Light dashboard]({assets}/widget-light-554.png) · [Dark dashboard]({assets}/widget-dark-554.png) · "
        f"[Status]({assets}/status-pfSense.png) · [Updates]({assets}/updates-pfSense.png)",
        "",
        "## Validation",
        "",
        " · ".join(evidence),
        "",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--published-tags", type=Path, required=True, help="One published GitHub release tag per line")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    index = json.loads((ROOT / "dist/release.json").read_text(encoding="utf-8"))
    if not re.fullmatch(VERSION, index["version"]):
        parser.error("Invalid package version in dist/release.json")
    source = ROOT / "docs/releases" / f"v{index['version']}.md"
    try:
        tags = args.published_tags.read_text(encoding="utf-8-sig").splitlines()
        notes = render_release(index, source.read_text(encoding="utf-8"), args.repository, tags, args.run_id)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Cannot prepare the release: {error}\n")
    args.output.write_text(notes, encoding="utf-8")


if __name__ == "__main__":
    main()
