#!/usr/bin/env python3
"""Generate or verify the small GitHub release index against the packaged artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "pfSense-pkg-SDWAN"


def index_contents():
    makefile = (ROOT / "Makefile").read_text()
    version = re.search(r"^PORTVERSION=\s*(\S+)$", makefile, re.MULTILINE)[1]
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}", version):
        raise SystemExit("Unsupported release version")
    artifact = ROOT / "dist" / f"{PACKAGE}-{version}.pkg"
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if artifact.with_suffix(".pkg.sha256").read_text().split() != [digest, artifact.name]:
        raise SystemExit("Checksum file and artifact differ")
    with tarfile.open(artifact, "r:*") as archive:
        manifest = json.load(archive.extractfile("+MANIFEST"))
    if manifest["name"] != PACKAGE or manifest["version"] != version:
        raise SystemExit("Package identity differs from the release version")
    return json.dumps({"schema": 1, "channel": "lab", "package": PACKAGE, "version": version, "sha256": digest}, indent=2) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()
    index = ROOT / "dist/release.json"
    expected = index_contents()
    if args.check:
        if not index.is_file() or index.read_text() != expected:
            raise SystemExit("GitHub release index differs from the distributed package")
        print("ok - GitHub release index, artifact and checksum agree")
    else:
        index.write_text(expected)
