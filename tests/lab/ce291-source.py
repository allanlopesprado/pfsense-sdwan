#!/usr/bin/env python3
"""Extract only audited generator inputs for the CE 2.9.1 policy lab."""
import argparse
import hashlib
from pathlib import Path
import tarfile

PACKAGE_HASH = "c3f3d904d78b050c256da9e4e7702f8a98ced66891fd092236c6db98e2b9073c"


def stage(archive, output):
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != PACKAGE_HASH:
            raise SystemExit("Expected the audited pfSense-system-2.9.1 archive")
    output.mkdir()
    with tarfile.open(archive, mode="r:*") as package:
        for name in ("filter.inc", "globals.inc", "util.inc"):
            matching = [item for item in package.getmembers() if item.name.lstrip("./") == f"etc/inc/{name}"]
            if len(matching) != 1 or not matching[0].isfile():
                raise SystemExit(f"Expected one regular native file for {name}")
            target = output / "src/etc/inc" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.extractfile(matching[0]).read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    stage(**vars(parser.parse_args()))
