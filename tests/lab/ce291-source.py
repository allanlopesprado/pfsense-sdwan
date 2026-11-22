#!/usr/bin/env python3
"""Extract only audited generator inputs for the CE policy lab."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

PACKAGE_HASHES = {
    "2.9.1": "c3f3d904d78b050c256da9e4e7702f8a98ced66891fd092236c6db98e2b9073c",
    "2.9.2": "3c45a06b6019aeea28ebe0855d61ad95adc8ec96b4b9fa2d4602d9a3bb9c49c4",
}


def stage(archive, output, ce_version):
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != PACKAGE_HASHES[ce_version]:
            raise SystemExit(f"Expected the audited pfSense-system-{ce_version} archive")
    output.mkdir()
    with tarfile.open(archive, mode="r:*") as package:
        manifest = json.load(package.extractfile("+MANIFEST"))
        if manifest["name"] != "pfSense-system" or manifest["version"] != ce_version:
            raise SystemExit(f"The archive does not identify itself as pfSense-system {ce_version}")
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
    parser.add_argument("--ce-version", choices=PACKAGE_HASHES, default="2.9.1")
    stage(**vars(parser.parse_args()))
