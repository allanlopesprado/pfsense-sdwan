#!/usr/bin/env python3
"""Prepare an isolated pair of source files for a pfSense laboratory build."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE_HASH = "4d0e6bb6b8d21ee614f61f4905fc6e6a22c2cba6937629349cb606bf62e6bc89"
CE_291_LAB_HASH = "6acd8621e4f88660759c5656488d81f580b49f4c9848b19048ae6a2570e177b4"
CE_292_LAB_HASH = "70758089d12a271ff08ccf3e20a180d3f441f8d468e984be6b1476c366c66c30"
FILTER = Path("src/etc/inc/filter.inc")
HERE = Path(__file__).resolve().parents[1] / "core"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Unmodified upstream source checkout")
    parser.add_argument("--out", type=Path, required=True, help="New directory for the two build inputs")
    release = parser.add_mutually_exclusive_group()
    release.add_argument("--ce-291-lab", dest="fingerprint", action="store_const", const=CE_291_LAB_HASH,
                         help="Use the explicitly fingerprinted CE 2.9.1 laboratory input")
    release.add_argument("--ce-292-lab", dest="fingerprint", action="store_const", const=CE_292_LAB_HASH,
                         help="Use the explicitly fingerprinted CE 2.9.2 laboratory input")
    parser.set_defaults(fingerprint=BASE_HASH)
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.out.resolve()
    if out.exists() or source == out or source in out.parents:
        parser.error("Use a new output directory outside the source checkout.")
    original = source / FILTER
    if not original.is_file() or hashlib.sha256(original.read_bytes()).hexdigest() != args.fingerprint:
        parser.error("This filter.inc differs from the audited upstream input. Review this base before porting.")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as work:
        overlay = Path(work) / "overlay"
        dest = overlay / FILTER
        dest.parent.mkdir(parents=True)
        shutil.copyfile(original, dest)
        diff = Path(work) / "filter-sdwan.patch"
        diff.write_bytes((HERE / diff.name).read_bytes().replace(b"\r\n", b"\n"))
        # Run outside a git worktree even when the requested output is inside one.
        # git apply otherwise limits paths to the current repository subdirectory.
        options = dict(cwd=overlay, check=True, env={**os.environ, "GIT_CEILING_DIRECTORIES": str(overlay.parent)})
        subprocess.run(["git", "apply", "--check", str(diff)], **options)
        subprocess.run(["git", "apply", str(diff)], **options)
        patched = dest.read_bytes()
        if (b"filter_sdwan_begin_reload($sdwan_persisted);" not in patched or
                b"filter_generate_gateways($sdwan_persisted);" not in patched or
                b"filter_sdwan_read_persisted_bindings()" not in patched):
            raise RuntimeError("git did not produce the expected native approval and gateway hooks")
        shutil.copyfile(HERE / "filter-sdwan.inc", dest.with_name("filter-sdwan.inc"))
        overlay.rename(out)
    print(f"Prepared {out / FILTER} and its filter-sdwan.inc dependency.")


if __name__ == "__main__":
    main()
