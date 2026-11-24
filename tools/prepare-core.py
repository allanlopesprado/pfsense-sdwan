#!/usr/bin/env python3
"""Prepare an isolated pair of source files for a pfSense laboratory build."""
import argparse
import hashlib
import json
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
    release.add_argument("--bundle-for", choices=("2.9.1", "2.9.2"),
                         help="Include a rollback copy and a manifest for this signed CE release")
    parser.set_defaults(fingerprint=BASE_HASH)
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.out.resolve()
    if out.exists() or source == out or source in out.parents:
        parser.error("Use a new output directory outside the source checkout.")
    original = source / FILTER
    stock = original.read_bytes() if original.is_file() else b""
    fingerprint = CE_292_LAB_HASH if args.bundle_for else args.fingerprint
    if hashlib.sha256(stock).hexdigest() != fingerprint:
        parser.error("This filter.inc differs from the audited upstream input. Review this base before porting.")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as work:
        overlay = Path(work) / "overlay"
        dest = overlay / FILTER
        dest.parent.mkdir(parents=True)
        dest.write_bytes(stock)
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
                b"filter_sdwan_read_persisted_bindings()" not in patched or
                (b"filter_sdwan_publish_withdrawal_proof($reload_filter_result, "
                 b"$PFConfig->sdwan_withdrawal_ruleset_hash(), true);") not in patched or
                b"if (!filter_sdwan_native_fallback_allowed())" not in patched or
                b"if (!filter_sdwan_precommit($PFConfig->sdwan_withdrawal_ruleset_hash()))" not in patched):
            raise RuntimeError("git did not produce the expected native approval and gateway hooks")
        adapter = dest.with_name("filter-sdwan.inc")
        shutil.copyfile(HERE / adapter.name, adapter)
        if args.bundle_for:
            rollback = overlay / "rollback" / FILTER.name
            rollback.parent.mkdir()
            rollback.write_bytes(stock)
            manifest = dict(schema=1, ce_version=args.bundle_for + "-RELEASE", abi="FreeBSD:16:amd64",
                            stock_sha256=fingerprint, generator_sha256=hashlib.sha256(patched).hexdigest(),
                            adapter_sha256=hashlib.sha256(adapter.read_bytes()).hexdigest())
            (overlay / "sdwan-overlay.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        overlay.rename(out)
    print(f"Prepared {out / FILTER} and its filter-sdwan.inc dependency.")
    if args.bundle_for:
        print(f"Included the CE {args.bundle_for} preflight manifest and audited stock rollback copy.")


if __name__ == "__main__":
    main()
