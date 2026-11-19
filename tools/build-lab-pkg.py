#!/usr/bin/env python3
"""Cross-package this script-only port for the CE 2.9.1 lab with FreeBSD pkg(8)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/usr/local"
# FreeBSD-ports sets arch and abi to OS:major:* for NO_ARCH ports.
TARGET = "FreeBSD:16:*"
# FreeBSD-src 4bdcff554368, sys/sys/param.h. Confirm on the target before installation.
OSVERSION = "1600018"
EXECUTABLES = {"/usr/local/etc/rc.d/sdwand.sh", "/usr/local/sbin/sdwand.php"}


def build(metadata, pkg, output, epoch):
    name = metadata["PORTNAME"]
    version = metadata["PORTVERSION"]
    original = ROOT / "files"
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        stage = work / "stage"
        meta = work / "meta"
        dest = work / "output"
        meta.mkdir()
        dest.mkdir()
        expected = {}
        plist = ["@owner root", "@group wheel"]
        for entry in (ROOT / "pkg-plist").read_text().splitlines():
            entry = entry.replace("%%DATADIR%%", f"share/{name}")
            if not re.fullmatch(r"/?[A-Za-z0-9_./-]+", entry) or ".." in Path(entry).parts:
                raise ValueError(f"Unrecognized packing-list entry: {entry!r}")
            path = entry if entry.startswith("/") else f"{PREFIX}/{entry}"
            source = original / path.lstrip("/")
            data = source.read_bytes()
            if path == f"{PREFIX}/share/{name}/info.xml":
                data = data.replace(b"%%PKGVERSION%%", version.encode())
            target = stage / path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            mode = 0o755 if path in EXECUTABLES else 0o644
            target.chmod(mode)
            expected[path] = (data, mode)
            plist.extend([f"@mode {mode:o}", path])
        actual = {"/" + str(p.relative_to(original)) for p in original.rglob("*")
                  if p.is_file() and p.parent != original}
        if actual != expected.keys():
            raise ValueError(f"Files tree disagrees with pkg-plist: {actual ^ expected.keys()}")
        (work / "plist").write_text("\n".join(plist) + "\n")
        manifest = dict(name=name, version=version, origin=f"net/{name}",
                        comment=metadata["COMMENT"], maintainer=metadata["MAINTAINER"],
                        www=metadata["WWW"], prefix=PREFIX, categories=["net"],
                        licenselogic="single", arch=TARGET.lower(), abi=TARGET)
        (meta / "+MANIFEST").write_text(json.dumps(manifest))
        (meta / "+DESC").write_bytes((ROOT / "pkg-descr").read_bytes())
        hooks = {}
        for phase in ["install", "deinstall"]:
            script = (original / f"pkg-{phase}.in").read_text().replace("%%PORTNAME%%", name)
            (meta / f"+{phase.upper()}").write_text(script)
            hooks[phase] = script.rstrip("\n")
        cmd = [pkg, "-o", "ABI=FreeBSD:16:amd64", "-o", f"OSVERSION={OSVERSION}"]
        subprocess.run(cmd + ["create", "-f", "txz", "-t", str(epoch), "-m", str(meta),
                              "-p", str(work / "plist"), "-r", str(stage), "-o", str(dest)],
                       check=True)
        files = list(dest.glob("*.pkg"))
        if len(files) != 1:
            raise ValueError(f"Expected one pkg v2 file, got {files}")
        package = files[0]
        subprocess.run(cmd + ["info", "-F", str(package)], check=True)
        with tarfile.open(package, mode="r:xz") as archive:
            built = json.load(archive.extractfile("+MANIFEST"))
            if any(built.get(key) != val for key, val in manifest.items()
                   if key in ("name", "version", "prefix", "origin", "abi")):
                raise ValueError("Manifest identity or ABI changed")
            if built.get("scripts") != hooks:
                raise ValueError("Lifecycle scripts changed")
            if expected.keys() != built.get("files", {}).keys():
                raise ValueError("Packaged file set differs from packing list")
            payload = [m for m in archive.getmembers() if not m.name.startswith("+")]
            if len(payload) != len(expected):
                raise ValueError("Unexpected payload count")
            for member in payload:
                path = "/" + member.name.lstrip("/")
                data, mode = expected[path]
                if (not member.isfile() or archive.extractfile(member).read() != data or
                        (member.mode & 0o7777) != mode or member.uid != 0 or member.gid != 0 or
                        member.uname != "root" or member.gname != "wheel"):
                    raise ValueError(f"Invalid payload, ownership or mode: {path} {member.mode:o} {member.uid} {member.gid} {member.uname} {member.gname}")
        output.mkdir(parents=True, exist_ok=True)
        result = output / package.name
        blob = package.read_bytes()
        result.write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        output.joinpath(result.name + ".sha256").write_text(f"{digest}  {result.name}\n")
        print(f"{result}: {len(expected)} files and both lifecycle hooks verified. SHA-256 {digest}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pkg", default="pkg", help="FreeBSD pkg v2 executable")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fields = dict(re.findall(r"^(PORTNAME|PORTVERSION|MAINTAINER|COMMENT|WWW)=\s*([^\n]+)$",
                             (ROOT / "Makefile").read_text(), flags=re.MULTILINE))
    build(fields, args.pkg, args.output, int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
