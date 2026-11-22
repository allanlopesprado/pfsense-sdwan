#!/usr/bin/env python3
"""Check installed files, package registration, and dashboard menu references."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import subprocess
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "files"
PREFIX = PurePosixPath("usr/local")
DATA = PREFIX / "share/pfSense-pkg-SDWAN"


def fail(message):
    raise SystemExit(message)


def read_plist():
    entries = set()
    for raw in (ROOT / "pkg-plist").read_text().splitlines():
        entry = raw.strip()
        if not entry or entry.startswith(("@", "#")):
            continue
        entry = entry.replace("%%DATADIR%%", "share/pfSense-pkg-SDWAN")
        path = PurePosixPath(entry)
        installed = path.relative_to("/") if path.is_absolute() else PREFIX / path
        if installed in entries:
            fail(f"Duplicate plist entry: {entry}")
        entries.add(installed)
    return entries


def check_distributed_package(installed, archive_parity):
    version = re.search(r"^PORTVERSION=\s*(\S+)$", (ROOT / "Makefile").read_text(), re.M)[1]
    versions = {
        tuple(map(int, match.groups())) for artifact in (ROOT / "dist").glob("*.pkg")
        if (match := re.fullmatch(r"pfSense-pkg-SDWAN-(\d+)\.(\d+)\.(\d+)\.pkg", artifact.name))
    }
    latest_changelog = re.search(r"^\| (\d+\.\d+\.\d+) \|", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    if not versions or tuple(map(int, version.split("."))) != max(versions) or (
            not latest_changelog or latest_changelog[1] != version):
        fail("Makefile, latest distributed package and changelog versions differ")
    path = ROOT / "dist" / f"pfSense-pkg-SDWAN-{version}.pkg"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    checksum = path.with_suffix(".pkg.sha256").read_text().split()
    if checksum != [digest, path.name]:
        fail("Release artifact digest or filename differs from published checksum")
    installer = (ROOT / "README.md").read_text(encoding="utf-8").split("<!-- install-command -->", 1)[1].split("```")[1]
    pin = re.search(r"https://raw\.githubusercontent\.com/allanlopesprado/pfsense-sdwan/([a-f0-9]{40})/dist/"
                    + re.escape(path.name) + "'", installer)
    if f"sha256 -c {digest} " not in installer or not pin:
        fail("The documented download must pin a commit, the current file and its digest")
    commit = subprocess.run(["git", "cat-file", "blob", f"{pin[1]}:dist/{path.name}"], cwd=ROOT,
                            capture_output=True, check=False)
    if commit.returncode or hashlib.sha256(commit.stdout).hexdigest() != digest:
        fail("The README pin does not contain the distributed package bytes; use a full Git checkout")
    with tarfile.open(path, "r:xz") as archive:
        manifest = json.load(archive.extractfile("+MANIFEST"))
        if (manifest["version"], manifest["name"]) != (version, "pfSense-pkg-SDWAN") or manifest.get("abi") not in (
                "FreeBSD:16:amd64", "FreeBSD:16:*"):
            fail("Incorrect package identity or ABI")
        contents = [m.name for m in archive.getmembers() if not m.name.startswith("+")]
        packaged_info = ET.parse(archive.extractfile("/" + str(DATA / "info.xml")))
        if sorted(contents) != sorted(manifest["files"]) or packaged_info.findtext(".//version") != version:
            fail("Distributed package manifest, archive contents and info.xml disagree")
        if not archive_parity:
            print("ok - version, package ABI, README commit and SHA-256 verified")
            return
        if sorted(contents) != sorted("/" + str(p) for p in installed):
            fail("Distributed package file list differs from current source")
        for name in contents:
            expected = (FILES / name.lstrip("/")).read_bytes()
            if name in ("/usr/local/share/pfSense-pkg-SDWAN/info.xml", "/usr/local/sbin/sdwand.php"):
                expected = expected.replace(b"%%PKGVERSION%%", version.encode())
            if archive.extractfile(name).read() != expected:
                fail("Distributed package contains stale source: " + name)
        for phase in ("install", "deinstall"):
            script = (FILES / f"pkg-{phase}.in").read_text().replace("%%PORTNAME%%", manifest["name"])
            if manifest["scripts"].get(phase) != script.rstrip("\n"):
                fail("Distributed package contains a stale lifecycle script: " + phase)
    print("ok - pinned README command, checksum, package, hooks and source agree")


def check_packaging(archive_parity=False):
    plist = read_plist()
    installed = {
        PurePosixPath(path.relative_to(FILES).as_posix())
        for path in FILES.rglob("*")
        if path.is_file() and path.relative_to(FILES).as_posix() not in ("pkg-install.in", "pkg-deinstall.in")
    }
    for path in installed:
        if path.is_relative_to("etc/inc") and path != PurePosixPath("etc/inc/priv/sdwan.priv.inc"):
            fail(f"A pfSense core integration cannot be installed by the package: {path}")
    if plist != installed:
        fail(f"Missing from plist: {sorted(installed - plist)}\n"
             f"Missing source files: {sorted(plist - installed)}")
    manifest = ET.parse(FILES / DATA / "info.xml")
    if manifest.findtext(".//version") != "%%PKGVERSION%%":
        fail("The source info.xml must use the build's package version")
    filename = manifest.findtext(".//configurationfile") or manifest.findtext(".//config_file")
    if not filename:
        fail("No package configuration XML registered in info.xml")
    xml = ET.parse(FILES / PREFIX / "pkg" / Path(filename).name)
    urls = [(item.text or "").strip() for item in xml.findall(".//menu/url")]
    if "/sdwan/status.php" not in ["/" + url.lstrip("/") for url in urls]:
        fail(f"SD-WAN status menu is missing: {urls}")
    for url in urls:
        page = url.split("?")[0].lstrip("/")
        if not (FILES / PREFIX / "www" / page).is_file():
            fail(f"Missing GUI for registered menu entry: {url}")
    tabs = (FILES / PREFIX / "www/sdwan/ui.inc.php").read_text(encoding="utf-8")
    for name in ("status", "slas", "members", "policies", "diagnostics", "updates", "forwarding"):
        if not re.search(r"^\s*'" + name + r"'\s*=>\s*gettext\(", tabs, re.MULTILINE):
            fail(f"Missing SD-WAN tab: {name}")
        if not (FILES / PREFIX / "www/sdwan" / (name + ".php")).is_file():
            fail(f"Missing SD-WAN page: {name}")
    check_distributed_package(installed, archive_parity)
    print(f"ok - {len(plist)} installed files match pkg-plist and GUI registration")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--source-only", action="store_true",
                      help="deprecated alias for the default source and release-index checks")
    mode.add_argument("--archive-parity", action="store_true",
                      help="also require the published payload and hooks to match current source")
    check_packaging(archive_parity=parser.parse_args().archive_parity)
