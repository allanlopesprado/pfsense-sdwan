#!/usr/bin/env python3
"""Check installed files, package registration, and dashboard menu references."""
import hashlib
import json
from pathlib import Path
import re
import tarfile
import subprocess
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "files"
PREFIX = Path("usr/local")
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
        path = Path(entry)
        installed = path.relative_to("/") if path.is_absolute() else PREFIX / path
        if installed in entries:
            fail(f"Duplicate plist entry: {entry}")
        entries.add(installed)
    return entries


def check_distributed_package(installed):
    version = re.search(r"^PORTVERSION=\s*(\S+)$", (ROOT / "Makefile").read_text(), re.M)[1]
    path = ROOT / "dist" / f"pfSense-pkg-SDWAN-{version}.pkg"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    checksum = path.with_suffix(".pkg.sha256").read_text().split()
    if checksum != [digest, path.name]:
        fail("Release artifact digest or filename differs from published checksum")
    installer = (ROOT / "README.md").read_text().split("<!-- install-command -->", 1)[1].split("```")[1]
    if f"sha256 -c {digest} " not in installer or not re.search(
            r"https://raw\.githubusercontent\.com/allanlopesprado/pfsense-sdwan/[a-f0-9]{40}/dist/"
            + re.escape(path.name) + "'", installer):
        fail("The documented download must pin a commit, the current file and its digest")
    with tarfile.open(path, "r:xz") as archive:
        manifest = json.load(archive.extractfile("+MANIFEST"))
        if manifest["version"] != version or manifest["name"] != "pfSense-pkg-SDWAN":
            fail("Incorrect package identity")
        contents = [m.name for m in archive.getmembers() if not m.name.startswith("+")]
        if sorted(contents) != sorted("/" + str(p) for p in installed):
            fail("Distributed package file list differs from port")
        for name in contents:
            expected = (FILES / name.lstrip("/")).read_bytes()
            if name.endswith("/share/pfSense-pkg-SDWAN/info.xml"):
                expected = expected.replace(b"%%PKGVERSION%%", version.encode())
            if archive.extractfile(name).read() != expected:
                fail("Distributed package contains stale source: " + name)
        for phase in ("install", "deinstall"):
            script = (FILES / f"pkg-{phase}.in").read_text().replace("%%PORTNAME%%", manifest["name"])
            if manifest["scripts"].get(phase) != script.rstrip("\n"):
                fail("Distributed package contains a stale lifecycle script: " + phase)
    print("ok - pinned README command, checksum, package, hooks and source agree")


def check_packaging():
    plist = read_plist()
    installed = {
        path.relative_to(FILES)
        for top in (FILES / "etc", FILES / "usr")
        for path in top.rglob("*")
        if path.is_file()
    }
    if plist != installed:
        fail(f"Missing from plist: {sorted(installed - plist)}\n"
             f"Missing source files: {sorted(plist - installed)}")
    check_distributed_package(installed)
    manifest = ET.parse(FILES / DATA / "info.xml")
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
    tabs = (FILES / PREFIX / "www/sdwan/ui.inc.php").read_text()
    for name in ("status", "slas", "members", "policies", "diagnostics", "updates"):
        if not re.search(r"^\s*'" + name + r"'\s*=>\s*gettext\(", tabs, re.MULTILINE):
            fail(f"Missing SD-WAN tab: {name}")
        if not (FILES / PREFIX / "www/sdwan" / (name + ".php")).is_file():
            fail(f"Missing SD-WAN page: {name}")
    service = FILES / PREFIX / "etc/rc.d/sdwand.sh"
    subprocess.run(["sh", "-n", str(service)], check=True)
    print(f"ok - {len(plist)} installed files match pkg-plist; XML, menu and rc syntax passed")


if __name__ == "__main__":
    check_packaging()
