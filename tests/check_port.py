#!/usr/bin/env python3
"""Check installed files, package registration, and dashboard menu references."""
from pathlib import Path
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
    for name in ("status", "slas", "members", "policies", "diagnostics"):
        if not (FILES / PREFIX / "www/sdwan" / (name + ".php")).is_file():
            fail(f"Missing SD-WAN page: {name}")
    service = FILES / PREFIX / "etc/rc.d/sdwand.sh"
    subprocess.run(["sh", "-n", str(service)], check=True)
    print(f"ok - {len(plist)} installed files match pkg-plist; XML, menu and rc syntax passed")


if __name__ == "__main__":
    check_packaging()
