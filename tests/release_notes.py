#!/usr/bin/env python3
"""Check release precedence and a release body built from the current package metadata."""
import json
from pathlib import Path
import re
import runpy

root = Path(__file__).resolve().parents[1]
helpers = runpy.run_path(str(root / "tools/render_release_notes.py"))
previous = helpers["previous_release"]
render = helpers["render_release"]

assert previous("0.4.13", ["v0.4.9", "v0.4.12", "legacy", "v0.5.0-rc.1"]) == "v0.4.12"
assert previous("0.10.0", ["v0.9.9", "v0.4.13"]) == "v0.9.9"
assert previous("0.1.0", []) is None
for invalid, published in [("0.4.9", ["v0.4.13"]), ("0.4.13", ["v0.4.13"]), ("0.04.13", [])]:
    try:
        previous(invalid, published)
    except ValueError:
        pass
    else:
        raise AssertionError(f"Accepted invalid release {invalid}")

index = json.loads((root / "dist/release.json").read_text(encoding="utf-8"))
tag = f"v{index['version']}"
changes = (root / "docs/releases" / f"{tag}.md").read_text(encoding="utf-8")
body = render(index, changes, "allanlopesprado/pfsense-sdwan", ["v0.1.0"], 42)
assert changes.strip() in body and f"v0.1.0...{tag}" in body
assert f"releases/download/{tag}/pfSense-pkg-SDWAN-{index['version']}.pkg.sha256" in body
assert f"releases/download/{tag}/widget-dark-554.png" in body and "/actions/runs/42" in body
assert "## Install or upgrade" in body and "## Validation" in body
install_anchor = "install-from-diagnostics--command-prompt"
assert f"blob/{tag}/README.md#{install_anchor}" in body
readme = (root / "README.md").read_text(encoding="utf-8")
heading = next(line for line in readme.splitlines() if line.startswith("## Install from "))
assert re.sub(r"[^a-z0-9 -]", "", heading.casefold()).strip().replace(" ", "-") == install_anchor

history = (root / "CHANGELOG.md").read_text(encoding="utf-8")
versions = re.findall(r"^\| (\d+\.\d+\.\d+) \|", history, re.M)
packages = [path.stem.removeprefix("pfSense-pkg-SDWAN-") for path in (root / "dist").glob("pfSense-pkg-SDWAN-*.pkg")]
assert versions == sorted(set(packages), key=lambda version: tuple(map(int, version.split("."))), reverse=True)
print("ok - numeric version ordering, downgrade refusal, version links and complete changelog")
