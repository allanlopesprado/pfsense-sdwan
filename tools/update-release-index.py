#!/usr/bin/env python3
"""Generate or verify the small GitHub release index against the packaged artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
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
    release = {
        "schema": 1,
        "channel": "main",
        "maturity": "experimental",
        "package": PACKAGE,
        "version": version,
        "sha256": digest,
    }
    return json.dumps(release, indent=2) + "\n"


def readme_with_installer(release, artifact_commit):
    if not re.fullmatch(r"[a-f0-9]{40}", artifact_commit):
        raise SystemExit("Expected the full Git commit containing the package")
    filename = f"{PACKAGE}-{release['version']}.pkg"
    artifact = f"dist/{filename}"

    def git_output(*arguments):
        process = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, text=True)
        if process.returncode:
            raise SystemExit(f"Cannot verify Git artifact {artifact} at {artifact_commit}")
        return process.stdout.strip()

    if git_output("cat-file", "-t", artifact_commit) != "commit":
        raise SystemExit("The installer must pin a Git commit")
    committed = git_output("rev-parse", "--verify", f"{artifact_commit}:{artifact}")
    if committed != git_output("hash-object", "--no-filters", artifact):
        raise SystemExit("The pinned Git commit contains different package bytes")
    url = f"https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/{artifact_commit}/{artifact}"
    command = (
        "d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && "
        f"(trap 'rm -rf \"$d\"' EXIT; p=\"$d/{filename}\"; "
        f"fetch -o \"$p\" '{url}' && sha256 -c {release['sha256']} \"$p\" && pkg add \"$p\")"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    marker = "<!-- install-command -->\n```sh\n"
    content, count = re.subn(
        re.escape(marker) + r".*?\n```", lambda _: marker + command + "\n```", readme, flags=re.S
    )
    if count != 1:
        raise SystemExit("Expected exactly one marked README install command")
    return content


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify without writing")
    mode.add_argument("--artifact-commit", help="also refresh the README installer using this committed package")
    args = parser.parse_args()
    index = ROOT / "dist/release.json"
    expected = index_contents()
    if args.check:
        if not index.is_file() or index.read_text() != expected:
            raise SystemExit("GitHub release index differs from the distributed package")
        print("ok - GitHub release index, artifact and checksum agree")
    else:
        readme = readme_with_installer(json.loads(expected), args.artifact_commit) if args.artifact_commit else None
        index.write_text(expected, encoding="utf-8", newline="\n")
        if readme is not None:
            (ROOT / "README.md").write_text(readme, encoding="utf-8", newline="\n")
