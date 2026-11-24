"""Verify enrollment, immutable policy artifacts, and recorded site reports."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


controller = Path(__file__).resolve().parents[1] / "tools/fleet-controller.py"
with tempfile.TemporaryDirectory(prefix="sdwan-controller-") as work:
    store = Path(work) / "sites"

    def command(*arguments, fails=False):
        output = subprocess.run([sys.executable, controller, store, *arguments],
                                capture_output=True, text=True, check=False)
        assert (output.returncode != 0) == fails, output.stderr
        return None if fails else json.loads(output.stdout)

    command("enroll", "../not-a-site", fails=True)
    command("enroll", "pilot")
    command("enroll", "pilot", fails=True)
    assert command("inventory") == [{"site": "pilot", "report": None}]
    revision = "8" * 64
    policy = command("publish", "pilot", "1", revision, "ERP", "lab", "balance")
    payload = Path(policy["path"]).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == policy["sha256"]
    assert json.loads(payload)["expected_config"] == revision
    command("publish", "pilot", "1", revision, "ERP", "lab", "cost", fails=True)
    assert Path(policy["path"]).read_bytes() == payload

    report = Path(work) / "report.json"
    evidence = {"schema": 1, "site": "pilot", "revision": 1, "observed_at": 100,
                "config_sha256": revision, "pfSense": "2.9.2-RELEASE", "package": "0.4.29",
                "paths": [{"policy": "ERP", "pf": "applied", "gateways": ["GW_A", "GW_B"]}]}
    report.write_text(json.dumps(evidence), encoding="utf-8")
    command("report", "pilot", report)
    assert command("inventory") == [{"site": "pilot", "report": evidence}]
    report.write_text(json.dumps({**evidence, "observed_at": 99}), encoding="utf-8")
    command("report", "pilot", report, fails=True)
    report.write_text(json.dumps({**evidence, "site": "elsewhere"}), encoding="utf-8")
    command("report", "pilot", report, fails=True)
    assert command("inventory") == [{"site": "pilot", "report": evidence}]
print("ok - fleet enrollment, immutable revisions, and site-report inventory")
