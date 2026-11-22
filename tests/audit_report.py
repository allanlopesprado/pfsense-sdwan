"""Check follow-up execution and keep the original unexpected result visible."""

import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from audit import run


def case_for_seed(driver, environment, php):
    seed = int(environment["SDWAN_AUDIT_SEED"])
    observed = {9: "new mismatch", 10: "correct", 42: "known mismatch"}[seed]
    row = {"id": "fixture.transition", "expected": "correct", "observed": observed}
    if seed == 42:
        row["known_observed"] = "known mismatch"
    return [row]


with tempfile.TemporaryDirectory(prefix="sdwan-audit-report-") as temporary:
    root = Path(temporary)
    with patch.object(run, "DRIVERS", ("fixture.php",)), patch.object(run, "read_cases", case_for_seed):
        unexpected = root / "unexpected"
        with patch.object(sys, "argv", ["run.py", "--seed", "9", "--output", str(unexpected)]):
            assert run.main() == 1
        first = json.loads((unexpected / "audit.json").read_text(encoding="utf-8"))
        follow_up = json.loads((unexpected / "follow-up/audit.json").read_text(encoding="utf-8"))
        assert first["counts"]["unexpected"] == 1
        assert first["follow_up"]["seed"] == follow_up["seed"] == 10
        assert follow_up["counts"]["passed"] == 1
        assert "follow-up" in (unexpected / "audit.md").read_text(encoding="utf-8")

        known = root / "known"
        with patch.object(sys, "argv", ["run.py", "--seed", "42", "--output", str(known)]):
            assert run.main() == 0
        original = json.loads((known / "audit.json").read_text(encoding="utf-8"))
        assert original["counts"]["known"] == 1
        assert not (known / "follow-up").exists()

print("ok - unexpected results get a separate follow-up and retain the original failure")
