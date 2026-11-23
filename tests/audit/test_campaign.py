"""Verify campaign evidence when rounds pass, fail, or repeat their inputs."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import campaign


class CampaignTest(unittest.TestCase):
    def run_campaign(self, fail=None, repeat=None, missing=None):
        launched = []

        def run(command, **kwargs):
            seed = int(command[command.index("--seed") + 1])
            launched.append(seed)
            output = Path(command[command.index("--output") + 1])
            if seed == missing:
                return subprocess.CompletedProcess(command, 2, stderr=b"audit did not complete")
            unexpected = int(seed == fail)
            counts = {"passed": 5 - unexpected, "known": 1, "resolved": 0, "unexpected": unexpected}
            digest = f"{(seed - 2 if seed == repeat else seed):064x}"
            report = {"seed": seed, "revision": "test-sha", "counts": counts,
                      "processes": [{"driver": "transitions.php", "input_sha256": digest}]}
            if unexpected:
                report["follow_up"] = {"seed": seed + 1, "counts": dict(counts, unexpected=0)}
            (output / "audit.json").write_text(json.dumps(report), encoding="utf-8")
            return subprocess.CompletedProcess(command, unexpected, stderr=b"")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            argv = ["campaign.py", "--start-seed", "10", "--rounds", "3", "--output", temporary]
            with (patch.object(campaign.subprocess, "run", run), patch.object(sys, "argv", argv),
                  patch.dict(os.environ, GITHUB_SHA="test-sha")):
                exit_code = campaign.main()
            report = json.loads((output / "campaign.json").read_text(encoding="utf-8"))
            summary = (output / "campaign.md").read_text(encoding="utf-8")
            self.assertEqual(launched, [10, 12, 14])
            self.assertEqual([r["seed"] for r in report["rounds"]], launched)
            self.assertTrue((output / "seed-14" / "audit.json").is_file())
            self.assertIn("| Total |", summary)
            return exit_code, report

    def test_each_passing_seed_keeps_distinct_inputs_and_counts(self):
        exit_code, report = self.run_campaign()
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["distinct_transition_inputs"], 3)
        self.assertEqual(report["counts"], {"passed": 15, "known": 3, "resolved": 0, "unexpected": 0})

    def test_a_passing_follow_up_does_not_hide_the_original_failure(self):
        exit_code, report = self.run_campaign(fail=12)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["failed_rounds"], 1)
        self.assertEqual(report["counts"]["unexpected"], 1)
        self.assertEqual(report["rounds"][1]["follow_up"]["seed"], 13)

    def test_duplicate_fingerprint_and_missing_report_fail_but_keep_later_results(self):
        exit_code, report = self.run_campaign(repeat=12, missing=10)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["rounds"][0]["runner_error"], "audit did not complete")
        self.assertEqual(report["distinct_transition_inputs"], 2)
        exit_code, report = self.run_campaign(repeat=12)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["failed_rounds"], 1)
        self.assertIn("Duplicate fingerprint", report["rounds"][1]["error"])


if __name__ == "__main__":
    unittest.main()
