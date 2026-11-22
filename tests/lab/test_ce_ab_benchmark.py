import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("benchmark", Path(__file__).with_name("ce-ab-benchmark.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def record(start, end, source=None):
    return {"start_ns": start * 1_000_000, "end_ns": end * 1_000_000,
            "status": "ok" if source else "timeout", "source": source}


class ApplicationBenchmarkTest(unittest.TestCase):
    def test_first_correct_reply_is_separate_from_first_reply(self):
        rows = [record(301, 310, "first"), record(400, 490),
                record(600, 610, "second"), record(800, 814, "second")]
        measured = benchmark.phase_stats(rows, 300_000_000, 850_000_000, "second")
        self.assertEqual(measured["first_reply_ms"], 10)
        self.assertEqual(measured["first_expected_source_ms"], 310)
        self.assertEqual(measured["reply_p95_ms"], 14)
        self.assertEqual(measured["loss_pct"], 25)
        self.assertEqual(measured["unexpected_source_replies"], 1)
        self.assertEqual(measured["tail_mismatches"], 0)

    def test_crossing_boundaries_is_not_a_failure(self):
        rows = [record(100, 302, "carry-in"), record(350, 420), record(700, 900, "carry-out")]
        measured = benchmark.phase_stats(rows, 300_000_000, 800_000_000, None)
        self.assertEqual(measured["excluded_boundary_attempts"], 1)
        self.assertEqual(measured["attempts"], 1)
        self.assertEqual(measured["loss_pct"], 100)
        self.assertIsNone(measured["first_reply_ms"])
        self.assertIsNone(measured["first_expected_source_ms"])

    def test_tail_mismatches_detect_wrong_source(self):
        rows = [record(109, 115, "wrong"), record(119, 120), record(130, 135, "right")]
        measured = benchmark.phase_stats(rows, 90_000_000, 140_000_000, "right")
        self.assertEqual(measured["tail_attempts"], 2)
        self.assertEqual(measured["tail_mismatches"], 1)

    def test_timeout_is_recorded(self):
        with patch.object(benchmark.socket, "create_connection", side_effect=TimeoutError):
            self.assertEqual(benchmark.transaction("192.0.2.162", b"marker", .1), {"status": "timeout"})


if __name__ == "__main__":
    unittest.main()
