import importlib.util
from io import StringIO
import json
from pathlib import Path
from types import SimpleNamespace
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
        self.assertEqual(measured["unexpected_source_runs"], 1)
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

    def test_streaming_skips_gaps_and_preserves_boundary_counts(self):
        phases = [{"start_ns": start * 1_000_000, "end_ns": end * 1_000_000}
                  for start, end in [(100, 200), (300, 400), (500, 600)]]
        rows = (record(start, end, "peer") for start, end in [(50, 100), (100, 111), (175, 200),
                                                               (200, 215), (500, 535), (600, 650)])
        result = {}
        latencies = []
        for index, samples in benchmark.by_phase(rows, phases):
            phase = phases[index]
            result[index] = benchmark.phase_stats(samples, phase["start_ns"], phase["end_ns"], "peer", latencies)
        self.assertEqual(set(result), {0, 2})
        self.assertEqual(result[0]["excluded_boundary_attempts"], 1)
        self.assertEqual(result[0]["attempts"], 1)
        self.assertEqual(result[2]["attempts"], 1)
        self.assertEqual(latencies, [11, 35])

    def test_timeout_is_recorded(self):
        with patch.object(benchmark.socket, "create_connection", side_effect=TimeoutError):
            self.assertEqual(benchmark.transaction("192.0.2.162", b"marker", .1),
                             {"status": "timeout", "stage": "connect"})
        with patch.object(benchmark.socket, "create_connection") as connect:
            conn = connect.return_value.__enter__.return_value
            peer = conn.makefile.return_value.__enter__.return_value
            peer.readline.side_effect = TimeoutError
            self.assertEqual(benchmark.transaction("192.0.2.162", b"marker", .1),
                             {"status": "timeout", "stage": "reply"})

    def test_freebsd_resource_query_uses_one_header_assignment_per_option(self):
        class Fixture:
            def worker_pid(self, _qemu):
                return 42680

            def command(self, _qemu, command):
                self.command_text = command
                return " 42680    0.1  41650\n"

        fixture = Fixture()
        storage = StringIO()
        experiment = SimpleNamespace(ce=fixture, qemu=None, mode="sdwan", resources=storage)
        benchmark.Experiment.resource_sample(experiment)
        self.assertEqual(fixture.command_text, "LC_ALL=C ps -p 42680 -o pid= -o pcpu= -o rss=")
        row = json.loads(storage.getvalue())
        self.assertEqual((row["pid"], row["cpu_pct_ps"], row["rss_kib"]), (42680, .1, 41650))


if __name__ == "__main__":
    unittest.main()
