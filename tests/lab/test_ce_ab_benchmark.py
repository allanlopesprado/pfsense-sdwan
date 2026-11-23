from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


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

    def test_backup_requires_replies_throughout_erp_only_phases(self):
        healthy = {"flow": "backup", "phase": "erp_only_loss", "attempts": 20,
                   "lost_or_invalid": 0, "unexpected_source_replies": 0, "tail_mismatches": 0}
        early_loss = healthy | {"lost_or_invalid": 1}
        wrong_source = healthy | {"phase": "erp_only_return", "unexpected_source_replies": 1}
        missing = healthy | {"attempts": 0}
        unaffected = [healthy, early_loss | {"flow": "erp"}, early_loss | {"phase": "wan1_loss"}]
        self.assertEqual(benchmark.backup_continuity_violations(unaffected + [early_loss, wrong_source, missing]),
                         [early_loss, wrong_source, missing])

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

    def test_binding_activation_errors_are_reported_outside_steady_scoring(self):
        with TemporaryDirectory() as path:
            output = Path(path)
            ce = SimpleNamespace(LAB="/lab", command=Mock(), wait_paths=Mock(), loaded=Mock(), assert_rules=Mock())
            experiment = SimpleNamespace(ce=ce, qemu=None, pair=1, mode="native", activations=[],
                                         clients={}, output=output, digest="fixture", activation_file=StringIO(),
                                         options=SimpleNamespace(ce_version="2.9.2", pairs=1, soak_hours=0,
                                                                 recovery_hold_seconds=15))
            with patch.object(benchmark.time, "monotonic_ns", side_effect=(300_000_000, 700_000_000)):
                benchmark.Experiment.activate(experiment, "sdwan")
            ce.command.assert_called_once_with(None, "php /lab/ce291-guest.php bind")
            ce.wait_paths.assert_called_once_with(None, "benchmark bind", {"G": "GW_A", "B": "GW_A"})
            ce.assert_rules.assert_called_once_with(ce.loaded.return_value, {"G": "GW_A", "B": "GW_A"})
            events = [json.loads(line) for line in experiment.activation_file.getvalue().splitlines()]
            self.assertEqual([entry["event"] for entry in events], ["start", "end"])
            self.assertTrue(events[1]["verified"])

            experiment.phases = [{"pair": 1, "mode": "sdwan", "phase": "baseline", "start_ns": 700_000_000,
                                  "end_ns": 900_000_000, "expected": {name: "peer" for name in benchmark.TARGETS}}]
            rows = [record(280, 315), record(305, 320, "peer"), record(400, 450) | {"stage": "connect"},
                    record(500, 550) | {"stage": "reply"}, record(699, 720), record(880, 895, "peer")]
            for flow in benchmark.TARGETS:
                (output / f"{flow}.ndjson").write_text("".join(json.dumps(row) + "\n" for row in rows),
                                                       encoding="utf-8")
            (output / "resources.ndjson").touch()
            with redirect_stdout(StringIO()):
                benchmark.Experiment.summarize(experiment)
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["activations"][0]["duration_ms"], 400)
            self.assertEqual(summary["activations"][0]["flows"]["erp"], {
                "attempts": 3, "successful_replies": 1, "excluded_boundary_attempts": 1,
                "errors": {"connect_timeout": 1, "reply_timeout": 1},
            })
            self.assertEqual(summary["tail_mismatches"], [])
            self.assertTrue(all(row["attempts"] == 1 and row["lost_or_invalid"] == 0 for row in summary["aggregates"]))

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
