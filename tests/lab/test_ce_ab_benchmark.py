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
        self.assertEqual(measured["source_switches"], 1)
        self.assertEqual((measured["first_source"], measured["last_source"]), ("first", "second"))
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
            self.assertEqual(benchmark.transaction("192.0.2.162", b"marker", .1, 20000),
                             {"status": "timeout", "stage": "connect"})
        with patch.object(benchmark.socket, "create_connection") as connect:
            conn = connect.return_value.__enter__.return_value
            peer = conn.makefile.return_value.__enter__.return_value
            peer.readline.side_effect = TimeoutError
            self.assertEqual(benchmark.transaction("192.0.2.162", b"marker", .1, 20000),
                             {"status": "timeout", "stage": "reply"})
            connect.assert_called_once_with(("192.0.2.162", 7), timeout=.1, source_address=("", 20000))

    def test_application_flows_use_disjoint_source_ports(self):
        ports = {name: {benchmark.connection_port(name, seq) for seq in range(1, 6001)}
                 for name in ("erp", "backup")}
        self.assertEqual(len(ports["erp"] | ports["backup"]), 12000)
        self.assertEqual(benchmark.connection_port("erp", 6001), benchmark.connection_port("erp", 1))

    def test_binding_activation_errors_are_reported_outside_steady_scoring(self):
        with TemporaryDirectory() as path:
            output = Path(path)
            ce = SimpleNamespace(LAB="/lab", command=Mock(), wait_paths=Mock(), loaded=Mock(), assert_rules=Mock())
            experiment = SimpleNamespace(ce=ce, qemu=None, pair=1, mode="native", activations=[],
                                         clients={}, output=output, digest="fixture", activation_file=StringIO(), timing=None,
                                         options=SimpleNamespace(ce_version="2.9.2", pairs=1, soak_hours=0,
                                                                 recovery_hold_seconds=15, profile="legacy"))
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
                "first_success_ns": 320_000_000, "last_success_ns": 320_000_000,
                "longest_success_gap_ms": None,
            })
            self.assertEqual(summary["tail_mismatches"], [])
            self.assertTrue(all(row["first_expected_source_p95_ms"] is None for row in summary["aggregates"]))
            self.assertTrue(all(row["attempts"] == 1 and row["lost_or_invalid"] == 0 for row in summary["aggregates"]))

    def test_approval_trace_requires_matching_receipt_and_exact_live_rule_once(self):
        stream = StringIO()
        ce = SimpleNamespace(GATEWAYS={"GW_A": ("first", "192.0.2.1"), "GW_B": ("second", "192.0.2.2")})
        window = {"pair": 1, "mode": "sdwan", "phase": "erp_only_loss", "start_ns": 100}
        trace = benchmark.TransitionTrace(ce, window, {"G": "GW_B", "B": "GW_A"}, stream, "probe_primary")
        erp = "pass in quick route-to (second 192.0.2.2) ridentifier 41001"
        backup = "pass in quick route-to (first 192.0.2.1) ridentifier 41003"
        state = {
            "snapshot": {
                "observed_at_ns": 30,
                "timing": {"service_checks_complete_ns": 32, "policy_evaluation_ns": 34,
                           "steering_decision_ns": 36, "pf_readback_ns": 38},
                "members": {"a": {"status": "online", "checks": {"probe_primary": "Timed out", "probe_secondary": "Passed"}}},
                "policies": {"ERP": {"selected": "b", "candidates": {"a": "Required service check failed"}},
                             "Backup": {"candidates": {"a": "Eligible"}}},
                "steering": {"G": {"gateway": "GW_B"}, "B": {"gateway": "GW_A"}},
            },
            "benchmark_pf_rules": [erp, backup], "benchmark_pf_read_ns": 40,
            "monotonic_ns": 41, "signature": "current", "pf": {"G": "applied", "B": "applied"},
            "receipt": {"signature": "old", "accepted": True, "confirmed": True},
        }
        receipt = state["receipt"] | {"signature": "current"}
        ce.observations = Mock(side_effect=[state | {"benchmark_pf_rules": [erp, erp, backup]},
                                           state, state | {"receipt": receipt}])
        with patch.object(benchmark.time, "monotonic_ns", side_effect=(110, 120, 210, 220, 310, 320)):
            for _ in range(3):
                trace.observe(None)
        self.assertEqual(trace.stages["detection_published"], {
            "host_lower_ns": None, "host_upper_ns": 120, "guest_ns": 32})
        self.assertIn("erp_failure_with_healthy_backup", trace.stages)
        self.assertEqual(trace.stages["live_pf_match"], {
            "host_lower_ns": 110, "host_upper_ns": 220, "guest_ns": 40})
        self.assertEqual(trace.stages["observer_pf_confirmed"], {
            "host_lower_ns": 210, "host_upper_ns": 320, "guest_ns": 38})
        self.assertEqual(len(stream.getvalue().splitlines()), 3)
        ce.observations.assert_called_with(None, benchmark=True)

    def test_https_fault_leaves_dns_traffic_outside_the_drop_rules(self):
        ce = SimpleNamespace(A="198.51.100.1", ERP="192.0.2.162")
        scoped = SimpleNamespace(ce=ce, erp_https=True)
        rules = benchmark.Experiment.erp_fault(scoped)
        self.assertEqual(rules, (
            'iifname "sw-wire0" ip saddr 198.51.100.1 ip daddr 192.0.2.162 tcp dport 7 drop',
            'iifname "sw-wire0" ip saddr 198.51.100.1 ip daddr 192.0.2.166 tcp dport 443 drop',
        ))
        scoped.erp_https = False
        self.assertIn("udp dport 53", benchmark.Experiment.erp_fault(scoped)[1])

    def test_activation_live_pf_recovery_can_precede_daemon_confirmation(self):
        gateway = "GW_A"
        ce = SimpleNamespace(GATEWAYS={gateway: ("first", "192.0.2.1")})
        window = {"pair": 1, "mode": "sdwan", "start_ns": 100}
        trace = benchmark.TransitionTrace(ce, window, {"G": gateway, "B": gateway}, StringIO(), "probe_primary")
        passes = [f"pass in quick route-to (first 192.0.2.1) ridentifier {tracker}"
                  for tracker in benchmark.TRACKERS.values()]
        blocks = [f"block drop in quick ridentifier {tracker}" for tracker in benchmark.TRACKERS.values()]
        initial = {"snapshot": None, "benchmark_pf_rules": passes, "benchmark_pf_read_ns": 21,
                   "monotonic_ns": 25, "signature": None, "pf": {}, "receipt": {}}
        steered = initial | {
            "snapshot": {"steering": {"G": {"gateway": gateway}, "B": {"gateway": gateway}}},
            "signature": "match", "pf": {"G": "applied", "B": "applied"},
            "receipt": {"signature": "match", "accepted": True, "confirmed": False},
        }
        confirmed = steered | {"receipt": steered["receipt"] | {"confirmed": True}}
        ce.observations = Mock(side_effect=[initial, initial | {"benchmark_pf_rules": blocks}, steered, confirmed])
        with patch.object(benchmark.time, "monotonic_ns", side_effect=(110, 120, 210, 220, 310, 320, 410, 420)):
            trace.observe(None)
            self.assertNotIn("live_pf_match", trace.stages)
            trace.observe(None)
            trace.observe(None)
            self.assertNotIn("observer_pf_confirmed", trace.stages)
            trace.observe(None)
        self.assertEqual(trace.stages["activation_guard_block_observed"]["host_upper_ns"], 220)
        self.assertEqual(trace.stages["live_pf_match"]["host_upper_ns"], 320)
        self.assertEqual(trace.stages["observer_pf_confirmed"]["host_upper_ns"], 420)

    def test_activation_gap_is_measured_between_successes(self):
        stats = benchmark.activation_stats([record(0, 5, "peer"), record(10, 20),
                                            record(800, 820, "peer"), record(1000, 1020, "peer")],
                                           1001 * 1_000_000)
        self.assertEqual(stats["longest_success_gap_ms"], 815)
        self.assertEqual(stats["excluded_boundary_attempts"], 1)

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
