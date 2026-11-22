#!/usr/bin/env python3
"""Measure LAN application replies on the isolated two-WAN CE appliance."""
import argparse
from contextlib import ExitStack
import csv
import http.server
import importlib.util
import json
import math
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time


SCRIPT = Path(__file__).resolve()
TARGETS = {"erp": "192.0.2.162", "backup": "192.0.2.163"}
TLS_NAME = "service.sdwan.test"
NS = 1_000_000_000


def appliance_module():
    spec = importlib.util.spec_from_file_location("ce_appliance", SCRIPT.with_name("ce291-appliance.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def phase_stats(rows, start_ns, end_ns, expected):
    scoped = [row for row in rows if start_ns <= row["start_ns"] < end_ns]
    replies = [row for row in scoped if row["status"] == "ok" and row["end_ns"] < end_ns]
    timed = [row for row in scoped if row["end_ns"] < end_ns]
    on_expected = [row for row in replies if row["source"] == expected]
    tail_start = end_ns - min(5 * NS, (end_ns - start_ns) // 2)
    tail = [row for row in timed if row["start_ns"] >= tail_start]
    tail_bad = [row for row in tail if (row.get("source") if row["status"] == "ok" else None) != expected]
    sources = {}
    unexpected_runs = 0
    last_source = expected
    for row in replies:
        source = row["source"]
        sources[source] = sources.get(source, 0) + 1
        if source != expected and source != last_source:
            unexpected_runs += 1
        last_source = source
    return {
        "attempts": len(timed),
        "successful_replies": len(replies),
        "lost_or_invalid": len(timed) - len(replies),
        "excluded_boundary_attempts": len(scoped) - len(timed),
        "loss_pct": 100 * (len(timed) - len(replies)) / len(timed) if timed else None,
        "reply_p95_ms": percentile([round((r["end_ns"] - r["start_ns"]) / 1e6, 3) for r in replies], .95),
        "first_reply_ms": round((replies[0]["end_ns"] - start_ns) / 1e6, 3) if replies else None,
        "first_expected_source_ms": round((on_expected[0]["end_ns"] - start_ns) / 1e6, 3) if on_expected else None,
        "sources": sources,
        "unexpected_source_replies": len(replies) - len(on_expected),
        "unexpected_source_runs": unexpected_runs,
        "tail_attempts": len(tail),
        "tail_mismatches": len(tail_bad),
    }


def transaction(target, marker, timeout):
    try:
        with socket.create_connection((target, 7), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(marker + b"\n")
            with conn.makefile("rb") as peer:
                reply = peer.readline(256)
        fields = reply.removesuffix(b"\n").split(b" ", 1)
        if not reply.endswith(b"\n") or len(fields) != 2 or fields[1] != marker:
            return {"status": "invalid_reply"}
        try:
            source = socket.inet_ntoa(socket.inet_aton(fields[0].decode("ascii")))
        except (OSError, UnicodeError):
            return {"status": "invalid_reply"}
        return {"status": "ok", "source": source}
    except TimeoutError:
        return {"status": "timeout"}
    except OSError as error:
        return {"status": "socket_error", "errno": error.errno}


def client(flow, interval, output):
    step = int(interval * NS)
    next_start = time.monotonic_ns()
    with open(output, "x", encoding="utf-8", buffering=1) as stream:
        sequence = 0
        while True:
            time.sleep(max(0, next_start - time.monotonic_ns()) / NS)
            start = time.monotonic_ns()
            sequence += 1
            marker = f"{flow}-{start}-{sequence}".encode("ascii")
            reply = transaction(TARGETS[flow], marker, min(.9, interval * .8))
            end = time.monotonic_ns()
            stream.write(json.dumps({"start_ns": start, "end_ns": end, "sequence": sequence, **reply}) + "\n")
            next_start = max(next_start + step, end)


class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


def serve_probes(cert, key):
    ce = appliance_module()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with ExitStack() as stack:
        for host in ("192.0.2.164", "192.0.2.165"):
            server = stack.enter_context(socketserver.UDPServer((host, 53), ce.DnsEcho))
            threading.Thread(target=server.serve_forever, daemon=True).start()
        for host in ("192.0.2.166", "192.0.2.167"):
            server = stack.enter_context(http.server.ThreadingHTTPServer((host, 443), Health))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print("ready", flush=True)
        threading.Event().wait()


def setup_probes(ce, qemu, cleanup):
    temp = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="sdwan-ab-")))
    ca, ca_key, req, leaf, key, ext = [temp / name for name in ("ca.pem", "ca.key", "tls.csr", "tls.pem", "tls.key", "tls.ext")]
    ext.write_text(f"subjectAltName=DNS:{TLS_NAME}\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    for args in (
        ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "8", "-subj", "/CN=Isolated SDWAN benchmark CA",
         "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", ca),
        ("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={TLS_NAME}", "-keyout", key, "-out", req),
        ("x509", "-req", "-in", req, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-extfile", ext,
         "-days", "8", "-out", leaf),
    ):
        subprocess.run(["openssl", *args], check=True, timeout=15, capture_output=True)
    server = subprocess.Popen(ce.in_ns("sdwan-peer", sys.executable, SCRIPT, "serve-probes", leaf, key),
                              stdout=subprocess.PIPE, text=True)
    cleanup.callback(server.stdout.close)
    cleanup.callback(ce.stop, server)
    if not select.select([server.stdout], [], [], 8)[0] or server.stdout.readline().strip() != "ready":
        raise RuntimeError("Benchmark DNS and TLS endpoints failed to start.")
    cert_path = f"{ce.LAB}/benchmark-ca.pem"
    ce.command(qemu, f"""umask 077
cat >{cert_path} <<'CERT_END'
{ca.read_text(encoding="ascii").rstrip()}
CERT_END
scan=$(/usr/local/bin/php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;')
test -d "$scan"
printf '%s\\n' 'curl.cainfo={cert_path}' >"$scan/99-sdwan-benchmark.ini"
/usr/local/bin/php -r 'exit(ini_get("curl.cainfo") === "{cert_path}" ? 0 : 1);'""")


def setup_package(ce, qemu):
    package = f"{ce.LAB}/candidate.pkg"
    digest = ce.command(qemu, f"sha256 -q {package}")
    if digest != ce.command(qemu, f"cat {ce.LAB}/candidate.sha256"):
        raise RuntimeError("Candidate package digest mismatch.")
    ce.command(qemu, f"pkg add -f {package}", timeout=180)
    ce.command(qemu, f"php {ce.LAB}/ce291-guest.php settings")
    ce.command(qemu, f"""php <<'BENCH_PHP'
<?php
require_once('config.inc');
require_once('/usr/local/pkg/sdwan.inc');
$original = sdwan_get_config();
$candidate = $original;
$candidate['slas'][0] += ['rttsd_ms' => '30'];
$candidate['slas'][0]['latency_ms'] = '40';
foreach ($candidate['members'] as $index => &$member) {{
    $member['probe_primary'] = 'dns://{TLS_NAME} 192.0.2.' . (164 + $index);
    $member['probe_secondary'] = 'https://{TLS_NAME}/healthz 192.0.2.' . (166 + $index);
}}
unset($member);
$errors = sdwan_save_config($candidate, sdwan_config_revision($original), true);
if ($errors) {{
    fwrite(fopen('php://stderr', 'w'), implode('; ', $errors) . PHP_EOL);
    exit(1);
}}
config_set_path('system/skip_rules_gw_down', '');
if (!is_array(write_config('Prevent native gateway bypass in the isolated comparison'))) {{
    exit(1);
}}
BENCH_PHP
cp -p /etc/inc/filter.inc {ce.LAB}/filter.stock
cp {ce.LAB}/filter*.inc /etc/inc/
/usr/local/etc/rc.d/sdwand.sh restart
/etc/rc.filter_configure_sync""")
    assert "ABI=2" in ce.command(qemu, f"php {ce.LAB}/ce291-guest.php mode")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        observed = ce.observations(qemu)["snapshot"] or {}
        rows = observed.get("members", {})
        if all(rows.get(name, {}).get("checks") == {"probe_primary": "Passed", "probe_secondary": "Passed"}
               for name in ("a", "b")):
            return digest
        time.sleep(1)
    raise RuntimeError(f"Benchmark DNS and validated HTTPS probes were not ready: {observed!r}")


class Experiment:
    def __init__(self, ce, qemu, cleanup, options):
        self.ce, self.qemu, self.options = ce, qemu, options
        self.output = options.output
        self.mode = self.pair = None
        self.phases = []
        self.event_file = cleanup.enter_context((self.output / "phases.ndjson").open("x", encoding="utf-8", buffering=1))
        self.resources = cleanup.enter_context((self.output / "resources.ndjson").open("x", encoding="utf-8", buffering=1))
        self.certificate = ce.management("benchmark baseline")
        setup_probes(ce, qemu, cleanup)
        self.digest = setup_package(ce, qemu)
        self.reference = ce.route_and_nat(qemu)
        self.next_resources = time.monotonic_ns()
        self.clients = {}
        for flow in TARGETS:
            output = self.output / f"{flow}.ndjson"
            child = subprocess.Popen(ce.in_ns("sdwan-client", sys.executable, SCRIPT, "client", flow,
                                              options.interval, output))
            self.clients[flow] = child
            cleanup.callback(ce.stop, child)

    def activate(self, mode):
        ce, qemu = self.ce, self.qemu
        if self.mode == "sdwan" and mode == "native":
            # Await the first native reload before asking to restore the next binding.
            ce.command(qemu, f"php {ce.LAB}/ce291-guest.php unbind G")
            ce.wait_paths(qemu, "benchmark unbind ERP", {"B": "GW_A"}, native_choices={"G": "GW_A"})
            ce.command(qemu, f"php {ce.LAB}/ce291-guest.php unbind B")
            ce.command(qemu, "/etc/rc.filter_configure_sync")
        if mode == "sdwan" and self.mode != mode:
            ce.command(qemu, f"php {ce.LAB}/ce291-guest.php bind")
            ce.wait_paths(qemu, "benchmark bind", {"G": "GW_A", "B": "GW_A"})
        if mode == "native":
            cmd = "require 'config.inc'; require '/usr/local/pkg/sdwan_steering.inc';"
            cmd += " exit(sdwan_steering_bindings() ? 1 : 0);"
            ce.command(qemu, f'php -r "{cmd}"')
        ce.assert_rules(ce.loaded(qemu), {"G": "GW_A", "B": "GW_A"})
        self.mode = mode

    def resource_sample(self):
        worker = self.ce.worker_pid(self.qemu)
        load = self.ce.command(self.qemu, f"ps -p {worker} -o pid=,pcpu=,rss=")
        pid, cpu, rss = load.split()
        self.resources.write(json.dumps({"at_ns": time.monotonic_ns(), "mode": self.mode, "pid": int(pid),
                                         "cpu_pct_ps": float(cpu), "rss_kib": int(rss)}) + "\n")

    def phase(self, label, seconds, expected, rules=(), steady=False):
        ce, qemu = self.ce, self.qemu
        if rules is not None:
            ce.fault(*rules)
        started = time.monotonic_ns()
        end = started + round(seconds * NS)
        phase = {"pair": self.pair, "mode": self.mode, "phase": label, "start_ns": started,
                 "end_ns": end, "expected": dict(zip(TARGETS, expected)), "steady": steady}
        self.event_file.write(json.dumps({"event": "start", **phase}) + "\n")
        while time.monotonic_ns() < end:
            if any(child.poll() is not None for child in self.clients.values()):
                raise RuntimeError("An isolated application client stopped unexpectedly.")
            if time.monotonic_ns() >= self.next_resources:
                self.resource_sample()
                self.next_resources = time.monotonic_ns() + round(self.options.sample_seconds * NS)
            time.sleep(min(1, max(0, end - time.monotonic_ns()) / NS))
        phase["pf"] = ce.loaded(qemu)
        phase["snapshot"] = (ce.observations(qemu)["snapshot"] or {}).get("members", {})
        self.phases.append(phase)
        self.event_file.write(json.dumps({"event": "end", **phase}) + "\n")

    def cycle(self):
        ce, opts = self.ce, self.options
        self.phase("baseline", 6, (ce.A, ce.A), steady=True)
        self.phase("wan1_loss", opts.outage_seconds, (ce.B, ce.B),
                   (f'iifname "sw-wire0" ip saddr {ce.A} drop',))
        self.phase("wan1_return", opts.recovery_seconds, (ce.A, ce.A))
        self.phase("erp_only_loss", opts.outage_seconds, (ce.B if self.mode == "sdwan" else None, ce.A),
                   (f'iifname "sw-wire0" ip saddr {ce.A} ip daddr {ce.ERP} tcp dport 7 drop',
                    f'iifname "sw-wire0" ip saddr {ce.A} ip daddr 192.0.2.164 udp dport 53 drop'))
        assert "192.0.2.42" in ce.command(self.qemu, "drill @198.51.100.2 health.test A")
        self.phase("erp_only_return", opts.recovery_seconds, (ce.A, ce.A))
        ce.management(f"benchmark {self.mode} pair {self.pair}", self.certificate)
        assert ce.route_and_nat(self.qemu) == self.reference

    def soak(self):
        ce, opts = self.ce, self.options
        deadline = time.monotonic_ns() + round(opts.soak_hours * 3600 * NS)
        cycle = 0
        while deadline - time.monotonic_ns() >= 6 * NS:
            remaining = (deadline - time.monotonic_ns()) / NS
            steady = min(opts.fault_interval_seconds, remaining)
            if remaining - steady < opts.outage_seconds + opts.recovery_seconds + 6:
                steady = remaining
            self.phase("soak_healthy", steady, (ce.A, ce.A), steady=True)
            if deadline - time.monotonic_ns() < (opts.outage_seconds + opts.recovery_seconds + 6) * NS:
                break
            cycle += 1
            self.phase("soak_wan1_loss", opts.outage_seconds, (ce.B, ce.B),
                       (f'iifname "sw-wire0" ip saddr {ce.A} drop',))
            self.phase("soak_wan1_return", opts.recovery_seconds, (ce.A, ce.A))
            ce.management(f"benchmark soak incident {cycle}", self.certificate)
            assert ce.route_and_nat(self.qemu) == self.reference

    def summarize(self):
        for child in self.clients.values():
            self.ce.stop(child)
        rows = {}
        for flow in TARGETS:
            with (self.output / f"{flow}.ndjson").open(encoding="utf-8") as stream:
                rows[flow] = [json.loads(line) for line in stream if line.endswith("\n")]
        headings = ("pair", "mode", "phase", "flow", "expected", "duration_seconds")
        all_metrics = []
        for phase in self.phases:
            for flow, expected in phase["expected"].items():
                stats = phase_stats(rows[flow], phase["start_ns"], phase["end_ns"], expected)
                all_metrics.append(dict(zip(headings, (phase["pair"], phase["mode"], phase["phase"], flow, expected,
                                                       (phase["end_ns"] - phase["start_ns"]) / NS))) | stats)
        if not all_metrics:
            raise RuntimeError("No measurement phases completed.")
        with (self.output / "phases.csv").open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(all_metrics[0]))
            writer.writeheader()
            writer.writerows(row | {"sources": json.dumps(row["sources"], sort_keys=True)} for row in all_metrics)
        aggregates = []
        keys = {(row["mode"], row["phase"], row["flow"]) for row in all_metrics}
        for mode, phase, flow in sorted(keys):
            selected = [row for row in all_metrics if (row["mode"], row["phase"], row["flow"]) == (mode, phase, flow)]
            recoveries = [row["first_expected_source_ms"] for row in selected if row["first_expected_source_ms"] is not None]
            attempts = sum(row["attempts"] for row in selected)
            losses = sum(row["lost_or_invalid"] for row in selected)
            all_replies = []
            for transition in self.phases:
                if (transition["mode"], transition["phase"]) == (mode, phase):
                    all_replies.extend(round((row["end_ns"] - row["start_ns"]) / 1e6, 3) for row in rows[flow]
                                       if row["status"] == "ok" and transition["start_ns"] <= row["start_ns"]
                                       and row["end_ns"] < transition["end_ns"])
            aggregates.append({"mode": mode, "phase": phase, "flow": flow, "runs": len(selected),
                               "attempts": attempts, "lost_or_invalid": losses,
                               "loss_pct": 100 * losses / attempts if attempts else None,
                               "reply_p95_ms": percentile(all_replies, .95),
                               "first_expected_source_p95_ms": percentile(recoveries, .95),
                               "censored": len(selected) - len(recoveries)})
        steady = [row for row in all_metrics if row["phase"] in ("baseline", "soak_healthy")]
        unexpected = sum(row["unexpected_source_replies"] for row in steady)
        mismatches = [row for row in all_metrics if not row["tail_attempts"] or row["tail_mismatches"]]
        with (self.output / "resources.ndjson").open(encoding="utf-8") as stream:
            samples = [json.loads(line) for line in stream]
        kinds = sorted({sample["mode"] for sample in samples})
        resources = {}
        for mode in kinds:
            scoped = [sample for sample in samples if sample["mode"] == mode]
            resources[mode] = {
                "samples": len(scoped),
                "cpu_pct_ps_p95": percentile([sample["cpu_pct_ps"] for sample in scoped], .95),
                "rss_kib_peak": max(sample["rss_kib"] for sample in scoped),
                "worker_pid_changes": sum(a["pid"] != b["pid"] for a, b in zip(scoped, scoped[1:])),
            }
        summary = {"ce_version": self.options.ce_version, "package_sha256": self.digest,
                   "pairs": self.options.pairs, "soak_hours_requested": self.options.soak_hours,
                   "soak_healthy_seconds": sum((p["end_ns"] - p["start_ns"]) / NS for p in self.phases
                                               if p["phase"] == "soak_healthy"),
                   "unexpected_steady_source_replies": unexpected, "tail_mismatches": mismatches,
                   "unexpected_steady_source_runs": sum(row["unexpected_source_runs"] for row in steady),
                   "resources": resources, "aggregates": aggregates}
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        if unexpected or mismatches:
            raise RuntimeError(f"Application paths did not match the expected steady results: {mismatches!r}")
        print(f"CE_APPLICATION_BENCHMARK_OK phases={len(self.phases)} output={self.output}", flush=True)


def main():
    if sys.argv[1:2] == ["client"]:
        client(sys.argv[2], float(sys.argv[3]), Path(sys.argv[4]))
        return
    if sys.argv[1:2] == ["serve-probes"]:
        serve_probes(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="disposable unbooted raw disk")
    parser.add_argument("ce_version", choices=("2.9.1", "2.9.2"))
    parser.add_argument("--output", type=Path, required=True, help="new directory for raw evidence")
    parser.add_argument("--pairs", type=int, default=2)
    parser.add_argument("--interval", type=float, default=.5)
    parser.add_argument("--outage-seconds", type=float, default=40)
    parser.add_argument("--recovery-seconds", type=float, default=65)
    parser.add_argument("--sample-seconds", type=float, default=60)
    parser.add_argument("--soak-hours", type=float, default=0)
    parser.add_argument("--fault-interval-seconds", type=float, default=1800)
    options = parser.parse_args()
    ranges = {"pairs": (0, 32), "interval": (.25, 5), "outage_seconds": (15, 300),
              "recovery_seconds": (35, 300), "sample_seconds": (1, 3600),
              "soak_hours": (0, 168), "fault_interval_seconds": (6, 86400)}
    for name, (lower, upper) in ranges.items():
        if not lower <= getattr(options, name) <= upper:
            parser.error(f"{name} must be between {lower} and {upper}")
    if not options.pairs and options.soak_hours < 6 / 3600:
        parser.error("Select at least one A/B pair or at least six seconds of soak.")
    options.output = options.output.resolve()
    options.output.mkdir(parents=True)
    ce = appliance_module()

    def scenario(qemu, cleanup, _provider):
        experiment = Experiment(ce, qemu, cleanup, options)
        for pair in range(options.pairs):
            experiment.pair = pair + 1
            for mode in (("native", "sdwan") if pair % 2 == 0 else ("sdwan", "native")):
                experiment.activate(mode)
                experiment.cycle()
        if options.soak_hours:
            experiment.pair = None
            experiment.activate("sdwan")
            experiment.soak()
        experiment.summarize()

    ce.appliance(options.image.resolve(), options.ce_version, scenario=scenario)


if __name__ == "__main__":
    main()
