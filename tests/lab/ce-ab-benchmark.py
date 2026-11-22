#!/usr/bin/env python3
"""Measure LAN application replies on the isolated two-WAN CE appliance."""
import argparse
from collections import defaultdict
from contextlib import ExitStack
import csv
import http.server
import importlib.util
from itertools import groupby
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


def phase_stats(rows, start_ns, end_ns, expected, aggregate_latencies=None):
    tail_start = end_ns - min(5 * NS, (end_ns - start_ns) // 2)
    attempts = boundary = tail_attempts = tail_mismatches = 0
    first_reply = first_expected = None
    sources = {}
    latencies = []
    unexpected_runs = 0
    last_source = expected
    for row in rows:
        if not start_ns <= row["start_ns"] < end_ns:
            continue
        if row["end_ns"] >= end_ns:
            boundary += 1
            continue
        attempts += 1
        replied = row["status"] == "ok"
        if row["start_ns"] >= tail_start:
            tail_attempts += 1
            tail_mismatches += (row["source"] if replied else None) != expected
        if not replied:
            continue
        source = row["source"]
        elapsed = round((row["end_ns"] - start_ns) / 1e6, 3)
        if first_reply is None:
            first_reply = elapsed
        if source == expected and first_expected is None:
            first_expected = elapsed
        latencies.append(round((row["end_ns"] - row["start_ns"]) / 1e6, 3))
        sources[source] = sources.get(source, 0) + 1
        if source != expected and source != last_source:
            unexpected_runs += 1
        last_source = source
    if aggregate_latencies is not None:
        aggregate_latencies.extend(latencies)
    replies = len(latencies)
    loss = attempts - replies
    return {
        "attempts": attempts,
        "successful_replies": replies,
        "lost_or_invalid": loss,
        "excluded_boundary_attempts": boundary,
        "loss_pct": 100 * loss / attempts if attempts else None,
        "reply_p95_ms": percentile(latencies, .95),
        "first_reply_ms": first_reply,
        "first_expected_source_ms": first_expected,
        "sources": sources,
        "unexpected_source_replies": replies - sources.get(expected, 0),
        "unexpected_source_runs": unexpected_runs,
        "tail_attempts": tail_attempts,
        "tail_mismatches": tail_mismatches,
    }


def by_phase(rows, phases):
    """Yield groups from a monotonic client stream without retaining raw attempts."""
    cursor = 0

    def locate(row):
        nonlocal cursor
        started = row["start_ns"]
        while cursor < len(phases) and started >= phases[cursor]["end_ns"]:
            cursor += 1
        if cursor < len(phases) and started >= phases[cursor]["start_ns"]:
            return cursor
        return None

    for index, group in groupby(rows, key=locate):
        if index is not None:
            yield index, group


def activation_stats(rows, end_ns):
    replies = boundary = 0
    errors = defaultdict(int)
    for row in rows:
        if row["end_ns"] >= end_ns:
            boundary += 1
        elif row["status"] == "ok":
            replies += 1
        else:
            kind = row["status"]
            if "stage" in row:
                kind = f"{row['stage']}_{kind}"
            errors[kind] += 1
    return {"attempts": replies + sum(errors.values()), "successful_replies": replies,
            "excluded_boundary_attempts": boundary, "errors": dict(errors)}


def transaction(target, marker, timeout):
    stage = "connect"
    try:
        with socket.create_connection((target, 7), timeout=timeout) as conn:
            stage = "send"
            conn.settimeout(timeout)
            conn.sendall(marker + b"\n")
            stage = "reply"
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
        return {"status": "timeout", "stage": stage}
    except OSError as error:
        return {"status": "socket_error", "stage": stage, "errno": error.errno}


def client(flow, interval, output):
    step = int(interval * NS)
    next_start = time.monotonic_ns()
    with open(output, "x", encoding="utf-8", buffering=1) as stream:
        sequence = 0
        while True:
            time.sleep(max(0, next_start - time.monotonic_ns()) / NS)
            start = time.monotonic_ns()
            wall_start = time.time_ns()
            sequence += 1
            marker = f"{flow}-{start}-{sequence}".encode("ascii")
            reply = transaction(TARGETS[flow], marker, min(.9, interval * .8))
            end = time.monotonic_ns()
            stream.write(json.dumps({"start_ns": start, "end_ns": end, "wall_start_ns": wall_start,
                                     "sequence": sequence, **reply}) + "\n")
            next_start = max(next_start + step, end)


def capture_erp(ce, cleanup, output):
    for link in range(3):
        interface = f"sw-out{link}"
        report = cleanup.enter_context((output / f"{interface}-capture.log").open("x"))
        capture = subprocess.Popen(["tcpdump", "-Z", "root", "-p", "-ni", interface, "-s", "96", "-U", "-C", "2", "-W", "2",
                                    "-w", str(output / f"{interface}-erp.pcap"),
                                    f"host {TARGETS['erp']} and tcp port 7"], stderr=report)
        cleanup.callback(ce.stop, capture)
        time.sleep(.1)
        if capture.poll() is not None:
            raise RuntimeError(f"ERP capture could not start on {interface}")


class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        source_file = self.server.unready_source
        try:
            is_unready = source_file is not None and source_file.read_text(encoding="ascii").strip() == self.client_address[0]
        except FileNotFoundError:
            is_unready = False
        body = b"no" if is_unready else b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def serve_probes(cert, key, dns_hosts=("192.0.2.164", "192.0.2.165"),
                 https_hosts=("192.0.2.166", "192.0.2.167"), unready_source=None):
    ce = appliance_module()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with ExitStack() as stack:
        for host in dns_hosts:
            server = stack.enter_context(socketserver.UDPServer((host, 53), ce.DnsEcho))
            threading.Thread(target=server.serve_forever, daemon=True).start()
        for host in https_hosts:
            server = stack.enter_context(http.server.ThreadingHTTPServer((host, 443), Health))
            server.unready_source = unready_source
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print("ready", flush=True)
        threading.Event().wait()


def setup_probes(ce, qemu, cleanup, *, shared_host=None):
    temp = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="sdwan-ab-")))
    unready_source = temp / "unready-source"
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
    command = [sys.executable, SCRIPT, "serve-probes", leaf, key]
    if shared_host is not None:
        command.extend([shared_host, unready_source])
    server = subprocess.Popen(ce.in_ns("sdwan-peer", *command),
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
    return unready_source


def setup_package(ce, qemu, recovery_hold_seconds):
    package = f"{ce.LAB}/candidate.pkg"
    digest = ce.command(qemu, f"sha256 -q {package}")
    if digest != ce.command(qemu, f"cat {ce.LAB}/candidate.sha256"):
        raise RuntimeError("Candidate package digest mismatch.")
    ce.command(qemu, f"pkg add -f {package}", timeout=180)
    ce.command(qemu, f"php {ce.LAB}/ce291-guest.php settings")
    hold = str(recovery_hold_seconds) if recovery_hold_seconds is not None else ""
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
if ('{hold}' !== '') {{
    foreach ($candidate['policies'] as &$policy) {{
        $policy['recover_seconds'] = '{hold}';
    }}
    unset($policy);
}}
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
        self.activations = []
        self.event_file = cleanup.enter_context((self.output / "phases.ndjson").open("x", encoding="utf-8", buffering=1))
        self.activation_file = cleanup.enter_context(
            (self.output / "activations.ndjson").open("x", encoding="utf-8", buffering=1))
        self.resources = cleanup.enter_context((self.output / "resources.ndjson").open("x", encoding="utf-8", buffering=1))
        self.certificate = ce.management("benchmark baseline")
        setup_probes(ce, qemu, cleanup)
        self.digest = setup_package(ce, qemu, options.recovery_hold_seconds)
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
        window = None
        if self.mode != mode:
            window = {"pair": self.pair, "from_mode": self.mode, "mode": mode,
                      "start_ns": time.monotonic_ns()}
            self.activation_file.write(json.dumps({"event": "start", **window}) + "\n")
        verified = False
        try:
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
            verified = True
        finally:
            if window is not None:
                window.update(end_ns=time.monotonic_ns(), verified=verified)
                self.activation_file.write(json.dumps({"event": "end", **window}) + "\n")
                self.activations.append(window)

    def resource_sample(self):
        worker = self.ce.worker_pid(self.qemu)
        # FreeBSD interprets everything after the first '=' as that header.
        load = self.ce.command(self.qemu, f"LC_ALL=C ps -p {worker} -o pid= -o pcpu= -o rss=")
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
        latencies = defaultdict(list)
        observations = {}
        activation_observations = {}
        timeline = [phase | {"phase_index": index} for index, phase in enumerate(self.phases)]
        timeline.extend(window | {"activation_index": index} for index, window in enumerate(self.activations))
        timeline.sort(key=lambda window: window["start_ns"])
        for flow in TARGETS:
            with (self.output / f"{flow}.ndjson").open(encoding="utf-8") as stream:
                rows = (json.loads(line) for line in stream if line.endswith("\n"))
                for index, samples in by_phase(rows, timeline):
                    window = timeline[index]
                    if "activation_index" in window:
                        activation = window["activation_index"], flow
                        activation_observations[activation] = activation_stats(samples, window["end_ns"])
                        continue
                    key = window["mode"], window["phase"], flow
                    observations[window["phase_index"], flow] = phase_stats(
                        samples, window["start_ns"], window["end_ns"], window["expected"][flow], latencies[key])
        no_attempts = activation_stats((), 0)
        activations = [
            window | {"duration_ms": (window["end_ns"] - window["start_ns"]) / 1e6,
                      "flows": {flow: activation_observations.get((index, flow), no_attempts) for flow in TARGETS}}
            for index, window in enumerate(self.activations)
        ]
        headings = ("pair", "mode", "phase", "flow", "expected", "duration_seconds")
        all_metrics = []
        for index, phase in enumerate(self.phases):
            for flow, expected in phase["expected"].items():
                stats = observations.get((index, flow))
                if stats is None:
                    stats = phase_stats((), phase["start_ns"], phase["end_ns"], expected)
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
            aggregates.append({"mode": mode, "phase": phase, "flow": flow, "runs": len(selected),
                               "attempts": attempts, "lost_or_invalid": losses,
                               "loss_pct": 100 * losses / attempts if attempts else None,
                               "reply_p95_ms": percentile(latencies[mode, phase, flow], .95),
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
                   "recovery_hold_seconds": self.options.recovery_hold_seconds,
                   "soak_completed_incidents": sum(1 for p in self.phases if p["phase"] == "soak_wan1_return"),
                   "soak_elapsed_seconds": sum((p["end_ns"] - p["start_ns"]) / NS for p in self.phases
                                                if p["phase"].startswith("soak_")),
                   "soak_healthy_seconds": sum((p["end_ns"] - p["start_ns"]) / NS for p in self.phases
                                               if p["phase"] == "soak_healthy"),
                   "unexpected_steady_source_replies": unexpected, "tail_mismatches": mismatches,
                   "unexpected_steady_source_runs": sum(row["unexpected_source_runs"] for row in steady),
                   "activations": activations, "resources": resources, "aggregates": aggregates}
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        if unexpected or mismatches:
            raise RuntimeError(f"Application paths did not match the expected steady results: {mismatches!r}")
        print(f"CE_APPLICATION_BENCHMARK_OK phases={len(self.phases)} output={self.output}", flush=True)


def main():
    if sys.argv[1:2] == ["client"]:
        client(sys.argv[2], float(sys.argv[3]), Path(sys.argv[4]))
        return
    if sys.argv[1:2] == ["serve-probes"]:
        cert, key = Path(sys.argv[2]), Path(sys.argv[3])
        if len(sys.argv) == 6:
            host = (sys.argv[4],)
            serve_probes(cert, key, host, host, Path(sys.argv[5]))
        else:
            serve_probes(cert, key)
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
    parser.add_argument("--soak-mode", choices=("native", "sdwan"), default="sdwan")
    parser.add_argument("--capture-erp", action="store_true", help="capture only lab ERP TCP on LAN and both WANs")
    parser.add_argument("--fault-interval-seconds", type=float, default=1800)
    parser.add_argument("--recovery-hold-seconds", type=int, choices=range(301), metavar="0..300")
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
        if options.capture_erp:
            capture_erp(ce, cleanup, options.output)
        for pair in range(options.pairs):
            experiment.pair = pair + 1
            for mode in (("native", "sdwan") if pair % 2 == 0 else ("sdwan", "native")):
                experiment.activate(mode)
                experiment.cycle()
        if options.soak_hours:
            experiment.pair = None
            experiment.activate(options.soak_mode)
            experiment.soak()
        experiment.summarize()

    ce.appliance(options.image.resolve(), options.ce_version, scenario=scenario)


if __name__ == "__main__":
    main()
