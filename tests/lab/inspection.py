#!/usr/bin/env python3
"""Exercise Suricata alert and drop rules on both simulated SD-WAN paths."""

from collections import Counter
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

from ikev2.run import PATHS as VPN_PATHS
from ikev2.run import create_network, inside, run, stop_process, wait_for

APP = "198.18.0.10"
CLIENT = "192.0.2.10"
ROUTER = "192.0.2.9"
PATHS = VPN_PATHS[:2]
ENGINE = Path(__file__).resolve().parents[2] / "files/usr/local/pkg/sdwan_engine.inc"
CONTENT = "sdwan-inspection-control"


def start(stack, work, node, label, *command):
    log = stack.enter_context((work / f"{label}.log").open("w"))
    process = subprocess.Popen(inside(node, *command), stdout=log, stderr=log)
    stack.callback(stop_process, process, signal.SIGTERM)
    return process


def request(client, name):
    probe = ("from urllib.request import build_opener, ProxyHandler; import sys; "
             "print(build_opener(ProxyHandler({})).open(sys.argv[1], timeout=2).read().decode())")
    result = run(inside(client, "python3", "-c", probe, f"http://{APP}/{name}"), check=False, timeout=4)
    return result.returncode == 0 and result.stdout.strip() == CONTENT


def recommendation(router):
    gateways = {}
    for path in PATHS:
        probe = run(inside(router, "ping", "-n", "-c", "1", "-W", "1",
                           "-I", "wan" + path.name, path.outer[1]), check=False)
        if probe.returncode == 0:
            sample = re.search(r"=\s+[\d.]+/([\d.]+)/[\d.]+/([\d.]+) ms", probe.stdout)
            if sample is None:
                raise RuntimeError(f"Could not read RTT on WAN {path.name}: {probe.stdout}")
            gateways[path.name] = {"status": "online", "substatus": "none", "delay": sample[1] + "ms",
                                   "stddev": sample[2] + "ms", "loss": "0%"}
        else:
            gateways[path.name] = {"status": "down"}
    config = {
        "members": [{"name": path.name, "gateway": path.name, "cost": idx}
                    for idx, path in enumerate(PATHS)],
        "slas": [{"name": "lab", "latency_ms": 500, "loss_pct": 1}],
        "policies": [{"name": "test", "members": ["a", "b"], "sla": "lab", "strategy": "cost"}],
    }
    script = ("require $argv[1]; [$config, $samples] = json_decode(stream_get_contents(STDIN), true); "
              "echo json_encode(sdwan_evaluate($config, $samples, time())['policies']['test']['selected']);")
    return json.loads(run(["php", "-r", script, "--", str(ENGINE)], data=json.dumps([config, gateways])).stdout)


def alert_counts(work):
    eve = work / "eve.json"
    counts = Counter()
    if eve.is_file():
        for line in eve.read_text().splitlines():
            if not line.endswith("}"):
                continue
            record = json.loads(line)
            if record.get("event_type") == "alert":
                alert = record["alert"]
                counts[alert["signature_id"], alert["action"]] += 1
    return counts


def wan_count(router, path):
    result = json.loads(run(inside(router, "nft", "-j", "list", "counter", "inet",
                                   "sdwan_inspection", "wan_" + path)).stdout)
    return next(item["counter"]["packets"] for item in result["nftables"] if "counter" in item)


def exercise(work, stack):
    suffix = str(os.getpid())
    client, router, server, wire = ["sdins" + name + suffix for name in ("cl", "rt", "srv", "wire")]
    create_network(stack, [router, server], wire, PATHS)
    run(["ip", "netns", "add", client])
    stack.callback(run, ["ip", "netns", "del", client], check=False)
    run(["ip", "-n", router, "link", "add", "lablan", "type", "veth", "peer", "name", "labclient", "netns", client])
    run(["ip", "-n", router, "addr", "add", ROUTER + "/30", "dev", "lablan"])
    run(["ip", "-n", client, "addr", "add", CLIENT + "/30", "dev", "labclient"])
    run(["ip", "-n", router, "link", "set", "lablan", "up"])
    run(["ip", "-n", client, "link", "set", "labclient", "up"])
    run(["ip", "-n", client, "route", "add", APP + "/32", "via", ROUTER])
    run(inside(router, "sysctl", "-w", "net.ipv4.ip_forward=1"))
    run(["ip", "-n", server, "addr", "add", APP + "/32", "dev", "lo"])

    def select(expected):
        selected = recommendation(router)
        if selected != expected:
            raise RuntimeError(f"Expected SD-WAN preference {expected}, got {selected}")
        path = next(path for path in PATHS if path.name == selected)
        run(["ip", "-n", router, "route", "replace", APP + "/32", "via", path.outer[1], "dev", "wan" + selected])
        run(["ip", "-n", server, "route", "replace", CLIENT + "/32", "via", path.outer[0], "dev", "wan" + selected])

    directory = work / "http"
    directory.mkdir()
    for name in ("allowed", "observe", "denied"):
        (directory / name).write_text(CONTENT)
    start(stack, work, server, "http", "python3", "-m", "http.server", "80", "--bind", APP, "--directory", str(directory))
    select("a")
    wait_for("HTTP server on the primary path", lambda: request(client, "allowed"), 10)

    rules = work / "lab.rules"
    rules.write_text(
        f'alert http any any -> {APP} 80 (msg:"SD-WAN lab alert"; flow:established,to_server; '
        'http.uri; content:"/observe"; startswith; endswith; sid:9900001; rev:1;)\n'
        f'drop http any any -> {APP} 80 (msg:"SD-WAN lab block"; flow:established,to_server; '
        'http.uri; content:"/denied"; startswith; endswith; sid:9900002; rev:1;)\n')
    run(inside(router, "nft", "-f", "-"), data=f"""table inet sdwan_inspection {{
        counter wan_a {{ }}
        counter wan_b {{ }}
        chain forward {{
            type filter hook forward priority 10; policy accept;
            oifname "wana" ip daddr {APP} tcp dport 80 counter name wan_a queue num 7
            oifname "wanb" ip daddr {APP} tcp dport 80 counter name wan_b queue num 7
            iifname {{ "wana", "wanb" }} ip saddr {APP} tcp sport 80 queue num 7
        }}
    }}
""")
    engine = start(stack, work, router, "suricata", "suricata", "-c", "/etc/suricata/suricata.yaml",
                   "-S", str(rules), "-l", str(work), "-q", "7", "-k", "none",
                   "--set", "stream.inline=yes", "--set", "unix-command.enabled=no")
    wait_for("Suricata forwarding the control request",
             lambda: engine.poll() is None and request(client, "allowed"), 18)

    def verify_inspection(active, other):
        before = alert_counts(work)
        sent, unused = wan_count(router, active), wan_count(router, other)
        if not request(client, "observe") or request(client, "denied") or not request(client, "allowed"):
            raise RuntimeError(f"Inspection did not produce the expected HTTP results on WAN {active}")
        expected = ((9900001, "allowed"), (9900002, "blocked"))
        wait_for("alert and block in EVE",
                 lambda: all(alert_counts(work)[key] > before[key] for key in expected), 10)
        if "GET /denied " in (work / "http.log").read_text():
            raise RuntimeError("The application received the request that Suricata should have blocked")
        if wan_count(router, active) <= sent or wan_count(router, other) != unused:
            raise RuntimeError("The monitored requests did not use the expected WAN")
        if recommendation(router) != active:
            raise RuntimeError("A blocked application changed SD-WAN gateway eligibility")
        print(f"ok - WAN {active}: alert passed, IPS drop held, control served, and gateway stayed eligible", flush=True)

    verify_inspection("a", "b")
    run(["ip", "-n", router, "link", "set", "wana", "down"])
    select("b")
    verify_inspection("b", "a")
    stop_process(engine, signal.SIGTERM)
    if request(client, "allowed") or recommendation(router) != "b":
        raise RuntimeError("The unserved inspection queue should fail closed while WAN B remains eligible")
    print("ok - stopping the inspection engine blocked queued traffic while WAN b remained eligible", flush=True)


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run as root in a disposable Linux VM with network namespaces.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="sdwan-inspection-") as tmp:
        work = Path(tmp)
        try:
            with ExitStack() as stack:
                exercise(work, stack)
        except Exception:
            for name in ("suricata.log", "http.log"):
                log = work / name
                if log.exists():
                    print(name, log.read_text()[-3500:], flush=True)
            raise
