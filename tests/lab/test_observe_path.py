"""Exercise the clone collector using synthetic tcpdump output with NAT."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import tempfile


COLLECTOR = Path(__file__).resolve().with_name("observe-path.sh")
FAKE_TCPDUMP = """#!/usr/bin/env python3
import os, signal, sys, time
iface = sys.argv[sys.argv.index("-i")+1]
case = os.environ["PATH_TEST_CASE"]
client = "192.0.2.10" if iface == "lan0" else "198.51.100.10"
peer = "203.0.113.50"
bpf = sys.argv[-1]
assert "src host " + client in bpf and "dst host " + client in bpf
assert "src host " + peer in bpf and "dst host " + peer in bpf
assert "icmp-echo)" in bpf and "icmp-echoreply)" in bpf
stopping = False
def stop(sig, frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
print("tcpdump: listening on " + iface, file=sys.stderr, flush=True)
while not stopping: time.sleep(0.01)
count = 0
for seq in ([] if case == "empty" else [1, 2]):
    for direction in ("request", "reply"):
        if case == "missing" and iface == "path0" and direction == "reply": continue
        address, dest = (client, peer) if direction == "request" else (peer, client)
        ident = 1562 if iface == "lan0" else 2834
        if case == "overlap" and seq == 2: ident += 1
        print(f"IP {address} > {dest}: ICMP echo {direction}, id {ident}, seq {seq}, length 64")
        count += 1
print(f"{count + int(case=='decode')} packets captured", file=sys.stderr)
print(f"{int(case=='drops')} packets dropped by kernel", file=sys.stderr)
"""


def run_case(params):
    binary_dir, case, expected_status, result = params
    env = dict(os.environ, PATH=f"{binary_dir}:{os.environ['PATH']}", PATH_TEST_CASE=case)
    command = ["sh", str(COLLECTOR), "lan0", "path0", "192.0.2.10",
               "198.51.100.10", "203.0.113.50", "5"]
    run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
    assert run.returncode == expected_status, (case, run.returncode, run.stderr, run.stdout)
    assert all(addr not in run.stdout + run.stderr for addr in command[-4:-1]), case
    if result is None:
        assert not run.stdout, case
    else:
        data = json.loads(run.stdout)
        assert data["result"] == result, (case, data)
        if case == "nat":
            assert data["complete_sequences"] == 2 and data["path_replies"] == 2
        if case == "missing":
            assert data["complete_sequences"] == 0 and data["path_replies"] == 0


if __name__ == "__main__":
    cases = [("nat", 0, "round_trip_observed"), ("empty", 1, "no_samples"),
             ("missing", 1, "incomplete"), ("overlap", 1, "multiple_flows"),
             ("drops", 2, None), ("decode", 2, None)]
    with tempfile.TemporaryDirectory() as directory:
        fake = Path(directory) / "tcpdump"
        fake.write_text(FAKE_TCPDUMP)
        fake.chmod(0o755)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(cases)) as workers:
            list(workers.map(run_case, [(directory, *case) for case in cases]))
    print("ok - collector accounts for both paths, NAT IDs, gaps, mixed flows and capture loss")
