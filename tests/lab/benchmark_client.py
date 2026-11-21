"""Measure end-to-end transactions inside the isolated FreeBSD PF VNET lab.

All timestamps share the VNET host's monotonic clock, in nanoseconds. Slots
use an absolute cadence. Each flow has its own worker, so a timeout cannot
stall the other flows. Scheduling delays remain visible in started_ns
rather than being counted as network latency.
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import math
import os
import pathlib
import socket
import struct
import threading
import time


ERP = ("192.0.2.162", 7)
BACKUP = ("192.0.2.165", 7)
DNS = ("192.0.2.162", 53)
DNS_ANSWER = "192.0.2.42"
DNS_NAME = b"\x06health\x05sdwan\x04test\x00"
DNS_QUESTION = DNS_NAME + struct.pack("!HH", 1, 1)
FIELDS = (
    "run", "mode", "scenario", "flow", "sequence", "planned_ns",
    "started_ns", "connect_ns", "ended_ns", "status", "peer_source", "marker", "error",
)
NANOSECONDS = 1_000_000_000


class ProtocolError(Exception):
    """The peer answered without proving the requested transaction."""


def set_deadline(sock, deadline_ns):
    remaining = (deadline_ns - time.monotonic_ns()) / NANOSECONDS
    if remaining <= 0:
        raise TimeoutError("transaction deadline elapsed")
    sock.settimeout(remaining)


class TcpPeer:
    def __init__(self, endpoint):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.endpoint = endpoint
        self.buffer = b""
        self.pending = set()
        self.source = ""

    def connect(self, deadline_ns):
        set_deadline(self.sock, deadline_ns)
        self.sock.connect(self.endpoint)

    def close(self):
        self.sock.close()

    def request(self, marker, deadline_ns):
        set_deadline(self.sock, deadline_ns)
        self.sock.sendall(marker.encode("ascii") + b"\n")
        self.pending.add(marker)

    def response(self, marker, deadline_ns):
        while True:
            while b"\n" not in self.buffer:
                set_deadline(self.sock, deadline_ns)
                chunk = self.sock.recv(256)
                if not chunk:
                    raise EOFError("peer closed the TCP stream")
                self.buffer += chunk
                if b"\n" not in self.buffer and len(self.buffer) > 256:
                    raise ProtocolError("overlong TCP reply without a terminator")
            line, self.buffer = self.buffer.split(b"\n", 1)
            try:
                source_text, echoed = line.decode("ascii").split(" ")
                source = str(ipaddress.IPv4Address(source_text))
            except ValueError as error:
                raise ProtocolError("invalid peer address or TCP reply format") from error
            if self.source and source != self.source:
                raise ProtocolError("reported source changed on one TCP session")
            if echoed not in self.pending:
                raise ProtocolError("unexpected TCP reply marker")
            self.source = source
            self.pending.remove(echoed)
            if echoed == marker:
                return source
            # A reply for a prior timed-out request proves only that the
            # prior request arrived. Never count it as this slot's response.


def validate_dns(reply, transaction):
    if len(reply) < 12:
        raise ProtocolError("short DNS header")
    identifier, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", reply)
    if identifier != transaction or not flags & 0x8000 or flags & 0x7A00 or questions != 1:
        raise ProtocolError("invalid DNS identifier, flags or question count")
    if flags & 0x000F:
        raise ProtocolError(f"DNS response code {flags & 0x000F}")
    offset = 12 + len(DNS_QUESTION)
    if reply[12:offset] != DNS_QUESTION or not answers:
        raise ProtocolError("DNS question mismatched or no answer returned")
    if reply[offset:offset + 2] == b"\xc0\x0c":
        offset += 2
    elif reply[offset:offset + len(DNS_NAME)] == DNS_NAME:
        offset += len(DNS_NAME)
    else:
        raise ProtocolError("DNS answer name did not match the query")
    if len(reply) < offset + 14:
        raise ProtocolError("short DNS answer")
    record_type, record_class, _, size = struct.unpack_from("!HHIH", reply, offset)
    if (record_type, record_class, size) != (1, 1, 4):
        raise ProtocolError("unexpected DNS record type, class or address length")
    address = socket.inet_ntoa(reply[offset + 10:offset + 14])
    if address != DNS_ANSWER:
        raise ProtocolError(f"unexpected DNS address {address}")


def dns_transaction(sequence, deadline_ns):
    transaction = sequence & 0xFFFF
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + DNS_QUESTION
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(DNS)
        set_deadline(sock, deadline_ns)
        sock.send(query)
        set_deadline(sock, deadline_ns)
        validate_dns(sock.recv(2048), transaction)


def classify(error):
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, ConnectionRefusedError):
        return "refused"
    if isinstance(error, (EOFError, ConnectionError)):
        return "closed"
    if isinstance(error, ProtocolError):
        return "protocol_error"
    return "os_error"


def sample_flow(flow, args, origin_ns, start, emit):
    persistent = flow == "erp_persistent"
    endpoint = BACKUP if flow == "backup" else ERP
    session = None
    broken = False
    start.wait()
    try:
        for sequence, offset in enumerate(range(0, args.duration_ns, args.interval_ns), start=1):
            planned_ns = origin_ns + offset
            wait_ns = planned_ns - time.monotonic_ns()
            if wait_ns > 0:
                time.sleep(wait_ns / NANOSECONDS)
            started_ns = time.monotonic_ns()
            deadline_ns = started_ns + args.timeout_ns
            row = dict(
                run=args.run, mode=args.mode, scenario=args.scenario, flow=flow,
                sequence=sequence, planned_ns=planned_ns, started_ns=started_ns,
                connect_ns="", status="ok", peer_source="", marker="", error="",
            )
            phase = "dns"
            try:
                if broken:
                    row["status"] = "session_lost"
                    row["error"] = "original TCP socket closed and was not reopened"
                elif flow == "dns":
                    dns_transaction(sequence, deadline_ns)
                    row["marker"] = DNS_ANSWER
                else:
                    row["marker"] = f"{flow}-{sequence:06d}"
                    if session is None:
                        phase = "connect"
                        session = TcpPeer(endpoint)
                        session.connect(deadline_ns)
                        row["connect_ns"] = time.monotonic_ns()
                    phase = "send"
                    session.request(row["marker"], deadline_ns)
                    phase = "receive"
                    row["peer_source"] = session.response(row["marker"], deadline_ns)
            except (OSError, EOFError, ProtocolError) as error:
                row["status"] = classify(error)
                row["error"] = f"{phase}: {error}"
                # A receive timeout leaves a possible recovery on the same
                # socket. A send failure leaves the TCP framing uncertain.
                broken = persistent and (row["status"] != "timeout" or phase != "receive")
            finally:
                row["ended_ns"] = time.monotonic_ns()
                if session is not None and (not persistent or broken):
                    session.close()
                    session = None
            emit(row)
    finally:
        if session is not None:
            session.close()


def positive_seconds(value):
    try:
        seconds = float(value)
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError
        nanoseconds = round(seconds * NANOSECONDS)
        if nanoseconds <= 0:
            raise ValueError
    except (OverflowError, ValueError):
        raise argparse.ArgumentTypeError("use a finite positive duration of at least 1 ns") from None
    return nanoseconds


def run(args):
    if args.ready_file is not None and args.ready_file.resolve() == args.output.resolve():
        raise ValueError("the ready file must differ from the transaction CSV")
    flows = ("erp", "backup", "dns", "erp_persistent")
    origin_ns = args.start_ns
    if origin_ns is None:
        origin_ns = time.monotonic_ns() + 250_000_000
    lock = threading.Lock()
    start = threading.Event()
    with args.output.open("x", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, FIELDS, lineterminator="\n")
        writer.writeheader()
        output.flush()

        def emit(row):
            with lock:
                writer.writerow(row)
                output.flush()

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(flows)) as executor:
            tasks = [executor.submit(sample_flow, flow, args, origin_ns, start, emit) for flow in flows]
            if args.ready_file is not None:
                temporary = args.ready_file.with_name(f".{args.ready_file.name}.{os.getpid()}.tmp")
                try:
                    temporary.write_text(f"{origin_ns}\n", encoding="ascii")
                    temporary.replace(args.ready_file)
                finally:
                    start.set()
            else:
                start.set()
            for task in tasks:
                task.result()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path, help="new CSV file for the transactions")
    parser.add_argument("--duration", dest="duration_ns", type=positive_seconds, required=True)
    parser.add_argument("--interval", dest="interval_ns", type=positive_seconds, required=True)
    parser.add_argument("--timeout", dest="timeout_ns", type=positive_seconds, required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--ready-file", type=pathlib.Path, help="publish a monotonic start time in ns")
    parser.add_argument("--start-ns", type=int, help="use a specified absolute monotonic start time")
    args = parser.parse_args()
    if args.start_ns is not None and args.start_ns <= 0:
        parser.error("--start-ns must be positive")
    run(args)


if __name__ == "__main__":
    main()
