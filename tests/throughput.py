"""Measure achieved TCP ingress throughput of both detectors and baselines on BMv2."""

import argparse
from contextlib import contextmanager
import csv
from datetime import datetime
import json
import math
from pathlib import Path
import shutil
import socket
import statistics
import struct
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time

import pynng
from bm_runtime.standard import Standard
from scapy.all import Ether, IP, TCP, Raw
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol
from thrift.transport import TSocket, TTransport

from performance import prepare_programs

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["program", "variant", "repetition", "tcp_flags", "packet_size_bytes", "flows",
          "warmup_packets", "requested", "sent", "received", "missing",
          "detections", "send_seconds", "drain_seconds", "elapsed_seconds",
          "tcp_packets_per_second", "status", "error"]


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be positive and finite")
    return number


def packet_pool(size, flows, flags):
    """Build valid frames and packet-in envelopes outside the measured interval."""
    messages = []
    for flow in range(flows):
        # Distinct clients, one destination: repeated SYNs model a sustained flood.
        client = socket.inet_ntoa(struct.pack("!I", 0xC6120001 + flow))
        frame = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                      / IP(src=client, dst="198.19.255.254")
                      / TCP(sport=1024 + flow % 64512, dport=80, flags=flags, seq=flow)
                      / Raw(bytes(size - 54)))
        messages.append(struct.pack("<iii", 3, 2, len(frame)) + frame)
    return messages


def drain(packets):
    try:
        while True:
            packets.recv()
    except pynng.Closed:
        pass


@contextmanager
def running_switch(program, log_path, timeout):
    """Use isolated IPC endpoints and an ephemeral Thrift port; no root needed."""
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    transport = TSocket.TSocket("127.0.0.1", port)
    transport.setTimeout(5000)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    with TemporaryDirectory(prefix="throughput_") as directory, log_path.open("w") as log:
        address = f"ipc://{directory}/packets.ipc"
        process = subprocess.Popen(
            ["simple_switch", "--packet-in", address, "--thrift-port", str(port),
             "--notifications-addr", f"ipc://{directory}/notifications.ipc",
             "--log-level", "off", str(program)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"Switch failed to start; see {log_path}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            transport.open()
            with pynng.Pair0(dial=address, send_timeout=math.ceil(timeout * 1000)) as packets:
                worker = Thread(target=drain, args=(packets,), daemon=True)
                worker.start()
                try:
                    yield Standard.Client(protocol), packets
                finally:
                    packets.close()
                    worker.join(timeout=2)
        finally:
            transport.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def ingress_counter(program):
    """Resolve the monitor name after the compiler has wrapped the ingress."""
    registers = json.loads(program.read_text())["register_arrays"]
    names = [r["name"] for r in registers
             if r["name"].endswith(".benchmark_counts") and r["size"] == 2
             and r["bitwidth"] == 32]
    if len(names) != 1:
        raise ValueError(f"{program}: expected one 32-bit, two-slot benchmark_counts register")
    return names[0]


def measure(client, packets, messages, count, timeout, label, counter):
    """Time a continuous batch through ingress, including sender and queue drain."""
    initial = client.bm_register_read(0, counter, 0)
    initial_detections = client.bm_register_read(0, counter, 1)
    state = {"sent": 0, "finished": None, "error": ""}
    stop, done = Event(), Event()

    def send():
        try:
            for index in range(count):
                if stop.is_set():
                    break
                packets.send(messages[index % len(messages)])
                state["sent"] += 1
        except Exception as error:
            state["error"] = f"{type(error).__name__}: {error}"
        finally:
            state["finished"] = time.perf_counter()
            done.set()

    started = time.perf_counter()
    next_progress = started + 5
    sender = Thread(target=send, daemon=True)
    sender.start()
    error = ""
    received = 0
    try:
        while True:
            # Once done is observed, sent is stable and the following read can
            # confirm completion. Reading first can race with the last send.
            finished = done.is_set()
            received = client.bm_register_read(0, counter, 0) - initial
            ended = time.perf_counter()
            if finished and received == state["sent"]:
                break
            if finished and ended - state["finished"] >= timeout:
                error = "Timed out waiting for completed ingress packets"
                break
            if ended >= next_progress:
                print(f"  {label}: sent={state['sent']:,}, ingress={received:,}", flush=True)
                next_progress = ended + 5
            time.sleep(0.001)
    finally:
        stop.set()
        sender.join(timeout=timeout + 1)
    detections = client.bm_register_read(0, counter, 1) - initial_detections
    elapsed = ended - started
    error = state["error"] or error
    complete = not error and state["sent"] == count and received == count
    return dict(requested=count, sent=state["sent"], received=received,
                missing=max(0, state["sent"] - received), detections=detections,
                send_seconds=state["finished"] - started,
                drain_seconds=max(0, ended - state["finished"]), elapsed_seconds=elapsed,
                tcp_packets_per_second=received / elapsed,
                status="ok" if complete else "incomplete", error=error)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=positive_int, default=250000,
                        help="Measured TCP packets per repetition (default: 250000).")
    parser.add_argument("--warmup", type=int, default=10000,
                        help="Unmeasured packets; detector state is retained (default: 10000).")
    parser.add_argument("--repetitions", type=positive_int, default=3)
    parser.add_argument("--packet-size", type=int, default=128,
                        help="Ethernet frame bytes excluding FCS (60–1514; default: 128).")
    parser.add_argument("--flows", type=positive_int, default=4096,
                        help="Distinct clients in the repeating packet pool (default: 4096).")
    parser.add_argument("--tcp-flags", choices=["S", "A", "SA", "PA"], default="S",
                        help="TCP flags; default S measures a SYN flood, not a normal TCP mix.")
    parser.add_argument("--timeout", type=positive_float, default=10,
                        help="Send timeout and final ingress drain timeout in seconds.")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.warmup < 0 or args.warmup + args.packets >= 2**32:
        parser.error("warmup must be nonnegative and warmup + packets must be below 2^32")
    if not 60 <= args.packet_size <= 1514:
        parser.error("packet-size must be between 60 and 1514")
    if args.flows > 65536:
        parser.error("flows must not exceed 65536")
    for command in ("p4c-bm2-ss", "simple_switch"):
        if not shutil.which(command):
            parser.error(f"Required executable not found: {command}")
    return args


def main():
    args = parse_args()
    output = (args.output_dir or ROOT / "tests/results" /
              datetime.now().strftime("throughput_%Y%m%d_%H%M%S_%f")).resolve()
    output.mkdir(parents=True, exist_ok=False)
    configuration = {key: str(value) if isinstance(value, Path) else value
                     for key, value in vars(args).items()}
    configuration["measurement"] = (
        "Completed TCP ingress packets / wall seconds from sender start to final ingress "
        "confirmation, including queue drain. Includes local sender/IPC/BMv2 overhead; "
        "achieved throughput, not proof of maximum capacity or forwarded throughput. "
        "Prebuilt IPv4/TCP frames repeat across a fixed client pool, entering port 2. "
        "Warmup retains detector state; each repetition uses a fresh switch. "
        "BMv2 logging is off and ENABLE_LOGGING is disabled in generated programs. "
        "P4 thresholds and detector monitoring counters are unchanged.")
    configuration["baseline"] = (
        "Uses performance.py's prepare_programs: original parser, verify, egress, "
        "checksum and deparser, with ingress replaced by two-port forwarding. "
        "Baseline adds the same completed-ingress counter used by the detector; "
        "its detection count remains zero. Detector gets the same forwarding "
        "wrapper before detection, preserving detector drops. Rates count ingress, "
        "not forwarded packets; baseline and detector can have different egress loads.")
    (output / "configuration.json").write_text(json.dumps(configuration, indent=2) + "\n")
    print(f"Results: {output}\nBuilding {args.flows:,} TCP frames...", flush=True)
    messages = packet_pool(args.packet_size, args.flows, args.tcp_flags)
    programs = {}
    for name in ("two_thresholds", "cms_reg_array"):
        source = ROOT / "src" / name / "main.p4"
        build = output / name
        build.mkdir()
        (build / "main.p4").write_text(source.read_text())
        for variant, compiled in prepare_programs(
                source, build, baseline_ingress_counter=True).items():
            programs[name, variant] = (compiled, ingress_counter(compiled))
    runs = []
    with (output / "throughput.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        file.flush()
        for repetition in range(1, args.repetitions + 1):
            # Alternate order to reduce consistent first/last-run bias.
            order = list(programs) if repetition % 2 else list(reversed(programs))
            for name, variant in order:
                label = f"{name}/{variant} {repetition}/{args.repetitions}"
                print(f"Running {label}", flush=True)
                compiled, counter = programs[name, variant]
                with running_switch(compiled, compiled.parent / f"{variant}_{repetition}.log",
                                    args.timeout) as (client, packets):
                    if args.warmup:
                        warmup = measure(client, packets, messages, args.warmup,
                                         args.timeout, label + " warmup", counter)
                        if warmup["status"] != "ok":
                            raise RuntimeError(f"{label}: warmup failed: {warmup}")
                    result = measure(client, packets, messages, args.packets, args.timeout, label, counter)
                row = dict(program=name, variant=variant, repetition=repetition, tcp_flags=args.tcp_flags,
                           packet_size_bytes=args.packet_size, flows=args.flows,
                           warmup_packets=args.warmup, **result)
                writer.writerow(row)
                file.flush()
                runs.append(row)
                print(f"  {result['tcp_packets_per_second']:,.0f} TCP packets/s; "
                      f"received {result['received']:,}/{result['sent']:,}; "
                      f"{result['elapsed_seconds']:.3f} s; {result['status']}", flush=True)
    summary_fields = ["program", "variant", "successful_runs", "failed_runs", "mean_tcp_packets_per_second",
                      "median_tcp_packets_per_second", "min_tcp_packets_per_second",
                      "max_tcp_packets_per_second"]
    with (output / "summary.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=summary_fields)
        writer.writeheader()
        for name, variant in programs:
            selected = [r for r in runs if r["program"] == name and r["variant"] == variant]
            rates = [r["tcp_packets_per_second"] for r in selected if r["status"] == "ok"]
            row = dict(program=name, variant=variant, successful_runs=len(rates),
                       failed_runs=len(selected)-len(rates))
            for key, function in (("mean", statistics.mean), ("median", statistics.median),
                                  ("min", min), ("max", max)):
                row[f"{key}_tcp_packets_per_second"] = function(rates) if rates else ""
            writer.writerow(row)
            if rates:
                print(f"{name}/{variant}: median {statistics.median(rates):,.0f} TCP packets/s "
                      f"(range {min(rates):,.0f}–{max(rates):,.0f}; "
                      f"{len(rates)} successful runs)")
            else:
                print(f"{name}/{variant}: no successful runs")
    print("Rates include sender/IPC overhead and may be sender-limited. "
          "Detector drops count as completed ingress, not delivery loss.")
    print(f"Per-run CSV: {output / 'throughput.csv'}\nSummary CSV: {output / 'summary.csv'}")
    if any(row["status"] != "ok" for row in runs):
        raise RuntimeError("Incomplete delivery; failed runs were recorded and excluded from summary rates")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            pynng.NNGException, TTransport.TTransportException) as error:
        raise SystemExit(f"Throughput benchmark failed: {error}")
