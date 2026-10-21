import argparse
import csv
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import socket
import statistics
import struct
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime


def uncomment(source):
    """Preserve offsets so matches can also be applied to the original source."""
    return re.sub(r"/\*.*?\*/|//[^\n]*",
                  lambda m: "".join("\n" if c == "\n" else " " for c in m[0]),
                  source, flags=re.S)


def prepare_programs(program, output, keep_logging=False, *, baseline_ingress_counter=False):
    """Wrap a conventional, six-control V1Switch without editing its source."""
    source = program.read_text()
    if not keep_logging:
        source = re.sub(r"^[ \t]*#define[ \t]+ENABLE_LOGGING\b[^\n]*",
                        "// ENABLE_LOGGING disabled for measurement",
                        source, flags=re.M)
    clean = uncomment(source)
    instance = r"([A-Za-z_]\w*)\s*\(\s*\)"
    main = re.search(r"\bV1Switch\s*\(\s*" + r"\s*,\s*".join([instance] * 6)
                     + r"\s*\)\s*main\s*;", clean)
    if not main:
        raise ValueError("Expected V1Switch(Parser(), Verify(), Ingress(), "
                         "Egress(), Checksum(), Deparser()) main;")
    ingress = main[3]
    control = re.search(r"\bcontrol\s+" + re.escape(ingress)
                        + r"\s*\((.*?)\)\s*\{", clean, flags=re.S)
    if not control:
        raise ValueError("Ingress control must be declared in the selected P4 file.")
    parameters = control[1].split(",")
    parsed = [re.fullmatch(r"\s*inout\s+(\w+)\s+(\w+)\s*", p)
              for p in parameters]
    if len(parsed) != 3 or not all(parsed) or parsed[2][1] != "standard_metadata_t":
        raise ValueError("Expected three inout ingress parameters: headers, "
                         "metadata, standard_metadata_t.")
    names = [p[2] for p in parsed]
    standard = names[2]
    programs = {}
    for variant in ("baseline", "detector"):
        wrapper_name = "PerformanceIngressWrapper"
        if re.search(r"\b" + wrapper_name + r"\b", clean):
            raise ValueError(f"Reserved benchmark name already used: {wrapper_name}")
        declaration = f"{ingress}() measured_ingress;" if variant == "detector" else ""
        call = f"measured_ingress.apply({', '.join(names)});" if variant == "detector" else ""
        monitoring = ""
        if variant == "baseline" and baseline_ingress_counter:
            # Match the detector's completed-ingress instrumentation. Index 1
            # remains zero because the baseline has no detection logic.
            declaration = "register<bit<32>>(2) benchmark_counts;"
            monitoring = """
        bit<32> processed;
        benchmark_counts.read(processed, 0);
        benchmark_counts.write(0, processed + 1);
"""
        wrapper = f"""
control {wrapper_name}({control[1]}) {{
    {declaration}
    apply {{
        // Set forwarding before detection so detector drops remain effective.
        {standard}.egress_spec = ({standard}.ingress_port == 1) ? 9w2 : 9w1;
        {call}
        {monitoring}
    }}
}}
"""
        start, end = main.span(3)
        generated = (source[:main.start()] + wrapper
                     + source[main.start():start] + wrapper_name + source[end:])
        p4_path = output / f"{variant}.p4"
        json_path = output / f"{variant}.json"
        p4_path.write_text(generated)
        subprocess.run(["p4c-bm2-ss", "-I", str(program.parent), str(p4_path),
                        "-o", str(json_path)], check=True)
        programs[variant] = json_path
    return programs


@contextmanager
def interfaces():
    # Unique names; never delete or stop interfaces/switches owned by another run.
    prefix = "pl" + secrets.token_hex(4)
    ports = [prefix + suffix for suffix in ("a", "b", "c", "d")]
    created = []
    try:
        for first, peer in (ports[:2], ports[2:]):
            subprocess.run(["ip", "link", "add", first, "type", "veth",
                            "peer", "name", peer], check=True)
            created.append(first)
            for port in (first, peer):
                subprocess.run(["ip", "link", "set", port, "up"], check=True)
        yield ports
    finally:
        for port in created:
            subprocess.run(["ip", "link", "del", port], check=False)


@contextmanager
def running_switch(program, ports, log_path):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        thrift_port = reservation.getsockname()[1]
    with log_path.open("w") as log:
        process = subprocess.Popen(
            ["simple_switch", "--thrift-port", str(thrift_port),
             "-i", f"1@{ports[0]}", "-i", f"2@{ports[2]}", str(program)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"BMv2 exited; see {log_path}")
                try:
                    with socket.create_connection(("127.0.0.1", thrift_port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"BMv2 startup timed out; see {log_path}")
                    time.sleep(0.05)
            time.sleep(0.2)
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


# Linux SO_TIMESTAMPNS (old ABI), native timespec. Reject unsupported hosts.
SO_TIMESTAMPNS = 35
TIMESPEC = struct.Struct("@ll")


def capture_socket(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        sock.bind((interface, 0))
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


def receive_timestamp(sock, marker):
    data, ancillary, flags, _ = sock.recvmsg(65535, socket.CMSG_SPACE(TIMESPEC.size))
    # Fixed Ethernet / IPv4 / TCP headers, with a run nonce + sequence in payload.
    if data[54:70] != marker:
        return None
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise RuntimeError("Truncated packet or timestamp ancillary data.")
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            seconds, nanoseconds = TIMESPEC.unpack(value[:TIMESPEC.size])
            return seconds * 1_000_000_000 + nanoseconds
    raise RuntimeError("Matched packet has no kernel timestamp.")


def measure(args, ports, variant, repetition, writer, process):
    from scapy.all import Ether, IP, TCP, Raw

    # Port 2 is the client side in cms_reg_array's server/client convention.
    ingress, sender, egress = ((ports[2], ports[3], ports[1])
                               if args.ingress_port == 2
                               else (ports[0], ports[1], ports[3]))
    nonce = secrets.token_bytes(8)
    latencies = []
    counts = {"sent": args.packets, "received": 0, "missing_ingress": 0,
              "missing_egress": 0, "invalid_timestamp": 0}
    with capture_socket(ingress) as rx_in, capture_socket(egress) as rx_out, \
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as tx, \
            selectors.DefaultSelector() as selector:
        tx.bind((sender, 0))
        selector.register(rx_in, selectors.EVENT_READ, "ingress")
        selector.register(rx_out, selectors.EVENT_READ, "egress")
        next_send = time.monotonic()
        for sequence in range(args.warmup + args.packets):
            marker = nonce + struct.pack("!Q", sequence)
            packet = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                           / IP(src="198.18.0.1", dst="198.18.0.2")
                           / TCP(sport=12345, dport=80, flags=args.tcp_flags, seq=sequence)
                           / Raw(marker + bytes(args.packet_size - 70)))
            time.sleep(max(0, next_send - time.monotonic()))
            if process.poll() is not None:
                raise RuntimeError("BMv2 exited during measurement; check its run log.")
            tx.send(packet)
            sent_at = time.monotonic()
            next_send = sent_at + args.interval_ms / 1000
            deadline = sent_at + args.timeout_ms / 1000
            stamps = {}
            while len(stamps) < 2:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                for key, _ in selector.select(remaining):
                    stamp = receive_timestamp(key.fileobj, marker)
                    if stamp is not None:
                        stamps.setdefault(key.data, stamp)
            latency = None
            if "ingress" not in stamps:
                status = "missing_ingress"
            elif "egress" not in stamps:
                status = "missing_egress"
            elif stamps["egress"] < stamps["ingress"]:
                status = "invalid_timestamp"
            else:
                status = "received"
                latency = (stamps["egress"] - stamps["ingress"]) / 1000
            warmup = sequence < args.warmup
            writer.writerow([variant, repetition, sequence, warmup, status,
                             stamps.get("ingress", ""), stamps.get("egress", ""),
                             "" if latency is None else latency])
            if not warmup:
                counts[status] += 1
                if latency is not None:
                    latencies.append(latency)
    return counts, latencies


def percentile(values, percent):
    ordered = sorted(values)
    position = (len(ordered) - 1) * percent / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(values):
    if not values:
        return None
    return {"mean_us": statistics.mean(values), "median_us": statistics.median(values),
            "p95_us": percentile(values, 95), "p99_us": percentile(values, 99),
            "min_us": min(values), "max_us": max(values)}


def positive_int(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def positive_float(value):
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be positive and finite")
    return value


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p4-program", "--p4_program", type=Path, required=True)
    parser.add_argument("--packets", type=positive_int, default=200,
                        help="Measured probes per run (default: 200).")
    parser.add_argument("--warmup", type=int, default=20,
                        help="Unmeasured probes per run; detector state is retained.")
    parser.add_argument("--repetitions", type=positive_int, default=3)
    parser.add_argument("--interval-ms", type=positive_float, default=10,
                        help="Minimum interval between probes; only one is outstanding.")
    parser.add_argument("--timeout-ms", type=positive_float, default=100)
    parser.add_argument("--packet-size", type=int, default=128,
                        help="Ethernet frame bytes excluding FCS (70–1514).")
    parser.add_argument("--tcp-flags", choices=["S", "A", "SA", "PA"], default="S")
    parser.add_argument("--ingress-port", type=int, choices=[1, 2], default=2)
    parser.add_argument("--keep-p4-logging", action="store_true")
    parser.add_argument("--compile-only", action="store_true",
                        help="Generate and compile both variants without root/network setup.")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.warmup < 0 or not 70 <= args.packet_size <= 1514:
        parser.error("--warmup must be nonnegative; --packet-size must be 70–1514")
    args.p4_program = args.p4_program.resolve()
    if not args.p4_program.is_file():
        parser.error(f"P4 source does not exist: {args.p4_program}")
    if os.name != "posix" or not hasattr(socket, "AF_PACKET") or TIMESPEC.size != 16:
        parser.error("This benchmark requires 64-bit Linux kernel packet timestamps.")
    for binary in (["p4c-bm2-ss"] if args.compile_only else ["p4c-bm2-ss", "simple_switch", "ip"]):
        if not shutil.which(binary):
            parser.error(f"Required executable not found: {binary}")
    if not args.compile_only and os.geteuid() != 0:
        parser.error("Run with sudo for raw sockets, veth setup and BMv2, "
                     "or use --compile-only.")
    return args


def main():
    args = parse_args()
    output = (args.output_dir or Path(__file__).parent / "results"
              / ("performance_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f"))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    programs = prepare_programs(args.p4_program, output, args.keep_p4_logging)
    print(f"Compiled baseline and detector variants: {output}", flush=True)
    if args.compile_only:
        return
    pooled = {"baseline": [], "detector": []}
    runs = []
    with (output / "packets.csv").open("w", newline="") as csv_file, interfaces() as ports:
        writer = csv.writer(csv_file)
        writer.writerow(["variant", "repetition", "sequence", "warmup", "status",
                         "ingress_timestamp_ns", "egress_timestamp_ns", "latency_us"])
        for repetition in range(1, args.repetitions + 1):
            order = ("baseline", "detector") if repetition % 2 else ("detector", "baseline")
            for variant in order:
                print(f"Run {repetition}/{args.repetitions}: {variant}", flush=True)
                log = output / f"{variant}_{repetition}.log"
                with running_switch(programs[variant], ports, log) as process:
                    counts, values = measure(args, ports, variant, repetition, writer, process)
                csv_file.flush()
                pooled[variant].extend(values)
                runs.append({"variant": variant, "repetition": repetition,
                             **counts, "latency": summarize(values)})
                print(f"  Received {counts['received']}/{counts['sent']} measured probes; "
                      f"median: {statistics.median(values):.2f} us" if values else
                      f"  No usable latency samples: {counts}", flush=True)
    summaries = {name: summarize(values) for name, values in pooled.items()}
    delta = None
    if all(summaries.values()):
        delta = {key: summaries["detector"][key] - summaries["baseline"][key]
                 for key in ("mean_us", "median_us", "p95_us", "p99_us")}
    result = {
        "configuration": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "measurement": "Kernel RX timestamp at switch ingress to kernel RX timestamp at "
                       "output peer. Delivered probes only; includes BMv2 and host overhead.",
        "baseline": "Same parser, verify, egress, checksum and deparser; ingress replaced "
                    "with two-port forwarding. Detector gets forwarding before its ingress.",
        "runs": runs, "pooled_latency": summaries,
        "detector_minus_baseline_us": delta,
        "all_measured_probes_received": all(r["received"] == r["sent"] for r in runs),
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = ["BMv2 delivered-packet latency (microseconds)",
             "Variant       Mean       Median       p95       p99"]
    for name, stats in summaries.items():
        if stats:
            lines.append(f"{name:<10} {stats['mean_us']:9.2f} {stats['median_us']:10.2f}"
                         f" {stats['p95_us']:9.2f} {stats['p99_us']:9.2f}")
        else:
            lines.append(f"{name:<10} No usable samples")
    for name in pooled:
        selected = [run for run in runs if run["variant"] == name]
        lines.append(f"{name}: " + ", ".join(
            f"{key}={sum(run[key] for run in selected)}"
            for key in ("sent", "received", "missing_ingress", "missing_egress",
                        "invalid_timestamp")))
    if delta:
        lines.append(f"Detector minus baseline median: {delta['median_us']:.2f} us")
    lines += [
        "Differences compare distributions, not matched per-packet added delays.",
        "This is a low-load, repeated-flow BMv2 measurement, not hardware pipeline latency.",
        "Timeouts can mean detector drops, host loss, or late packets; they are not zero latency.",
        "Missing samples make the comparison conditional on packet delivery.",
        "Negative differences are possible from host noise; inspect repeat variability.",
        f"Results: {output}",
    ]
    report = "\n".join(lines) + "\n"
    (output / "summary.txt").write_text(report)
    print(report, end="")
    if not all(summaries.values()):
        raise RuntimeError("At least one variant has no usable samples; no overhead estimate.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Performance benchmark failed: {error}")
