"""Replay all dataset PCAPs against both detectors, without tuning thresholds."""

import argparse
from collections import Counter
from contextlib import closing, contextmanager
import csv
from datetime import datetime, timedelta, timezone
from itertools import groupby
import math
from pathlib import Path
import socket
import struct
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import time

import pynng
from bm_runtime.standard import Standard
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from scapy.utils import RawPcapReader
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol
from thrift.transport import TSocket, TTransport
from tqdm import tqdm

ROOT = Path(__file__).resolve().parents[1]
COUNTS = "SYNControllerIngress.benchmark_counts"
DATASET_TZ = timezone(timedelta(hours=-4))
OUTCOMES = {"TP": ("Correct attack detection", "#2ca02c"),
            "FN": ("Missed attack", "#d62728"),
            "FP": ("False alarm", "#ff7f0e"),
            "TN": ("Correct non-attack", "#1f77b4")}


def attack_intervals():
    intervals = []
    with (ROOT / "datasets/Syn-day-1.csv").open() as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            if row["Label"].strip().lower() == "syn":
                start = datetime.fromisoformat(row["Timestamp"]).replace(tzinfo=DATASET_TZ).timestamp()
                intervals.append((start, start + float(row["Flow Duration"]) / 1e6))
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if not merged:
        raise ValueError("No SYN attack labels found")
    return merged


def tcp_frames(paths, counts, progress=None):
    """Only header layouts actually supported by these P4 parsers."""
    previous = -math.inf
    for path in paths:
        with closing(RawPcapReader(str(path))) as reader:
            if reader.linktype != 1:
                raise ValueError(f"{path}: expected Ethernet PCAP")
            if progress is not None:
                progress.update(24)  # Classic PCAP file header.
            for raw, meta in reader:
                if progress is not None:
                    progress.update(16 + meta.caplen)
                stamp = meta.sec + meta.usec / (1e9 if reader.nano else 1e6)
                if stamp < previous:
                    raise ValueError(f"{path}: packets are not in timestamp order")
                previous = stamp
                counts["pcap_packets"] += 1
                if len(raw) >= 54 and raw[12:14] == b"\x08\x00" and raw[23] == 6:
                    if raw[14] != 0x45 or int.from_bytes(raw[20:22], "big") & 0x3fff:
                        counts["unsupported_tcp"] += 1
                        continue
                    offset, src, dst = 34, raw[26:30], raw[30:34]
                elif len(raw) >= 74 and raw[12:14] == b"\x86\xdd" and raw[20] == 6:
                    offset, src, dst = 54, raw[22:38], raw[38:54]
                else:
                    counts["other_skipped"] += 1
                    continue
                yield stamp, raw, src + raw[offset:offset+2], dst + raw[offset+2:offset+4], raw[offset+13]


def drain(packets):
    # Consume packet-out messages so the switch's output queue cannot stall.
    try:
        while True:
            packets.recv()
    except pynng.Closed:
        pass


@contextmanager
def switch(program, directory):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    address = f"ipc://{directory}/packets.ipc"
    transport = TSocket.TSocket("127.0.0.1", port)
    transport.setTimeout(5000)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    with (program.parent / "switch.log").open("w") as log:
        process = subprocess.Popen(
            ["simple_switch", "--packet-in", address, "--thrift-port", str(port),
             "--notifications-addr", f"ipc://{directory}/notifications.ipc",
             "--log-level", "off", str(program)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"Switch failed to start; see {log.name}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            transport.open()
            with pynng.Pair0(dial=address, send_timeout=5000) as packets:
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


def plot_results(rows, window_size, path):
    """Match benchmark.py's filled traffic plot; leave unscored gaps blank."""
    if not rows:
        return
    figure = Figure(figsize=(12, 5.5), layout="constrained")
    FigureCanvasAgg(figure)
    axes = figure.subplots()
    slots = {round((row[2] - rows[0][2]) / window_size): row for row in rows}
    boundaries = sorted(set(slots) | {slot + 1 for slot in slots})
    edges = [slot * window_size for slot in boundaries]
    for outcome, (label, color) in OUTCOMES.items():
        values = [slots[slot][4] if slot in slots and slots[slot][-1] == outcome else math.nan
                  for slot in boundaries[:-1]]
        axes.stairs(values, edges, fill=True, color=color, alpha=0.85, label=label)
    for slot, row in slots.items():
        axes.axvspan(slot * window_size, (slot + 1) * window_size, ymin=0, ymax=0.018,
                     color=OUTCOMES[row[-1]][1], linewidth=0)
    start = datetime.fromtimestamp(rows[0][2], DATASET_TZ).replace(tzinfo=None)
    axes.set(title=f"TCP traffic per {window_size:g} s window — {rows[0][0]}/{rows[0][1]}",
             xlabel=f"Seconds since {start} (UTC−4)", ylabel="TCP packets",
             xlim=(0, edges[-1]), ylim=(0, None))
    axes.grid(axis="y", alpha=0.25)
    axes.legend(loc="upper center", bbox_to_anchor=(0.5, -0.19), ncol=3, fontsize=9)
    figure.savefig(path, dpi=160)


def replay(client, packets, paths, intervals, window_size, writer, program, dataset,
           progress=None, plot_path=None):
    directions, counts = {}, Counter()
    rows = []
    sent = last_detections = 0
    frames = tcp_frames(paths, counts, progress)
    for window, frames_in_window in groupby(frames, key=lambda frame: math.floor(frame[0] / window_size)):
        start = window * window_size
        n = syns = 0
        sources = set()
        for _, raw, src, dst, flags in frames_in_window:
            # Learn both directions from SYN or SYN/ACK; midstream flows default to client.
            if flags & 2:
                port = 1 if flags & 16 else 2
                directions[src, dst], directions[dst, src] = port, 3 - port
            port = directions.get((src, dst), 2)
            packets.send(struct.pack("<iii", 3, port, len(raw)) + raw)
            n += 1
            if flags & 0x12 == 2:
                syns += 1
                sources.add(src[:-2])
        sent += n
        # A window is scored only after every injected packet has completed ingress.
        deadline = time.monotonic() + 10
        while client.bm_register_read(0, COUNTS, 0) != sent:
            if time.monotonic() > deadline:
                raise RuntimeError(f"{program}/{dataset}: incomplete delivery; results are incomplete")
            time.sleep(0.001)
        detections = client.bm_register_read(0, COUNTS, 1)
        hits = detections - last_detections
        last_detections = detections
        attack = any(a < start + window_size and b >= start for a, b in intervals)
        outcome = ("TP" if attack else "FP") if hits else ("FN" if attack else "TN")
        counts[outcome] += 1
        row = [program, dataset, start, attack, n, syns, len(sources), hits, outcome]
        writer.writerow(row)
        rows.append(row)
        if progress is not None:
            progress.set_postfix(received=sent, detections=detections,
                                 **{key: counts[key] for key in OUTCOMES}, refresh=False)
    tqdm.write(f"{program}/{dataset}: received={sent:,}, detections={last_detections:,}, "
          f"TP={counts['TP']} FP={counts['FP']} TN={counts['TN']} FN={counts['FN']}; "
          f"skipped={counts['unsupported_tcp'] + counts['other_skipped']:,}")
    if plot_path is not None:
        plot_results(rows, window_size, plot_path)
    return [program, dataset, sent, last_detections, counts["TP"], counts["FP"],
            counts["TN"], counts["FN"], counts["unsupported_tcp"], counts["other_skipped"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p4-program", "--p4_program", type=Path,
                        help="Run one detector instead of both")
    parser.add_argument("--window-size", "--window_size", type=float, default=1.0,
                        help="Capture-time scoring window in seconds; does not reset detector state")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not math.isfinite(args.window_size) or args.window_size <= 0:
        parser.error("--window-size must be positive and finite")
    programs = [args.p4_program.resolve()] if args.p4_program else [
        ROOT / "src" / name / "main.p4" for name in ("two_thresholds", "cms_reg_array")]
    output = args.output_dir or ROOT / "tests/results" / datetime.now().strftime("benchmark2_%Y%m%d_%H%M%S_%f")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    print(f"Loading labels; results: {output}", flush=True)
    intervals = attack_intervals()
    groups = [(name, sorted((ROOT / "datasets" / name).glob("*.pcap")))
              for name in ("benign", "syn-flood-cicddos")]
    if any(not paths for _, paths in groups):
        raise ValueError("Expected PCAPs in datasets/benign and datasets/syn-flood-cicddos")
    with (output / "windows.csv").open("w", newline="") as windows, \
            (output / "summary.csv").open("w", newline="") as summary:
        writer, totals = csv.writer(windows), csv.writer(summary)
        writer.writerow(["program", "dataset", "window_start_unix", "attack", "received",
                         "syn_packets", "syn_sources", "detections", "outcome"])
        totals.writerow(["program", "dataset", "received", "detections", "TP", "FP", "TN", "FN",
                         "unsupported_tcp", "other_skipped"])
        for program in programs:
            build = output / program.parent.name
            build.mkdir()
            (build / "main.p4").write_text(program.read_text())
            compiled = build / "main.json"
            subprocess.run(["p4c-bm2-ss", str(program), "-o", str(compiled)], check=True, timeout=60)
            for dataset, paths in groups:
                # Fresh state for benign vs CIC; continuous state across the four CIC files.
                with TemporaryDirectory(prefix="benchmark2_") as tmp, \
                        switch(compiled, tmp) as (client, packets), \
                        tqdm(total=sum(path.stat().st_size for path in paths), unit="B", unit_scale=True,
                             desc=f"{program.parent.name}/{dataset} PCAP", mininterval=1) as progress:
                    totals.writerow(replay(client, packets, paths,
                                           [] if dataset == "benign" else intervals,
                                           args.window_size, writer, program.parent.name, dataset,
                                           progress, build / f"{dataset}.png"))
                windows.flush()
                summary.flush()
    print(f"Complete in {(time.monotonic() - started) / 60:.1f} minutes. Results: {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, pynng.NNGException) as error:
        raise SystemExit(f"Benchmark failed: {error}")
