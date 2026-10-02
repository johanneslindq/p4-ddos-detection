import argparse
import csv
import math
import multiprocessing
import os
import queue
import subprocess
import threading
import time
import re

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta, timezone
from scapy.all import IP, TCP, PcapReader, conf


# CIC-DDoS2019 was recorded in New Brunswick.
# On 1 Dec 2018 the dataset's local time was UTC-4.
DATASET_UTC_OFFSET_HOURS = -4

DETECTION_COUNTER = "SYNControllerIngress.detection_count"


@dataclass
class WindowSummary:
    start: float
    packets: int
    packet_types: dict
    syn_packets: int
    attack_syn_packets: int


@dataclass
class DetectionSample:
    # None means a boundary was missed; the counter cannot recover history.
    detected_attack: bool | None
    delay: float


def main(dataset: str, traffic_answer_sheet: str, p4_program: str, window_size: float = 1.0):
    if not math.isfinite(window_size) or window_size <= 0:
        raise ValueError("window_size must be a positive, finite number")

    # ------------------------------------------------------------
    # Load SYN-labelled flows for packet-level ground truth
    # ------------------------------------------------------------
    print_dataset_info(dataset)
    print(f"Loading SYN-labelled flows from {traffic_answer_sheet}...")

    attack_flows = load_attack_flows(traffic_answer_sheet)
    csv_syn_flows = sum(len(flows) for flows in attack_flows.values())

    print(
        f"Loaded {csv_syn_flows:,} SYN-labelled flows "
        f"across {len(attack_flows):,} forward 5-tuples"
    )

    # Do CSV matching before replay, retaining counts rather than the capture.
    print("Preparing packet-level ground truth before continuous replay...")
    windows = summarize_windows(dataset, attack_flows, window_size)
    initialize_P4_program(p4_program)

    # ------------------------------------------------------------
    # Benchmark statistics
    # ------------------------------------------------------------

    window_number = 0
    total_packets = 0
    total_packet_types = dict.fromkeys(("TCP", "Non-TCP"), 0)
    total_syn_packets = 0
    total_attack_syn_packets = 0

    attack_windows = 0
    non_attack_windows = 0

    # P4 detection statistics:
    #
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0
    unmeasured_windows = 0
    max_sample_delay = 0.0

    # ------------------------------------------------------------
    # Replay and sample independently of evaluation and terminal output
    # ------------------------------------------------------------


    with closing(measure_detection_windows(dataset, windows, window_size)) as measurements:
        for window, sample in measurements:

            window_number += 1
            total_packets += window.packets

            # Convert PCAP timestamps into the same local time
            # representation used by the CIC CSV.
            dataset_window_start = pcap_timestamp_to_dataset_time(window.start)

            # --------------------------------------------------------
            # Ground truth
            # --------------------------------------------------------

            window_packet_types = window.packet_types
            tcp_packets = window_packet_types["TCP"]
            syn_packets = window.syn_packets
            attack_syn_packets = window.attack_syn_packets

            for protocol, count in window_packet_types.items():
                total_packet_types[protocol] += count
            total_syn_packets += syn_packets
            total_attack_syn_packets += attack_syn_packets

            # A SYN-labelled flow does not imply continuous attack traffic.
            # Only actual initial SYN packets matched to that flow count.
            syn_attack_present = attack_syn_packets > 0

            if syn_attack_present:
                attack_windows += 1
            else:
                non_attack_windows += 1

            # --------------------------------------------------------
            # P4 detector
            # --------------------------------------------------------

            detected_attack = sample.detected_attack
            max_sample_delay = max(max_sample_delay, sample.delay)
            if detected_attack is None:
                unmeasured_windows += 1
            elif detected_attack and syn_attack_present:
                true_positives += 1
            elif detected_attack and not syn_attack_present:
                false_positives += 1
            elif not detected_attack and syn_attack_present:
                false_negatives += 1
            else:
                true_negatives += 1

            # --------------------------------------------------------
            # Display status
            # --------------------------------------------------------

            clear_terminal()

            print("=== BENCHMARK STATUS ===")
            print(f"Window:                  {window_number}")
            print(f"Dataset time:            {dataset_window_start}")
            print()
            print("PCAP packets (TCP replayed; non-TCP skipped):")
            print(f"{'Type':<27}{'This window':>14}{'Total':>14}")
            print(f"{'All packets':<27}{window.packets:>14,}{total_packets:>14,}")
            print(f"{'TCP packets':<27}{tcp_packets:>14,}{total_packet_types['TCP']:>14,}")
            print(f"{'Non-TCP packets':<27}{window_packet_types['Non-TCP']:>14,}{total_packet_types['Non-TCP']:>14,}")
            print(f"{'Initial SYN packets':<27}{syn_packets:>14,}{total_syn_packets:>14,}")
            print(f"{'Labelled attack SYN packets':<27}{attack_syn_packets:>14,}{total_attack_syn_packets:>14,}")
            print("Replay counts do not confirm receipt by BMv2.")
            print()
            print(f"Attack windows:          {attack_windows}")
            print(f"Non-attack windows:      {non_attack_windows}")
            print()
            print(f"True P4 positives:       {true_positives}")
            print(f"False P4 positives:      {false_positives}")
            print(f"True P4 negatives:       {true_negatives}")
            print(f"False P4 negatives:      {false_negatives}")
            print(f"Unmeasured P4 windows:   {unmeasured_windows}")
            print(f"Counter boundary delay: {sample.delay:.6f} s (upper bound)")
            print()
            print(f"SYN attack this window:  {syn_attack_present}")
            print(f"P4 detected attack:      {detected_attack}")

    print(f"Maximum counter boundary delay: {max_sample_delay:.6f} s (upper bound)")
    matched_csv_flows = sum(
        flow["matched"]
        for flows in attack_flows.values()
        for flow in flows
    )
    print()
    print("=== GROUND-TRUTH VALIDATION ===")
    print(f"CSV SYN-labelled flows loaded: {csv_syn_flows:,}")
    print(f"Distinct CSV SYN-flow entries matched: {matched_csv_flows:,}")
    print(f"Total PCAP packets: {total_packets:,}")
    print(f"Total TCP packets: {total_packet_types['TCP']:,}")
    print(f"Total initial SYN packets: {total_syn_packets:,}")
    print(f"Initial SYN packets matched to SYN-labelled flows: {total_attack_syn_packets:,}")
    print(f"Initial SYN packets not matched to SYN-labelled flows: {total_syn_packets - total_attack_syn_packets:,}")


def summarize_windows(dataset, attack_flows, window_size):
    summaries = []

    for start, packets in read_aligned_windows(dataset, window_size):

        tcp_packets = 0
        non_tcp_packets = 0
        syn_packets = 0
        attack_syn_packets = 0

        for packet in packets:

            if packet.haslayer(TCP):
                tcp_packets += 1
            else:
                non_tcp_packets += 1
                continue

            if not is_initial_tcp_syn(packet):
                continue

            syn_packets += 1

            if is_labelled_attack_syn(packet, attack_flows):
                attack_syn_packets += 1

        packet_types = {
            "TCP": tcp_packets,
            "Non-TCP": non_tcp_packets,
        }

        summaries.append(
            WindowSummary(
                start,
                len(packets),
                packet_types,
                syn_packets,
                attack_syn_packets,
            )
        )

    return summaries


def count_packet_types(packets):
    """Count packets with a decoded TCP layer and all remaining packets.

    TCP includes IPv4 and IPv6. Packets without a decoded TCP layer,
    including undecoded fragments, are grouped as Non-TCP and skipped.
    These are PCAP classifications, independent of the P4 parser.
    """
    counts = dict.fromkeys(("TCP", "Non-TCP"), 0)
    for packet in packets:
        protocol = "TCP" if packet.haslayer(TCP) else "Non-TCP"
        counts[protocol] += 1
    return counts


def read_aligned_windows(pcap_file: str, window_size: float = 1.0):
    """
    Read a PCAP and divide packets into fixed time windows.

    Example with a 1-second window:

        13:30:30.000 -> 13:30:31.000
        13:30:31.000 -> 13:30:32.000
        13:30:32.000 -> 13:30:33.000
    """

    if not math.isfinite(window_size) or window_size <= 0:
        raise ValueError("window_size must be a positive, finite number")

    with PcapReader(pcap_file) as pcap:

        current_window = []
        current_window_index = None
        previous_timestamp = None

        for packet in pcap:

            timestamp = float(packet.time)
            if not math.isfinite(timestamp) or (
                previous_timestamp is not None and timestamp < previous_timestamp
            ):
                raise ValueError("PCAP timestamps must be finite and nondecreasing")
            previous_timestamp = timestamp

            # Align packet timestamp to an absolute
            # window boundary.
            window_index = math.floor(timestamp / window_size)

            if current_window_index is None:
                current_window_index = window_index

            # Include silence in the measurement timeline. Use integer indices
            # to avoid accumulating floating-point error across empty windows.
            while current_window_index < window_index:
                yield current_window_index * window_size, current_window
                current_window = []
                current_window_index += 1

            current_window.append(packet)

        # Yield final window
        if current_window:

            yield (
                current_window_index * window_size,
                current_window
            )


def load_attack_flows(csv_file: str):
    """Index SYN-labelled CSV flows by their forward IPv4 5-tuple.

    Flow Duration is in microseconds. The interval restricts packet
    matching; it does not mean every packet in the flow is an attack SYN.
    Keep each CSV row separately, including rows sharing the same tuple.
    """
    attack_flows = {}

    with open(csv_file, "r", newline="") as f:

        reader = csv.DictReader(
            f,
            skipinitialspace=True
        )

        for row in reader:

            if row["Label"].strip().lower() != "syn":
                continue

            flow_key = (
                row["Source IP"].strip(),
                int(row["Source Port"]),
                row["Destination IP"].strip(),
                int(row["Destination Port"]),
                int(row["Protocol"])
            )
            start = datetime.strptime(
                row["Timestamp"].strip(),
                "%Y-%m-%d %H:%M:%S.%f"
            )

            duration_microseconds = float(
                row["Flow Duration"]
            )

            end = start + timedelta(
                microseconds=duration_microseconds
            )

            attack_flows.setdefault(flow_key, []).append({
                "start": start,
                "end": end,
                "matched": False
            })

    for flows in attack_flows.values():
        flows.sort(key=lambda flow: flow["start"])

    return attack_flows


def get_ipv4_5_tuple(packet):
    """Return the forward IPv4 TCP tuple, or None for other packets."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    return (
        packet[IP].src,
        int(packet[TCP].sport),
        packet[IP].dst,
        int(packet[TCP].dport),
        6
    )


def is_initial_tcp_syn(packet):
    """Require SYN=1 and ACK=0; other TCP flags may also be set."""
    if not packet.haslayer(TCP):
        return False

    flags = int(packet[TCP].flags)
    return bool(flags & 0x02) and not bool(flags & 0x10)


def is_labelled_attack_syn(packet, attack_flows):
    """Match an actual initial SYN to a labelled flow's tuple and time.

    Record every matching CSV entry for diagnostics. A packet still counts
    only once even if several entries match. Reverse tuples are not tried.
    """
    if not is_initial_tcp_syn(packet):
        return False

    flow_key = get_ipv4_5_tuple(packet)
    if flow_key is None or flow_key not in attack_flows:
        return False

    packet_time = pcap_timestamp_to_dataset_time(float(packet.time))
    matched = False
    for flow in attack_flows[flow_key]:
        if flow["start"] > packet_time:
            break
        if packet_time <= flow["end"]:
            flow["matched"] = True
            matched = True

    return matched


def pcap_timestamp_to_dataset_time(timestamp: float):
    """
    PCAP timestamps are Unix timestamps.

    First interpret the timestamp as UTC, then convert it
    to the local timezone used in the CIC-DDoS2019 CSV.

    This avoids depending on the timezone configured
    on the computer running the benchmark.
    """

    utc_time = datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    )

    dataset_time = (
        utc_time
        + timedelta(
            hours=DATASET_UTC_OFFSET_HOURS
        )
    )

    # CSV timestamps do not contain timezone information,
    # so convert back to a naive datetime for comparison.
    return dataset_time.replace(
        tzinfo=None
    )


def clear_terminal():
    os.system("clear")

def print_dataset_info(dataset: str):
    """Describe packet-level ground truth without assuming labels from filenames."""
    print(f"Benchmarking dataset: {os.path.basename(dataset)}")
    print("Ground truth uses initial SYN packets matched to SYN-labelled CSV flows.")

def initialize_P4_program(path_to_p4_program: str):
    p4_path = Path(path_to_p4_program)
    if not p4_path.exists():
        raise FileNotFoundError(f"P4 program not found: {path_to_p4_program}")
    output_json_path = p4_path.with_suffix('.json')

    # Make sure simple_switch is not already running
    subprocess.run(["sudo", "pkill", "simple_switch"], check=False)

    # Deleting one end of a veth pair also deletes its peer.
    subprocess.run(["sudo", "ip", "link", "del", "veth0"], check=False)
    subprocess.run(["sudo", "ip", "link", "del", "veth2"], check=False)

    # Compile the P4 program
    print(f"Compiling P4 program: {path_to_p4_program}...")
    result = subprocess.run(
        [
            "p4c-bm2-ss",
            str(p4_path),
            "-o",
            str(output_json_path)
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("P4 compilation failed:")
        print(result.stderr)
        raise SystemExit(1)

    print(f"P4 compiled successfully: {output_json_path}")

    # Set up a two port setup for the P4 program using simple_switch
    commands = [
        ["sudo", "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"],
        ["sudo", "ip", "link", "add", "veth2", "type", "veth", "peer", "name", "veth3"],

        # The capture contains frames larger than the default 1500-byte MTU.
        ["sudo", "ip", "link", "set", "veth0", "mtu", "9000", "up"],
        ["sudo", "ip", "link", "set", "veth1", "mtu", "9000", "up"],
        ["sudo", "ip", "link", "set", "veth2", "mtu", "9000", "up"],
        ["sudo", "ip", "link", "set", "veth3", "mtu", "9000", "up"],
    ]

    for command in commands:
        subprocess.run(command, check=True)

    # Recreated interfaces have new indices; discard Scapy's cached values.
    conf.ifaces.reload()

    # Start the P4 program using simple_switch
    print("Starting P4 program using simple_switch...")
    command = [
        "sudo",
        "simple_switch",
        "--thrift-port", "9090",
        "-i", "1@veth0",
        "-i", "2@veth2",
        str(output_json_path)
    ]

    # Keep the background switch's terminal I/O separate from the status display.
    log_path = output_json_path.with_suffix('.bmv2.log')
    with log_path.open("w") as log_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT
        )

    # Give BMv2 a moment to start
    time.sleep(1)

    # Check if it immediately crashed
    if process.poll() is not None:
        raise RuntimeError(f"BMv2 failed to start; see {log_path}")

    print(f"BMv2 started successfully; logs: {log_path}")

def send_packets_to_p4(packets, replay_socket, replay_start, capture_start):
    """Stream TCP on one monotonic timeline, including gaps between windows.

    The socket and clock epoch are shared across the entire capture. Packet
    timestamps remain unchanged for ground truth. Absolute deadlines avoid
    accumulating send overhead; Scapy/OS scheduling is still best effort.
    """
    sent = 0
    max_lateness = 0.0
    for packet in packets:
        if not packet.haslayer(TCP):
            continue
        deadline = replay_start + (float(packet.time) - capture_start)
        frame = bytes(packet)
        delay = deadline - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        replay_socket.send(frame)
        max_lateness = max(max_lateness, time.monotonic() - deadline)
        sent += 1
    return sent, max_lateness


def replay_worker(dataset, capture_start, connection):
    """Own the replay socket in a process isolated from Python evaluation work."""
    try:
        with PcapReader(dataset) as packets, conf.L2socket(
            iface="veth1", promisc=False
        ) as replay_socket:
            connection.send(("ready", None))
            replay_start = connection.recv()
            result = send_packets_to_p4(
                packets, replay_socket, replay_start, capture_start
            )
        connection.send(("done", result))
    except Exception as error:
        connection.send(("error", f"{type(error).__name__}: {error}"))
    finally:
        connection.close()


def sample_detection_counts(window_count, window_size, replay_start,
                            previous_count, samples, stop):
    """Sample absolute boundaries without waiting for status rendering."""
    previous_boundary_valid = True
    try:
        for index in range(window_count):
            deadline = replay_start + (index + 1) * window_size
            if stop.wait(max(0.0, deadline - time.monotonic())):
                return
            current_count = read_p4_detection_count()
            # The CLI does not timestamp the register read. Completion gives
            # an upper bound on its delay relative to the requested boundary.
            delay = max(0.0, time.monotonic() - deadline)
            boundary_valid = delay < window_size
            detected = (
                current_count != previous_count
                if boundary_valid and previous_boundary_valid else None
            )
            samples.put(DetectionSample(detected, delay))
            previous_count = current_count
            previous_boundary_valid = boundary_valid
    except Exception as error:
        samples.put(error)


def receive_replay_message(connection):
    try:
        state, result = connection.recv()
    except EOFError as error:
        raise RuntimeError("Packet replay exited without reporting a result") from error
    if state == "error":
        raise RuntimeError(f"Packet replay failed: {result}")
    return state, result


def measure_detection_windows(dataset, windows, window_size):
    """Yield window measurements while replay and counter sampling run freely."""
    if not windows:
        read_p4_detection_count()
        return

    context = multiprocessing.get_context("spawn")
    connection, worker_connection = context.Pipe()
    replay = context.Process(
        target=replay_worker, args=(dataset, windows[0].start, worker_connection)
    )
    samples = queue.SimpleQueue()
    stop = threading.Event()
    sampler = None
    replay_result = None
    started = False
    try:
        replay.start()
        started = True
        worker_connection.close()
        state, _ = receive_replay_message(connection)
        if state != "ready":
            raise RuntimeError("Packet replay did not initialize")

        # Both workers are ready before starting the capture clock. The first
        # window's aligned boundary is time zero, even when it starts with UDP.
        previous_count = read_p4_detection_count()
        replay_start = time.monotonic() + 0.1
        sampler = threading.Thread(
            target=sample_detection_counts,
            args=(len(windows), window_size, replay_start, previous_count, samples, stop),
            daemon=True,
        )
        sampler.start()
        connection.send(replay_start)

        for window in windows:
            while True:
                if replay_result is None and connection.poll():
                    state, replay_result = receive_replay_message(connection)
                    if state != "done":
                        raise RuntimeError(f"Unexpected replay state: {state}")
                try:
                    sample = samples.get(timeout=0.1)
                    break
                except queue.Empty:
                    continue
            if isinstance(sample, Exception):
                raise sample
            yield window, sample

        if replay_result is None:
            state, replay_result = receive_replay_message(connection)
            if state != "done":
                raise RuntimeError(f"Unexpected replay state: {state}")
        sent, max_lateness = replay_result
        if sent != sum(window.packet_types["TCP"] for window in windows):
            raise RuntimeError("Replay TCP count differs from the prepared capture")
        print(f"TCP packets sent: {sent:,}; maximum replay lateness: {max_lateness:.6f} s")
        if max_lateness >= window_size:
            print("WARNING: Replay fell behind by at least one window; accuracy counts are unreliable.")
    finally:
        stop.set()
        # Stop traffic promptly on interruption, before waiting for an active
        # CLI read to finish (or reach its timeout).
        if started:
            if replay.is_alive():
                replay.terminate()
            replay.join()
            replay.close()
        if sampler is not None and sampler.ident is not None:
            sampler.join()
        connection.close()
        worker_connection.close()

# interact with the P4 program using simple_switch_CLI via Thrift
def run_p4_cli(command):
    result = subprocess.run(
        [
            "simple_switch_CLI",
            "--thrift-port",
            "9090",
        ],
        input=command + "\n",
        capture_output=True,
        text=True,
        timeout=10,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"simple_switch_CLI failed:\n{result.stderr}"
        )

    return result.stdout

def read_p4_detection_count():
    """Read the cumulative 32-bit event counter without changing switch state."""

    output = run_p4_cli(
        f"register_read {DETECTION_COUNTER} 0"
    )

    match = re.search(r"=\s*(\d+)", output)

    if match is None:
        raise RuntimeError(
            f"Could not read detection counter:\n{output}"
        )

    return int(match.group(1))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark SYN attack detection.")
    parser.add_argument(
        "--p4-program", "--p4_program",
        default=str(Path(__file__).resolve().parent.parent / "src" / "main.p4"),
        help="Path to the P4 program (default: repository src/main.p4)."
    )
    parser.add_argument(
        "--window-size", "--window_size",
        type=float,
        default=1.0,
        help="Size of each benchmark window in seconds (default: 1.0)."
    )
    args = parser.parse_args()
    if not math.isfinite(args.window_size) or args.window_size <= 0:
        parser.error("--window-size must be a positive, finite number")

    dataset_dir = Path(__file__).resolve().parent / "datasets"
    main(
        str(dataset_dir / "syn-flood-cicddos" / "SAT-01-12-2018_0618.pcap"),
        str(dataset_dir / "Syn-day-1.csv"),
        p4_program=args.p4_program,
        window_size=args.window_size
    )
