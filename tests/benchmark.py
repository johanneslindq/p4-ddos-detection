import argparse
import csv
import math
import os
import subprocess
import time
import re

from pathlib import Path
from datetime import datetime, timedelta, timezone
from scapy.all import TCP, PcapReader, conf, sendp


# Globals:

# CIC-DDoS2019 was recorded in New Brunswick.
# On 1 Dec 2018 the dataset's local time was UTC-4.
DATASET_UTC_OFFSET_HOURS = -4

ATTACK_REGISTER = "SYNControllerIngress.attack_detected"

COUNT_MIN_REGISTERS = [
    "SYNControllerIngress.count_min_register_1",
    "SYNControllerIngress.count_min_register_2",
    "SYNControllerIngress.count_min_register_3",
    "SYNControllerIngress.count_min_register_4",
]

HLL_REGISTER = "SYNControllerIngress.hll_register"

def main(
    dataset: str,
    traffic_answer_sheet: str,
    p4_program: str,
    window_size: float = 1.0
):

    # ------------------------------------------------------------
    # Initialize P4 program
    # ------------------------------------------------------------
    initialize_P4_program(p4_program)


    # ------------------------------------------------------------
    # Load ground-truth SYN attack periods from the CSV
    # ------------------------------------------------------------
    print_dataset_info(dataset)
    print(f"Loading SYN attack intervals from {traffic_answer_sheet}...")

    attack_intervals = load_attack_intervals(
        traffic_answer_sheet
    )

    # Merge overlapping attack flows into larger attack periods.
    # This makes checking each window much faster.

    print("Merging overlapping SYN attack intervals...")

    attack_intervals = merge_intervals(
        attack_intervals
    )

    print(
        f"Loaded {len(attack_intervals)} merged SYN attack intervals"
    )

    # ------------------------------------------------------------
    # Benchmark statistics
    # ------------------------------------------------------------

    window_number = 0
    total_packets = 0
    total_packet_types = dict.fromkeys(("TCP", "Non-TCP"), 0)

    attack_windows = 0
    non_attack_windows = 0

    # P4 detection statistics:
    #
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    # ------------------------------------------------------------
    # Process PCAP one time window at a time
    # ------------------------------------------------------------

    for window_start, window_end, packets in read_aligned_windows(
        dataset,
        window_size
    ):

        window_number += 1
        total_packets += len(packets)

        # Convert PCAP timestamps into the same local time
        # representation used by the CIC CSV.
        dataset_window_start = pcap_timestamp_to_dataset_time(
            window_start
        )

        dataset_window_end = pcap_timestamp_to_dataset_time(
            window_end
        )

        # --------------------------------------------------------
        # Ground truth
        # --------------------------------------------------------

        syn_attack_present = syn_attack_in_window(
            dataset_window_start,
            dataset_window_end,
            attack_intervals
        )

        if syn_attack_present:
            attack_windows += 1
        else:
            non_attack_windows += 1

        # --------------------------------------------------------
        # P4 detector
        # --------------------------------------------------------

        # Reset sketches and detection state for this window. This is necessary because the P4 program does not know when a new window begins.
        reset_p4_window()

        # Send only TCP packets in this window through BMv2
        send_packets_to_p4(packets)
        window_packet_types = count_packet_types(packets)
        for protocol, count in window_packet_types.items():
            total_packet_types[protocol] += count

        # Determine whether P4 detected a SYN flood
        detected_attack = p4_detected_attack()
        if detected_attack and syn_attack_present:
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
        print(f"{'Type':<12}{'This window':>14}{'Total':>14}")
        print(f"{'All packets':<12}{len(packets):>14,}{total_packets:>14,}")
        for protocol, count in window_packet_types.items():
            print(f"{protocol:<12}{count:>14,}{total_packet_types[protocol]:>14,}")
        print("Replay counts do not confirm receipt by BMv2.")
        print()
        print(f"Attack windows:          {attack_windows}")
        print(f"Non-attack windows:      {non_attack_windows}")
        print()
        print(f"True P4 positives:       {true_positives}")
        print(f"False P4 positives:      {false_positives}")
        print(f"True P4 negatives:       {true_negatives}")
        print(f"False P4 negatives:      {false_negatives}")
        print()
        print(f"SYN attack this window:  {syn_attack_present}")


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

    with PcapReader(pcap_file) as pcap:

        current_window = []
        current_window_start = None

        for packet in pcap:

            timestamp = float(packet.time)

            # Align packet timestamp to an absolute
            # window boundary.
            window_start = (
                math.floor(timestamp / window_size)
                * window_size
            )

            if current_window_start is None:
                current_window_start = window_start

            # Packet belongs to the current window
            if window_start == current_window_start:

                current_window.append(packet)

            # Packet belongs to the next window
            else:

                yield (
                    current_window_start,
                    current_window_start + window_size,
                    current_window
                )

                current_window = [packet]
                current_window_start = window_start

        # Yield final window
        if current_window:

            yield (
                current_window_start,
                current_window_start + window_size,
                current_window
            )


def load_attack_intervals(csv_file: str):
    """
    Read all SYN attack flows from the CSV.

    Each CSV row describes one labeled flow.

    The attack interval is:

        Timestamp
            ->
        Timestamp + Flow Duration

    Flow Duration is stored in microseconds.
    """

    intervals = []

    with open(csv_file, "r") as f:

        reader = csv.DictReader(
            f,
            skipinitialspace=True
        )

        for row in reader:

            # Since this is a SYN answer sheet this should normally
            # always be true, but checking the label makes the code
            # safer.
            if row["Label"].strip().lower() != "syn":
                continue

            start = datetime.strptime(
                row["Timestamp"],
                "%Y-%m-%d %H:%M:%S.%f"
            )

            duration_microseconds = float(
                row["Flow Duration"]
            )

            end = start + timedelta(
                microseconds=duration_microseconds
            )

            intervals.append(
                (start, end)
            )

    return intervals


def merge_intervals(intervals):
    """
    Merge overlapping SYN-flow intervals.

    Example:

        13:30:30 -> 13:30:40
        13:30:35 -> 13:30:50

    becomes:

        13:30:30 -> 13:30:50

    This avoids checking every individual CSV flow
    for every PCAP window.
    """

    if not intervals:
        return []

    intervals.sort(
        key=lambda interval: interval[0]
    )

    merged = []

    current_start, current_end = intervals[0]

    for start, end in intervals[1:]:

        # Overlapping intervals
        if start <= current_end:

            if end > current_end:
                current_end = end

        # Gap between attacks
        else:

            merged.append(
                (current_start, current_end)
            )

            current_start = start
            current_end = end

    merged.append(
        (current_start, current_end)
    )

    return merged


def syn_attack_in_window(window_start : datetime, window_end : datetime, attack_intervals : list):
    """
    Return True if this benchmark window overlaps
    at least one known SYN attack interval.

    Two time ranges overlap when:

        attack_start < window_end
        AND
        attack_end >= window_start
    """

    for attack_start, attack_end in attack_intervals:

        # Since intervals are sorted, once an attack begins
        # after the window ends, there is no need to continue.
        if attack_start >= window_end:
            return False

        if (
            attack_start < window_end
            and attack_end >= window_start
        ):
            return True

    return False


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
    """
    This looks at the name of the dataset file and prints what the user can expect to see in the benchmark.
    """
    
    # Strip the path and just get the filename
    dataset = os.path.basename(dataset)
    print(f"Benchmarking dataset: {dataset}")

    if (dataset == "SAT-01-12-2018_0617.pcap"):
        print("This is the flow of traffic right before the SYN flood attack. Only the last window of this dataset contains a SYN flood attack.")
    elif (dataset == "SAT-01-12-2018_0618.pcap"):
        print("This dataset contains a SYN flood attack throughouts the entire dataset. All windows of this dataset contain a SYN flood attack.")
    elif (dataset == "SAT-01-12-2018_0619.pcap"):
        print("This dataset contains a SYN flood attack throughouts the entire dataset. All windows of this dataset contain a SYN flood attack.")
    elif (dataset == "SAT-01-12-2018_0620.pcap"):
        print("This is the end of the SYN flood attack. Only the first window of this dataset contains a SYN flood attack.")
    else:
        print("Unknown dataset. No information available.")

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

def send_packets_to_p4(packets):
    """Replay only packets with a decoded TCP layer into BMv2 port 1."""
    tcp_packets = [packet for packet in packets if packet.haslayer(TCP)]
    if not tcp_packets:
        return

    sendp(
        tcp_packets,
        iface="veth1",
        promisc=False,
        verbose=False
    )

def run_p4_cli(commands):
    if isinstance(commands, str):
        commands = [commands]

    result = subprocess.run(
        [
            "simple_switch_CLI",
            "--thrift-port",
            "9090",
        ],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"simple_switch_CLI failed:\n{result.stderr}"
        )

    return result.stdout

def reset_p4_window():
    commands = [
        f"register_reset {ATTACK_REGISTER}",
        f"register_reset {HLL_REGISTER}",
    ]

    for register in COUNT_MIN_REGISTERS:
        commands.append(
            f"register_reset {register}"
        )

    run_p4_cli(commands)

def p4_detected_attack():

    output = run_p4_cli(
        f"register_read {ATTACK_REGISTER} 0"
    )

    match = re.search(r"=\s*(\d+)", output)

    if match is None:
        raise RuntimeError(
            f"Could not read attack register:\n{output}"
        )

    return int(match.group(1)) != 0

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
        str(dataset_dir / "syn-flood-cicddos" / "SAT-01-12-2018_0620.pcap"),
        str(dataset_dir / "Syn-day-1.csv"),
        p4_program=args.p4_program,
        window_size=args.window_size
    )
