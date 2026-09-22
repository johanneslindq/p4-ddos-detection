import argparse
import csv
import math
import os

from datetime import datetime, timedelta, timezone
from scapy.all import PcapReader


# CIC-DDoS2019 was recorded in New Brunswick.
# On 1 Dec 2018 the dataset's local time was UTC-4.
DATASET_UTC_OFFSET_HOURS = -4

def main(dataset: str, traffic_answer_sheet: str, window_size: float = 1.0):

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

    attack_windows = 0
    non_attack_windows = 0

    # P4 detection statistics:
    #
    # true_positives = 0
    # false_positives = 0
    # true_negatives = 0
    # false_negatives = 0

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

        # Later:
        #
        # 1. Send packets in this window through BMv2
        # 2. Determine whether P4 detected a SYN flood
        #
        # p4_detected_attack = ...
        #
        # Then compare:
        #
        # if syn_attack_present and p4_detected_attack:
        #     true_positives += 1
        #
        # elif not syn_attack_present and p4_detected_attack:
        #     false_positives += 1
        #
        # elif syn_attack_present and not p4_detected_attack:
        #     false_negatives += 1
        #
        # else:
        #     true_negatives += 1

        # --------------------------------------------------------
        # Display status
        # --------------------------------------------------------

        clear_terminal()

        print("=== BENCHMARK STATUS ===")
        print(f"Window:                  {window_number}")
        print(f"Dataset time:            {dataset_window_start}")
        print()
        print(f"Packets this window:     {len(packets)}")
        print(f"Total packets processed: {total_packets}")
        print()
        print(f"Attack windows:          {attack_windows}")
        print(f"Non-attack windows:      {non_attack_windows}")
        print()
        print(f"SYN attack this window:  {syn_attack_present}")


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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark SYN attack detection.")
    parser.add_argument(
        "--window-size", "--window_size",
        type=float,
        default=1.0,
        help="Size of each benchmark window in seconds (default: 1.0)."
    )
    args = parser.parse_args()
    if not math.isfinite(args.window_size) or args.window_size <= 0:
        parser.error("--window-size must be a positive, finite number")

    main(
        "datasets/syn-flood-cicddos/SAT-01-12-2018_0620.pcap",
        "datasets/Syn-day-1.csv",
        window_size=args.window_size
    )
