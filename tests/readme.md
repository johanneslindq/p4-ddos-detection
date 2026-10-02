## Overall workflow

This readme was mostly made using AI. Cause I can't be bothered making an extensive readme

The benchmark follows this general workflow:

```text
CSV labels + PCAP
       |
       v
Prepare ground-truth counts per aligned window
       |
       v
Initialize P4; read baseline counter; share replay clock
       |
       +----------------------+-----------------------+
       |                      |                       |
       v                      v                       v
Replay process         Counter sampler          Evaluation/display
Stream TCP packets     Read at window ends      Consume queued samples
on one timeline        Queue observations       Compare with ground truth
       |                      |                       |
       v                      +---------------------->v
      P4                                       TP / FP / TN / FN
```


# 1. Starting the P4 environment

After preparing ground truth and before replaying traffic, the benchmark prepares the BMv2 environment.

It:

- compiles the supplied P4 program,
- recreates the required virtual Ethernet interfaces,
- starts `simple_switch`,
- connects the switch to the configured interfaces, and opens the Thrift interface used by `simple_switch_CLI`.

The benchmark then reads the P4 detection counter once before replay begins.

This first value acts as the baseline for later detection measurements.

The benchmark intentionally does **not** reset the P4 sketches or detector state between evaluation windows.

The current design assumes that any reset, ageing, or time-management logic required by the detector will eventually be handled by the P4 program or switch implementation itself.


# 2. Packet-level ground truth

The ground truth is derived from the **actual packets in the PCAP**, rather than from the existence of a labelled flow alone.

For every packet in an evaluation window, the benchmark first checks whether it is an initial TCP SYN:

```text
SYN = 1
ACK = 0
```

A SYN+ACK response is therefore not considered an attack SYN.

For an initial IPv4 SYN packet, the benchmark extracts:

```text
(
    Source IP,
    Source Port,
    Destination IP,
    Destination Port,
    Protocol = 6
)
```

The packet is classified as a labelled attack SYN only if:

1. its forward 5-tuple exists among the CSV flows labelled `Syn`, and
2. its timestamp falls within the time interval belonging to one of those matching flows.

Conceptually:

```text
PCAP packet
    |
    v
Is it TCP SYN with ACK = 0?
    |
   yes
    |
    v
Extract forward 5-tuple
    |
    v
Does the tuple match a SYN-labelled CSV flow?
    |
   yes
    |
    v
Is the packet timestamp inside that flow?
    |
   yes
    |
    v
Labelled attack SYN packet
```

This keeps the benchmark ground truth tied to both:

- the dataset's own labels, and
- packets that actually occur in the PCAP.

---

# 3. Timestamp handling

The PCAP uses Unix timestamps, while the CIC-DDoS2019 CSV stores timestamps as local date/time values without timezone information.

The benchmark therefore converts PCAP timestamps into the same local representation used by the CSV before comparing packet times with labelled flow intervals.

For the current dataset, the configured offset is:

```text
UTC-4
```

This conversion is important because a correct 5-tuple can otherwise fail to match simply because the PCAP and CSV timestamps are represented in different timezones.

---

# 4. Evaluation windows

The PCAP is processed using fixed, aligned evaluation windows.

For example, with a one-second window:

```text
13:30:30.000 -> 13:30:31.000
13:30:31.000 -> 13:30:32.000
13:30:32.000 -> 13:30:33.000
```

Windows define the unit used for TP/FP/TN/FN evaluation. They do not divide replay into separate send calls.

Empty windows between captured packets are included as non-attack windows. Windows containing only non-TCP traffic are also measured. Both preserve the original capture's elapsed time. The final window is measured at its aligned end, even if its last packet arrived earlier.

Within every window, the benchmark counts:

```text
All packets
TCP packets
Non-TCP packets
Initial SYN packets
Labelled attack SYN packets
```

Ground truth for the window is currently defined as:

```python
syn_attack_present = attack_syn_packets > 0
```

This means that an evaluation window is considered an attack window when at least one actual initial SYN packet in that window can be matched to a CSV flow labelled `Syn`.

No additional packet-rate threshold is added by the benchmark.

---

# 5. Replaying traffic through the P4 program

Only packets containing TCP are currently replayed through BMv2.

A preparation pass reads the PCAP and computes ground truth before replay starts. It retains compact window summaries, not the entire capture in memory. The PCAP must have finite, nondecreasing timestamps and must remain unchanged during the benchmark.

A separate process streams the PCAP through one Scapy layer-2 socket. Every TCP packet is scheduled against the same monotonic clock:

```text
send deadline = replay start + (packet timestamp - first aligned window start)
```

This preserves gaps across window boundaries and skipped non-TCP packets, including the delay before the first TCP packet. Slow register reads, CSV matching, and status printing do not introduce pauses into the replay loop. The replay process performs no per-window synchronization.

Packet decoding, socket writes, and OS scheduling still take time. Absolute deadlines prevent that overhead from accumulating as an extra delay per packet, but replay remains best effort. The final report includes the maximum observed send lateness; falling behind by a full window produces a warning that accuracy counts are unreliable.

The P4 program then processes the packets using its own detection logic.

The benchmark does not inspect Count-Min Sketch values, HyperLogLog values, thresholds, or other internal detection state when deciding whether an attack exists.

Those are implementation details of the detector.

---

# 6. Observing P4 detections

The detector exposes a cumulative register:

```text
SYNControllerIngress.detection_count
```

This is treated as an **event counter**, rather than as a Boolean attack flag.

Before traffic replay begins, the benchmark records:

```text
previous_detection_count
```

An independent sampler thread reads at each window's absolute end deadline:

```text
current_detection_count
```

A P4 detection is considered to have occurred during the window when:

```python
current_detection_count != previous_detection_count
```

Afterwards:

```python
previous_detection_count = current_detection_count
```

Using a cumulative counter avoids two problems that occur with a simple Boolean register.

### Persistent Boolean problem

If P4 sets:

```text
attack_detected = 1
```

and leaves it set, every later window could incorrectly appear to contain a new detection.

### Short-lived Boolean problem

If P4 briefly sets and clears the Boolean between benchmark reads, the benchmark could miss the detection entirely.

A monotonically increasing counter preserves the information that one or more detection events occurred.

The benchmark does not reset this counter between evaluation windows. Samples are queued so that slow status output does not block the sampler or replay process. Replay and sampling failures are propagated, and both workers are stopped when the benchmark exits or is interrupted. Each CLI invocation has a ten-second timeout.

Counter reads are approximate boundary observations: CLI startup, Thrift latency, and switch processing can place an event in a neighboring window. Each sample reports the time between its requested boundary and CLI completion as an upper bound on boundary delay. If a read finishes a whole window late, that boundary and both intervals touching it cannot be reliably evaluated. Those intervals display `P4 detected attack: None`, increment `Unmeasured P4 windows`, and are excluded from TP/FP/TN/FN.

---

# 7. Comparing detection against ground truth

Each window with usable counter boundaries results in two independent Boolean values:

```text
Ground truth:
Did the PCAP contain at least one labelled attack SYN?

P4 result:
Did the detection counter change?
```

They are compared using a standard confusion matrix:

| Ground truth | P4 detector | Result |
|---|---|---|
| Attack | Attack detected | True Positive |
| No attack | Attack detected | False Positive |
| Attack | No detection | False Negative |
| No attack | No detection | True Negative |

These values are accumulated throughout the benchmark.

---

# 8. Ground-truth validation

Packet-to-flow matching is a critical part of the benchmark, so validation statistics are printed after the PCAP has been processed.

These include:

```text
CSV SYN-labelled flows loaded
Distinct CSV SYN-flow entries matched
Total PCAP packets
Total TCP packets
Total initial SYN packets
Initial SYN packets matched to SYN-labelled flows
Initial SYN packets not matched to SYN-labelled flows
```

These values are primarily sanity checks.

For example, if the benchmark loads a large number of SYN-labelled CSV flows but matches zero attack SYN packets in the corresponding PCAP, this likely indicates a problem such as:

- incorrect timezone conversion,
- incorrect PCAP/CSV pairing,
- incorrect tuple direction,
- incorrect field parsing, or
- another mismatch between the CSV and PCAP.

The ground-truth validation should therefore be checked before detector accuracy numbers are trusted.

---


# Current limitations and future work

The current implementation still has some limitations.

## Timing and boundary attribution remain best effort

Continuous replay removes the artificial pauses caused by window evaluation. It cannot guarantee that Scapy or BMv2 keeps up with a high-rate capture, or that packets have been processed by the time a counter read completes. Sent-packet counts do not confirm receipt by BMv2.

The cumulative counter has no event timestamps, so exact attribution near a window boundary would require additional switch instrumentation. Review the reported replay lateness, counter boundary delays, and unmeasured-window count alongside accuracy results. No changes to the P4 program are needed for the continuous replay implementation.

---

## IPv4 is used for attack-flow matching

The current CSV ground-truth lookup uses IPv4 forward 5-tuples.

General TCP traffic may still be counted/replayed, but packet-level attack matching currently expects IPv4 addresses.

---

## Any matched attack SYN makes a window positive

Currently:

```python
syn_attack_present = attack_syn_packets > 0
```

This is intentionally simple and directly tied to the dataset labels.

It may later be useful to record attack intensity or attack packet counts for analysis, but an arbitrary benchmark-side threshold should not be introduced without a clear methodological reason.

---

# Running the regression tests

From the repository root:

```sh
python3 -m unittest discover -s tests -p 'test_benchmark*.py' -v
```

The tests cover ground truth, capture gaps, continuous replay timing, delayed counter reads, counter wraparound, worker failures, and slow status consumers. Packet sockets and BMv2 are mocked; no traffic is sent by the tests.
