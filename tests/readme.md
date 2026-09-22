# TCP benchmark

[benchmark.py](benchmark.py) replays TCP traffic from a PCAP through a P4 program
running in BMv2 and labels time windows using the CIC-DDoS2019 SYN ground-truth
CSV. It displays packet counts and window classification statistics in the terminal.


## Example of how to run the benchmark

From the repository root, using the Miniforge environment used in this project:

```bash
sudo /home/breman/miniforge3/bin/python3 tests/benchmark.py \
  --p4-program TCP_Traffic_Detection/TCP_Detector.p4
```

To use half-second capture windows:

```bash
sudo /home/breman/miniforge3/bin/python3 tests/benchmark.py \
  --p4-program TCP_Traffic_Detection/TCP_Detector.p4 \
  --window-size 0.5
```

| Argument | Meaning | Default |
| --- | --- | --- |
| `--p4-program`, `--p4_program` | Path to the P4 source, relative to the current directory or absolute. | Required |
| `--window-size`, `--window_size` | Positive, finite capture-window duration in seconds. | `1.0` |
