# Remote ID Evaluation & Benchmarking Suite

This directory contains the benchmarking harnesses, automated sweep orchestrators, and consolidated plotting suite used to evaluate the RF capacity, packet delivery rate (PDR), deadline compliance, and propagation latencies of ASTM F3411 Remote ID broadcasts over Wi-Fi and Bluetooth Low Energy (BLE).

---

## Directory Overview

```
evaluation/
├── ble_capacity.py            # Core BLE benchmark sweep harness (raw HCI injection)
├── wifi_capacity.py           # Core Wi-Fi benchmark sweep harness (raw AF_PACKET 802.11)
├── hopping_evaluation.py      # Wi-Fi monitor mode channel switching latency & scanner calibration
├── run_ble_benchmark.py       # Automated multi-mode & multi-adapter BLE sweep orchestrator
│
├── plot_common.py             # Shared plotting & metric normalization engine (Seaborn/Matplotlib)
├── plot_capacity.py           # Unified CLI plotter for single or multi-dataset comparisons
├── plot_ble_comparisons.py    # Batch comparison generator (5 structured analysis categories)
│
├── data/                      # Output benchmark JSON datasets (gitignored / reproducible)
├── plots/                     # Output directory for individual sweep plots
└── comparison_plots/          # Output directory for categorized BLE comparison suites
```

---

## 1. Running Capacity Experiments

### A. Automated BLE Multi-Mode Benchmark (`run_ble_benchmark.py`)
Sweeps across all BLE modes (`extended`, `ext-legacy`, `dual`, `legacy`), adapters (`hci0`, `hci1`), and advertising intervals (20ms to 200ms) with automatic early termination on consecutive missed deadlines.

```bash
# Full sweep across all default modes on internal adapter (hci0)
sudo .venv/bin/python evaluation/run_ble_benchmark.py --adapters hci0 --drones 1-40:1

# Custom per-adapter specification:
sudo .venv/bin/python evaluation/run_ble_benchmark.py \
  --spec "hci0:extended,ext-legacy,dual" "hci1:legacy" \
  --drones 1-40:1 --duration 10.0
```

### B. Direct BLE Capacity Sweep (`ble_capacity.py`)
Run an isolated sweep for a specific BLE configuration:

```bash
# BLE 5 Extended Advertising (20ms interval)
sudo .venv/bin/python evaluation/ble_capacity.py \
  --tx-adapter hci0 --ble-mode extended --ble-interval-ms 20 \
  --drones 5,10,15,20,25,30,35,40 --duration 10.0 \
  --out evaluation/data/extended_20ms_hci0.json

# BLE Dual Mode (Extended @ 20ms fixed, Legacy @ 100ms)
sudo .venv/bin/python evaluation/ble_capacity.py \
  --tx-adapter hci0 --ble-mode dual --extended-interval-ms 20 --legacy-interval-ms 100 \
  --drones 1-30:1 --out evaluation/data/dual_ext20ms_leg100ms_hci0.json
```

### C. Wi-Fi Beacon Capacity Sweep (`wifi_capacity.py`)
Sweeps drone swarms over raw 802.11 monitor mode interfaces:

```bash
# Sweep Social Channel 6 (2.4 GHz) vs Channel 149 (5.8 GHz)
sudo .venv/bin/python evaluation/wifi_capacity.py \
  --interface wlan1 --channels 6,149 --drones 10,25,50,100,150,200 \
  --out evaluation/data/wifi_capacity_comparison.json
```

### D. Wi-Fi Channel Hopping Latency & Calibration (`hopping_evaluation.py`)
Measures exact monitor mode channel switching latencies, demonstrating that switching latency is **governed by target frequency** (rather than frequency jump distance $\Delta f$) with near source-band invariance. Evaluates the complete 4-phase lifecycle (Previous Frequency Drain $\rightarrow$ RF Synthesizer Blind Spot $\rightarrow$ Physical Target Lock $\rightarrow$ Command Completion). Supports active pulse injection via an auxiliary interface (`--tx-interface`) to provide deterministic ground-truth timing:

```bash
# 1. Active Injection Mode: Transmit deterministic 500 Hz calibration pulses from wlan0 while switching on wlx00c0cabb1654:
sudo .venv/bin/python evaluation/hopping_evaluation.py \
  -i wlx00c0cabb1654 --tx-interface wlan0 --pulse-rate 500 --plot

# 2. Passive Ambient Sniffing Mode on single interface:
sudo .venv/bin/python evaluation/hopping_evaluation.py -i wlx00c0cabb1654 --plot

# 3. Replay exact scanner sequence for 10 cycles (ratio k=1):
sudo .venv/bin/python evaluation/hopping_evaluation.py -i wlx00c0cabb1654 --mode scanner_sequence --cycles 10

# 4. Pairwise N x N matrix across all channels:
sudo .venv/bin/python evaluation/hopping_evaluation.py -i wlx00c0cabb1654 --mode matrix -n 10

# 5. Dry-run simulation (no root / physical hardware required):
.venv/bin/python evaluation/hopping_evaluation.py --mock --plot
```

---

## 2. Plotting & Visualization

All plotting logic is consolidated into a single shared engine ([plot_common.py](plot_common.py)) with two frontends:

### A. Unified CLI Plotter (`plot_capacity.py`)
Plots one or more arbitrary JSON datasets from `evaluation/data/` for BLE, Wi-Fi, or cross-transport analysis:

```bash
# Plot a single BLE sweep:
.venv/bin/python evaluation/plot_capacity.py \
  -i evaluation/data/ext-legacy_interval_100ms_hci0.json \
  -o evaluation/plots/ext_legacy_100ms/

# Compare multiple BLE interval datasets side-by-side:
.venv/bin/python evaluation/plot_capacity.py \
  -i evaluation/data/ext-legacy_interval_*_hci0.json \
  -o evaluation/plots/ext_legacy_intervals_comparison/

# Plot Wi-Fi capacity results:
.venv/bin/python evaluation/plot_capacity.py \
  -i evaluation/data/wifi_capacity_comparison.json \
  -o evaluation/plots/wifi_capacity/
```

### B. Categorized BLE Batch Comparison (`plot_ble_comparisons.py`)
Scans all JSON files in `evaluation/data/` and automatically renders 5 publication-ready analysis folders under `evaluation/comparison_plots/`:

```bash
.venv/bin/python evaluation/plot_ble_comparisons.py
```

Generated categories:
1. `01_single_transport/`: Single transport sweeps across individual intervals.
2. `02_internal_vs_external/`: Hardware comparison (`hci0` vs `hci1`).
3. `03_legacy_vs_ext_legacy/`: BLE 4 Classic vs BLE 5 Ext-Legacy advertising on `hci1`.
4. `04_cross_transport_comparison/`: Side-by-side comparison of all modes at fixed intervals (100ms, 200ms, 20ms stress test).
5. `05_dual_mode_analysis/`: Receiver performance under Dual Mode (BLE4 vs BLE5 sniffers).

---

## 3. Generated Figure Reference

Each plotting run produces the following standard high-resolution (300 DPI) figures:

| Figure File | Description |
| :--- | :--- |
| `pdr_over_the_air.png` | Packet Delivery Rate (PDR %) over the air vs number of spoofed drones (with 100% ideal & 80% compliance threshold lines). |
| `missed_deadlines.png` | Count of missed periodic update deadlines (1 Hz kinematic tick) as drone swarm scales. |
| `dispatch_execution_time.png` | Kernel / HCI socket transmission execution latency per cycle in milliseconds. |
| `total_loop_duration.png` | Total loop cycle duration compared against the **1000ms deadline** (1 Hz ASTM update requirement). |
| `inject_times_boxplot.png` | Boxplot distribution of per-packet HCI/socket injection latencies. |
| `inject_times_boxplot_log.png` | Log-scale boxplot distribution highlighting injection outliers and kernel buffer saturation. |
| `build_times_boxplot.png` | Boxplot distribution of ASTM F3411 payload serialization & frame assembly times. |
| `loop_times_boxplot.png` | Boxplot distribution of total cycle execution time per drone count. |
| `propagation_latency_boxplot.png` | Propagation latency distribution from transmitter socket dispatch to air sniffer capture. |
| `iat_distribution_boxplot.png` | Inter-Arrival Time (IAT) distribution of received packets at the sniffer. |
| `summary_dashboard.png` | 4-panel executive dashboard combining PDR, Deadlines, Injection Latency, and Loop Duration. |

---

## 4. Benchmark Dataset Format

Output JSON files in `evaluation/data/` adhere to the standardized schema parsed by `plot_common.py`:

```json
{
  "all_runs": [
    {
      "drones": 10,
      "transport": "extended",
      "tx_adapter": "hci0",
      "ble_interval_ms": 100,
      "pdr_rx_percent": 98.5,
      "pdr_tx_percent": 100.0,
      "missed_deadlines": 0,
      "avg_inject_time_ms": 1.42,
      "avg_build_time_ms": 0.28,
      "avg_loop_time_ms": 12.5,
      "propagation_latency_stats_ms": { "avg": 4.2, "p95": 8.1 },
      "raw_data": {
        "inject_times_ms": [...],
        "build_times_ms": [...],
        "loop_times_ms": [...],
        "propagation_latencies_ms": [...]
      }
    }
  ]
}
```
