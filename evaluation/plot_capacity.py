#!/usr/bin/env python3
"""
Unified Capacity Evaluation Plot Generator for Wi-Fi and BLE Remote ID Spoofer.

Ingests one or more benchmark JSON results from evaluation/data/ and produces
high-resolution comparative figures (PDR, Deadlines, Injection times, Loop
durations, Boxplots, and 4-Panel Executive Dashboard).

Usage:
  # Plot a single BLE or Wi-Fi dataset:
  python evaluation/plot_capacity.py -i evaluation/data/ext-legacy_interval_100ms_hci0.json -o plots/

  # Compare multiple BLE datasets (e.g., across intervals or adapters):
  python evaluation/plot_capacity.py -i evaluation/data/ext-legacy_interval_*_hci0.json -o plots_ext_legacy/

  # Compare Wi-Fi 2.4 GHz vs 5.8 GHz:
  python evaluation/plot_capacity.py -i evaluation/data/wifi_capacity_comparison.json -o plots_wifi/
"""

import argparse
import glob
import os
import sys
from typing import List

# Ensure evaluation folder is in sys.path
eval_dir = os.path.dirname(os.path.abspath(__file__))
if eval_dir not in sys.path:
    sys.path.insert(0, eval_dir)

from plot_common import (
    auto_label_runs,
    extract_raw_dataframes,
    generate_plot_suite,
    load_dataset,
)


def main():
    parser = argparse.ArgumentParser(
        description="Unified Plot Generator for Drone Remote ID Capacity Benchmarks"
    )
    parser.add_argument(
        "--input", "-i", nargs="+", required=True,
        help="One or more input benchmark JSON files (supports wildcard globs)"
    )
    parser.add_argument(
        "--outdir", "-o", type=str, default="plots_output",
        help="Output directory for generated plots (default: plots_output)"
    )
    parser.add_argument(
        "--title", "-t", type=str, default=None,
        help="Custom title prefix for generated figures"
    )

    args = parser.parse_args()

    # Expand any glob patterns in input
    expanded_files: List[str] = []
    for pattern in args.input:
        matches = glob.glob(pattern)
        if matches:
            expanded_files.extend(sorted(matches))
        elif os.path.exists(pattern):
            expanded_files.append(pattern)
        else:
            print(f"[!] Warning: Input file/pattern '{pattern}' not found. Skipping.")

    if not expanded_files:
        print("[-] Error: No valid benchmark JSON input files found.")
        sys.exit(1)

    print(f"[*] Ingesting {len(expanded_files)} benchmark dataset(s)...")
    all_runs = []
    for fpath in expanded_files:
        runs = load_dataset(fpath)
        all_runs.extend(runs)

    if not all_runs:
        print("[-] Error: No valid benchmark runs could be loaded from input files.")
        sys.exit(1)

    print(f"[+] Loaded {len(all_runs)} total benchmark run points across {len(expanded_files)} file(s).")

    # Detect primary transport for titles and labels
    is_wifi = any(r.get('is_wifi', False) for r in all_runs)
    is_ble = any(not r.get('is_wifi', False) for r in all_runs)

    if args.title:
        title_prefix = args.title
    elif is_wifi and not is_ble:
        title_prefix = "Wi-Fi Beacon Capacity"
    elif is_ble and not is_wifi:
        title_prefix = "Bluetooth Low Energy Capacity"
    else:
        title_prefix = "Remote ID Transport Capacity"

    # Build aggregated dataframe with auto-series labeling
    df_agg = auto_label_runs(all_runs)

    # Extract raw distributions for boxplots
    raw_dfs = extract_raw_dataframes(all_runs)

    # Generate all plots
    os.makedirs(args.outdir, exist_ok=True)
    generate_plot_suite(
        df_agg=df_agg,
        df_raw=raw_dfs,
        output_dir=args.outdir,
        title_prefix=title_prefix,
        hue_col='Series',
        is_wifi=is_wifi
    )

    print(f"\n[***] All figures successfully generated in '{args.outdir}' directory:")
    for f in sorted(os.listdir(args.outdir)):
        if f.endswith(".png"):
            print(f"  • {f}")


if __name__ == "__main__":
    main()
