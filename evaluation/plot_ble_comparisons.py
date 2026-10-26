#!/usr/bin/env python3
"""
Automated BLE Capacity Evaluation Comparison Plot Generator

Categorizes and plots BLE capacity benchmark results from evaluation/data/
into structured comparison subfolders:
  01_single_transport/
  02_internal_vs_external/
  03_legacy_vs_ext_legacy/
  04_cross_transport_comparison/
  05_dual_mode_analysis/

Properly accounts for Dual Mode configuration: Extended advertising fixed at 20ms
with varying Legacy advertising pulse intervals (20ms..200ms).

Uses evaluation/plot_common.py for shared normalization, styling, and figure generation.
"""

import argparse
import glob
import os
import sys
from typing import Any, Dict, List

import pandas as pd

# Ensure evaluation folder is in sys.path
eval_dir = os.path.dirname(os.path.abspath(__file__))
if eval_dir not in sys.path:
    sys.path.insert(0, eval_dir)

from plot_common import (
    extract_raw_dataframes,
    generate_plot_suite,
    load_dataset,
)


def process_all_comparisons(all_runs: List[Dict[str, Any]], base_outdir: str):
    """Orchestrates all defined comparison subcategories and generates plots."""

    # =========================================================================
    # 01_single_transport: Single folder per transport method across its intervals
    # =========================================================================
    print("\n[+] Generating Category 1: Single Transport Sweeps...")

    single_configs = [
        # (Folder, Mode, Adapter, RX Mode, Title)
        ("extended_internal", "extended", "hci0", None, "BLE 5 Extended (Internal / hci0)"),
        ("extended_external", "extended", "hci1", None, "BLE 5 Extended (External / hci1)"),
        ("ext_legacy_internal", "ext-legacy", "hci0", None, "BLE 5 Ext-Legacy (Internal / hci0)"),
        ("ext_legacy_external", "ext-legacy", "hci1", None, "BLE 5 Ext-Legacy (External / hci1)"),
        ("legacy_external", "legacy", "hci1", None, "BLE 4 Classic Legacy (External / hci1)"),
        ("dual_internal_rx_ble5", "dual", "hci0", "ble5", "BLE Dual Mode (Internal / hci0, RX: BLE5 Sniffer)"),
        ("dual_internal_rx_ble4", "dual", "hci0", "ble4", "BLE Dual Mode (Internal / hci0, RX: BLE4 Sniffer)"),
        ("dual_external_rx_ble5", "dual", "hci1", "ble5", "BLE Dual Mode (External / hci1, RX: BLE5 Sniffer)"),
        ("dual_external_rx_ble4", "dual", "hci1", "ble4", "BLE Dual Mode (External / hci1, RX: BLE4 Sniffer)"),
    ]

    for folder_name, target_mode, target_adapter, target_rx, title in single_configs:
        matching = [
            r for r in all_runs
            if r['mode'] == target_mode and r['adapter'] == target_adapter and (target_rx is None or r.get('rx_mode') == target_rx)
        ]
        if not matching:
            continue

        target_dir = os.path.join(base_outdir, "01_single_transport", folder_name)
        df_agg = pd.DataFrame(matching)

        if target_mode == "dual":
            df_agg['Interval'] = df_agg['legacy_interval_ms'].apply(lambda x: f"Leg: {x}ms (Ext: 20ms)")
            hue_fn = lambda r: f"Leg: {r['legacy_interval_ms']}ms (Ext: 20ms)"
        else:
            df_agg['Interval'] = df_agg['ble_interval_ms'].apply(lambda x: f"{x}ms")
            hue_fn = lambda r: f"{r['ble_interval_ms']}ms"

        raw_dfs = extract_raw_dataframes(matching, hue_fn)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Interval'})

        generate_plot_suite(df_agg, raw_dfs, target_dir, title, hue_col='Interval')
        print(f"  -> Generated {folder_name} ({len(df_agg)} datapoints)")

    # =========================================================================
    # 02_internal_vs_external: Compare Internal (hci0) vs External (hci1)
    # =========================================================================
    print("\n[+] Generating Category 2: Internal vs External Hardware Comparison...")

    int_ext_configs = [
        # (Folder, Mode, RX Mode, Title)
        ("extended", "extended", None, "Internal vs External - BLE 5 Extended"),
        ("ext_legacy", "ext-legacy", None, "Internal vs External - BLE 5 Ext-Legacy"),
        ("dual_rx_ble5", "dual", "ble5", "Internal vs External - BLE Dual Mode (RX: BLE5)"),
        ("dual_rx_ble4", "dual", "ble4", "Internal vs External - BLE Dual Mode (RX: BLE4)"),
    ]

    for folder_name, target_mode, target_rx, title in int_ext_configs:
        matching = [
            r for r in all_runs
            if r['mode'] == target_mode and (target_rx is None or r.get('rx_mode') == target_rx)
        ]
        if not matching:
            continue

        target_dir = os.path.join(base_outdir, "02_internal_vs_external", folder_name)
        df_agg = pd.DataFrame(matching)

        if target_mode == "dual":
            df_agg['Comparison'] = df_agg.apply(lambda r: f"{r['adapter_short']} (Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)", axis=1)
            hue_fn = lambda r: f"{r['adapter_short']} (Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)"
        else:
            df_agg['Comparison'] = df_agg.apply(lambda r: f"{r['adapter_short']} ({r['ble_interval_ms']}ms)", axis=1)
            hue_fn = lambda r: f"{r['adapter_short']} ({r['ble_interval_ms']}ms)"

        raw_dfs = extract_raw_dataframes(matching, hue_fn)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Comparison'})

        generate_plot_suite(df_agg, raw_dfs, target_dir, title, hue_col='Comparison')
        print(f"  -> Generated {folder_name} ({len(df_agg)} datapoints)")

    # =========================================================================
    # 03_legacy_vs_ext_legacy: Compare Classic Legacy vs Extended Legacy on hci1
    # =========================================================================
    print("\n[+] Generating Category 3: Legacy Advertising vs Extended Legacy Advertising...")

    matching_legacy_cmp = [
        r for r in all_runs
        if r['mode'] in ('legacy', 'ext-legacy') and r['adapter'] == 'hci1' and r['ble_interval_ms'] in (100, 150, 200)
    ]

    if matching_legacy_cmp:
        # All shared intervals on hci1
        target_dir = os.path.join(base_outdir, "03_legacy_vs_ext_legacy", "external_adapter_hci1")
        df_agg = pd.DataFrame(matching_legacy_cmp)
        df_agg['Mode_Interval'] = df_agg.apply(
            lambda r: f"{'Classic Legacy' if r['mode'] == 'legacy' else 'Ext-Legacy'} ({r['ble_interval_ms']}ms)", axis=1
        )
        hue_fn = lambda r: f"{'Classic Legacy' if r['mode'] == 'legacy' else 'Ext-Legacy'} ({r['ble_interval_ms']}ms)"
        raw_dfs = extract_raw_dataframes(matching_legacy_cmp, hue_fn)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Mode_Interval'})

        generate_plot_suite(df_agg, raw_dfs, target_dir, "Classic Legacy vs Extended Legacy (hci1)", hue_col='Mode_Interval')
        print(f"  -> Generated external_adapter_hci1 ({len(df_agg)} datapoints)")

        # Per-interval breakdowns (100ms, 150ms, 200ms)
        for int_val in [100, 150, 200]:
            sub_matching = [r for r in matching_legacy_cmp if r['ble_interval_ms'] == int_val]
            if sub_matching:
                int_dir = os.path.join(base_outdir, "03_legacy_vs_ext_legacy", f"interval_{int_val}ms")
                df_sub = pd.DataFrame(sub_matching)
                df_sub['Method'] = df_sub['mode'].apply(lambda m: 'Classic Legacy (BT4)' if m == 'legacy' else 'Ext-Legacy (BT5)')
                raw_sub_dfs = extract_raw_dataframes(sub_matching, lambda r: 'Classic Legacy (BT4)' if r['mode'] == 'legacy' else 'Ext-Legacy (BT5)')
                for k in raw_sub_dfs:
                    if not raw_sub_dfs[k].empty:
                        raw_sub_dfs[k] = raw_sub_dfs[k].rename(columns={'Series': 'Method'})
                generate_plot_suite(df_sub, raw_sub_dfs, int_dir, f"Legacy vs Ext-Legacy @ {int_val}ms (hci1)", hue_col='Method')
                print(f"  -> Generated interval_{int_val}ms ({len(df_sub)} datapoints)")

    # =========================================================================
    # 04_cross_transport_comparison: Comparing all modes at fixed intervals
    # =========================================================================
    print("\n[+] Generating Category 4: Cross-Transport Comparisons...")

    def label_cross_transport(r):
        if r['mode'] == 'dual':
            return f"Dual (RX: {r['rx_mode'].upper()}, Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)"
        elif r['mode'] == 'legacy':
            return f"Classic Legacy ({r['ble_interval_ms']}ms)"
        elif r['mode'] == 'ext-legacy':
            return f"Ext-Legacy ({r['ble_interval_ms']}ms)"
        return f"BLE 5 Extended ({r['ble_interval_ms']}ms)"

    # A. 200ms Comparison on External Adapter (hci1)
    cmp_200ms_hci1 = [
        r for r in all_runs
        if r['adapter'] == 'hci1' and ((r['mode'] != 'dual' and r['ble_interval_ms'] == 200) or (r['mode'] == 'dual' and r['legacy_interval_ms'] == 200))
    ]
    if cmp_200ms_hci1:
        target_dir = os.path.join(base_outdir, "04_cross_transport_comparison", "all_transports_200ms_hci1")
        df_agg = pd.DataFrame(cmp_200ms_hci1)
        df_agg['Transport'] = df_agg.apply(label_cross_transport, axis=1)
        raw_dfs = extract_raw_dataframes(cmp_200ms_hci1, label_cross_transport)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Transport'})
        generate_plot_suite(df_agg, raw_dfs, target_dir, "All Transports Comparison @ 200ms (External / hci1)", hue_col='Transport')
        print(f"  -> Generated all_transports_200ms_hci1 ({len(df_agg)} datapoints)")

    # B. 100ms Comparison on External Adapter (hci1)
    cmp_100ms_hci1 = [
        r for r in all_runs
        if r['adapter'] == 'hci1' and ((r['mode'] != 'dual' and r['ble_interval_ms'] == 100) or (r['mode'] == 'dual' and r['legacy_interval_ms'] == 100))
    ]
    if cmp_100ms_hci1:
        target_dir = os.path.join(base_outdir, "04_cross_transport_comparison", "all_transports_100ms_hci1")
        df_agg = pd.DataFrame(cmp_100ms_hci1)
        df_agg['Transport'] = df_agg.apply(label_cross_transport, axis=1)
        raw_dfs = extract_raw_dataframes(cmp_100ms_hci1, label_cross_transport)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Transport'})
        generate_plot_suite(df_agg, raw_dfs, target_dir, "All Transports Comparison @ 100ms (External / hci1)", hue_col='Transport')
        print(f"  -> Generated all_transports_100ms_hci1 ({len(df_agg)} datapoints)")

    # C. 200ms Comparison on Internal Adapter (hci0)
    cmp_200ms_hci0 = [
        r for r in all_runs
        if r['adapter'] == 'hci0' and ((r['mode'] != 'dual' and r['ble_interval_ms'] == 200) or (r['mode'] == 'dual' and r['legacy_interval_ms'] == 200))
    ]
    if cmp_200ms_hci0:
        target_dir = os.path.join(base_outdir, "04_cross_transport_comparison", "all_transports_200ms_hci0")
        df_agg = pd.DataFrame(cmp_200ms_hci0)
        df_agg['Transport'] = df_agg.apply(label_cross_transport, axis=1)
        raw_dfs = extract_raw_dataframes(cmp_200ms_hci0, label_cross_transport)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Transport'})
        generate_plot_suite(df_agg, raw_dfs, target_dir, "All Transports Comparison @ 200ms (Internal / hci0)", hue_col='Transport')
        print(f"  -> Generated all_transports_200ms_hci0 ({len(df_agg)} datapoints)")

    # D. 20ms High-Throughput Stress Test on Internal Adapter (hci0)
    cmp_20ms_hci0 = [
        r for r in all_runs
        if r['adapter'] == 'hci0' and ((r['mode'] != 'dual' and r['ble_interval_ms'] == 20) or (r['mode'] == 'dual' and r['legacy_interval_ms'] == 20))
    ]
    if cmp_20ms_hci0:
        target_dir = os.path.join(base_outdir, "04_cross_transport_comparison", "stress_test_20ms_hci0")
        df_agg = pd.DataFrame(cmp_20ms_hci0)
        df_agg['Transport'] = df_agg.apply(label_cross_transport, axis=1)
        raw_dfs = extract_raw_dataframes(cmp_20ms_hci0, label_cross_transport)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Transport'})
        generate_plot_suite(df_agg, raw_dfs, target_dir, "20ms Minimum Interval Stress Test (Internal / hci0)", hue_col='Transport')
        print(f"  -> Generated stress_test_20ms_hci0 ({len(df_agg)} datapoints)")

    # =========================================================================
    # 05_dual_mode_analysis: Dual Mode Legacy vs Extended Receiver & Interval Analysis
    # =========================================================================
    print("\n[+] Generating Category 5: Dual Mode Analysis...")

    # A. RX BLE4 vs RX BLE5 on Internal Adapter (hci0)
    dual_hci0 = [r for r in all_runs if r['mode'] == 'dual' and r['adapter'] == 'hci0']
    if dual_hci0:
        target_dir = os.path.join(base_outdir, "05_dual_mode_analysis", "rx_ble4_vs_rx_ble5_internal")
        df_agg = pd.DataFrame(dual_hci0)
        df_agg['Receiver_Interval'] = df_agg.apply(
            lambda r: f"RX: {r['rx_mode'].upper()} (Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)", axis=1
        )
        hue_fn = lambda r: f"RX: {r['rx_mode'].upper()} (Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)"
        raw_dfs = extract_raw_dataframes(dual_hci0, hue_fn)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Receiver_Interval'})
        generate_plot_suite(df_agg, raw_dfs, target_dir, "Dual Mode Receiver Comparison (Internal / hci0)", hue_col='Receiver_Interval')
        print(f"  -> Generated rx_ble4_vs_rx_ble5_internal ({len(df_agg)} datapoints)")

    # B. RX BLE4 vs RX BLE5 on External Adapter (hci1)
    dual_hci1 = [r for r in all_runs if r['mode'] == 'dual' and r['adapter'] == 'hci1']
    if dual_hci1:
        target_dir = os.path.join(base_outdir, "05_dual_mode_analysis", "rx_ble4_vs_rx_ble5_external")
        df_agg = pd.DataFrame(dual_hci1)
        df_agg['Receiver_Interval'] = df_agg.apply(
            lambda r: f"RX: {r['rx_mode'].upper()} (Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)", axis=1
        )
        hue_fn = lambda r: f"RX: {r['rx_mode'].upper()} (Leg: {r['legacy_interval_ms']}ms, Ext: 20ms)"
        raw_dfs = extract_raw_dataframes(dual_hci1, hue_fn)
        for k in raw_dfs:
            if not raw_dfs[k].empty:
                raw_dfs[k] = raw_dfs[k].rename(columns={'Series': 'Receiver_Interval'})
        generate_plot_suite(df_agg, raw_dfs, target_dir, "Dual Mode Receiver Comparison (External / hci1)", hue_col='Receiver_Interval')
        print(f"  -> Generated rx_ble4_vs_rx_ble5_external ({len(df_agg)} datapoints)")


def main():
    parser = argparse.ArgumentParser(description="Generate categorized comparative plots for BLE evaluation datasets.")
    parser.add_argument("--data-dir", "-d", type=str, default="evaluation/data",
                        help="Directory containing evaluation JSON files (default: evaluation/data)")
    parser.add_argument("--outdir", "-o", type=str, default="evaluation/comparison_plots",
                        help="Base output directory for generated comparison plots (default: evaluation/comparison_plots)")
    args = parser.parse_args()

    json_files = sorted(glob.glob(os.path.join(args.data_dir, "*.json")))
    if not json_files:
        print(f"[!] No JSON files found in '{args.data_dir}'. Exiting.")
        sys.exit(1)

    print(f"[*] Found {len(json_files)} evaluation JSON files in '{args.data_dir}'. Ingesting datasets...")

    all_runs = []
    for fpath in json_files:
        runs = load_dataset(fpath)
        all_runs.extend(runs)

    print(f"[+] Loaded {len(all_runs)} total benchmark run points across all datasets.")

    process_all_comparisons(all_runs, args.outdir)
    print(f"\n[***] All comparison plots successfully generated under: {args.outdir}")


if __name__ == "__main__":
    main()
