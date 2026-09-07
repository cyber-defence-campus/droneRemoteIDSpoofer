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

Outputs high-resolution, publication-ready figures for each category.
"""

import argparse
import glob
import json
import os
import sys
from typing import Dict, List, Any, Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


# Set styling defaults
sns.set_theme(style="whitegrid", palette="tab10", font_scale=1.05)
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['figure.autolayout'] = True


def load_dataset(filepath: str) -> List[Dict[str, Any]]:
    """Loads and normalizes a JSON benchmark dataset."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return []

    runs = []
    if isinstance(data, list):
        runs = data
    elif isinstance(data, dict):
        if 'all_runs' in data:
            runs = data['all_runs']
        elif 'ble4' in data or 'ble5' in data:
            runs = data.get('ble4', []) + data.get('ble5', [])
        elif 'runs' in data:
            runs = data['runs']

    normalized = []
    for r in runs:
        if not isinstance(r, dict):
            continue
        raw_mode = r.get('ble_mode', r.get('transport', 'extended'))
        rx_mode = r.get('rx_mode')
        adapter = r.get('tx_adapter', 'hci0')
        drones = r.get('drones', 0)
        
        # Determine clean mode string
        mode_clean = str(raw_mode).lower().replace('_', '-')
        if mode_clean in ('ble4', 'legacy'):
            mode_clean = 'legacy'
        elif mode_clean in ('ext-legacy', 'ext_legacy'):
            mode_clean = 'ext-legacy'
        elif mode_clean in ('ble5', 'extended'):
            mode_clean = 'extended'
        elif mode_clean == 'dual':
            mode_clean = 'dual'

        leg_interval = r.get('legacy_interval_ms')
        ext_interval = r.get('extended_interval_ms', 20)

        if mode_clean == 'dual':
            # In dual mode, extended advertising is fixed at 20ms and legacy interval varies (20ms..200ms)
            ble_interval = leg_interval if leg_interval is not None else 200
        else:
            ble_interval = r.get('ble_interval_ms', leg_interval if leg_interval is not None else 200)

        adapter_name = "Internal (hci0)" if adapter == "hci0" else ("External (hci1)" if adapter == "hci1" else adapter)
        adapter_short = "Internal" if adapter == "hci0" else ("External" if adapter == "hci1" else adapter)

        normalized.append({
            'source_file': os.path.basename(filepath),
            'drones': drones,
            'mode': mode_clean,
            'rx_mode': rx_mode,
            'adapter': adapter,
            'adapter_name': adapter_name,
            'adapter_short': adapter_short,
            'ble_interval_ms': ble_interval,
            'legacy_interval_ms': leg_interval if leg_interval is not None else ble_interval,
            'extended_interval_ms': ext_interval,
            'pdr_rx': r.get('pdr_rx_percent', 0.0),
            'pdr_tx': r.get('pdr_tx_percent', 0.0),
            'missed_deadlines': r.get('missed_deadlines', r.get('performance', {}).get('missed_deadlines', 0)),
            'avg_jitter_ms': r.get('avg_jitter_ms', 0.0),
            'avg_inject_ms': r.get('avg_inject_time_ms', 0.0),
            'max_inject_ms': r.get('max_inject_time_ms', 0.0),
            'avg_build_ms': r.get('avg_build_time_ms', 0.0),
            'avg_loop_ms': r.get('avg_loop_time_ms', 0.0),
            'avg_prop_latency_ms': r.get('propagation_latency_stats_ms', {}).get('avg', 0.0),
            'p95_prop_latency_ms': r.get('propagation_latency_stats_ms', {}).get('p95', 0.0),
            'avg_iat_ms': r.get('iat_stats_ms', {}).get('avg', 0.0),
            'raw_data': r.get('raw_data', {})
        })

    return normalized


def generate_plot_suite(df_agg: pd.DataFrame, df_raw: Dict[str, pd.DataFrame], output_dir: str, title_prefix: str, hue_col: str):
    """
    Generates the complete suite of comparative figures for a given dataframe:
    1. pdr_over_the_air.png
    2. missed_deadlines.png
    3. hci_dispatch_time.png
    4. total_loop_duration.png
    5. propagation_latency_boxplot.png
    6. iat_distribution_boxplot.png
    7. summary_dashboard.png
    """
    if df_agg.empty:
        return

    os.makedirs(output_dir, exist_ok=True)
    
    # Sort dataframe for clean plotting
    df_agg = df_agg.sort_values(by=['drones', hue_col])
    num_hues = len(df_agg[hue_col].unique())
    palette = sns.color_palette("tab10", n_colors=num_hues) if num_hues <= 10 else sns.color_palette("husl", n_colors=num_hues)

    # --- Plot 1: Air PDR (%) ---
    plt.figure(figsize=(10, 5.5))
    sns.lineplot(data=df_agg, x='drones', y='pdr_rx', hue=hue_col, marker='o', linewidth=2.2, markersize=7, palette=palette)
    plt.axhline(100, color='gray', linestyle=':', alpha=0.6, label='100% Ideal PDR')
    plt.axhline(80, color='orange', linestyle='--', alpha=0.5, label='80% Compliance Threshold')
    plt.title(f"{title_prefix} - Air Packet Delivery Rate (PDR)", fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('Number of Spoofed Drones', fontweight='bold')
    plt.ylabel('Air PDR (%)', fontweight='bold')
    plt.ylim(-2, 105)
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'pdr_over_the_air.png'), dpi=300)
    plt.close()

    # --- Plot 2: Missed Deadlines ---
    plt.figure(figsize=(10, 5.5))
    sns.lineplot(data=df_agg, x='drones', y='missed_deadlines', hue=hue_col, marker='s', linewidth=2.2, markersize=7, palette=palette)
    plt.title(f"{title_prefix} - Missed Periodic Deadlines", fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('Number of Spoofed Drones', fontweight='bold')
    plt.ylabel('Missed Deadlines (per evaluation window)', fontweight='bold')
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'missed_deadlines.png'), dpi=300)
    plt.close()

    # --- Plot 3: HCI Dispatch Execution Time (ms) ---
    plt.figure(figsize=(10, 5.5))
    sns.lineplot(data=df_agg, x='drones', y='avg_inject_ms', hue=hue_col, marker='^', linewidth=2.2, markersize=7, palette=palette)
    plt.title(f"{title_prefix} - Average HCI Injection Execution Time", fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('Number of Spoofed Drones', fontweight='bold')
    plt.ylabel('HCI Dispatch Time (ms)', fontweight='bold')
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'hci_dispatch_time.png'), dpi=300)
    plt.close()

    # --- Plot 4: Loop Duration vs 1000ms Deadline ---
    plt.figure(figsize=(10, 5.5))
    sns.lineplot(data=df_agg, x='drones', y='avg_loop_ms', hue=hue_col, marker='D', linewidth=2.2, markersize=7, palette=palette)
    plt.axhline(1000, color='red', linestyle='--', linewidth=1.8, label='1000ms Frame Deadline (1 Hz)')
    plt.title(f"{title_prefix} - Total Cycle Loop Execution Duration", fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('Number of Spoofed Drones', fontweight='bold')
    plt.ylabel('Loop Duration (ms)', fontweight='bold')
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'total_loop_duration.png'), dpi=300)
    plt.close()

    # --- Plot 5: Propagation Latency Boxplot ---
    df_prop = df_raw.get('prop', pd.DataFrame())
    if not df_prop.empty:
        plt.figure(figsize=(12, 6))
        df_prop = df_prop.sort_values(by=['drones', hue_col])
        sns.boxplot(x='drones', y='time_ms', hue=hue_col, data=df_prop, showfliers=True,
                    palette=palette, flierprops={"marker": "x", "markersize": 3, "alpha": 0.4})
        plt.title(f"{title_prefix} - Propagation Latency (HCI TX to Air RX)", fontsize=13, fontweight='bold', pad=12)
        plt.xlabel('Number of Spoofed Drones', fontweight='bold')
        plt.ylabel('Propagation Latency (ms)', fontweight='bold')
        plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'propagation_latency_boxplot.png'), dpi=300)
        plt.close()

    # --- Plot 6: Inter-Arrival Time (IAT) Boxplot ---
    df_iat = df_raw.get('iat', pd.DataFrame())
    if not df_iat.empty:
        plt.figure(figsize=(12, 6))
        df_iat = df_iat.sort_values(by=['drones', hue_col])
        sns.boxplot(x='drones', y='time_ms', hue=hue_col, data=df_iat, showfliers=True,
                    palette=palette, flierprops={"marker": "x", "markersize": 3, "alpha": 0.4})
        plt.title(f"{title_prefix} - Inter-Arrival Time (IAT) Distribution", fontsize=13, fontweight='bold', pad=12)
        plt.xlabel('Number of Spoofed Drones', fontweight='bold')
        plt.ylabel('IAT (ms)', fontweight='bold')
        plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'iat_distribution_boxplot.png'), dpi=300)
        plt.close()

    # --- Plot 7: 4-Panel Executive Summary Dashboard ---
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    
    # 1. PDR
    sns.lineplot(ax=axes[0, 0], data=df_agg, x='drones', y='pdr_rx', hue=hue_col, marker='o', linewidth=2, palette=palette)
    axes[0, 0].axhline(100, color='gray', linestyle=':', alpha=0.5)
    axes[0, 0].axhline(80, color='orange', linestyle='--', alpha=0.5)
    axes[0, 0].set_title('Air PDR (%)', fontweight='bold')
    axes[0, 0].set_ylim(-2, 105)
    axes[0, 0].set_xlabel('Spoofed Drones')
    axes[0, 0].set_ylabel('PDR (%)')
    
    # 2. Missed Deadlines
    sns.lineplot(ax=axes[0, 1], data=df_agg, x='drones', y='missed_deadlines', hue=hue_col, marker='s', linewidth=2, palette=palette)
    axes[0, 1].set_title('Missed Deadlines', fontweight='bold')
    axes[0, 1].set_xlabel('Spoofed Drones')
    axes[0, 1].set_ylabel('Count')

    # 3. HCI Dispatch Time
    sns.lineplot(ax=axes[1, 0], data=df_agg, x='drones', y='avg_inject_ms', hue=hue_col, marker='^', linewidth=2, palette=palette)
    axes[1, 0].set_title('HCI Dispatch Time (ms)', fontweight='bold')
    axes[1, 0].set_xlabel('Spoofed Drones')
    axes[1, 0].set_ylabel('Time (ms)')

    # 4. Total Loop Duration
    sns.lineplot(ax=axes[1, 1], data=df_agg, x='drones', y='avg_loop_ms', hue=hue_col, marker='D', linewidth=2, palette=palette)
    axes[1, 1].axhline(1000, color='red', linestyle='--', linewidth=1.5, label='1000ms Limit')
    axes[1, 1].set_title('Total Cycle Duration (ms)', fontweight='bold')
    axes[1, 1].set_xlabel('Spoofed Drones')
    axes[1, 1].set_ylabel('Duration (ms)')

    # Add single common legend
    handles, labels = axes[0, 0].get_legend_handles_labels()
    for ax in axes.flat:
        if ax.get_legend():
            ax.get_legend().remove()
    if handles and labels:
        fig.legend(handles, labels, loc='lower center', ncol=min(len(labels), 5), bbox_to_anchor=(0.5, -0.02), frameon=True)
    fig.suptitle(f"{title_prefix} - Performance Overview Dashboard", fontsize=16, fontweight='bold', y=1.01)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'summary_dashboard.png'), dpi=300, bbox_inches='tight')
    plt.close()


def prepare_raw_dataframes(runs: List[Dict[str, Any]], hue_func) -> Dict[str, pd.DataFrame]:
    """Extracts raw sample arrays (latency, IAT, inject) for boxplots."""
    prop_records = []
    iat_records = []
    inject_records = []

    for r in runs:
        hue_val = hue_func(r)
        drones = r['drones']
        raw = r.get('raw_data', {})

        for v in raw.get('propagation_latencies_ms', []):
            prop_records.append({'drones': drones, 'series': hue_val, 'time_ms': v})
        for v in raw.get('iat_intervals_ms', []):
            iat_records.append({'drones': drones, 'series': hue_val, 'time_ms': v})
        for v in raw.get('inject_times_ms', []):
            inject_records.append({'drones': drones, 'series': hue_val, 'time_ms': v})

    return {
        'prop': pd.DataFrame(prop_records).rename(columns={'series': 'Series'}),
        'iat': pd.DataFrame(iat_records).rename(columns={'series': 'Series'}),
        'inject': pd.DataFrame(inject_records).rename(columns={'series': 'Series'}),
    }


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

        raw_dfs = prepare_raw_dataframes(matching, hue_fn)
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

        raw_dfs = prepare_raw_dataframes(matching, hue_fn)
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
        raw_dfs = prepare_raw_dataframes(matching_legacy_cmp, hue_fn)
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
                raw_sub_dfs = prepare_raw_dataframes(sub_matching, lambda r: 'Classic Legacy (BT4)' if r['mode'] == 'legacy' else 'Ext-Legacy (BT5)')
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
        raw_dfs = prepare_raw_dataframes(cmp_200ms_hci1, label_cross_transport)
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
        raw_dfs = prepare_raw_dataframes(cmp_100ms_hci1, label_cross_transport)
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
        raw_dfs = prepare_raw_dataframes(cmp_200ms_hci0, label_cross_transport)
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
        raw_dfs = prepare_raw_dataframes(cmp_20ms_hci0, label_cross_transport)
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
        raw_dfs = prepare_raw_dataframes(dual_hci0, hue_fn)
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
        raw_dfs = prepare_raw_dataframes(dual_hci1, hue_fn)
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
