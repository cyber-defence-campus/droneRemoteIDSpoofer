#!/usr/bin/env python3
"""
Shared Plotting and Normalization Engine for Drone Remote ID Spoofer Evaluations.

Provides common data ingestion, metric extraction, statistical aggregation,
and publication-ready Seaborn/Matplotlib figure generation for BLE, Wi-Fi,
and cross-transport capacity benchmarks.
"""

import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# Styling Defaults
sns.set_theme(style="whitegrid", palette="tab10", font_scale=1.05)
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['figure.autolayout'] = True


# =============================================================================
# 1. Data Ingestion and Normalization
# =============================================================================

def get_wifi_band(ch: int) -> str:
    """Returns frequency band string for a Wi-Fi channel."""
    if ch in (149, 153, 157, 161, 165) or ch >= 149:
        return "5.8GHz"
    elif ch >= 36:
        return "5.2GHz"
    return "2.4GHz"


def load_dataset(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads and normalizes a JSON benchmark dataset (BLE or Wi-Fi).
    Handles multiple root structures: raw list, dict with 'all_runs', 'runs',
    'ble4'/'ble5', or 'social_channel'/'non_social_channel'.
    """
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
        elif 'social_channel' in data or 'non_social_channel' in data:
            runs = data.get('social_channel', []) + data.get('non_social_channel', [])
        elif 'runs' in data:
            runs = data['runs']
        else:
            # Maybe a single run dict
            runs = [data]

    normalized = []
    for r in runs:
        if not isinstance(r, dict):
            continue

        raw_mode = r.get('ble_mode', r.get('transport', r.get('mode', 'extended')))
        rx_mode = r.get('rx_mode')
        adapter = r.get('tx_adapter', 'hci0')
        drones = r.get('drones', 0)
        ch = r.get('channel')

        # Detect transport type
        is_wifi = (ch is not None) or (str(raw_mode).lower() in ('wifi', 'wifi_beacon'))

        if is_wifi:
            ch_num = int(ch) if ch is not None else 6
            is_soc = r.get('is_social_channel', ch_num in (6, 149))
            band_str = get_wifi_band(ch_num)
            mode_clean = 'wifi'
            leg_interval = None
            ext_interval = None
            ble_interval = None
            adapter_name = adapter
            adapter_short = adapter
        else:
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
                ble_interval = leg_interval if leg_interval is not None else 200
            else:
                ble_interval = r.get('ble_interval_ms', leg_interval if leg_interval is not None else 200)

            adapter_name = "Internal (hci0)" if adapter == "hci0" else ("External (hci1)" if adapter == "hci1" else adapter)
            adapter_short = "Internal" if adapter == "hci0" else ("External" if adapter == "hci1" else adapter)
            is_soc = None
            band_str = None

        perf = r.get('performance', {})
        missed = r.get('missed_deadlines', perf.get('missed_deadlines', 0))

        prop_stats = r.get('propagation_latency_stats_ms', {})
        iat_stats = r.get('iat_stats_ms', {})

        normalized.append({
            'source_file': os.path.basename(filepath),
            'drones': drones,
            'is_wifi': is_wifi,
            'mode': mode_clean,
            'channel': ch,
            'is_social_channel': is_soc,
            'band': band_str,
            'rx_mode': rx_mode,
            'adapter': adapter,
            'adapter_name': adapter_name,
            'adapter_short': adapter_short,
            'interval': r.get('interval', 1.0),
            'ble_interval_ms': ble_interval,
            'legacy_interval_ms': leg_interval if leg_interval is not None else ble_interval,
            'extended_interval_ms': ext_interval,
            'pdr_rx': float(r.get('pdr_rx_percent', 0.0)),
            'pdr_tx': float(r.get('pdr_tx_percent', 0.0)),
            'missed_deadlines': int(missed),
            'avg_jitter_ms': float(r.get('avg_jitter_ms', 0.0)),
            'avg_inject_ms': float(r.get('avg_inject_time_ms', 0.0)),
            'max_inject_ms': float(r.get('max_inject_time_ms', 0.0)),
            'avg_build_ms': float(r.get('avg_build_time_ms', 0.0)),
            'avg_loop_ms': float(r.get('avg_loop_time_ms', 0.0)),
            'avg_prop_latency_ms': float(prop_stats.get('avg', 0.0)),
            'p95_prop_latency_ms': float(prop_stats.get('p95', 0.0)),
            'avg_iat_ms': float(iat_stats.get('avg', 0.0)),
            'raw_data': r.get('raw_data', {})
        })

    return normalized


# =============================================================================
# 2. Labeling and Formatting Helpers
# =============================================================================

def format_mode_label(mode: str, rx_mode: Optional[str] = None) -> str:
    """Formats standardized BLE mode title."""
    m = str(mode).lower().replace("_", "-")
    if m in ("ext-legacy", "ext_legacy"):
        return "BLE 5 Ext-Legacy"
    elif m == "dual":
        if rx_mode == "ble5":
            return "BLE Dual (RX: Ext)"
        elif rx_mode == "ble4":
            return "BLE Dual (RX: Leg)"
        return "BLE Dual (Ext+Leg)"
    elif m in ("ble4", "legacy"):
        return "BLE 4 Legacy"
    elif m in ("wifi", "wifi_beacon"):
        return "Wi-Fi Beacon"
    else:
        return "BLE 5 Extended"


def auto_label_runs(runs: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Constructs an aggregated DataFrame with intelligent hue/series labels
    based on the diversity of modes, intervals, adapters, and channels present.
    """
    if not runs:
        return pd.DataFrame()

    modes = set(r['mode'] for r in runs)
    rx_modes = set(r.get('rx_mode') for r in runs if r.get('rx_mode'))
    adapters = set(r['adapter'] for r in runs if r.get('adapter'))
    ble_ints = set(r['ble_interval_ms'] for r in runs if r.get('ble_interval_ms') is not None)
    channels = set(r['channel'] for r in runs if r.get('channel') is not None)

    multi_modes = len(modes) > 1 or len(rx_modes) > 1
    multi_adapters = len(adapters) > 1
    multi_intervals = len(ble_ints) > 1
    multi_channels = len(channels) > 1

    records = []
    for r in runs:
        rec = dict(r)
        if r['is_wifi']:
            ch = r.get('channel', 6)
            band_str = r.get('band', get_wifi_band(ch))
            is_soc = r.get('is_social_channel', ch in (6, 149))
            soc_tag = "Social" if is_soc else "Non-Social"
            if multi_channels:
                series_label = f"Ch {ch} ({soc_tag}, {band_str})"
            else:
                series_label = f"Wi-Fi (Ch {ch}, {band_str})"
        else:
            base = format_mode_label(r['mode'], r.get('rx_mode'))
            is_dual = r['mode'] == 'dual'
            parts = [base]
            if multi_intervals or is_dual:
                if is_dual:
                    parts.append(f"Leg:{r['legacy_interval_ms']}ms,Ext:20ms")
                else:
                    parts.append(f"{r['ble_interval_ms']}ms")
            if multi_adapters:
                parts.append(r['adapter_short'])

            series_label = " - ".join(parts) if (multi_modes or multi_intervals or multi_adapters or is_dual) else base

        rec['Series'] = series_label
        records.append(rec)

    return pd.DataFrame(records)


def extract_raw_dataframes(runs: List[Dict[str, Any]], hue_fn: Optional[Callable[[Dict[str, Any]], str]] = None) -> Dict[str, pd.DataFrame]:
    """Extracts raw sample time series arrays (inject, build, loop, prop, iat) for boxplots."""
    inject_records = []
    build_records = []
    loop_records = []
    prop_records = []
    iat_records = []

    # If no hue_fn provided, compute default Series label via auto_label_runs
    if hue_fn is None:
        df_labeled = auto_label_runs(runs)
        series_map = {id(runs[i]): df_labeled.iloc[i]['Series'] for i in range(len(runs))}
        hue_fn = lambda r: series_map.get(id(r), "Default")

    for r in runs:
        hue_val = hue_fn(r)
        drones = r['drones']
        raw = r.get('raw_data', {})

        # Support backward compatibility with older result structures
        for v in raw.get('inject_times_ms', r.get('inject_times_ms', [])):
            inject_records.append({'drones': drones, 'Series': hue_val, 'time_ms': float(v)})
        for v in raw.get('build_times_ms', []):
            build_records.append({'drones': drones, 'Series': hue_val, 'time_ms': float(v)})
        for v in raw.get('loop_times_ms', []):
            loop_records.append({'drones': drones, 'Series': hue_val, 'time_ms': float(v)})
        for v in raw.get('propagation_latencies_ms', []):
            prop_records.append({'drones': drones, 'Series': hue_val, 'time_ms': float(v)})
        for v in raw.get('iat_intervals_ms', []):
            iat_records.append({'drones': drones, 'Series': hue_val, 'time_ms': float(v)})

    return {
        'inject': pd.DataFrame(inject_records),
        'build': pd.DataFrame(build_records),
        'loop': pd.DataFrame(loop_records),
        'prop': pd.DataFrame(prop_records),
        'iat': pd.DataFrame(iat_records),
    }


# =============================================================================
# 3. Figure Plotting Suite
# =============================================================================

def generate_plot_suite(
    df_agg: pd.DataFrame,
    df_raw: Dict[str, pd.DataFrame],
    output_dir: str,
    title_prefix: str = "Capacity Evaluation",
    hue_col: str = "Series",
    is_wifi: bool = False
) -> None:
    """
    Generates publication-ready figures for a benchmark dataset:
      1. pdr_over_the_air.png (Air PDR % curve)
      2. missed_deadlines.png (Deadlines missed count)
      3. dispatch_execution_time.png (Kernel TX / HCI socket send time)
      4. total_loop_duration.png (Cycle loop duration vs 1000ms deadline)
      5. inject_times_boxplot.png (Boxplot of socket injection times)
      6. inject_times_boxplot_log.png (Log-scale boxplot for injection times)
      7. build_times_boxplot.png (Boxplot of packet construction times)
      8. loop_times_boxplot.png (Boxplot of loop durations)
      9. propagation_latency_boxplot.png (Propagation latency Kernel TX -> Air RX)
      10. iat_distribution_boxplot.png (Inter-Arrival Times)
      11. summary_dashboard.png (4-panel executive overview)
    """
    if df_agg.empty:
        return

    os.makedirs(output_dir, exist_ok=True)
    df_agg = df_agg.sort_values(by=['drones', hue_col])
    num_hues = len(df_agg[hue_col].unique())
    palette = sns.color_palette("tab10", n_colors=num_hues) if num_hues <= 10 else sns.color_palette("husl", n_colors=num_hues)

    dispatch_label = "Socket send() Time (ms)" if is_wifi else "HCI Injection Time (ms)"
    dispatch_title = "Socket send() Execution Time" if is_wifi else "HCI Injection Execution Time"

    # --- 1. Air PDR (%) ---
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

    # --- 2. Missed Deadlines ---
    plt.figure(figsize=(10, 5.5))
    sns.lineplot(data=df_agg, x='drones', y='missed_deadlines', hue=hue_col, marker='s', linewidth=2.2, markersize=7, palette=palette)
    plt.title(f"{title_prefix} - Missed Periodic Deadlines", fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('Number of Spoofed Drones', fontweight='bold')
    plt.ylabel('Missed Deadlines', fontweight='bold')
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'missed_deadlines.png'), dpi=300)
    plt.close()

    # --- 3. Dispatch Execution Time (ms) ---
    plt.figure(figsize=(10, 5.5))
    sns.lineplot(data=df_agg, x='drones', y='avg_inject_ms', hue=hue_col, marker='^', linewidth=2.2, markersize=7, palette=palette)
    plt.title(f"{title_prefix} - {dispatch_title}", fontsize=13, fontweight='bold', pad=12)
    plt.xlabel('Number of Spoofed Drones', fontweight='bold')
    plt.ylabel(dispatch_label, fontweight='bold')
    plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'dispatch_execution_time.png'), dpi=300)
    # Also save as legacy filename for backward compatibility
    plt.savefig(os.path.join(output_dir, 'hci_dispatch_time.png'), dpi=300)
    plt.close()

    # --- 4. Loop Duration vs 1000ms Deadline ---
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

    # Helper function for boxplots
    def _plot_box(df: pd.DataFrame, title: str, filename: str, y_label: str, use_log: bool = False):
        if df.empty:
            return
        plt.figure(figsize=(12, 6))
        df_sorted = df.sort_values(by=['drones', hue_col])
        sns.boxplot(x='drones', y='time_ms', hue=hue_col, data=df_sorted, showfliers=True,
                    palette=palette, flierprops={"marker": "x", "markersize": 3, "alpha": 0.4})
        plt.title(f"{title_prefix} - {title}", fontsize=13, fontweight='bold', pad=12)
        plt.xlabel('Number of Spoofed Drones', fontweight='bold')
        plt.ylabel(y_label if not use_log else f"{y_label} (Log Scale)", fontweight='bold')
        if use_log:
            plt.yscale('log')
        plt.legend(bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, filename), dpi=300)
        plt.close()

    # --- 5 to 10: Boxplots ---
    _plot_box(df_raw.get('inject', pd.DataFrame()), dispatch_title, 'inject_times_boxplot.png', dispatch_label)
    _plot_box(df_raw.get('inject', pd.DataFrame()), f"{dispatch_title} (Log Scale)", 'inject_times_boxplot_log.png', dispatch_label, use_log=True)
    _plot_box(df_raw.get('build', pd.DataFrame()), 'ASTM Packet Build Times per Cycle', 'build_times_boxplot.png', 'Build Time (ms)')
    _plot_box(df_raw.get('loop', pd.DataFrame()), 'Total Loop Execution Times', 'loop_times_boxplot.png', 'Loop Time (ms)')
    _plot_box(df_raw.get('prop', pd.DataFrame()), 'Propagation Latency (Kernel TX to Air RX)', 'propagation_latency_boxplot.png', 'Latency (ms)')
    _plot_box(df_raw.get('iat', pd.DataFrame()), 'Inter-Arrival Time (IAT) Distribution', 'iat_distribution_boxplot.png', 'IAT (ms)')

    # --- 11. 4-Panel Executive Summary Dashboard ---
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))

    # Top-Left: PDR
    sns.lineplot(ax=axes[0, 0], data=df_agg, x='drones', y='pdr_rx', hue=hue_col, marker='o', linewidth=2, palette=palette)
    axes[0, 0].axhline(100, color='gray', linestyle=':', alpha=0.5)
    axes[0, 0].axhline(80, color='orange', linestyle='--', alpha=0.5)
    axes[0, 0].set_title('Air PDR (%)', fontweight='bold')
    axes[0, 0].set_ylim(-2, 105)
    axes[0, 0].set_xlabel('Spoofed Drones')
    axes[0, 0].set_ylabel('PDR (%)')

    # Top-Right: Missed Deadlines
    sns.lineplot(ax=axes[0, 1], data=df_agg, x='drones', y='missed_deadlines', hue=hue_col, marker='s', linewidth=2, palette=palette)
    axes[0, 1].set_title('Missed Deadlines', fontweight='bold')
    axes[0, 1].set_xlabel('Spoofed Drones')
    axes[0, 1].set_ylabel('Count')

    # Bottom-Left: Dispatch Execution Time
    sns.lineplot(ax=axes[1, 0], data=df_agg, x='drones', y='avg_inject_ms', hue=hue_col, marker='^', linewidth=2, palette=palette)
    axes[1, 0].set_title(dispatch_title, fontweight='bold')
    axes[1, 0].set_xlabel('Spoofed Drones')
    axes[1, 0].set_ylabel('Time (ms)')

    # Bottom-Right: Total Loop Duration
    sns.lineplot(ax=axes[1, 1], data=df_agg, x='drones', y='avg_loop_ms', hue=hue_col, marker='D', linewidth=2, palette=palette)
    axes[1, 1].axhline(1000, color='red', linestyle='--', linewidth=1.5, label='1000ms Limit')
    axes[1, 1].set_title('Total Cycle Duration (ms)', fontweight='bold')
    axes[1, 1].set_xlabel('Spoofed Drones')
    axes[1, 1].set_ylabel('Duration (ms)')

    # Common Legend for Dashboard
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
