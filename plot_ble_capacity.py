import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import argparse
import os

def load_data(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def create_plots(data_list, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Extract data into a structured format (pandas DataFrame)
    records = []
    runs = []
    
    for item in data_list:
        if isinstance(item, dict):
            if 'ble4' in item or 'ble5' in item:
                runs.extend(item.get('ble4', []) + item.get('ble5', []))
            else:
                runs.extend(item.get('all_runs', []))
        elif isinstance(item, list):
            runs.extend(item)
            
    # Check if multiple modes, intervals or adapters are being compared
    modes_present = set(r.get('ble_mode', r.get('transport', 'extended')) for r in runs)
    rx_modes_present = set(r.get('rx_mode') for r in runs if r.get('rx_mode'))
    intervals_present = set(r.get('ble_interval_ms', 200) for r in runs)
    adapters_present = set(r.get('tx_adapter', 'hci0') for r in runs)
    multi_modes = (len(modes_present) > 1) or (len(rx_modes_present) > 1)
    multi_intervals = len(intervals_present) > 1
    multi_adapters = len(adapters_present) > 1

    def format_mode_label(transport_str: str, rx_mode_str: str = None) -> str:
        t = str(transport_str).lower().replace("_", "-")
        if t in ("ext-legacy", "ext_legacy"):
            return "BLE 5 Ext-Legacy"
        elif t == "dual":
            if rx_mode_str == "ble5":
                return "BLE Dual (RX: Ext)"
            elif rx_mode_str == "ble4":
                return "BLE Dual (RX: Leg)"
            return "BLE Dual (Ext+Leg)"
        elif t in ("ble4", "legacy"):
            return "BLE 4 Legacy"
        else:
            return "BLE 5 Extended"

    for run in runs:
        drones = run.get('drones', 0)
        raw_mode = run.get('ble_mode', run.get('transport', 'extended'))
        rx_mode = run.get('rx_mode')
        t_base = format_mode_label(raw_mode, rx_mode)
        is_dual = str(raw_mode).lower().replace("_", "-") == "dual"
        ble_int = run.get('legacy_interval_ms', run.get('ble_interval_ms', 200)) if is_dual else run.get('ble_interval_ms', 200)
        adapter = run.get('tx_adapter', 'hci0')
        adapter_label = "Internal" if adapter == "hci0" else ("External" if adapter == "hci1" else adapter)
        
        parts = [t_base]
        if multi_intervals or is_dual:
            parts.append(f"Leg:{ble_int}ms,Ext:20ms" if is_dual else f"{ble_int}ms")
        if multi_adapters:
            parts.append(adapter_label)
        t_label = " - ".join(parts) if (multi_modes or multi_intervals or multi_adapters or is_dual) else t_base
        interval = run.get('interval', 1.0)
        
        # Aggregated stats
        records.append({
            'Drones': drones,
            'Transport': t_label,
            'Adv Interval (ms)': ble_int,
            'Adapter': adapter_label,
            'Interval': interval,
            'PDR (Air) %': run.get('pdr_rx_percent', 0),
            'PDR (Kernel) %': run.get('pdr_tx_percent', 0),
            'Missed Deadlines': run.get('performance', {}).get('missed_deadlines', run.get('missed_deadlines', 0)),
            'Avg Jitter (ms)': run.get('avg_jitter_ms', 0),
            'Avg Inject (ms)': run.get('avg_inject_time_ms', 0),
            'Avg Loop (ms)': run.get('avg_loop_time_ms', 0),
            'Avg Propagation (ms)': run.get('propagation_latency_stats_ms', {}).get('avg', 0),
        })
        
    df_agg = pd.DataFrame(records)
    
    # 2. Extract raw data for boxplots
    raw_inject = []
    raw_build = []
    raw_loop = []
    raw_prop = []
    raw_iat = []
    
    for run in runs:
        drones = run.get('drones', 0)
        raw_mode = run.get('ble_mode', run.get('transport', 'extended'))
        rx_mode = run.get('rx_mode')
        t_base = format_mode_label(raw_mode, rx_mode)
        is_dual = str(raw_mode).lower().replace("_", "-") == "dual"
        ble_int = run.get('legacy_interval_ms', run.get('ble_interval_ms', 200)) if is_dual else run.get('ble_interval_ms', 200)
        adapter = run.get('tx_adapter', 'hci0')
        adapter_label = "Int" if adapter == "hci0" else ("Ext" if adapter == "hci1" else adapter)
        
        parts = [t_base]
        if multi_intervals or is_dual:
            parts.append(f"Leg:{ble_int}ms,Ext:20ms" if is_dual else f"{ble_int}ms")
        if multi_adapters:
            parts.append(adapter_label)
        t_label = " - ".join(parts) if (multi_modes or multi_intervals or multi_adapters or is_dual) else t_base
        
        box_parts = [f"{drones}D"]
        if multi_modes:
            box_parts.append(t_base)
        if multi_intervals or is_dual:
            box_parts.append(f"Leg:{ble_int}ms" if is_dual else f"{ble_int}ms")
        if multi_adapters:
            box_parts.append(adapter_label)
        label = "\n".join(box_parts)
        
        rd = run.get('raw_data', {})
        
        for val in rd.get('inject_times_ms', run.get('inject_times_ms', [])):
            raw_inject.append({'Drones': drones, 'Transport': t_label, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('build_times_ms', []):
            raw_build.append({'Drones': drones, 'Transport': t_label, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('loop_times_ms', []):
            raw_loop.append({'Drones': drones, 'Transport': t_label, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('propagation_latencies_ms', []):
            raw_prop.append({'Drones': drones, 'Transport': t_label, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('iat_intervals_ms', []):
            raw_iat.append({'Drones': drones, 'Transport': t_label, 'Label': label, 'Time (ms)': val})
            
    df_inject = pd.DataFrame(raw_inject)
    df_build = pd.DataFrame(raw_build)
    df_loop = pd.DataFrame(raw_loop)
    df_prop = pd.DataFrame(raw_prop)
    df_iat = pd.DataFrame(raw_iat)
    
    sns.set_theme(style="whitegrid")
    
    # --- Plot 1: PDR Comparison ---
    if not df_agg.empty and df_agg['PDR (Air) %'].max() > 0:
        plt.figure(figsize=(10, 6))
        sns.lineplot(data=df_agg, x='Drones', y='PDR (Air) %', hue='Transport', marker='o', linewidth=2, markersize=8)
        plt.title('BLE Packet Delivery Rate (PDR) over the Air vs Number of Drones')
        plt.ylim(0, 105)
        plt.ylabel('PDR (%)')
        plt.xlabel('Number of Drones')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'ble_pdr_comparison.png'), dpi=300)
        plt.close()
    
    # --- Plot 2: Missed Deadlines ---
    if not df_agg.empty:
        plt.figure(figsize=(10, 6))
        sns.lineplot(data=df_agg, x='Drones', y='Missed Deadlines', hue='Transport', marker='s', linewidth=2, markersize=8)
        plt.title('BLE Missed Deadlines vs Number of Drones')
        plt.ylabel('Missed Deadlines')
        plt.xlabel('Number of Drones')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'ble_missed_deadlines.png'), dpi=300)
        plt.close()

    # --- Plot 3: HCI / Socket Send Execution Time ---
    if not df_agg.empty:
        plt.figure(figsize=(10, 6))
        sns.lineplot(data=df_agg, x='Drones', y='Avg Inject (ms)', hue='Transport', marker='^', linewidth=2, markersize=8)
        plt.title('Average HCI Dispatch Time per Cycle vs Number of Drones')
        plt.ylabel('Time (ms)')
        plt.xlabel('Number of Drones')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'ble_hci_dispatch_time.png'), dpi=300)
        plt.close()

    # --- Plot 4: Loop Execution Duration vs 1000ms Deadline ---
    if not df_agg.empty:
        plt.figure(figsize=(10, 6))
        sns.lineplot(data=df_agg, x='Drones', y='Avg Loop (ms)', hue='Transport', marker='D', linewidth=2, markersize=8)
        plt.axhline(1000, color='red', linestyle='--', linewidth=1.5, label='1000ms Deadline (1 Hz)')
        plt.title('Total BLE Cycle Duration vs Number of Drones (1000ms Deadline)')
        plt.ylabel('Cycle Duration (ms)')
        plt.xlabel('Number of Drones')
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'ble_loop_duration_deadline.png'), dpi=300)
        plt.close()

    # Helper function for boxplots
    def plot_boxplot(df, title, filename, y_label, use_log=False):
        if df.empty: return
        plt.figure(figsize=(12, 6))
        df = df.sort_values(by=['Drones', 'Transport'])
        sns.boxplot(x='Drones', y='Time (ms)', hue='Transport', data=df, showfliers=True, 
                    flierprops={"marker": "x", "markersize": 3, "alpha": 0.5})
        plt.title(title)
        plt.ylabel(y_label)
        plt.xlabel('Number of Drones')
        if use_log:
            plt.yscale('log')
            plt.ylabel(y_label + " (Log Scale)")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, filename), dpi=300)
        plt.close()

    plot_boxplot(df_inject, 'BLE HCI Dispatch Execution Times', 'ble_inject_times_boxplot.png', 'Time (ms)')
    plot_boxplot(df_build, 'BLE Packet Build Times per Cycle', 'ble_build_times_boxplot.png', 'Time (ms)')
    plot_boxplot(df_loop, 'BLE Total Loop Execution Times', 'ble_loop_times_boxplot.png', 'Time (ms)')
    plot_boxplot(df_prop, 'BLE Propagation Latency (HCI TX to Air RX)', 'ble_propagation_latency_boxplot.png', 'Latency (ms)')
    plot_boxplot(df_iat, 'BLE Inter-Arrival Time (IAT) of Advertisements', 'ble_iat_boxplot.png', 'IAT (ms)')
    
    print(f"BLE plots generated successfully in '{output_dir}' directory.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot BLE Capacity Test Results")
    parser.add_argument("--input", "-i", nargs="+", default=["ble_capacity_results.json"], help="One or more input JSON files to compare")
    parser.add_argument("--outdir", "-o", type=str, default="plots_output_ble", help="Output directory for plots")
    args = parser.parse_args()
    
    datasets = []
    for path in args.input:
        if os.path.exists(path):
            datasets.append(load_data(path))
        else:
            print(f"Warning: Input file '{path}' not found. Skipping.")
            
    if not datasets:
        print("Error: No valid input files found.")
        exit(1)
        
    create_plots(datasets, args.outdir)
