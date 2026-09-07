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

def get_band_str(ch: int) -> str:
    if ch in (149, 153, 157, 161, 165) or ch >= 149:
        return "5.8GHz"
    elif ch >= 36:
        return "5.2GHz"
    return "2.4GHz"

def create_plots(data, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Extract data into a structured format (pandas DataFrame)
    records = []
    
    # Check if this is the channel split format
    if 'social_channel' in data or 'non_social_channel' in data:
        runs = data.get('social_channel', []) + data.get('non_social_channel', [])
    else:
        runs = data if isinstance(data, list) else data.get('all_runs', [])
        
    for run in runs:
        drones = run.get('drones', 0)
        ch = run.get('channel', 0)
        is_soc = run.get('is_social_channel', ch in (6, 149))
        band_str = get_band_str(ch)
        ch_type = f"Social (Ch {ch}, {band_str})" if is_soc else f"Non-Social (Ch {ch}, {band_str})"
        interval = run.get('interval', 0)
        
        # Aggregated stats
        records.append({
            'Drones': drones,
            'Channel Type': ch_type,
            'Interval': interval,
            'PDR (Air) %': run.get('pdr_rx_percent', 0),
            'PDR (Kernel) %': run.get('pdr_tx_percent', 0),
            'Missed Deadlines': run.get('missed_deadlines', 0),
            'Avg Jitter (ms)': run.get('avg_jitter_ms', 0),
            'Avg Propagation (ms)': run.get('propagation_latency_stats_ms', {}).get('avg', 0),
        })
        
    df_agg = pd.DataFrame(records)
    
    # 2. Extract raw data for boxplots (Inject, Build, Loop, Propagation, IAT)
    raw_inject = []
    raw_build = []
    raw_loop = []
    raw_prop = []
    raw_iat = []
    
    for run in runs:
        drones = run.get('drones', 0)
        ch = run.get('channel', 0)
        is_soc = run.get('is_social_channel', ch in (6, 149))
        band_str = get_band_str(ch)
        ch_type = f"Ch {ch} (Social, {band_str})" if is_soc else f"Ch {ch} (Non-Social, {band_str})"
        label = f"{drones} Drones\n({ch_type})"
        
        rd = run.get('raw_data', {})
        
        for val in rd.get('inject_times_ms', []):
            raw_inject.append({'Drones': drones, 'Channel': ch_type, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('build_times_ms', []):
            raw_build.append({'Drones': drones, 'Channel': ch_type, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('loop_times_ms', []):
            raw_loop.append({'Drones': drones, 'Channel': ch_type, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('propagation_latencies_ms', []):
            raw_prop.append({'Drones': drones, 'Channel': ch_type, 'Label': label, 'Time (ms)': val})
            
        for val in rd.get('iat_intervals_ms', []):
            raw_iat.append({'Drones': drones, 'Channel': ch_type, 'Label': label, 'Time (ms)': val})
            
    df_inject = pd.DataFrame(raw_inject)
    df_build = pd.DataFrame(raw_build)
    df_loop = pd.DataFrame(raw_loop)
    df_prop = pd.DataFrame(raw_prop)
    df_iat = pd.DataFrame(raw_iat)
    
    sns.set_theme(style="whitegrid")
    
    # --- Plot 1: PDR Comparison ---
    plt.figure(figsize=(10, 6))
    sns.lineplot(data=df_agg, x='Drones', y='PDR (Air) %', hue='Channel Type', marker='o', linewidth=2, markersize=8)
    plt.title('Packet Delivery Rate (PDR) over the Air vs Number of Drones')
    plt.ylim(0, 105)
    plt.ylabel('PDR (%)')
    plt.xlabel('Number of Drones')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'pdr_comparison.png'), dpi=300)
    plt.close()
    
    # --- Plot 2: Missed Deadlines ---
    plt.figure(figsize=(10, 6))
    sns.lineplot(data=df_agg, x='Drones', y='Missed Deadlines', hue='Channel Type', marker='s', linewidth=2, markersize=8)
    plt.title('Missed Deadlines vs Number of Drones')
    plt.ylabel('Missed Deadlines')
    plt.xlabel('Number of Drones')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'missed_deadlines.png'), dpi=300)
    plt.close()

    # Helper function for boxplots with log scale option
    def plot_boxplot(df, title, filename, y_label, use_log=False):
        if df.empty: return
        plt.figure(figsize=(12, 6))
        
        # Sort by drones
        df = df.sort_values(by=['Drones', 'Channel'])
        
        ax = sns.boxplot(x='Drones', y='Time (ms)', hue='Channel', data=df, showfliers=True, 
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

    # --- Plot 3: Inject Times (Linear and Log Scale to show the outliers clearly) ---
    plot_boxplot(df_inject, 'Socket send() Execution (Inject) Times', 'inject_times_boxplot.png', 'Time (ms)')
    plot_boxplot(df_inject, 'Socket send() Execution (Inject) Times (Log Scale)', 'inject_times_boxplot_log.png', 'Time (ms)', use_log=True)
    
    # --- Plot 4: Build Times ---
    plot_boxplot(df_build, 'Packet Build Times per Cycle', 'build_times_boxplot.png', 'Time (ms)')
    
    # --- Plot 5: Loop Times ---
    plot_boxplot(df_loop, 'Total Loop Execution Times', 'loop_times_boxplot.png', 'Time (ms)')
    
    # --- Plot 6: Propagation Latencies ---
    plot_boxplot(df_prop, 'Propagation Latency (Kernel TX to Air RX)', 'propagation_latency_boxplot.png', 'Latency (ms)')
    
    # --- Plot 7: Inter-Arrival Times (IAT) ---
    plot_boxplot(df_iat, 'Inter-Arrival Time (IAT) of Packets', 'iat_boxplot.png', 'IAT (ms)')
    
    print(f"Plots generated successfully in '{output_dir}' directory.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot Wi-Fi Capacity Test Results")
    parser.add_argument("--input", "-i", type=str, default="wifi_capacity_comparison.json", help="Input JSON file")
    parser.add_argument("--outdir", "-o", type=str, default="plots_output", help="Output directory for plots")
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        exit(1)
        
    data = load_data(args.input)
    create_plots(data, args.outdir)
