#!/usr/bin/env python3
"""
Automated Multi-Mode BLE Capacity Benchmark Orchestrator

Sweeps through BLE modes ('extended', 'ext-legacy', 'legacy', 'dual'),
sensible advertising intervals (e.g. 20ms..200ms), and 1-drone step increments.
Automatically saves structured JSON results into evaluation/data/ and
generates comparative plots in evaluation/plots/.
"""

import argparse
import glob
import logging
import os
import subprocess
import sys
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("ble_benchmark")

# Sensible default intervals (ms) by mode:
# Extended, Ext-legacy & Dual support down to 20ms (BLE 5 spec minimum)
# Legacy (classic HCI) spec minimum is 100ms (BT 4.x spec minimum)
DEFAULT_MODE_INTERVALS = {
    "extended": [20, 30, 50, 75, 100, 150, 200],
    "ext-legacy": [20, 30, 50, 75, 100, 150, 200],
    "dual": [20, 30, 50, 75, 100, 150, 200],
    "legacy": [100, 150, 200],
}


def main():
    parser = argparse.ArgumentParser(description="Automated Multi-Mode BLE Capacity Benchmark Suite")
    parser.add_argument("--spec", nargs="+", default=None,
                        help="Adapter-specific mode specifications (e.g. --spec 'hci0:extended,ext-legacy,dual' 'hci1:legacy'). Overrides --adapters and --modes.")
    parser.add_argument("--modes", type=str, default="extended,ext-legacy,dual",
                        help="Comma-separated BLE modes to evaluate: 'extended', 'ext-legacy', 'legacy', 'dual' (default: extended,ext-legacy,dual)")
    parser.add_argument("--adapters", type=str, default="hci0",
                        help="Comma-separated HCI adapter(s) to test (e.g. 'hci0' or 'hci0,hci1')")
    parser.add_argument("--intervals", type=str, default=None,
                        help="Override advertising intervals in ms (comma-separated, e.g. '20,50,100,200'). If not set, uses sensible defaults per mode.")
    parser.add_argument("--drones", type=str, default="1-40:1",
                        help="Drone count sweep specification (default: 1-40:1)")
    parser.add_argument("--duration", type=float, default=10.0,
                        help="Evaluation duration per test in seconds (default: 10.0)")
    parser.add_argument("--consecutive-misses", type=int, default=2,
                        help="Auto-stop sweep after N consecutive runs with 100%% missed deadlines (default: 2)")
    parser.add_argument("--nrf-port", type=str, default=None,
                        help="Serial port for nRF sniffer (auto-detected if omitted)")
    parser.add_argument("--data-dir", type=str,
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"),
                        help="Directory to save JSON benchmark datasets (default: evaluation/data)")
    parser.add_argument("--plot-dir", type=str,
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "plots"),
                        help="Directory to save generated comparative plots (default: evaluation/plots)")
    parser.add_argument("--optimize-params", action="store_true", default=True,
                        help="Omit redundant HCI parameter re-configuration on each drone pulse (default: True)")
    parser.add_argument("--no-optimize-params", action="store_false", dest="optimize_params",
                        help="Force per-drone HCI parameter re-application on every pulse")
    parser.add_argument("--plot-all", action="store_true", default=True,
                        help="Include all existing JSON files in data-dir when plotting (default: True)")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip benchmark runs whose output JSON file already exists")
    parser.add_argument("--no-plot", action="store_true",
                        help="Skip generating plots at the end of the benchmark suite")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the planned benchmark matrix without executing")
    parser.add_argument("--cooldown", type=float, default=5.0,
                        help="Cooldown in seconds between separate interval sweeps (default: 5.0s)")

    args = parser.parse_args()

    override_intervals = None
    if args.intervals:
        override_intervals = [int(x.strip()) for x in args.intervals.split(",") if x.strip()]

    os.makedirs(args.data_dir, exist_ok=True)
    os.makedirs(args.plot_dir, exist_ok=True)

    ble_capacity_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ble_capacity.py")
    plot_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plot_ble_capacity.py")

    planned_runs = []
    if args.spec:
        # Parse custom per-adapter specs: e.g. "hci0:extended,ext-legacy,dual" "hci1:legacy"
        for item in args.spec:
            parts = item.split(":")
            if len(parts) == 2:
                adapter = parts[0].strip().lower()
                modes_for_adapter = [m.strip().lower().replace("_", "-") for m in parts[1].split(",") if m.strip()]
                for mode in modes_for_adapter:
                    intervals = override_intervals if override_intervals is not None else DEFAULT_MODE_INTERVALS.get(mode, [100, 200])
                    for int_ms in intervals:
                        if mode == "dual":
                            for rx_m in ["ble5", "ble4"]:
                                out_filename = f"dual_ext20ms_leg{int_ms}ms_rx_{rx_m}_{adapter}.json"
                                out_path = os.path.join(args.data_dir, out_filename)
                                planned_runs.append({
                                    "adapter": adapter,
                                    "mode": mode,
                                    "interval_ms": int_ms,
                                    "rx_mode": rx_m,
                                    "out_path": out_path
                                })
                        else:
                            rx_m = "ble5" if mode == "extended" else "ble4"
                            out_filename = f"{mode}_interval_{int_ms}ms_{adapter}.json"
                            out_path = os.path.join(args.data_dir, out_filename)
                            planned_runs.append({
                                "adapter": adapter,
                                "mode": mode,
                                "interval_ms": int_ms,
                                "rx_mode": rx_m,
                                "out_path": out_path
                            })
    else:
        modes = [m.strip().lower().replace("_", "-") for m in args.modes.split(",") if m.strip()]
        adapters = [a.strip().lower() for a in args.adapters.split(",") if a.strip()]
        for adapter in adapters:
            for mode in modes:
                intervals = override_intervals if override_intervals is not None else DEFAULT_MODE_INTERVALS.get(mode, [100, 200])
                for int_ms in intervals:
                    if mode == "dual":
                        for rx_m in ["ble5", "ble4"]:
                            out_filename = f"dual_ext20ms_leg{int_ms}ms_rx_{rx_m}_{adapter}.json"
                            out_path = os.path.join(args.data_dir, out_filename)
                            planned_runs.append({
                                "adapter": adapter,
                                "mode": mode,
                                "interval_ms": int_ms,
                                "rx_mode": rx_m,
                                "out_path": out_path
                            })
                    else:
                        rx_m = "ble5" if mode == "extended" else "ble4"
                        out_filename = f"{mode}_interval_{int_ms}ms_{adapter}.json"
                        out_path = os.path.join(args.data_dir, out_filename)
                        planned_runs.append({
                            "adapter": adapter,
                            "mode": mode,
                            "interval_ms": int_ms,
                            "rx_mode": rx_m,
                            "out_path": out_path
                        })

    logger.info("=" * 80)
    logger.info(f"Planned BLE Benchmark Runs ({len(planned_runs)} total configurations):")
    skipped_count = 0
    for idx, run in enumerate(planned_runs, start=1):
        if run['mode'] == 'dual':
            int_desc = f"ext20ms+leg{run['interval_ms']}ms (RX: {run['rx_mode'].upper()})"
        else:
            int_desc = f"{run['interval_ms']}ms"

        file_exists = os.path.exists(run["out_path"]) and os.path.getsize(run["out_path"]) > 10
        if args.skip_existing and file_exists:
            status_tag = "[SKIP]"
            skipped_count += 1
        elif file_exists:
            status_tag = "[OVERWRITE]"
        else:
            status_tag = "[NEW]"

        logger.info(f"  [{idx:02d}/{len(planned_runs):02d}] {status_tag:<11} Adapter: {run['adapter']:<5} | Mode: {run['mode']:<11} | Interval/RX: {int_desc:<25} -> {os.path.basename(run['out_path'])}")

    to_run_count = len(planned_runs) - skipped_count
    if args.skip_existing:
        logger.info(f"Summary: {to_run_count} to execute, {skipped_count} to skip (already completed).")
    else:
        logger.info(f"Summary: {to_run_count} to execute.")
    logger.info("=" * 80)

    if args.dry_run:
        logger.info("[Dry Run] Exiting without running tests.")
        return

    generated_files = []
    total_start = time.time()

    for idx, run in enumerate(planned_runs, start=1):
        if args.skip_existing and os.path.exists(run["out_path"]) and os.path.getsize(run["out_path"]) > 10:
            logger.info(f"[{idx}/{len(planned_runs)}] Skipping {os.path.basename(run['out_path'])} (already completed).")
            generated_files.append(run["out_path"])
            continue

        logger.info(f"\n[{idx}/{len(planned_runs)}] >>> Starting {run['mode']} ({run['interval_ms']}ms, RX: {run['rx_mode'].upper()}) on {run['adapter']} <<<")

        cmd = [
            sys.executable, ble_capacity_script,
            "--tx-adapter", run["adapter"],
            "--ble-mode", run["mode"],
            "--rx-mode", run["rx_mode"],
            "--drones", args.drones,
            "--duration", str(args.duration),
            "--consecutive-misses", str(args.consecutive_misses),
            "--out", run["out_path"]
        ]

        if run["mode"] == "dual":
            cmd.extend(["--legacy-interval-ms", str(run["interval_ms"]), "--extended-interval-ms", "20"])
        else:
            cmd.extend(["--ble-interval-ms", str(run["interval_ms"])])

        if args.nrf_port:
            cmd.extend(["--nrf-port", args.nrf_port])
        if args.optimize_params:
            cmd.append("--optimize-params")

        try:
            res = subprocess.run(cmd, check=True)
            if res.returncode == 0 and os.path.exists(run["out_path"]):
                generated_files.append(run["out_path"])
        except KeyboardInterrupt:
            logger.warning("\n[!] Benchmark suite interrupted by user (Ctrl+C).")
            break
        except subprocess.CalledProcessError as e:
            logger.error(f"[-] Error executing sweep for {run['mode']} ({run['interval_ms']}ms): {e}")

        if idx < len(planned_runs):
            logger.info(f"Cooling down for {args.cooldown:.1f}s before next sweep...")
            time.sleep(args.cooldown)

    elapsed_total = time.time() - total_start
    logger.info(f"\n[+] Completed {len(generated_files)}/{len(planned_runs)} benchmark sweeps in {elapsed_total/60:.1f} minutes.")

    # Generate comprehensive comparative plots
    if not args.no_plot:
        files_to_plot = sorted(glob.glob(os.path.join(args.data_dir, "*.json"))) if args.plot_all else generated_files
        if files_to_plot:
            logger.info(f"Generating comparative plots from {len(files_to_plot)} dataset(s) into '{args.plot_dir}'...")
            plot_cmd = [
                sys.executable, plot_script,
                "--input"
            ] + files_to_plot + [
                "--outdir", args.plot_dir
            ]
            try:
                subprocess.run(plot_cmd, check=True)
                logger.info(f"[+] All comparative plots successfully generated in '{args.plot_dir}'")
            except Exception as e:
                logger.error(f"[-] Failed to generate plots: {e}")


if __name__ == "__main__":
    main()
