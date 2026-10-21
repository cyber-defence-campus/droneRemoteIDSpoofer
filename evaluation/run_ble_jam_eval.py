#!/usr/bin/env python3
"""
Orchestrator script to run BLE capacity evaluation and trigger a GNU Radio jammer after a delay.
Uses the nRF sniffer dongle for packet reception and hci0 adapter for raw HCI transmission.
Captures both stdout/stderr live to terminal (with distinct tags) and saves them to separate log files.
Automatically shuts down the jammer when evaluation finishes and triggers capacity plotting.
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time

MAGENTA = "\033[35m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
RESET = "\033[0m"


def stream_reader(pipe, prefix: str, color: str, log_file, on_line_cb=None):
    """Read lines from a pipe, display with colored prefix, and write to log file."""
    try:
        for line in iter(pipe.readline, ''):
            if not line:
                break
            sys.stdout.write(f"{color}{prefix}{RESET} {line}")
            sys.stdout.flush()
            if log_file:
                log_file.write(line)
                log_file.flush()
            if on_line_cb:
                try:
                    on_line_cb(line)
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        pipe.close()


def stop_child_proc(proc, name="process", timeout=3.0):
    """Safely terminate a child process, escalating to sudo kill if permissions require it."""
    if not proc or proc.poll() is not None:
        return
    print(f"Stopping {name}...")
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=timeout)
        return
    except (PermissionError, Exception):
        subprocess.run(["sudo", "kill", "-INT", str(proc.pid)], check=False)
        try:
            proc.wait(timeout=timeout)
            return
        except Exception:
            pass

    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except (PermissionError, Exception):
        subprocess.run(["sudo", "kill", "-TERM", str(proc.pid)], check=False)
        try:
            proc.wait(timeout=timeout)
            return
        except Exception:
            subprocess.run(["sudo", "kill", "-KILL", str(proc.pid)], check=False)


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_venv_python = os.path.join(repo_root, ".venv", "bin", "python")
    default_jam_script = os.path.expanduser("/home/davidalexander/blejam.py")

    parser = argparse.ArgumentParser(description="Run BLE Capacity Evaluation and trigger GNU Radio Jammer after a delay")
    parser.add_argument("--tx-adapter", default="hci0", help="Transmit Bluetooth HCI adapter (default: hci0)")
    parser.add_argument("--nrf-port", default="/dev/ttyACM0", help="Serial port for nRF sniffer dongle (default: /dev/ttyACM0)")
    parser.add_argument("--ble-mode", choices=["extended", "ext-legacy", "legacy", "dual"], default="extended", help="BLE transmission mode (default: extended)")
    parser.add_argument("--ble-interval-ms", type=int, default=100, help="BLE advertising interval in ms (default: 100)")
    parser.add_argument("--legacy-interval-ms", type=int, default=None, help="BLE 4 legacy advertising interval in ms (for dual/legacy)")
    parser.add_argument("--extended-interval-ms", type=int, default=None, help="BLE 5 extended advertising interval in ms (for dual/extended)")
    parser.add_argument("--rx-mode", choices=["auto", "ble4", "ble5"], default="auto", help="Sniffer capture mode (default: auto)")
    parser.add_argument("-c", "--filter-channel", dest="filter_channels", type=int, nargs="+", choices=range(0, 40), metavar="CH", help="Only count sniffed packets received on these BLE RF channels (e.g. 37)")
    parser.add_argument("--duration", type=float, default=20.0, help="Evaluation duration in seconds (default: 20.0)")
    parser.add_argument("--drones", type=str, default="10", help="Drone count or spec (default: 10)")
    parser.add_argument("--interval", type=float, default=1.0, help="Main spoofer update interval in seconds (default: 1.0)")
    parser.add_argument("--delay", type=float, default=5.0, help="Delay before starting jammer in seconds (default: 5.0)")
    parser.add_argument("--no-wait-transmit", action="store_true", help="Do not wait for first drone batch transmission before starting delay timer")
    parser.add_argument("--jam-nice", type=int, default=-20, help="Scheduling priority for jammer via nice (default: -20)")
    parser.add_argument("--jam-script", default=default_jam_script, help="Path to GNU Radio script (default: ~/blejam.py)")
    parser.add_argument("--jam-python", default="/usr/bin/python3", help="Python interpreter for jammer (default: /usr/bin/python3)")
    parser.add_argument("--eval-python", default=default_venv_python, help="Python interpreter for evaluation")
    parser.add_argument("--out", default="evaluation/data/ble_eval_jam.json", help="Output JSON path")
    parser.add_argument("--plots-dir", default="evaluation/plots/ble_jam", help="Output directory for generated plots")
    parser.add_argument("--eval-log", default="evaluation/data/ble_eval.log", help="Log file for evaluation output")
    parser.add_argument("--jam-log", default="evaluation/data/ble_jam.log", help="Log file for jammer output")
    parser.add_argument("--no-jam", "--dry-run", dest="no_jam", action="store_true", help="Dry run: skip launching GNU Radio jammer")
    parser.add_argument("--no-plot", action="store_true", help="Skip automatic plotting")

    args = parser.parse_args()

    # Ensure output directories exist
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.eval_log)), exist_ok=True)

    # Auto-detect fallback for nRF sniffer if given port doesn't exist
    if not os.path.exists(args.nrf_port):
        for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
            if os.path.exists(candidate):
                args.nrf_port = candidate
                break

    print(f"\n{BOLD}{GREEN}=== Starting BLE Jamming Experiment Orchestrator ==={RESET}")
    print(f"  • TX Adapter:      {args.tx_adapter}")
    print(f"  • RX Dongle:       {args.nrf_port} (nRF Sniffer)")
    print(f"  • BLE Mode:        {args.ble_mode} (@ {args.ble_interval_ms}ms interval)")
    print(f"  • Drones:          {args.drones}")
    print(f"  • Total Duration:  {args.duration}s")
    if args.no_jam:
        print(f"  • Jammer:          {BOLD}{YELLOW}DISABLED (Dry run mode - no RF interference){RESET}")
    else:
        print(f"  • Jammer Trigger:  after {args.delay}s (post-transmission start)")
        print(f"  • Jammer Priority: sudo nice -n {args.jam_nice}")
        print(f"  • Jammer Script:   {args.jam_script}")
    print(f"  • Output JSON:     {args.out}")
    print(f"  • Eval Log:        {args.eval_log}")
    if not args.no_jam:
        print(f"  • Jammer Log:      {args.jam_log}")
    print()

    eval_log_f = open(args.eval_log, "w")
    jam_log_f = open(args.jam_log, "w") if not args.no_jam else None

    eval_cmd = [
        "sudo", args.eval_python, os.path.join(repo_root, "evaluation", "ble_capacity.py"),
        "--tx-adapter", args.tx_adapter,
        "--ble-mode", args.ble_mode,
        "--ble-interval-ms", str(args.ble_interval_ms),
        "--duration", str(args.duration),
        "--interval", str(args.interval),
        "--drones", str(args.drones),
        "--rx-mode", args.rx_mode,
        "--out", args.out
    ]
    if args.nrf_port and os.path.exists(args.nrf_port):
        eval_cmd.extend(["--nrf-port", args.nrf_port])
    if args.legacy_interval_ms is not None:
        eval_cmd.extend(["--legacy-interval-ms", str(args.legacy_interval_ms)])
    if args.extended_interval_ms is not None:
        eval_cmd.extend(["--extended-interval-ms", str(args.extended_interval_ms)])
    if args.filter_channels:
        eval_cmd.extend(["--filter-channel", *map(str, args.filter_channels)])

    if args.jam_nice is not None:
        jam_cmd = [
            "sudo", "-E", "nice", "-n", str(args.jam_nice), args.jam_python, args.jam_script
        ]
    else:
        jam_cmd = [
            args.jam_python, args.jam_script
        ]

    eval_proc = None
    jam_proc = None

    def cleanup_processes(sig=None, frame=None):
        print(f"\n{BOLD}{RED}[!] Cleaning up child processes...{RESET}")
        stop_child_proc(jam_proc, "jammer")
        stop_child_proc(eval_proc, "BLE evaluation")
        # Ensure UART locks on nRF dongle are cleared
        subprocess.run(["killall", "-9", "nrfutil", "nrfutil-ble-sniffer"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        if not eval_log_f.closed:
            eval_log_f.close()
        if jam_log_f and not jam_log_f.closed:
            jam_log_f.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_processes)
    signal.signal(signal.SIGTERM, cleanup_processes)

    try:
        tx_started_event = threading.Event()

        def check_tx_line(line: str):
            if "Starting AUTOMATIC MODE" in line or "Sent batch 1" in line:
                tx_started_event.set()

        # 1. Start BLE evaluation process
        print(f"{BOLD}[ORCHESTRATOR]{RESET} Launching BLE capacity evaluation on {args.tx_adapter}...")
        eval_proc = subprocess.Popen(
            eval_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
            cwd=repo_root
        )

        t_eval = threading.Thread(
            target=stream_reader,
            args=(eval_proc.stdout, "[BLE-EVAL]", MAGENTA, eval_log_f, check_tx_line),
            daemon=True
        )
        t_eval.start()

        # 2. Wait for transmission to commence (accounting for nRF radio setup & stabilization)
        if not args.no_wait_transmit:
            print(f"{BOLD}[ORCHESTRATOR]{RESET} Waiting for nRF sniffer stabilization and drone transmission start...")
            while not tx_started_event.is_set():
                if eval_proc.poll() is not None:
                    print(f"{RED}[ORCHESTRATOR] BLE evaluation exited before transmission started!{RESET}")
                    break
                time.sleep(0.2)

        if not args.no_jam:
            # 3. Wait for baseline delay duration
            if eval_proc.poll() is None:
                print(f"{BOLD}[ORCHESTRATOR]{RESET} Drone transmissions active. Recording baseline for {args.delay}s before starting jammer...")
                t_start = time.time()
                while time.time() - t_start < args.delay:
                    if eval_proc.poll() is not None:
                        print(f"{RED}[ORCHESTRATOR] Evaluation exited prematurely before jammer start!{RESET}")
                        break
                    time.sleep(0.2)

            # 4. Trigger GNU Radio Jammer
            if eval_proc.poll() is None:
                print(f"\n{BOLD}[ORCHESTRATOR]{RESET} {BOLD}{YELLOW}>>> Triggering GNU Radio Jammer (sudo nice -n {args.jam_nice}) now! <<<{RESET}\n")
                jam_env = os.environ.copy()
                if "XAUTHORITY" not in jam_env and os.path.exists(os.path.expanduser("~/.Xauthority")):
                    jam_env["XAUTHORITY"] = os.path.expanduser("~/.Xauthority")

                jam_proc = subprocess.Popen(
                    jam_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1,
                    env=jam_env,
                    cwd=os.path.dirname(args.jam_script) if os.path.exists(os.path.dirname(args.jam_script)) else repo_root
                )

                t_jam = threading.Thread(
                    target=stream_reader,
                    args=(jam_proc.stdout, "[JAMMER]", YELLOW, jam_log_f),
                    daemon=True
                )
                t_jam.start()
        else:
            print(f"\n{BOLD}[ORCHESTRATOR]{RESET} {BOLD}{YELLOW}Dry run mode: GNU Radio jammer disabled. Running undisturbed evaluation for {args.duration}s...{RESET}\n")

        # 5. Wait for BLE evaluation to complete
        eval_proc.wait()
        print(f"\n{BOLD}[ORCHESTRATOR]{RESET} BLE evaluation finished with code {eval_proc.returncode}.")

    finally:
        # 6. Cleanly stop the jammer
        stop_child_proc(jam_proc, "jammer")
        if not eval_log_f.closed:
            eval_log_f.close()
        if jam_log_f and not jam_log_f.closed:
            jam_log_f.close()

    # 7. Generate plots
    if not args.no_plot and os.path.exists(args.out):
        print(f"\n{BOLD}[ORCHESTRATOR]{RESET} Generating BLE capacity & PDR plots...")
        plot_cmd = [
            args.eval_python,
            os.path.join(repo_root, "evaluation", "plot_capacity.py"),
            "-i", args.out,
            "-o", args.plots_dir
        ]
        subprocess.run(plot_cmd, cwd=repo_root)

        pdr_plot = os.path.join(args.plots_dir, "pdr_over_the_air.png")
        if os.path.exists(pdr_plot):
            print(f"\n{BOLD}{GREEN}[✓] Success! BLE PDR graph generated:{RESET} {pdr_plot}")
            print(f"To open: xdg-open {pdr_plot}\n")
    else:
        if not os.path.exists(args.out):
            print(f"{RED}[!] Notice: Output JSON {args.out} was not found (did the evaluation finish?){RESET}")


if __name__ == "__main__":
    main()
