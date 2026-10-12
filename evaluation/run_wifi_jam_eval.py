#!/usr/bin/env python3
"""
Orchestrator script to run Wi-Fi evaluation and trigger a GNU Radio jammer after 5 seconds.
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

CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
RESET = "\033[0m"


def stream_reader(pipe, prefix: str, color: str, log_file):
    """Read lines from a pipe, display with colored prefix, and write to log file."""
    try:
        for line in iter(pipe.readline, ''):
            if not line:
                break
            # Print to stdout
            sys.stdout.write(f"{color}{prefix}{RESET} {line}")
            sys.stdout.flush()
            # Write to log file
            if log_file:
                log_file.write(line)
                log_file.flush()
    except Exception:
        pass
    finally:
        pipe.close()


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_venv_python = os.path.join(repo_root, ".venv", "bin", "python")
    default_jam_script = os.path.expanduser("~/gnuradio/wifijam.py")

    parser = argparse.ArgumentParser(description="Run Wi-Fi Evaluation and trigger GNU Radio Jammer after a delay")
    parser.add_argument("--tx-iface", default="wlx00c0ca9910ea", help="TX monitor interface")
    parser.add_argument("--rx-iface", default="wlx00c0cabb1654", help="RX monitor interface")
    parser.add_argument("--channel", type=int, default=6, help="Wi-Fi channel (default: 6)")
    parser.add_argument("--duration", type=float, default=20.0, help="Evaluation duration in seconds (default: 20.0)")
    parser.add_argument("--drones", type=str, default="300", help="Drone count (default: 10)")
    parser.add_argument("--delay", type=float, default=5.0, help="Delay before starting jammer in seconds (default: 2.0)")
    parser.add_argument("--jam-nice", type=int, default=-20, help="Scheduling priority for jammer via nice (default: -20)")
    parser.add_argument("--jam-script", default=default_jam_script, help="Path to wifijam.py script")
    parser.add_argument("--jam-python", default="/usr/bin/python3", help="Python interpreter for jammer (default: /usr/bin/python3)")
    parser.add_argument("--eval-python", default=default_venv_python, help="Python interpreter for evaluation")
    parser.add_argument("--out", default="evaluation/data/wifi_ch6_eval_jam.json", help="Output JSON path")
    parser.add_argument("--plots-dir", default="evaluation/plots/wifi_ch6_jam", help="Output directory for generated plots")
    parser.add_argument("--eval-log", default="evaluation/data/wifi_eval.log", help="Log file for evaluation output")
    parser.add_argument("--jam-log", default="evaluation/data/wifijam.log", help="Log file for jammer output")
    parser.add_argument("--no-jam", "--dry-run", dest="no_jam", action="store_true", help="Dry run: skip launching GNU Radio jammer")
    parser.add_argument("--no-plot", action="store_true", help="Skip automatic plotting")

    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.eval_log)), exist_ok=True)

    print(f"\n{BOLD}{GREEN}=== Starting Wi-Fi Jamming Experiment Orchestrator ==={RESET}")
    print(f"  • TX Interface:    {args.tx_iface}")
    print(f"  • RX Interface:    {args.rx_iface}")
    print(f"  • Channel:         {args.channel}")
    print(f"  • Drones:          {args.drones}")
    print(f"  • Total Duration:  {args.duration}s")
    if args.no_jam:
        print(f"  • Jammer:          {BOLD}{YELLOW}DISABLED (Dry run mode - no RF interference){RESET}")
    else:
        print(f"  • Jammer Trigger:  after {args.delay}s")
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
        "sudo", args.eval_python, os.path.join(repo_root, "evaluation", "wifi_capacity.py"),
        "--tx-iface", args.tx_iface,
        "--rx-iface", args.rx_iface,
        "--channel", str(args.channel),
        "--duration", str(args.duration),
        "--drones", str(args.drones),
        "--out", args.out
    ]

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

    def stop_child_proc(proc, name="process", timeout=3.0):
        if not proc or proc.poll() is not None:
            return
        print(f"Stopping {name}...")
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=timeout)
            return
        except (PermissionError, Exception):
            # If started with sudo and caller lacks root, use sudo kill
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
            except Exception:
                subprocess.run(["sudo", "kill", "-KILL", str(proc.pid)], check=False)

    def cleanup_processes(sig=None, frame=None):
        print(f"\n{BOLD}{RED}[!] Cleaning up child processes...{RESET}")
        stop_child_proc(jam_proc, "jammer")
        stop_child_proc(eval_proc, "evaluation")
        if not eval_log_f.closed:
            eval_log_f.close()
        if jam_log_f and not jam_log_f.closed:
            jam_log_f.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_processes)
    signal.signal(signal.SIGTERM, cleanup_processes)

    try:
        # 1. Start Evaluation process
        print(f"{BOLD}[ORCHESTRATOR]{RESET} Launching Wi-Fi capacity evaluation...")
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
            args=(eval_proc.stdout, "[EVAL]", CYAN, eval_log_f),
            daemon=True
        )
        t_eval.start()

        if not args.no_jam:
            # 2. Wait for the delay duration
            print(f"{BOLD}[ORCHESTRATOR]{RESET} Evaluation running. Waiting {args.delay}s before starting jammer...")
            t_start = time.time()
            while time.time() - t_start < args.delay:
                if eval_proc.poll() is not None:
                    print(f"{RED}[ORCHESTRATOR] Evaluation exited prematurely before jammer start!{RESET}")
                    break
                time.sleep(0.5)

            # 3. Start Jammer process if evaluation is still alive
            if eval_proc.poll() is None:
                print(f"\n{BOLD}[ORCHESTRATOR]{RESET} {BOLD}{YELLOW}>>> Triggering GNU Radio Jammer (sudo nice -n {args.jam_nice}) now! <<<{RESET}\n")
                # Preserve user DISPLAY & XAUTHORITY for Qt GUI
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
            print(f"\n{BOLD}[ORCHESTRATOR]{RESET} {BOLD}{YELLOW}Dry run mode: GNU Radio jammer disabled. Running undisturbed Wi-Fi evaluation for {args.duration}s...{RESET}\n")

        # 4. Wait for Wi-Fi evaluation to complete
        eval_proc.wait()
        print(f"\n{BOLD}[ORCHESTRATOR]{RESET} Wi-Fi evaluation finished with code {eval_proc.returncode}.")

    finally:
        # 5. Stop the jammer cleanly
        stop_child_proc(jam_proc, "jammer")
        if not eval_log_f.closed:
            eval_log_f.close()
        if not jam_log_f.closed:
            jam_log_f.close()

    # 6. Generate plots
    if not args.no_plot and os.path.exists(args.out):
        print(f"\n{BOLD}[ORCHESTRATOR]{RESET} Generating capacity & PDR plots...")
        plot_cmd = [
            args.eval_python,
            os.path.join(repo_root, "evaluation", "plot_capacity.py"),
            "-i", args.out,
            "-o", args.plots_dir
        ]
        subprocess.run(plot_cmd, cwd=repo_root)

        pdr_plot = os.path.join(args.plots_dir, "pdr_over_the_air.png")
        if os.path.exists(pdr_plot):
            print(f"\n{BOLD}{GREEN}[✓] Success! PDR graph generated:{RESET} {pdr_plot}")
            print(f"To open: xdg-open {pdr_plot}\n")
    else:
        if not os.path.exists(args.out):
            print(f"{RED}[!] Notice: Output JSON {args.out} was not found (did the evaluation finish?){RESET}")


if __name__ == "__main__":
    main()
