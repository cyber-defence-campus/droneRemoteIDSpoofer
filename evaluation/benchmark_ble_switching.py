#!/usr/bin/env python3
"""
Reproducible Benchmark: BLE 4 / BLE 5 Mode Switching Latencies on Nordic nRF52840 Dongle.
Measures Teardown, Subprocess Spawn, UART Handshake / Header Sync, and Time Till First Reception (TTFR).
"""

import argparse
import json
import os
import signal
import statistics
import struct
import subprocess
import sys
import threading
import time


def run_benchmark(
    nrf_port: str = "/dev/ttyACM0",
    iterations: int = 10,
    fifo_path: str = "/tmp/nrf_detailed_bench.fifo",
    output_json: str = "evaluation/data/ble_mode_switching_benchmark.json"
):
    if os.path.exists(fifo_path):
        os.remove(fifo_path)
    os.mkfifo(fifo_path)

    cmd_bt5 = [
        "nrfutil", "ble-sniffer", "sniff",
        "--only-advertising",
        "--port", nrf_port,
        "--output-pcap-file", fifo_path,
        "--scan-follow-aux",
        "--scan-follow-aux-chain",
        "--coded"
    ]
    cmd_bt4 = [
        "nrfutil", "ble-sniffer", "sniff",
        "--only-legacy_advertising",
        "--port", nrf_port,
        "--output-pcap-file", fifo_path
    ]

    records = []
    total_transitions = iterations * 2

    print(f"[*] Starting BLE Mode Switching Benchmark on {nrf_port} ({total_transitions} transitions)...")

    # Warmup
    p = subprocess.Popen(cmd_bt5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    with open(fifo_path, "rb") as f:
        f.read(24)
        f.read(16)
    time.sleep(0.5)

    current_mode = "bt5"

    for i in range(total_transitions):
        from_mode = current_mode
        to_mode = "bt4" if from_mode == "bt5" else "bt5"
        next_cmd = cmd_bt4 if to_mode == "bt4" else cmd_bt5

        # 1. Start transition measurement
        t_start = time.perf_counter()
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        p.wait()
        t_killed = time.perf_counter()

        # 2. Spawn next mode
        p = subprocess.Popen(next_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        t_spawned = time.perf_counter()

        # 3. Read FIFO in thread
        read_meta = {}
        def reader():
            try:
                with open(fifo_path, "rb") as f:
                    hdr = f.read(24)
                    read_meta["t_hdr"] = time.perf_counter()
                    pkthdr = f.read(16)
                    read_meta["t_pkt"] = time.perf_counter()
                    if len(pkthdr) == 16:
                        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkthdr)
                        data = f.read(incl_len)
                        read_meta["len"] = incl_len
                        if b"\xfa\xff" in data:
                            read_meta["is_rid"] = True
            except Exception as e:
                read_meta["err"] = str(e)

        r_thread = threading.Thread(target=reader)
        r_thread.start()
        r_thread.join(timeout=3.0)

        t_hdr = read_meta.get("t_hdr", t_spawned)
        t_pkt = read_meta.get("t_pkt", t_hdr)

        teardown_ms = (t_killed - t_start) * 1000.0
        spawn_ms = (t_spawned - t_killed) * 1000.0
        hdr_ready_ms = (t_hdr - t_start) * 1000.0
        ttfr_ms = (t_pkt - t_start) * 1000.0
        pcap_sync_ms = (t_hdr - t_spawned) * 1000.0

        record = {
            "iteration": i + 1,
            "direction": f"{from_mode.upper()} -> {to_mode.upper()}",
            "from_mode": from_mode,
            "to_mode": to_mode,
            "teardown_ms": round(teardown_ms, 3),
            "spawn_ms": round(spawn_ms, 3),
            "pcap_sync_ms": round(pcap_sync_ms, 3),
            "header_ready_total_ms": round(hdr_ready_ms, 3),
            "ttfr_ms": round(ttfr_ms, 3),
            "first_pkt_len": read_meta.get("len", 0),
            "first_pkt_has_rid": read_meta.get("is_rid", False),
        }
        records.append(record)
        print(f"  [{i+1:02d}/{total_transitions}] {record['direction']:^12} | Teardown: {teardown_ms:>5.2f}ms | Spawn: {spawn_ms:>5.2f}ms | Radio Ready: {hdr_ready_ms:>5.2f}ms | TTFR: {ttfr_ms:>5.2f}ms")

        current_mode = to_mode
        time.sleep(0.3)

    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    p.wait()
    if os.path.exists(fifo_path):
        os.remove(fifo_path)

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, "w") as f:
        json.dump(records, f, indent=2)

    # Print summary statistics
    bt5_to_bt4 = [d for d in records if d["direction"] == "BT5 -> BT4"]
    bt4_to_bt5 = [d for d in records if d["direction"] == "BT4 -> BT5"]

    def print_table(title, subset):
        print(f"\n### {title} (N = {len(subset)})")
        print(f"{'Metric':<25} | {'Mean':>8} | {'StdDev':>8} | {'Median':>8} | {'Min':>8} | {'Max':>8}")
        print("-" * 76)
        for label, key in [
            ("1. Teardown (SIGTERM)", "teardown_ms"),
            ("2. Process Spawn", "spawn_ms"),
            ("3. PCAP Header Sync", "pcap_sync_ms"),
            ("4. Radio Ready Time", "header_ready_total_ms"),
            ("5. Time Till 1st Pkt (TTFR)", "ttfr_ms"),
        ]:
            vals = [r[key] for r in subset]
            mean_v = statistics.mean(vals)
            std_v = statistics.stdev(vals) if len(vals) > 1 else 0.0
            med_v = statistics.median(vals)
            min_v = min(vals)
            max_v = max(vals)
            print(f"{label:<25} | {mean_v:>7.2f}m | {std_v:>7.2f}m | {med_v:>7.2f}m | {min_v:>7.2f}m | {max_v:>7.2f}m")

    print_table("Direction: BT5 -> BT4 (Extended to Legacy)", bt5_to_bt4)
    print_table("Direction: BT4 -> BT5 (Legacy to Extended)", bt4_to_bt5)
    print_table("Overall (Combined Bidirectional)", records)

    print(f"\n[+] Benchmark finished. Data saved to {output_json}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BLE Mode Switching Benchmark")
    parser.add_argument("-p", "--port", default="/dev/ttyACM0", help="Serial port for nRF sniffer")
    parser.add_argument("-n", "--iterations", type=int, default=10, help="Number of round-trip cycles")
    parser.add_argument("-o", "--output", default="evaluation/data/ble_mode_switching_benchmark.json", help="Output JSON path")
    args = parser.parse_args()

    run_benchmark(nrf_port=args.port, iterations=args.iterations, output_json=args.output)
