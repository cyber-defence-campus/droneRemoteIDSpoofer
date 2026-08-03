#!/usr/bin/env python3
"""
btmon_alerter.py

Parses `btmon` output via stdin and alerts if an advertising session ends without
a completed advertising event, or if the time between enable and disable is too short.

Usage:
  sudo btmon | python3 experiments/btmon_alerter.py
"""

import sys
import re
import argparse

def main():
    parser = argparse.ArgumentParser(description="Monitor btmon for failed advertising events")
    parser.add_argument("--min-time-ms", type=float, default=15.0,
                        help="Alert if Advertising Enable -> Disable is faster than this (default: 15.0 ms)")
    args = parser.parse_args()

    print(f"[*] Starting btmon alerter. Monitoring for failed packets (< {args.min_time_ms}ms)...")

    # Regex to extract timestamp from btmon header lines
    # Example: < HCI Command: LE Set Advertising Enable (0x08|0x000a) plen 1  [hci0] 12.345678
    ts_pattern = re.compile(r'\[hci\d+\]\s+(\d+\.\d+)')
    
    current_ts = None
    last_enable_ts = None
    
    try:
        for line in sys.stdin:
            # 1. Update the current timestamp if the line has one
            ts_match = ts_pattern.search(line)
            if ts_match:
                current_ts = float(ts_match.group(1))

            # 2. Check for completed events (BLE 5 Extended Advertising)
            events_match = re.search(r'Number of completed extended advertising events:\s+(\d+)', line)
            if events_match:
                count = int(events_match.group(1))
                if count == 0:
                    print(f"\n[!] ALERT [{current_ts}]: Extended Advertising terminated with 0 completed events!")
                    print('\a', end='', flush=True)  # Terminal bell
                else:
                    # Positive notice for successful transmission
                    print(f"[{current_ts}] [+] Successfully transmitted {count} extended event(s)")

            # 3. Track Legacy / Extended Enable
            if "Advertising: Enabled (0x01)" in line or "Enable: True (0x01)" in line:
                last_enable_ts = current_ts

            # 4. Track Legacy / Extended Disable and calculate delta
            if "Advertising: Disabled (0x00)" in line or "Enable: False (0x00)" in line:
                if last_enable_ts is not None and current_ts is not None:
                    delta_ms = (current_ts - last_enable_ts) * 1000.0
                    if delta_ms < args.min_time_ms:
                        print(f"\n[!] ALERT [{current_ts}]: Advertising disabled too quickly!")
                        print(f"    Duration was only {delta_ms:.2f} ms (Minimum required: {args.min_time_ms} ms)")
                        print(f"    This likely means NO packet was actually transmitted over the air.")
                        print('\a', end='', flush=True)  # Terminal bell
                last_enable_ts = None

            # 5. Check for any other command failures (Status != 0x00)
            status_match = re.search(r'^\s*Status:\s+(.+?)\s+\(0x([0-9a-fA-F]+)\)', line)
            if status_match:
                status_msg = status_match.group(1)
                status_code = status_match.group(2).lower()
                # Ignore Success (00), Command Disallowed (0c), and Limit Reached (43)
                if status_code not in ["00", "0c", "43"]:
                    print(f"\n[!] ALERT [{current_ts}]: HCI Command Failed with Status: {status_msg} (0x{status_code})")
                    print('\a', end='', flush=True)

    except KeyboardInterrupt:
        print("\n[*] Exiting btmon alerter.")

if __name__ == '__main__':
    main()
