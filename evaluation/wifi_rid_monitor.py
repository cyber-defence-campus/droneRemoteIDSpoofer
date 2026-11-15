#!/usr/bin/env python3
"""Passively count Wi-Fi Remote ID beacon frames over time."""

import argparse
import csv
import os
import select
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Optional

RID_OUI = b"\xfa\x0b\xbc"
RID_APP_CODE = 0x0D
CSV_HEADER = (
    "run_started_at",
    "interface",
    "interval_started_at",
    "elapsed_seconds",
    "interval_packets",
    "cumulative_packets",
)


def is_rid_beacon(frame: bytes) -> bool:
    """Return whether a radiotap 802.11 frame is a beacon carrying a RID vendor IE."""
    if len(frame) < 8:
        return False

    radiotap_length = struct.unpack_from("<H", frame, 2)[0]
    if radiotap_length < 8 or len(frame) < radiotap_length + 36:
        return False

    frame_control = frame[radiotap_length]
    if frame_control & 0xFC != 0x80:
        return False

    offset = radiotap_length + 36
    while offset + 2 <= len(frame):
        element_id = frame[offset]
        element_length = frame[offset + 1]
        offset += 2
        end = offset + element_length
        if end > len(frame):
            return False

        if element_id == 221:
            info = frame[offset:end]
            if len(info) >= 4 and info[:3] == RID_OUI and info[3] == RID_APP_CODE:
                return True

        offset = end

    return False


def record_counts(interface: str, output_path: str, interval: float, duration: Optional[float]) -> None:
    output_directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_directory, exist_ok=True)

    file_exists = os.path.exists(output_path) and os.path.getsize(output_path) > 0
    if file_exists:
        with open(output_path, newline="", encoding="utf-8") as existing_file:
            existing_header = next(csv.reader(existing_file), None)
        if tuple(existing_header or ()) != CSV_HEADER:
            raise ValueError(f"{output_path} does not have the expected CSV header")

    output = open(output_path, "a", newline="", encoding="utf-8")
    try:
        writer = csv.writer(output)
        if not file_exists:
            writer.writerow(CSV_HEADER)
            output.flush()

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        try:
            sock.bind((interface, 0))
            print(f"Listening passively on {interface}; saving counts to {output_path}. Press Ctrl+C to stop.")

            run_started = time.monotonic()
            run_started_wall = time.time()
            run_started_at = datetime.fromtimestamp(run_started_wall, timezone.utc).isoformat()
            bucket_started = run_started
            bucket_packets = 0
            cumulative_packets = 0

            try:
                while duration is None or time.monotonic() - run_started < duration:
                    now = time.monotonic()
                    bucket_deadline = bucket_started + interval
                    if now >= bucket_deadline:
                        elapsed = bucket_deadline - run_started
                        cumulative_packets += bucket_packets
                        writer.writerow((
                            run_started_at,
                            interface,
                            datetime.fromtimestamp(
                                run_started_wall + bucket_started - run_started,
                                timezone.utc,
                            ).isoformat(),
                            f"{elapsed:.3f}",
                            bucket_packets,
                            cumulative_packets,
                        ))
                        output.flush()
                        print(f"{elapsed:.1f}s: {bucket_packets} RID packets (total {cumulative_packets})")
                        bucket_packets = 0
                        bucket_started = bucket_deadline
                        continue

                    timeout = min(bucket_deadline - now, 0.2)
                    if duration is not None:
                        timeout = min(timeout, max(0.0, duration - (now - run_started)))
                    ready, _, _ = select.select([sock], [], [], timeout)
                    if ready and is_rid_beacon(sock.recv(8192)):
                        bucket_packets += 1
            except KeyboardInterrupt:
                print("\nStopping; recording the final partial interval.")

            now = time.monotonic()
            if now > bucket_started:
                elapsed = now - run_started
                cumulative_packets += bucket_packets
                writer.writerow((
                    run_started_at,
                    interface,
                    datetime.fromtimestamp(
                        run_started_wall + bucket_started - run_started,
                        timezone.utc,
                    ).isoformat(),
                    f"{elapsed:.3f}",
                    bucket_packets,
                    cumulative_packets,
                ))
                output.flush()
                print(f"{elapsed:.1f}s: {bucket_packets} RID packets (total {cumulative_packets})")
        finally:
            sock.close()
    finally:
        output.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Passively count Wi-Fi Remote ID beacons over time.")
    parser.add_argument("-i", "--interface", required=True, help="Monitor-mode Wi-Fi interface")
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds per count interval (default: 1.0)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Stop after this many seconds (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="evaluation/data/wifi_rid_counts.csv",
        help="CSV output path; new runs are appended (default: evaluation/data/wifi_rid_counts.csv)",
    )
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be greater than zero")

    try:
        record_counts(args.interface, args.output, args.interval, args.duration)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
