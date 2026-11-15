#!/usr/bin/env python3
"""
Measure the in-place BLE mode-switch latency: the cost of REQ_SCAN_CONT on an
already-running scan, the mechanism (UartHopper._switch) that replaced restarting
nrfutil per switch. See evaluation/nrf_sniffer/sniffers/nrf_uart.py.

Traffic-independent metrics (do not depend on any advertiser being present):
  scan_write       host-side cost of issuing the REQ_SCAN_CONT command (os.write)
  baseline_rtt     firmware command round-trip (REQ_TIMESTAMP -> RESP_TIMESTAMP), no switch
  post_switch_rtt  the same round-trip issued immediately AFTER a mode switch; if switching
                   stalled the firmware this would exceed baseline_rtt
  per_switch_host  scan_write + post_switch_rtt = what UartHopper._switch() spends per switch

Optional traffic-dependent metric (--ttfr), only meaningful with a live BLE advertiser
nearby, and confounded by frames the firmware buffered before the switch -- report with care.

Usage:
  python3 -I evaluation/measure_mode_switch_latency.py -n 40
  python3 -I evaluation/measure_mode_switch_latency.py --port /dev/ttyACM0 -n 40 --ttfr
"""
import argparse
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "nrf_sniffer"))

from sniffers.nrf_uart import (  # noqa: E402
    NordicSnifferUart, SCAN_SETTINGS, EVENT_PACKET_IDS, packet_id,
)


def ms(ns: int) -> float:
    return ns / 1e6


def summ(name: str, xs, unit: str = "ms") -> None:
    xs = sorted(xs)
    n = len(xs)
    p95 = xs[min(n - 1, int(0.95 * n))]
    print(f"  {name:20s} n={n:3d}  min={xs[0]:7.3f}  median={statistics.median(xs):7.3f}  "
          f"mean={statistics.fmean(xs):7.3f}  p95={p95:7.3f}  max={xs[-1]:7.3f}  ({unit})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/ttyACM0", help="nRF sniffer serial port (default /dev/ttyACM0)")
    ap.add_argument("-n", "--switches", type=int, default=40, help="number of BT5<->BT4 switches to time")
    ap.add_argument("--ttfr", action="store_true", help="also measure time-to-first-frame (needs live traffic)")
    ap.add_argument("--ttfr-timeout", type=float, default=1.5, help="per-switch wait for the first frame (s)")
    args = ap.parse_args()

    u = NordicSnifferUart(args.port)
    u.open()
    try:
        ver = u.handshake()
        print(f"[+] sniffer firmware protocol-3, version {ver!r} on {args.port}")

        # Start a scan so every measured switch is a *change* on an already-running scan.
        u.scan(**SCAN_SETTINGS["bt5"])
        u.timestamp()  # one warm round-trip (discard)
        time.sleep(0.3)

        scan_write, baseline_rtt, post_switch_rtt, per_switch, ttfr = [], [], [], [], []
        for i in range(args.switches):
            target = "bt4" if (i % 2 == 0) else "bt5"  # genuine change each iteration

            # Baseline: command round-trip with no switch preceding it
            b0 = time.perf_counter_ns(); u.timestamp(); b1 = time.perf_counter_ns()
            baseline_rtt.append(ms(b1 - b0))

            # Switch: issue REQ_SCAN_CONT, then a round-trip to confirm the firmware stayed responsive
            s0 = time.perf_counter_ns(); u.scan(**SCAN_SETTINGS[target]); s1 = time.perf_counter_ns()
            u.timestamp(); s2 = time.perf_counter_ns()
            scan_write.append(ms(s1 - s0))
            post_switch_rtt.append(ms(s2 - s1))
            per_switch.append(ms(s2 - s0))

            if args.ttfr:
                t0 = time.perf_counter_ns()
                for pkt in u.packets(args.ttfr_timeout):
                    if packet_id(pkt) in EVENT_PACKET_IDS:
                        ttfr.append(ms(time.perf_counter_ns() - t0))
                        break
            else:
                time.sleep(0.02)

        print(f"\n[+] {args.switches} alternating BT5<->BT4 switches on a running scan\n")
        summ("scan_write", scan_write)
        summ("baseline_rtt", baseline_rtt)
        summ("post_switch_rtt", post_switch_rtt)
        summ("per_switch_host", per_switch)
        if args.ttfr:
            if ttfr:
                summ("ttfr (traffic)", ttfr)
                print(f"  (first adv frame seen after {len(ttfr)}/{args.switches} switches; "
                      f"confounded by pre-switch buffering -- interpret with care)")
            else:
                print("  ttfr: no advertising traffic observed (no live BLE advertiser nearby)")
        return 0
    finally:
        u.close()


if __name__ == "__main__":
    raise SystemExit(main())
