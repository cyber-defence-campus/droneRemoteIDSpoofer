#!/usr/bin/env python3
"""
Quantify jamming effectiveness from the per-second PDR buckets the jam-eval
orchestrators record. For each run it splits the receive PDR time series at the
jammer onset (the orchestrator's --delay, in seconds from transmit start) into a
jam-free baseline window and a during-jam window, and reports:

  baseline_pdr   mean RX PDR before the jammer starts (should be near 100%)
  during_pdr     mean RX PDR after onset (skipping the onset transition bucket)
  drop_pp        baseline - during, in percentage points
  effectiveness  (baseline - during) / baseline, as a percentage
  collapse_s     seconds from onset until RX PDR falls to <=10% of baseline
  tx_pdr         mean TX PDR (sender is air-side-independent; stays ~100%)

Usage:
  python evaluation/analyze_jam_effectiveness.py --delay 5 evaluation/data/jam_eval/*.json
"""
import argparse
import glob
import json
import os
from typing import List, Optional


def _mean(xs: List[float]) -> Optional[float]:
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def rx_pdr_series(run: dict) -> List[Optional[float]]:
    pss = run.get("per_second_stats", {})
    exp = pss.get("expected", []) or []
    rx = pss.get("rx_sniffed", []) or []
    out = []
    for i in range(min(len(exp), len(rx))):
        out.append(100.0 * rx[i] / exp[i] if exp[i] else None)
    return out


def tx_pdr_series(run: dict) -> List[Optional[float]]:
    pss = run.get("per_second_stats", {})
    exp = pss.get("expected", []) or []
    tx = pss.get("tx_sniffed", []) or []
    return [100.0 * tx[i] / exp[i] if exp[i] else None for i in range(min(len(exp), len(tx)))]


def analyze(run: dict, delay: float, assume_baseline: Optional[float] = None) -> dict:
    """
    The SDR jammer emits a bounded burst, so RX PDR dips during the burst and then recovers; a
    naive onset->end average blends the recovery back in. We therefore measure the baseline from
    the pre-onset window and the effect from the burst itself: the depth of the dip (min bucket)
    and the mean over the contiguous depressed window around it (buckets after onset that fall
    below half the baseline).
    """
    rx = rx_pdr_series(run)
    tx = tx_pdr_series(run)
    onset = int(round(delay))
    measured_baseline = _mean(rx[:onset])
    # The no-jam window should be ~100% PDR; by default normalize the effect against an assumed
    # 100% so a lossy sniffer baseline (e.g. single-channel BLE) does not deflate the result.
    baseline = assume_baseline if assume_baseline is not None else measured_baseline

    post = [(i, rx[i]) for i in range(onset, len(rx)) if rx[i] is not None]
    min_pdr = min((v for _, v in post), default=None)
    min_at = next((i for i, v in post if v == min_pdr), None)

    # Contiguous "jam window": buckets around the minimum that sit below half the baseline.
    jam_vals = []
    jam_len = 0
    if baseline is not None and min_at is not None:
        thresh = 0.5 * baseline
        lo = hi = min_at
        while lo - 1 >= onset and rx[lo - 1] is not None and rx[lo - 1] < thresh:
            lo -= 1
        while hi + 1 < len(rx) and rx[hi + 1] is not None and rx[hi + 1] < thresh:
            hi += 1
        jam_vals = [rx[i] for i in range(lo, hi + 1) if rx[i] is not None]
        jam_len = hi - lo + 1
    jam_pdr = _mean(jam_vals)

    drop = (baseline - min_pdr) if (baseline is not None and min_pdr is not None) else None
    eff = (100.0 * drop / baseline) if (drop is not None and baseline) else None
    return {
        "baseline_pdr": measured_baseline,   # measured pre-onset PDR (sanity: should be ~100%)
        "ref_baseline": baseline,            # baseline used for drop/effectiveness (assumed or measured)
        "min_pdr": min_pdr,          # deepest point of the dip
        "jam_pdr": jam_pdr,          # mean over the depressed burst window
        "jam_window_s": jam_len,     # how many 1 s buckets stayed below half baseline
        "drop_pp": drop,             # baseline - min (percentage points)
        "effectiveness_pct": eff,    # fraction of baseline delivery denied at the dip
        "tx_pdr": _mean(tx),
        "buckets": len(rx),
    }


def main():
    ap = argparse.ArgumentParser(description="Quantify jamming effectiveness from jam-eval JSON runs")
    ap.add_argument("files", nargs="+", help="jam-eval result JSON files (globs ok)")
    ap.add_argument("--delay", type=float, default=5.0, help="Jammer onset in seconds from transmit start (orchestrator --delay)")
    ap.add_argument("--assume-baseline", type=float, default=100.0,
                    help="No-jam PDR to normalize effectiveness against (default: 100; pass 0 to use the measured baseline)")
    args = ap.parse_args()
    assume = args.assume_baseline if args.assume_baseline and args.assume_baseline > 0 else None

    paths = []
    for f in args.files:
        paths.extend(sorted(glob.glob(f)) or [f])

    print(f"{'run':<34} {'base%':>7} {'min%':>6} {'jam%':>6} {'win_s':>6} {'drop_pp':>8} {'effect%':>8} {'tx%':>6}")
    print("-" * 86)
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f"{os.path.basename(p):<34} ERROR {e}")
            continue
        run = d[0] if isinstance(d, list) and d else d
        if not isinstance(run, dict) or not run.get("per_second_stats"):
            print(f"{os.path.basename(p)[:34]:<34} NO DATA (empty/failed run — did it overrun or get killed?)")
            continue
        m = analyze(run, args.delay, assume_baseline=assume)
        def fmt(x, s="{:.1f}"):
            return s.format(x) if x is not None else "  -"
        name = os.path.basename(p)[:34]
        print(f"{name:<34} {fmt(m['baseline_pdr']):>7} {fmt(m['min_pdr']):>6} {fmt(m['jam_pdr']):>6} "
              f"{str(m['jam_window_s']):>6} {fmt(m['drop_pp']):>8} {fmt(m['effectiveness_pct']):>8} {fmt(m['tx_pdr']):>6}")


if __name__ == "__main__":
    main()
