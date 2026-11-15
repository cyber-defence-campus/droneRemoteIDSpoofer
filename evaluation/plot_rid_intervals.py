#!/usr/bin/env python3
"""Plot the inter-beacon interval distribution of the chamber RID capture.

Produces a log-scale histogram that shows the three sharp timing modes (S, M, L)
together with the rare dropped-beacon merges. Output: figures/avata_interval_hist.pdf

The figure is drawn at the thesis text width with the document body font size, so
it can be included 1:1 (\\includegraphics[width=\\linewidth]{...}) without scaling
the in-figure lettering. Set --width-in to your \\the\\textwidth in inches
(pt / 72.27) and --fontsize to your body font size in pt.

Usage: python3 plot_rid_intervals.py [capture.pcapng] [--width-in W] [--fontsize PT]
"""
import argparse
import importlib.util
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))


def load_intervals(path, window_s=None):
    spec = importlib.util.spec_from_file_location("a", os.path.join(HERE, "analyze_rid_timing.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    from collections import defaultdict

    times = defaultdict(list)
    for src, t, rid in mod.parse_epbs(path):
        if rid:
            times[src].append(t)
    ts = sorted(max(times.values(), key=len))
    if window_s is not None:  # restrict to the first window_s to avoid the capture tail
        ts = [t for t in ts if t - ts[0] <= window_s]
    return np.array([(b - a) * 1e3 for a, b in zip(ts, ts[1:])])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", nargs="?", default=os.path.join(HERE, "data/RID_anechoicchamber.pcapng"))
    # Defaults reproduce the thesis figure: textwidth 443.57848pt / 72.27 = 6.138in,
    # 10pt body font, linear y-scale.
    ap.add_argument("--width-in", type=float, default=6.138,
                    help="figure width in inches = thesis \\the\\textwidth / 72.27")
    ap.add_argument("--fontsize", type=float, default=10.0,
                    help="base font size in pt = thesis body font size")
    ap.add_argument("--aspect", type=float, default=0.52, help="height/width ratio (default 0.52)")
    ap.add_argument("--yscale", choices=["log", "linear"], default="linear")
    ap.add_argument("--out", default=None, help="output PDF path (default figures/avata_interval_hist[_linear].pdf)")
    ap.add_argument("--window-s", type=float, default=100.0,
                    help="analyse only the first N seconds (avoids the capture wind-down tail); 0 = whole capture")
    args = ap.parse_args()
    islog = args.yscale == "log"
    d = load_intervals(args.capture, window_s=args.window_s or None)

    ACCENT = "#3b6ea5"  # single series -> one hue; value (position) carries meaning
    INK = "#222222"
    fs = args.fontsize
    plt.rcParams.update({
        "font.size": fs, "axes.labelsize": fs, "xtick.labelsize": fs - 1,
        "ytick.labelsize": fs - 1, "axes.edgecolor": "#888888", "axes.linewidth": 0.8,
        # Computer Modern serif to match a standard LaTeX thesis typeface
        # (bundled with matplotlib; usetex would need dvipng, which is absent).
        "font.family": "serif", "font.serif": ["cmr10", "CMU Serif", "Computer Modern Roman"],
        "mathtext.fontset": "cm", "axes.formatter.use_mathtext": True,
        "axes.unicode_minus": False,
    })

    fig, ax = plt.subplots(figsize=(args.width_in, args.width_in * args.aspect))
    # 10 ms bins offset so each sharp mode (80, 240, 320) and each drop cluster
    # (400, 560) falls cleanly inside one bin rather than being split across two.
    bins = np.arange(55, 595, 10)
    counts, _, _ = ax.hist(d, bins=bins, color=ACCENT, edgecolor="white", linewidth=0.3)
    peak = counts.max()
    ax.set_yscale(args.yscale)
    ax.set_ylim(0.7, peak * 3) if islog else ax.set_ylim(0, peak * 1.18)
    ax.set_xlim(55, 590)
    ax.set_xlabel("Inter-beacon interval [ms]")
    ax.set_ylabel("Count (log scale)" if islog else "Count")
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#dddddd", linewidth=0.6, which="major")
    ax.set_axisbelow(True)

    # label the three modes above their bars (counts are read off the y-axis)
    lab_yv = peak * 1.5 if islog else peak * 1.06
    for lab, x in [("S", 80), ("M", 240), ("L", 320)]:
        ax.text(x, lab_yv, lab, ha="center", va="bottom", fontsize=fs,
                color=INK, fontweight="bold")

    fig.tight_layout()
    suffix = "" if islog else "_linear"
    out = args.out or os.path.join(HERE, f"figures/avata_interval_hist{suffix}.pdf")
    if not os.path.isabs(out):
        out = os.path.join(HERE, out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig.savefig(out, bbox_inches="tight")
    print("wrote", out)


if __name__ == "__main__":
    main()
