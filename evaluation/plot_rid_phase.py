#!/usr/bin/env python3
"""Phase-folded view of the RID beacon schedule.

Each beacon's arrival time has the shared cycle clock removed and is plotted as a
within-cycle offset against its cycle index. The three beacons per cycle then
appear as three flat, constant offsets (0, ~80, ~320 ms) -- i.e. the "three
parallel lines, same slope P" made visible. Dropped beacons appear as gaps and are
circled. Output: figures/avata_phase_lines.pdf
"""
import argparse
import importlib.util
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path, window_s):
    spec = importlib.util.spec_from_file_location("a", os.path.join(HERE, "analyze_rid_timing.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    from collections import defaultdict

    times = defaultdict(list)
    for src, t, rid in m.parse_epbs(path):
        if rid:
            times[src].append(t)
    ts = sorted(max(times.values(), key=len))
    if window_s:
        ts = [t for t in ts if t - ts[0] <= window_s]
    return np.array(ts)


def fit_period(ts):
    dms = [(b - a) * 1e3 for a, b in zip(ts, ts[1:])]
    cen = [79.9, 240.0, 320.0]
    lab = "SML"
    syms = [lab[min(range(3), key=lambda i: abs(x - cen[i]))] for x in dms]
    starts = [ts[i] for i in range(len(syms)) if syms[i] == "S"]
    t0 = starts[0]
    P = 0.6395  # rough seed; refined below so the integer cycle count is self-consistent
    for _ in range(5):
        cyc = [round((s - t0) / P) for s in starts]
        mx = sum(cyc) / len(cyc)
        my = sum(starts) / len(starts)
        P = sum((c - mx) * (s - my) for c, s in zip(cyc, starts)) / sum((c - mx) ** 2 for c in cyc)
    return t0, P


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", nargs="?", default=os.path.join(HERE, "data/RID_anechoicchamber.pcapng"))
    ap.add_argument("--width-in", type=float, default=6.138)
    ap.add_argument("--fontsize", type=float, default=10.0)
    ap.add_argument("--aspect", type=float, default=0.50)
    ap.add_argument("--window-s", type=float, default=100.0)
    # marker/label knobs: shrink for a narrow (half-width) panel so the dense bands
    # stay as distinguishable points rather than smearing into solid lines.
    ap.add_argument("--markersize", type=float, default=4.0, help="beacon marker area (pt^2)")
    ap.add_argument("--dropsize", type=float, default=46.0, help="dropped-beacon circle area (pt^2)")
    ap.add_argument("--droplw", type=float, default=1.1, help="dropped-beacon circle line width")
    ap.add_argument("--band-labels", choices=["on", "off"], default="on",
                    help="right-edge band names; off saves width on a narrow panel (y-ticks already name them)")
    ap.add_argument("--out", default="figures/avata_phase_lines.pdf")
    a = ap.parse_args()

    ts = load(a.capture, a.window_s or None)
    t0, P = fit_period(ts)
    rel = ts - t0
    shift = 0.040  # move the phase-wrap boundary into empty space (the 0 ms band)
    k = np.floor((rel + shift) / P).astype(int)
    phase = (rel - k * P) * 1e3  # within-cycle offset, ms
    offsets = [0.0, 80.0, 320.0]
    band = np.array([int(np.argmin([abs(p - o) for o in offsets])) for p in phase])

    present = set(zip(k.tolist(), band.tolist()))
    kmin, kmax = int(k.min()), int(k.max())
    # only interior cycles: the first/last may be partial (capture starts/ends mid-cycle)
    missing = [(kk, bb) for kk in range(kmin + 1, kmax) for bb in range(3) if (kk, bb) not in present]

    fs = a.fontsize
    plt.rcParams.update({
        "font.size": fs, "axes.labelsize": fs, "xtick.labelsize": fs - 1, "ytick.labelsize": fs - 1,
        "axes.edgecolor": "#888888", "axes.linewidth": 0.8,
        "font.family": "serif", "font.serif": ["cmr10", "CMU Serif", "Computer Modern Roman"],
        "mathtext.fontset": "cm", "axes.formatter.use_mathtext": True, "axes.unicode_minus": False,
    })
    ACCENT, DROP = "#3b6ea5", "#cc3311"
    fig, ax = plt.subplots(figsize=(a.width_in, a.width_in * a.aspect))
    ax.scatter(k, phase, s=a.markersize, color=ACCENT, linewidths=0, zorder=3, label="beacon")
    if missing:
        ax.scatter([m[0] for m in missing], [offsets[m[1]] for m in missing], s=a.dropsize,
                   facecolors="none", edgecolors=DROP, linewidths=a.droplw, zorder=4, label="dropped beacon")

    ax.set_yticks([0, 80, 320])
    ax.set_ylim(-25, 360)
    ax.set_xlim(kmin - 2, kmax + 2)
    ax.set_xlabel("cycle index $k$")
    ax.set_ylabel("within-cycle offset [ms]")
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#dddddd", linewidth=0.6)
    ax.set_axisbelow(True)
    # name each band on the right edge (skip on a narrow panel: the y-ticks already do)
    if a.band_labels == "on":
        for o, txt in [(0, "cycle start"), (80, "after S"), (320, "after S$+$M")]:
            ax.text(kmax + 2, o, "  " + txt, va="center", ha="left", fontsize=fs - 1.5, color="#555555")
    ax.legend(loc="center right", frameon=False, fontsize=fs - 1, handletextpad=0.3,
              bbox_to_anchor=(1.0, 0.62))
    fig.tight_layout()
    out = a.out if os.path.isabs(a.out) else os.path.join(HERE, a.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig.savefig(out, bbox_inches="tight")
    print("wrote", out, "| P =", round(P * 1e3, 3), "ms | drops =", len(missing))


if __name__ == "__main__":
    main()
