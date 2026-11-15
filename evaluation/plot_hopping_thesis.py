#!/usr/bin/env python3
"""
Thesis-sized replots of the Wi-Fi channel-switching evaluation.

Re-renders the two figures used in the channel-switching section as vector PDFs
drawn at the thesis text width with the document body font size, so the legend,
axis and tick lettering come out at the correct typeface size once the figure is
included at \\linewidth (no downscaling, hence no shrunken text). This mirrors
plot_rid_intervals.py / plot_rid_phase.py and depends only on matplotlib+numpy
(no pandas/seaborn), so it runs in the same environment as the other plot
scripts.

Set --width-in to your \\the\\textwidth in inches (pt / 72.27) and --fontsize to
your body font size in pt.

Figures produced (into figures/ by default):
  channel_switching_target_latency_boxplot.pdf  -- per-destination-channel command
      latency, split by originating band (source invariance).
  channel_switching_lifecycle.pdf               -- four-phase transition lifecycle
      by destination band.

Usage:
  python3 plot_hopping_thesis.py [RUN.json ...] [--width-in W] [--fontsize PT]
Default input is the pulse-injected MT76x0U run used in the thesis.
"""
import argparse
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from hopping_evaluation import get_wifi_band, get_freq_for_channel  # noqa: E402

DEFAULT_RUN = os.path.join(
    HERE, "data", "hopping_eval_wlx00c0cabb1654_20260912_092156.json"
)

# Originating-band groups for the latency boxplot.
SRC_GROUPS = ["From 2.4 GHz", "From 5.8 GHz"]
SRC_COLORS = {"From 2.4 GHz": "#1f77b4", "From 5.8 GHz": "#d62728"}

# Lifecycle phases, in chronological order, with colours.
PHASES = [
    ("1. Previous-freq. drain", "raw_src_drain_ms", "#3498db"),
    ("2. RF synthesiser blind spot", "raw_rf_blind_spot_ms", "#9b59b6"),
    ("3. Target-channel lock (1st pkt)", "raw_rf_ready_ms", "#27ae60"),
    ("4. Command completion (blocking)", "raw_latencies_ms", "#e74c3c"),
]
BANDS = ["Target: 2.4 GHz", "Target: 5.8 GHz"]

# Short tokens for --phases selection (drain and blind-spot were only instrumented
# in the newest run, so a multi-run pool should restrict the lifecycle figure to the
# phases present in every pooled run -- ready,cmd -- to keep all boxes at one N).
PHASE_TOKENS = {"drain": 0, "blind": 1, "ready": 2, "cmd": 3}


def _src_label(band):
    return "From 2.4 GHz" if "2.4" in band else "From 5.8 GHz"


def _dst_label(band):
    return "Target: 2.4 GHz" if "2.4" in band else "Target: 5.8 GHz"


def load(paths, phases=PHASES):
    """Collect raw per-sample latencies, pooled over the given run JSON(s)."""
    # latency[dst_channel][src_group] -> list of command latencies
    lat = {}
    # inter[dst_band][src_group] -> list of command latencies (band x band factorial)
    inter = {b: {g: [] for g in SRC_GROUPS} for b in BANDS}
    # life[band][phase_name] -> list of durations
    life = {b: {p[0]: [] for p in phases} for b in BANDS}
    rec, iface = {}, "wlan"
    for p in paths:
        with open(p) as fh:
            d = json.load(fh)
        rec = d.get("recommendations", rec)
        iface = d.get("metadata", {}).get("interface", iface)
        for tr in d.get("transition_results", []):
            src, dst = tr.get("src_channel"), tr.get("dst_channel")
            sg = _src_label(get_wifi_band(src))
            band = _dst_label(get_wifi_band(dst))
            cmd = tr.get("raw_latencies_ms", [])
            lat.setdefault(dst, {g: [] for g in SRC_GROUPS})
            lat[dst][sg].extend(cmd)
            inter[band][sg].extend(cmd)
            for name, key, _ in phases:
                life[band][name].extend(tr.get(key, []))
    return lat, inter, life, rec, iface


def set_thesis_style(fs):
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.size": fs, "axes.labelsize": fs,
        "xtick.labelsize": fs - 1, "ytick.labelsize": fs - 1,
        "legend.fontsize": fs - 1, "legend.title_fontsize": fs - 1,
        "axes.edgecolor": "#888888", "axes.linewidth": 0.8,
        "axes.grid": True, "grid.color": "#dddddd", "grid.linewidth": 0.6,
        # Computer Modern serif to match a standard LaTeX thesis typeface
        # (bundled with matplotlib; usetex would need dvipng, which may be absent).
        "font.family": "serif", "font.serif": ["cmr10", "CMU Serif", "Computer Modern Roman"],
        "mathtext.fontset": "cm", "axes.formatter.use_mathtext": True,
        "axes.unicode_minus": False,
    })


def _grouped_box(ax, categories, groups, data, colors, box_w, group_gap=0.8):
    """Draw grouped boxplots. data[cat][group] -> samples (empty allowed)."""
    from matplotlib.patches import Patch

    n = len(groups)
    centres = np.arange(len(categories)) * (n * box_w + group_gap)
    # offsets so the group cluster is centred on each category tick
    offs = (np.arange(n) - (n - 1) / 2.0) * box_w
    rng = np.random.default_rng(0)
    for gi, g in enumerate(groups):
        for ci, cat in enumerate(categories):
            vals = [v for v in data[cat].get(g, []) if v is not None]
            if not vals:
                continue
            pos = centres[ci] + offs[gi]
            bp = ax.boxplot(vals, positions=[pos], widths=box_w * 0.82,
                            patch_artist=True, showfliers=False, manage_ticks=False)
            bp["boxes"][0].set(facecolor=colors[g], edgecolor="#333333",
                               linewidth=0.7, alpha=0.9)
            for med in bp["medians"]:
                med.set(color="#111111", linewidth=1.0)
            for w in bp["whiskers"] + bp["caps"]:
                w.set(color="#333333", linewidth=0.7)
            # faint jittered raw points
            x = pos + (rng.random(len(vals)) - 0.5) * box_w * 0.5
            ax.plot(x, vals, ".", ms=1.8, color=colors[g], alpha=0.30, zorder=1)
    ax.set_xticks(centres)
    ax.set_xticklabels(categories)
    ax.set_xlim(centres[0] - n * box_w / 2 - group_gap / 2,
                centres[-1] + n * box_w / 2 + group_gap / 2)
    handles = [Patch(facecolor=colors[g], edgecolor="#333333", label=g) for g in groups]
    return handles


def plot_target_boxplot(lat, rec, width_in, aspect, out):
    import matplotlib.pyplot as plt

    dsts = sorted(lat.keys(), key=get_freq_for_channel)
    cats = [f"Ch {c}" for c in dsts]
    data = {f"Ch {c}": lat[c] for c in dsts}

    fig, ax = plt.subplots(figsize=(width_in, width_in * aspect))
    handles = _grouped_box(ax, cats, SRC_GROUPS, data, SRC_COLORS, box_w=0.5)
    for key, col, lbl in (("recommended_delay_to_2g_ms", "#1f77b4", "2.4 GHz"),
                          ("recommended_delay_to_5g_ms", "#d62728", "5 GHz")):
        if key in rec:
            ln = ax.axhline(rec[key], color=col, ls="--", lw=1.1)
            ln.set_label(f"Rec. to {lbl}: {rec[key]} ms")
            handles.append(ln)
    ax.set_xlabel("Destination channel (sorted by centre frequency)")
    ax.set_ylabel("Command execution time (ms)")
    ax.legend(handles=handles, title="Originating band", loc="upper left",
              frameon=True, framealpha=0.9, ncol=2, columnspacing=1.0,
              handletextpad=0.4, borderpad=0.4)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_band_interaction(inter, width_in, aspect, out):
    """Factorial target-band x source-band grouped boxplot (summary panel B,
    rendered as boxes so the distribution -- not just the mean -- is shown)."""
    import matplotlib.pyplot as plt

    bands = [b for b in BANDS if any(inter[b][g] for g in SRC_GROUPS)]
    if not bands:
        return None
    data = {b: inter[b] for b in bands}

    fig, ax = plt.subplots(figsize=(width_in, width_in * aspect))
    handles = _grouped_box(ax, bands, SRC_GROUPS, data, SRC_COLORS,
                           box_w=0.34, group_gap=1.0)
    ax.set_xlabel("Destination (target) band")
    ax.set_ylabel("Command execution time (ms)")
    ax.legend(handles=handles, title="Originating band", loc="upper left",
              frameon=True, framealpha=0.9, handletextpad=0.4, borderpad=0.4)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_lifecycle(life, width_in, aspect, out, phases=PHASES):
    import matplotlib.pyplot as plt

    if not any(life[b][p[0]] for b in BANDS for p in phases):
        return None
    bands = [b for b in BANDS if any(life[b][p[0]] for p in phases)]
    groups = [p[0] for p in phases]
    colors = {p[0]: p[2] for p in phases}
    data = {b: {g: life[b][g] for g in groups} for b in bands}

    fig, ax = plt.subplots(figsize=(width_in, width_in * aspect))
    handles = _grouped_box(ax, bands, groups, data, colors, box_w=0.42, group_gap=1.1)
    # Renumber the leading "N." of each legend label to the drawn order, so a phase
    # subset (e.g. ready,cmd when pooling runs) reads 1,2 rather than 3,4.
    import re
    for i, (h, g) in enumerate(zip(handles, groups)):
        h.set_label(re.sub(r"^\d+\.", f"{i + 1}.", g))
    ax.set_xlabel("Destination frequency band")
    ax.set_ylabel("Switch command duration (ms)")
    # Modest headroom so the (title-less, four-row) legend clears the boxes it
    # would otherwise overlap on the 5 GHz side.
    vmax = max((v for b in bands for g in groups for v in data[b][g]), default=1.0)
    ax.set_ylim(0, vmax * 1.42)
    ax.legend(handles=handles, loc="upper left",
              frameon=True, framealpha=0.9, handletextpad=0.4, borderpad=0.4)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    plt.close(fig)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="*", default=[DEFAULT_RUN],
                    help="one or more hopping_eval_*.json runs (pooled if several)")
    # Defaults reproduce the thesis figure: textwidth 443.57848pt / 72.27 = 6.138 in,
    # body font size 10pt -- matching plot_rid_intervals.py / plot_rid_phase.py.
    ap.add_argument("--width-in", type=float, default=6.138,
                    help="figure width in inches = thesis \\the\\textwidth / 72.27")
    ap.add_argument("--fontsize", type=float, default=10.0,
                    help="base font size in pt = thesis body font size")
    ap.add_argument("--aspect", type=float, default=0.56,
                    help="height/width ratio (default 0.56)")
    ap.add_argument("--outdir", default=os.path.join(HERE, "figures"),
                    help="output directory for the PDFs (default evaluation/figures)")
    ap.add_argument("--suffix", default="",
                    help="appended to each output basename, e.g. _half for side-by-side figures")
    ap.add_argument("--phases", default="drain,blind,ready,cmd",
                    help="comma list of lifecycle phases to draw, from "
                         "drain,blind,ready,cmd (default all four). Use ready,cmd when "
                         "pooling several runs, since drain/blind are single-run only.")
    args = ap.parse_args()

    try:
        phases = [PHASES[PHASE_TOKENS[t.strip()]] for t in args.phases.split(",") if t.strip()]
    except KeyError as e:
        sys.exit(f"Unknown --phases token {e}; choose from {','.join(PHASE_TOKENS)}")

    runs = args.runs if args.runs else [DEFAULT_RUN]
    lat, inter, life, rec, iface = load(runs, phases)
    if not lat:
        sys.exit("No measurement rows found in the given run(s).")

    import matplotlib
    matplotlib.use("Agg")
    set_thesis_style(args.fontsize)
    os.makedirs(args.outdir, exist_ok=True)
    sfx = args.suffix

    print("wrote", plot_target_boxplot(
        lat, rec, args.width_in, args.aspect,
        os.path.join(args.outdir, f"channel_switching_target_latency_boxplot{sfx}.pdf")))
    print("wrote", plot_band_interaction(
        inter, args.width_in, args.aspect * 0.9,
        os.path.join(args.outdir, f"channel_switching_band_interaction{sfx}.pdf")))
    f2 = plot_lifecycle(
        life, args.width_in, args.aspect,
        os.path.join(args.outdir, f"channel_switching_lifecycle{sfx}.pdf"), phases)
    print("wrote", f2) if f2 else print(
        "lifecycle figure skipped (no drain/blind-spot/RF-ready samples in run)")


if __name__ == "__main__":
    main()
