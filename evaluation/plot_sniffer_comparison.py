#!/usr/bin/env python3
"""
Plot the nRF-vs-HCI Remote ID reception comparison produced by compare_sniffers.py.

Reads the multi-run JSON (a list of round objects, each with an ``aggregate`` block
and per-run detail) and renders a publication-ready grouped bar chart: per round
(BT5 extended, BT4 ext-legacy) the mean PDR and mean raw-packet count for each
receiver, with error bars over the repeated runs. The two panels keep separate
single y-axes (never a dual-axis chart). Saves both PNG (raster) and PDF (vector,
for LaTeX inclusion).

Usage:
  .venv/bin/python evaluation/plot_sniffer_comparison.py \
      --in evaluation/data/sniffer_comparison.json \
      --out evaluation/plots/sniffer_comparison.png
"""

import argparse
import json
import os
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# Receiver identity colours (Okabe-Ito, colourblind-safe; validated CVD deltaE 21.9).
# Colour follows the entity, not its rank, and is fixed across every figure.
RECEIVERS = [("nRF", "nrf", "#0072B2"), ("HCI", "hci", "#D55E00")]


def load_rounds(path: str) -> List[Dict[str, Any]]:
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]
    rounds = [r for r in data if isinstance(r, dict) and "aggregate" in r]
    if not rounds:
        raise SystemExit(f"[!] No aggregated rounds found in {path}. "
                         "Run compare_sniffers.py first (it writes this file).")
    return rounds


def _series(rounds: List[Dict[str, Any]], key: str, metric: str):
    """Return (means, errors) lists across rounds for one receiver and metric."""
    means = [r["aggregate"][key][metric]["mean"] for r in rounds]
    errs = [r["aggregate"][key][metric]["std"] for r in rounds]
    return np.array(means), np.array(errs)


def _grouped_bars(ax, rounds, metric: str, error_kind: str, value_fmt: str,
                  as_sem: bool, annot_fontsize: float):
    labels = [r.get("label", r.get("mode", "?")) for r in rounds]
    x = np.arange(len(rounds))
    width = 0.38
    gap = 0.02  # 2px-equivalent surface gap between adjacent bars

    for i, (name, key, colour) in enumerate(RECEIVERS):
        means, stds = _series(rounds, key, metric)
        if as_sem:
            n = np.array([max(r["aggregate"].get("n_runs", 1), 1) for r in rounds], dtype=float)
            errs = stds / np.sqrt(n)
        else:
            errs = stds
        offset = (i - 0.5) * (width + gap)
        bars = ax.bar(x + offset, means, width, label=name, color=colour,
                      edgecolor="white", linewidth=0.8, zorder=3)
        ax.errorbar(x + offset, means, yerr=errs, fmt="none", ecolor="#333333",
                    elinewidth=1.2, capsize=4, capthick=1.2, zorder=4)
        # Direct value labels (mean) above the error bar, in ink — never the series colour.
        for b, m, e in zip(bars, means, errs):
            ax.annotate(value_fmt.format(m), (b.get_x() + b.get_width() / 2, m + e),
                        textcoords="offset points", xytext=(0, 4), ha="center", va="bottom",
                        fontsize=annot_fontsize, color="#222222")

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.margins(y=0.15)
    return labels


PT_PER_INCH = 72.27  # TeX points per inch, for converting \textwidth to a figure size


def make_figure(rounds: List[Dict[str, Any]], error_kind: str,
                width_in: float, aspect: float, font_pt: float) -> plt.Figure:
    as_sem = (error_kind == "sem")

    # Set the whitegrid look first, then pin every font size in points so the text
    # renders at the document's size when the figure is included at its natural
    # width (i.e. without LaTeX rescaling). Ticks/legend are one point smaller.
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans"],
        "font.size": font_pt,
        "axes.titlesize": font_pt,
        "axes.labelsize": font_pt,
        "xtick.labelsize": font_pt - 1,
        "ytick.labelsize": font_pt - 1,
        "legend.fontsize": font_pt - 1,
        "legend.title_fontsize": font_pt - 1,
        "figure.titlesize": font_pt,
    })
    annot_fontsize = font_pt - 1

    # constrained_layout + an "outside" legend keep all content inside the fixed
    # canvas, so the saved PDF's bounding box equals figsize exactly (no tight crop).
    fig, (ax_pdr, ax_pkt) = plt.subplots(
        1, 2, figsize=(width_in, width_in * aspect), layout="constrained")

    _grouped_bars(ax_pdr, rounds, "pdr_percent", error_kind, "{:.1f}", as_sem, annot_fontsize)
    ax_pdr.set_ylabel("Message reception rate / PDR (%)")
    ax_pdr.set_ylim(0, 108)  # headroom above 100 so value labels clear the title
    ax_pdr.set_yticks([0, 20, 40, 60, 80, 100])
    ax_pdr.set_title("Reception rate")

    _grouped_bars(ax_pkt, rounds, "duplication_rate", error_kind, "{:.2f}", as_sem, annot_fontsize)
    ax_pkt.set_ylabel("Valid copies captured per message")
    ax_pkt.set_title("Capture redundancy")

    # One legend for the whole figure (identity is never colour-alone: it is also
    # labelled here and the panels are directly value-labelled).
    handles, labels = ax_pdr.get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside lower center", ncol=2, frameon=False)
    # No on-figure suptitle: the LaTeX \caption describes the figure (and states
    # the error-bar meaning and run count), which is the thesis convention.
    return fig


def main() -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_in = os.path.join(repo_root, "evaluation", "data", "sniffer_comparison.json")
    default_out = os.path.join(repo_root, "evaluation", "plots", "sniffer_comparison.png")

    p = argparse.ArgumentParser(description="Plot the nRF-vs-HCI sniffer reception comparison.")
    p.add_argument("--in", dest="in_path", default=default_in, help="Input JSON from compare_sniffers.py")
    p.add_argument("--out", default=default_out, help="Output image path (PNG; a PDF is written alongside)")
    p.add_argument("--error", choices=["std", "sem"], default="std",
                   help="Error bars: standard deviation (default) or standard error of the mean")
    p.add_argument("--width-pt", type=float, default=455.0,
                   help="Target width in LaTeX points, i.e. the value of \\the\\textwidth (or "
                        "\\the\\columnwidth) in your document (default: 455, a typical article textwidth)")
    p.add_argument("--fraction", type=float, default=1.0,
                   help="Fraction of --width-pt to occupy, matching \\includegraphics[width=<frac>\\textwidth] "
                        "(default: 1.0 -- include at full width)")
    p.add_argument("--aspect", type=float, default=0.5,
                   help="Figure height / width ratio (default: 0.5)")
    p.add_argument("--font-pt", type=float, default=10.0,
                   help="Document body font size in points, matched by the figure text (default: 10)")
    p.add_argument("--dpi", type=int, default=300, help="Raster (PNG) output DPI (default: 300)")
    args = p.parse_args()

    rounds = load_rounds(args.in_path)
    width_in = args.width_pt * args.fraction / PT_PER_INCH
    fig = make_figure(rounds, args.error, width_in, args.aspect, args.font_pt)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    # Save at the exact canvas size (no bbox_inches="tight", which would crop the
    # margins and change the dimensions): the PDF is then exactly width_in wide, so
    # \includegraphics{...} at natural size -- or width=<fraction>\textwidth -- keeps
    # the fonts at their intended point size.
    fig.savefig(args.out, dpi=args.dpi)
    pdf_path = os.path.splitext(args.out)[0] + ".pdf"
    fig.savefig(pdf_path)
    print(f"[+] Saved {args.out} and {pdf_path}  ({width_in:.2f} in = "
          f"{args.width_pt * args.fraction:.0f} pt wide, {args.font_pt:g} pt fonts)")


if __name__ == "__main__":
    main()
