#!/usr/bin/env python3
"""Render metrics.json into an animated GIF showing the tuning process.

Each frame shows one iteration: profile metrics, attack results, detection
status, and score — building up a cumulative view of how the profile evolves.

Requires: pip install pillow matplotlib

Usage:
    python3 render-metrics-gif.py results/metrics.json results/tune.gif
    python3 render-metrics-gif.py results/metrics.json results/tune.gif --title "webapp (ubuntu-24.04)"
"""
import argparse
import json
import sys
from io import BytesIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image


# ── Colour palette ──────────────────────────────────────────────────────────
C_BG       = "#1a1b26"
C_PANEL    = "#24283b"
C_BORDER   = "#414868"
C_TEXT     = "#c0caf5"
C_DIM      = "#565f89"
C_GREEN    = "#9ece6a"
C_RED      = "#f7768e"
C_YELLOW   = "#e0af68"
C_BLUE     = "#7aa2f7"
C_CYAN     = "#7dcfff"


def load_metrics(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def draw_frame(records: list[dict], up_to: int, title: str, width=960, height=720) -> Image.Image:
    """Draw one frame showing iterations 0..up_to."""
    fig, axes = plt.subplots(2, 2, figsize=(width / 100, height / 100), dpi=100,
                             gridspec_kw={"height_ratios": [1.2, 1], "hspace": 0.35, "wspace": 0.3})
    fig.patch.set_facecolor(C_BG)

    current = records[up_to]
    phase = current["phase"]
    iteration = current["iteration"]
    score = current["score"]

    # ── Title bar ───────────────────────────────────────────────────────────
    result_text = "PERFECT" if score == 0 and up_to > 0 else f"score={score}"
    result_color = C_GREEN if score == 0 and up_to > 0 else C_YELLOW if score <= 2 else C_RED
    fig.suptitle(f"{title}  |  iter {iteration}: {phase}  |  {result_text}",
                 fontsize=14, fontweight="bold", color=result_color, y=0.97,
                 fontfamily="monospace")

    # ── Top-left: Profile metrics bar chart ─────────────────────────────────
    ax = axes[0, 0]
    ax.set_facecolor(C_PANEL)
    categories = ["Opens", "Execs", "Syscalls", "Endpoints", "Rules"]
    keys = ["opens", "execs", "syscalls", "endpoints", "policy_rules"]
    vals = [current[k] for k in keys]
    bars = ax.barh(categories, vals, color=[C_BLUE, C_CYAN, C_DIM, C_GREEN, C_YELLOW], height=0.6)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9, color=C_TEXT, fontfamily="monospace")
    ax.set_xlim(0, max(vals) * 1.3 if max(vals) > 0 else 10)
    ax.set_title("Profile Entries", fontsize=11, color=C_TEXT, fontfamily="monospace")
    ax.tick_params(colors=C_DIM, labelsize=8)
    for spine in ax.spines.values():
        spine.set_color(C_BORDER)

    # ── Top-right: Score over iterations ────────────────────────────────────
    ax = axes[0, 1]
    ax.set_facecolor(C_PANEL)
    iters = [r["iteration"] for r in records[:up_to + 1]]
    scores = [r["score"] for r in records[:up_to + 1]]
    missed = [r["missed_detections"] for r in records[:up_to + 1]]
    fps = [r["false_positives"] for r in records[:up_to + 1]]

    ax.fill_between(iters, scores, alpha=0.15, color=C_RED)
    ax.plot(iters, scores, "o-", color=C_RED, markersize=8, linewidth=2, label="Total Score")
    ax.plot(iters, missed, "s--", color=C_YELLOW, markersize=5, linewidth=1, label="Missed")
    ax.plot(iters, fps, "^--", color=C_BLUE, markersize=5, linewidth=1, label="FP")

    for i, s in zip(iters, scores):
        ax.annotate(str(s), (i, s), textcoords="offset points", xytext=(0, 10),
                    ha="center", fontsize=10, fontweight="bold", color=C_TEXT, fontfamily="monospace")

    ax.set_xlabel("Iteration", fontsize=9, color=C_DIM, fontfamily="monospace")
    ax.set_ylabel("Score", fontsize=9, color=C_DIM, fontfamily="monospace")
    ax.set_title("Score Evolution", fontsize=11, color=C_TEXT, fontfamily="monospace")
    ax.set_ylim(-0.5, max(max(scores), 1) + 1)
    if len(iters) > 1:
        ax.set_xticks(iters)
    ax.legend(fontsize=7, loc="upper right", facecolor=C_PANEL, edgecolor=C_BORDER, labelcolor=C_TEXT)
    ax.tick_params(colors=C_DIM, labelsize=8)
    for spine in ax.spines.values():
        spine.set_color(C_BORDER)

    # ── Bottom-left: Attack results ─────────────────────────────────────────
    ax = axes[1, 0]
    ax.set_facecolor(C_PANEL)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("Attacks", fontsize=11, color=C_TEXT, fontfamily="monospace")
    ax.axis("off")

    attacks = current.get("attacks", [])
    if attacks:
        y = 0.95
        for a in attacks[:10]:  # limit to 10 rows
            icon = "\u2713" if a["success"] else "\u2717"
            color = C_GREEN if a["success"] else C_RED
            ax.text(0.02, y, icon, fontsize=10, color=color, fontfamily="monospace",
                    va="top", transform=ax.transAxes)
            ax.text(0.08, y, a["name"], fontsize=8, color=C_TEXT, fontfamily="monospace",
                    va="top", transform=ax.transAxes)
            y -= 0.1
    else:
        ax.text(0.5, 0.5, "(not tested)", fontsize=10, color=C_DIM,
                ha="center", va="center", fontfamily="monospace", transform=ax.transAxes)

    # ── Bottom-right: Detection results ─────────────────────────────────────
    ax = axes[1, 1]
    ax.set_facecolor(C_PANEL)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("Detections", fontsize=11, color=C_TEXT, fontfamily="monospace")
    ax.axis("off")

    detections = current.get("detections", [])
    if detections:
        y = 0.95
        for d in detections:
            icon = "\u2713" if d["found"] else "\u2717"
            color = C_GREEN if d["found"] else C_RED
            ax.text(0.02, y, icon, fontsize=10, color=color, fontfamily="monospace",
                    va="top", transform=ax.transAxes)
            label = f'{d["rule_id"]} {d["rule_name"]}'
            if len(label) > 35:
                label = label[:35] + "\u2026"
            ax.text(0.08, y, label, fontsize=8, color=C_TEXT, fontfamily="monospace",
                    va="top", transform=ax.transAxes)
            y -= 0.12
    else:
        ax.text(0.5, 0.5, "(not tested)", fontsize=10, color=C_DIM,
                ha="center", va="center", fontfamily="monospace", transform=ax.transAxes)

    # ── Render to PIL Image ─────────────────────────────────────────────────
    buf = BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor(), bbox_inches="tight", pad_inches=0.3)
    plt.close(fig)
    buf.seek(0)
    return Image.open(buf).convert("RGBA")


def main():
    parser = argparse.ArgumentParser(description="Render tune metrics as animated GIF")
    parser.add_argument("metrics_json", help="Path to metrics.json")
    parser.add_argument("output_gif", help="Output GIF path")
    parser.add_argument("--title", default="bobctl tune", help="Title text")
    parser.add_argument("--duration", type=int, default=2000, help="Frame duration in ms")
    parser.add_argument("--last-duration", type=int, default=4000, help="Last frame duration in ms")
    args = parser.parse_args()

    records = load_metrics(args.metrics_json)
    if not records:
        print("No iterations in metrics.json", file=sys.stderr)
        sys.exit(1)

    print(f"Rendering {len(records)} frames...", file=sys.stderr)
    frames = []
    for i in range(len(records)):
        frame = draw_frame(records, i, args.title)
        # Convert RGBA to P (palette) for GIF
        frames.append(frame.convert("RGB").quantize(colors=128, method=Image.Quantize.MEDIANCUT))

    durations = [args.duration] * len(frames)
    durations[-1] = args.last_duration  # hold last frame longer

    frames[0].save(
        args.output_gif,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
    )
    size_kb = Path(args.output_gif).stat().st_size / 1024
    print(f"Wrote {args.output_gif} ({len(frames)} frames, {size_kb:.0f} KB)", file=sys.stderr)


if __name__ == "__main__":
    main()
