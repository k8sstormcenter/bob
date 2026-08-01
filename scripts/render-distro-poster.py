#!/usr/bin/env python3
"""Render an A4 four-panel poster comparing redis-protocol distros.

Each panel is a full rule-coverage card produced by the SAME renderer as the
single-app cards (scripts/render-rule-coverage-gif.py), so a panel here and a
standalone card are the same artifact — no second drawing path to drift.

The panels animate in lockstep: frame N lights the Nth verified rule in every
distro at once. That is the whole point. Reading across a row you can see, at
the same instant, which distros lit a rule and which did not — similarities and
differences in one glance rather than four GIFs opened side by side.

Distros that finish lighting early simply hold their final frame, so a shorter
column is itself the signal that it covers fewer rules.

Usage:
  render-distro-poster.py --out poster.gif \
      --ruleset kubescape/default-rules.yaml \
      --config kubescape/rule-coverage.yaml \
      --results results/distros \
      --distro redis-oss --distro valkey --distro keydb --distro dragonfly
"""
import argparse
import importlib.util
import sys
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent


def load_card_module():
    """Import the single-app card renderer so panels use its exact drawing code."""
    path = HERE / "render-rule-coverage-gif.py"
    spec = importlib.util.spec_from_file_location("rulecard", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# A4 portrait at 150dpi is 1240x1754. Four stacked panels plus a header strip.
A4_W, A4_H = 1240, 1754
HEADER_H = 96
PANEL_W = A4_W - 40
PANEL_H = (A4_H - HEADER_H - 50) // 4


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ruleset", required=True)
    ap.add_argument("--results", required=True, help="dir with <distro>/metrics.json")
    ap.add_argument("--distro", action="append", required=True)
    ap.add_argument("--suite", action="append", required=True,
                    help="attack suite(s) every distro was tested with")
    ap.add_argument("--title", default="redis-protocol distros: identical suite, identical pod spec")
    ap.add_argument("--probe", default="")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--observed", default="")
    ap.add_argument("--duration", type=int, default=520)
    ap.add_argument("--last-duration", type=int, default=5000)
    args = ap.parse_args()

    card = load_card_module()
    ruleset = card.load_ruleset(args.ruleset)
    asserted, labels, probe_attacks, by_rule = card.asserted_rules(args.suite)

    panels = []
    for name in args.distro:
        mf = Path(args.results) / name / "metrics.json"
        metrics = [str(mf)] if mf.is_file() else []
        verified = card.verified_rules(metrics)
        order, state = card.classify(
            ruleset, asserted, verified,
            card.csv_set(args.probe), card.csv_set(args.exclude),
            bool(metrics), observed=card.csv_set(args.observed))
        lit_seq = [(r, *by_rule.get(r, ("(unasserted)", ""))) for r in order if state[r] == "verified"]
        panels.append({"name": name, "order": order, "state": state, "lit_seq": lit_seq,
                       "have": bool(metrics)})
        if not metrics:
            print(f"warn: no metrics for {name} — panel will show it as uncovered", file=sys.stderr)

    n_frames = max((len(p["lit_seq"]) for p in panels), default=0) + 1
    print(f"Rendering {n_frames} frames x {len(panels)} panels (A4 {A4_W}x{A4_H})...", file=sys.stderr)

    frames = []
    for f in range(n_frames):
        sheet = Image.new("RGB", (A4_W, A4_H), card.C_BG)
        d = ImageDraw.Draw(sheet)
        d.text((28, 30), args.title, fill=card.C_TITLE)
        d.text((28, 58), f"frame {f}/{n_frames - 1}   panels light in lockstep; "
                         "a short column means fewer rules covered", fill=card.C_SUB)
        for i, p in enumerate(panels):
            lit = min(f, len(p["lit_seq"]))
            img = card.draw(p["order"], p["state"], lit, p["name"],
                            "same suite", [p["name"]], "", probe_attacks,
                            card.csv_set(args.exclude), (PANEL_W, PANEL_H), p["lit_seq"])
            sheet.paste(img.convert("RGB"), (20, HEADER_H + i * PANEL_H))
        frames.append(sheet.quantize(colors=192, method=Image.Quantize.MEDIANCUT))

    durations = [args.duration] * len(frames)
    durations[-1] = args.last_duration
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(args.out, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0)
    print(f"Wrote {args.out} ({len(frames)} frames, {A4_W}x{A4_H})")
    for p in panels:
        print(f"  {p['name']:<12} {len(p['lit_seq'])} verified rules"
              + ("" if p["have"] else "  (NO METRICS)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
