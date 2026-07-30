#!/usr/bin/env python3
"""Render a kubescape rule-coverage GIF for a contrast SBoB.

This is the generator for the animation used by example/redis-client/redis-killchain.gif:
one tile per rule in the cluster ruleset, lighting up as each rule is confirmed
firing, with the un-confirmed rules classified honestly rather than left blank.

  green  verified  the rule is asserted by an attack AND was observed firing
  amber  probe     exercised but not assertable here (kernel-gated, EPERM,
                   baseline-suppressed, not emitted by this node-agent build)
  grey   excluded  deliberately out of scope for this app
  red    gap       in the ruleset, nothing in the suite covers it

The point of the four states is that a rule which cannot fire is NOT the same
as a rule nobody tried to cover. A blank grid hides that distinction; this one
forces every rule in the ruleset to be accounted for.

"verified" is taken from tuner output (`metrics.json` detections with
found=true) when --metrics is given, which is the same evidence the tune scored
on. Without it, an asserted rule is shown as verified on the suite's word alone.

Probes and exclusions cannot be derived from the YAML — a probe attack carries
`expectedDetections: []` and names no rule — so they are passed explicitly and
should match the reason comments in the suite.

Usage:
  render-rule-coverage-gif.py --out redis-killchain.gif \
      --ruleset kubescape/default-rules.yaml \
      --suite example/redis-attacks.yaml \
      --metrics results/metrics.json \
      --title "redis" --agent "node-agent v0.3.158" \
      --probe R0004,R0040,R1002 --exclude R0003,R1007
"""
import argparse
import glob
import json
import sys
from io import BytesIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image
import yaml

# Palette lifted from the reference GIF so every app's card looks like one family.
C_BG = "#0d1220"
C_TITLE = "#e6edf3"
C_SUB = "#58a6ff"
C_CARD = "#161d2e"
C_TILE_DARK = "#1b2233"      # verified but not yet lit
C_TILE_DARK_TX = "#7d8590"
C_VERIFIED = "#2ea043"
C_VERIFIED_TX = "#eafff0"
C_PROBE = "#3f3517"
C_PROBE_TX = "#d4a017"
C_EXCL = "#242b3a"
C_EXCL_TX = "#565e6b"
C_GAP = "#3d1a20"
C_GAP_TX = "#f85149"

COLS = 6


def load_ruleset(path):
    """Every rule id the cluster ruleset defines, in ascending id order."""
    doc = yaml.safe_load(Path(path).read_text())
    found = {}

    def walk(o):
        if isinstance(o, dict):
            rid = o.get("id") or o.get("ruleID")
            name = o.get("name") or o.get("ruleName")
            if rid and name:
                found[rid] = name
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(doc)
    return found


def asserted_rules(suite_paths):
    """Rule ids the suites claim, the suite names, the probe-attack count, and the
    ATTACK that first asserts each rule — the reference card names the attack per
    frame, not just the rule."""
    rules, labels, probes = set(), [], 0
    by_rule = {}
    for p in suite_paths:
        doc = yaml.safe_load(Path(p).read_text())
        labels.append(doc.get("metadata", {}).get("name") or Path(p).stem)
        for a in doc.get("attacks") or []:
            det = a.get("expectedDetections") or []
            if not det:
                probes += 1
            for d in det:
                rid = d.get("ruleID")
                if not rid:
                    continue
                rules.add(rid)
                by_rule.setdefault(rid, (a.get("name", "?"), a.get("type", "")))
    return rules, labels, probes, by_rule


def verified_rules(metrics_paths):
    """Rule ids the tuner actually observed firing (detections with found=true)."""
    seen = set()
    for p in metrics_paths:
        for entry in json.loads(Path(p).read_text()):
            for d in entry.get("detections") or []:
                if d.get("found") and d.get("rule_id"):
                    seen.add(d["rule_id"])
    return seen


def classify(ruleset, asserted, verified, probe, exclude, have_metrics, observed=frozenset()):
    """Assign every rule in the ruleset exactly one state."""
    order = sorted(ruleset)
    state = {}
    for rid in order:
        if rid in exclude:
            state[rid] = "excluded"
        elif rid in probe:
            state[rid] = "probe"
        elif rid in asserted:
            # With metrics, only rules actually seen firing earn "verified"; an
            # asserted-but-unseen rule is a gap, not a pass.
            state[rid] = "verified" if (not have_metrics or rid in verified) else "gap"
        elif rid in verified or rid in observed:
            # Confirmed firing in-cluster without a suite asserting it (R0002 is
            # the usual case — it fires on every container).
            state[rid] = "verified"
        else:
            state[rid] = "gap"
    return order, state


def draw(order, state, lit, title, agent, suite_labels, note, probes, exclude, size, lit_seq):
    n_verified = sum(1 for r in order if state[r] == "verified")
    n_probe = sum(1 for r in order if state[r] == "probe")
    w, h = size
    fig = plt.figure(figsize=(w / 100, h / 100), dpi=100, facecolor=C_BG)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_axis_off()
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)

    head = f"{title} — kubescape rules verified firing ({agent})"
    # Monospace at fontsize F occupies ~F*0.6 px per char; shrink to fit the width
    # rather than overflow the canvas.
    tsize = min(15.0, (w * 0.94) / (len(head) * 0.62))
    ax.text(0.032, 0.945, head, color=C_TITLE, fontsize=tsize,
            fontweight="bold", va="center", family="monospace")
    ax.text(0.032, 0.882, f"{lit} / {n_verified} verified rules lit   ·   "
                          "amber = kernel-flaky/gated probe   ·   grey = excluded",
            color=C_SUB, fontsize=9.5, va="center", family="monospace")

    rows = (len(order) + COLS - 1) // COLS
    gx0, gx1, gy_top, gy_bot = 0.030, 0.972, 0.815, 0.285
    cw = (gx1 - gx0) / COLS
    chh = (gy_top - gy_bot) / max(rows, 1)
    pad_x, pad_y = cw * 0.035, chh * 0.14

    shown = 0
    for i, rid in enumerate(order):
        r, c = divmod(i, COLS)
        st = state[rid]
        if st == "verified":
            shown += 1
            on = shown <= lit
            face, txt = (C_VERIFIED, C_VERIFIED_TX) if on else (C_TILE_DARK, C_TILE_DARK_TX)
        elif st == "probe":
            face, txt = C_PROBE, C_PROBE_TX
        elif st == "excluded":
            face, txt = C_EXCL, C_EXCL_TX
        else:
            face, txt = C_GAP, C_GAP_TX

        x = gx0 + c * cw + pad_x
        y = gy_top - (r + 1) * chh + pad_y
        ax.add_patch(FancyBboxPatch((x, y), cw - 2 * pad_x, chh - 2 * pad_y,
                                    boxstyle="round,pad=0.004,rounding_size=0.012",
                                    linewidth=0, facecolor=face))
        ax.text(x + (cw - 2 * pad_x) / 2, y + (chh - 2 * pad_y) / 2, rid,
                color=txt, fontsize=10, fontweight="bold", ha="center", va="center",
                family="monospace")

    # Footer card
    fx, fy, fw, fh = 0.030, 0.045, 0.942, 0.205
    ax.add_patch(FancyBboxPatch((fx, fy), fw, fh,
                                boxstyle="round,pad=0.004,rounding_size=0.010",
                                linewidth=1, edgecolor="#232b3d", facecolor=C_CARD))
    # Frame 0 shows the suite; every later frame names the attack that lit the
    # rule and which rule it fired — that per-attack provenance is the whole
    # reason the card is more useful than a static grid.
    if lit > 0 and lit <= len(lit_seq):
        rid, atk_name, atk_type = lit_seq[lit - 1]
        headline, sub = atk_name, (f"type: {atk_type}" if atk_type else "")
        fires = f"fires: {rid}"
    else:
        headline = suite_labels[0] if len(suite_labels) == 1 else f"{len(suite_labels)} suites"
        sub = note
        excl_txt = f" · {len(exclude)} excluded" if exclude else ""
        fires = (f"{n_verified} rules fire · {n_probe} kernel/gated probes"
                 f"{excl_txt} · {probes} probe attacks")
    ax.text(fx + 0.022, fy + fh - 0.055, headline, color=C_TITLE, fontsize=11.5,
            fontweight="bold", va="center", family="monospace")
    if sub:
        ax.text(fx + 0.022, fy + fh - 0.108, sub, color=C_TILE_DARK_TX, fontsize=9,
                va="center", family="monospace")
    ax.text(fx + 0.022, fy + 0.042, fires,
            color=C_VERIFIED, fontsize=9.5, fontweight="bold", va="center", family="monospace")

    for k, (lbl, col) in enumerate([("verified", C_VERIFIED), ("probe", C_PROBE_TX),
                                    ("excl", C_EXCL_TX), ("gap", C_GAP_TX)]):
        lx = fx + fw - 0.335 + k * 0.085
        ly = fy + fh - 0.058
        ax.add_patch(FancyBboxPatch((lx, ly - 0.012), 0.014, 0.024,
                                    boxstyle="round,pad=0.002,rounding_size=0.004",
                                    linewidth=0, facecolor=col))
        ax.text(lx + 0.019, ly, lbl, color=C_TILE_DARK_TX, fontsize=7.5,
                va="center", family="monospace")

    buf = BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return Image.open(buf).convert("RGBA")


def csv_set(v):
    return {x.strip() for x in (v or "").split(",") if x.strip()}


def render_one(ruleset, out, suites, metrics, title, agent, note, probe, exclude,
               observed, size, duration, last_duration):
    """Render one app's card. Returns (verified, probe, excluded, gaps)."""
    metrics = [m for m in metrics if Path(m).is_file()]
    asserted, labels, probe_attacks, by_rule = asserted_rules(suites)
    verified = verified_rules(metrics)
    order, state = classify(ruleset, asserted, verified, probe, exclude,
                            bool(metrics), observed=observed)

    # Tiles light in grid order; each step names the attack that asserts that rule.
    lit_seq = [(r, *by_rule.get(r, ("(fires without being asserted)", "")))
               for r in order if state[r] == "verified"]
    n_verified = len(lit_seq)
    frames = [draw(order, state, lit, title, agent, labels, note, probe_attacks,
                   exclude, size, lit_seq) for lit in range(n_verified + 1)]

    cw = max(f.width for f in frames)
    ch = max(f.height for f in frames)
    out_frames = []
    for f in frames:
        if f.size != (cw, ch):
            canvas = Image.new("RGBA", (cw, ch), f.getpixel((0, 0)))
            canvas.paste(f, (0, 0))
            f = canvas
        out_frames.append(f.convert("RGB").quantize(colors=128, method=Image.Quantize.MEDIANCUT))

    durations = [duration] * len(out_frames)
    durations[-1] = last_duration
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    out_frames[0].save(out, save_all=True, append_images=out_frames[1:],
                       duration=durations, loop=0)
    gaps = [r for r in order if state[r] == "gap"]
    return n_verified, sum(1 for r in order if state[r] == "probe"), \
        sum(1 for r in order if state[r] == "excluded"), gaps


def run_config(args):
    """Batch mode: render a card for every app in the config."""
    cfg = yaml.safe_load(Path(args.config).read_text())
    ruleset = load_ruleset(args.ruleset)
    dflt = cfg.get("defaults") or {}
    apps = cfg.get("apps") or []
    if args.app:
        apps = [a for a in apps if a.get("name") in set(args.app)]
        if not apps:
            print(f"no app matching {args.app} in {args.config}", file=sys.stderr)
            return 1
    rc = 0
    for a in apps:
        name = a.get("name", "?")
        missing = [s for s in (a.get("suites") or []) if not Path(s).is_file()]
        if missing:
            print(f"{name}: SKIP — missing suite(s) {', '.join(missing)}", file=sys.stderr)
            continue
        metrics = list(a.get("metrics") or [])
        if a.get("metrics_glob"):
            metrics += sorted(glob.glob(a["metrics_glob"]))
        v, p, e, gaps = render_one(
            ruleset, a["out"], a["suites"],
            metrics,
            a.get("title", name), a.get("agent", dflt.get("agent", "node-agent")),
            a.get("note", ""),
            set(dflt.get("probe", [])) | set(a.get("probe", [])),
            set(dflt.get("exclude", [])) | set(a.get("exclude", [])),
            set(dflt.get("observed", [])) | set(a.get("observed", [])),
            (args.width, args.height), args.duration, args.last_duration)
        print(f"{name:<16} -> {a['out']}  ({v} verified · {p} probe · {e} excluded · "
              f"{len(gaps)} gap" + (f": {','.join(gaps)}" if gaps else "") + ")")
    return rc


def main():
    ap = argparse.ArgumentParser(description="Render a kubescape rule-coverage GIF")
    ap.add_argument("--config", help="render every app in this config (batch mode)")
    ap.add_argument("--app", action="append", help="with --config: only these apps")
    ap.add_argument("--out")
    ap.add_argument("--ruleset", required=True)
    ap.add_argument("--suite", action="append")
    ap.add_argument("--metrics", action="append", default=[])
    ap.add_argument("--title")
    ap.add_argument("--agent", default="node-agent")
    ap.add_argument("--note", default="")
    ap.add_argument("--observed", default="",
                    help="comma-separated rules confirmed firing in-cluster but not asserted by any suite")
    ap.add_argument("--probe", default="", help="comma-separated rules exercised but not assertable here")
    ap.add_argument("--exclude", default="", help="comma-separated rules deliberately out of scope")
    ap.add_argument("--width", type=int, default=990)
    ap.add_argument("--height", type=int, default=594)
    ap.add_argument("--duration", type=int, default=420)
    ap.add_argument("--last-duration", type=int, default=4200)
    args = ap.parse_args()

    if args.config:
        return run_config(args)
    if not args.out or not args.suite or not args.title:
        ap.error("--out, --suite and --title are required unless --config is given")

    ruleset = load_ruleset(args.ruleset)
    if not ruleset:
        print(f"no rules parsed from {args.ruleset}", file=sys.stderr)
        return 1
    metrics = [m for m in args.metrics if Path(m).is_file()]
    asserted, labels, probe_attacks, by_rule = asserted_rules(args.suite)
    verified = verified_rules(metrics)
    order, state = classify(ruleset, asserted, verified,
                            csv_set(args.probe), csv_set(args.exclude), bool(metrics),
                            observed=csv_set(args.observed))

    lit_seq = [(r, *by_rule.get(r, ("(fires without being asserted)", "")))
               for r in order if state[r] == "verified"]
    n_verified = len(lit_seq)
    frames = []
    for lit in range(n_verified + 1):
        frames.append(draw(order, state, lit, args.title, args.agent, labels,
                           args.note, probe_attacks, csv_set(args.exclude),
                           (args.width, args.height), lit_seq))

    cw = max(f.width for f in frames)
    ch = max(f.height for f in frames)
    out = []
    for f in frames:
        if f.size != (cw, ch):
            canvas = Image.new("RGBA", (cw, ch), f.getpixel((0, 0)))
            canvas.paste(f, (0, 0))
            f = canvas
        out.append(f.convert("RGB").quantize(colors=128, method=Image.Quantize.MEDIANCUT))

    durations = [args.duration] * len(out)
    durations[-1] = args.last_duration
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out[0].save(args.out, save_all=True, append_images=out[1:], duration=durations, loop=0)

    gaps = [r for r in order if state[r] == "gap"]
    print(f"{args.out}: {len(out)} frames · {n_verified} verified · "
          f"{sum(1 for r in order if state[r]=='probe')} probe · "
          f"{sum(1 for r in order if state[r]=='excluded')} excluded · {len(gaps)} gap"
          + (f" ({','.join(gaps)})" if gaps else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
