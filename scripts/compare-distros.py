#!/usr/bin/env python3
"""Compare tuned distros and report whether they are CONTRAST-EQUIVALENT.

The question: does a contrast SBoB actually distinguish valkey from redis, or
are they the same thing as far as runtime detection is concerned?

That only has a defensible answer if the distros were held identical except for
the implementation — same pod spec, same Service and container names, same
attack suite, one namespace each (see example/redis/distros/). Given that, two
distros are compared on two independent axes:

  CONTRAST   which detection rules fired. This is the axis that matters for a
             SBoB: if two distros light the same rules, one SBoB's contrast
             behaviour transfers to the other.

  BEHAVIOUR  what the learned profile contains (execs / opens / network). Two
             distros can be contrast-equivalent while having quite different
             baselines — that is the interesting case, and it is precisely why
             the two axes are reported separately rather than collapsed into a
             single "same/different" verdict.

A difference in BEHAVIOUR alone does not invalidate reusing a SBoB's attack
suite; a difference in CONTRAST does.

Usage:
  compare-distros.py results/distros --baseline redis-oss
"""
import argparse
import json
import sys
from pathlib import Path


def load(distro_dir):
    """Return (rules_fired, rules_missed, profile_metrics) for one distro."""
    mf = distro_dir / "metrics.json"
    if not mf.is_file():
        return None
    entries = json.loads(mf.read_text())
    live = [e for e in entries if e.get("phase") != "raw-baseline"] or entries
    best = min(live, key=lambda e: (e.get("score", 0), e.get("total_entries", 0)))

    fired, missed = set(), set()
    for d in best.get("detections") or []:
        (fired if d.get("found") else missed).add(d.get("rule_id"))
    return {
        "fired": fired,
        "missed": missed,
        "score": best.get("score"),
        "opens": best.get("opens"),
        "execs": best.get("execs"),
        "syscalls": best.get("syscalls"),
        "entries": best.get("total_entries"),
        "attacks": {a["name"]: a.get("success") for a in (best.get("attacks") or [])},
    }


def main():
    ap = argparse.ArgumentParser(description="Compare tuned redis-protocol distros")
    ap.add_argument("results_dir")
    ap.add_argument("--baseline", default="redis-oss")
    ap.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = ap.parse_args()

    root = Path(args.results_dir)
    data = {}
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        got = load(sub)
        if got:
            data[sub.name] = got
        else:
            print(f"warn: no metrics.json for {sub.name}", file=sys.stderr)

    if args.baseline not in data:
        print(f"baseline '{args.baseline}' has no results; have: {', '.join(data) or 'none'}",
              file=sys.stderr)
        return 2

    base = data[args.baseline]
    verdicts = {}

    print(f"baseline: {args.baseline}\n")
    print(f"{'distro':<14}{'score':>6}{'execs':>7}{'opens':>7}{'entries':>9}   rules fired")
    print("-" * 78)
    for name, d in data.items():
        print(f"{name:<14}{d['score']:>6}{d['execs']:>7}{d['opens']:>7}{d['entries']:>9}   "
              f"{len(d['fired'])}: {' '.join(sorted(d['fired']))}")

    print()
    for name, d in data.items():
        if name == args.baseline:
            continue
        only_here = sorted(d["fired"] - base["fired"])
        only_base = sorted(base["fired"] - d["fired"])
        contrast_same = not only_here and not only_base

        # Behaviour axis: profile shape, independent of which rules fired.
        beh = []
        for k in ("execs", "opens", "syscalls"):
            if d[k] != base[k]:
                beh.append(f"{k} {base[k]}->{d[k]}")

        # An attack that succeeds on one distro and not the other explains a
        # contrast difference without being one itself.
        atk = [a for a, ok in d["attacks"].items()
               if base["attacks"].get(a) is not None and ok != base["attacks"][a]]

        verdicts[name] = {
            "contrast_equivalent": contrast_same,
            "rules_only_in_this": only_here,
            "rules_only_in_baseline": only_base,
            "behaviour_delta": beh,
            "attack_outcome_delta": atk,
        }

        print(f"{name} vs {args.baseline}")
        print(f"  CONTRAST : {'EQUIVALENT — same rules fire' if contrast_same else 'DIFFERS'}")
        if only_here:
            print(f"      only in {name}: {' '.join(only_here)}")
        if only_base:
            print(f"      only in {args.baseline}: {' '.join(only_base)}")
        print(f"  BEHAVIOUR: {', '.join(beh) if beh else 'identical profile shape'}")
        if atk:
            print(f"  attacks differing in outcome ({len(atk)}): {' '.join(sorted(atk)[:6])}"
                  + (" …" if len(atk) > 6 else ""))
        print()

    equiv = [n for n, v in verdicts.items() if v["contrast_equivalent"]]
    diff = [n for n, v in verdicts.items() if not v["contrast_equivalent"]]
    print("summary")
    print(f"  contrast-equivalent to {args.baseline}: {', '.join(equiv) or 'none'}")
    print(f"  contrast-differs      : {', '.join(diff) or 'none'}")

    if args.json:
        print(json.dumps({"baseline": args.baseline, "verdicts": verdicts}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
