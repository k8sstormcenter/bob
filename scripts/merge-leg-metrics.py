#!/usr/bin/env python3
"""Merge per-leg tune metrics into one metrics.json for a product-wide GIF.

A single Argo CD subcomponent tunes in two or three iterations, so its GIF is
only two or three frames — the profiles are already minimal and the over-broad
guard blocks the degenerate collapse. The interesting story for Argo CD is not
one component shrinking, it is that the SAME contrast method lands on all seven
containers of one product.

So each output frame is a COMPONENT rather than an iteration: its tuned profile
size, its kill-chain coverage, and its score. The `phase` field carries the
component name, which the design-1 renderer prints in the title bar.

Usage:
  merge-leg-metrics.py <dir-of-<leg>.json> <out.json> [leg ...]
"""
import json
import sys
from pathlib import Path


def best_entry(entries):
    """The frame worth showing: lowest score, then the most-collapsed profile."""
    live = [e for e in entries if e.get("phase") != "raw-baseline"] or entries
    return min(live, key=lambda e: (e.get("score", 0), e.get("total_entries", 0)))


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    legs = sys.argv[3:] or sorted(p.stem for p in src.glob("*.json"))

    merged = []
    for i, leg in enumerate(legs, start=1):
        f = src / f"{leg}.json"
        if not f.is_file():
            print(f"skip {leg}: no metrics", file=sys.stderr)
            continue
        e = dict(best_entry(json.loads(f.read_text())))
        e["iteration"] = i
        e["phase"] = leg.replace("argocd-", "") or leg
        merged.append(e)

    if not merged:
        print("no leg metrics found", file=sys.stderr)
        return 1

    out.write_text(json.dumps(merged, indent=1))
    total = sum(len(e.get("detections") or []) for e in merged)
    worst = max(e.get("score", 0) for e in merged)
    print(f"{out}: {len(merged)} frames, {total} expected detections, worst score {worst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
