#!/usr/bin/env python3
"""Generate a mermaid chart markdown file from metrics.json for GitHub step summary.

Usage:
    python3 render-summary-chart.py metrics.json output.md --app webapp --os ubuntu-24.04
"""
import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics_json")
    parser.add_argument("output_md")
    parser.add_argument("--app", default="unknown")
    parser.add_argument("--os", default="unknown")
    args = parser.parse_args()

    with open(args.metrics_json) as f:
        data = json.load(f)
    if not data:
        print("Empty metrics.json — nothing to chart", file=sys.stderr)
        sys.exit(0)

    n = len(data)
    labels = ", ".join(f'"i{r["iteration"]}"' for r in data)
    scores = [r["score"] for r in data]
    opens_list = [r["opens"] for r in data]
    entries_list = [r["total_entries"] for r in data]
    last = data[-1]

    badge = "PERFECT" if last["score"] == 0 and n > 1 else f'score={last["score"]}'

    lines = []
    lines.append(f"#### {args.app} ({args.os}) — {badge}")
    lines.append("")

    # Score chart
    max_score = max(max(scores), 1) + 1
    lines.append("```mermaid")
    lines.append("xychart-beta")
    lines.append(f'  title "Score over iterations ({n} iters)"')
    lines.append(f"  x-axis [{labels}]")
    lines.append(f'  y-axis "Score" 0 --> {max_score}')
    lines.append(f"  bar [{', '.join(str(s) for s in scores)}]")
    lines.append(f"  line [{', '.join(str(s) for s in scores)}]")
    lines.append("```")
    lines.append("")

    # Profile compactness chart
    lines.append("```mermaid")
    lines.append("xychart-beta")
    lines.append('  title "Profile compactness"')
    lines.append(f"  x-axis [{labels}]")
    lines.append('  y-axis "Entries"')
    lines.append(f"  bar [{', '.join(str(e) for e in entries_list)}]")
    lines.append(f"  line [{', '.join(str(o) for o in opens_list)}]")
    lines.append("```")
    lines.append("")

    # Detection summary table (last iteration only, deduplicated)
    detections = last.get("detections", [])
    if detections:
        lines.append("| Rule | Name | Command | Found |")
        lines.append("|------|------|---------|-------|")
        seen = set()
        for d in detections:
            key = (d["rule_id"], d["rule_name"])
            if key in seen:
                continue
            seen.add(key)
            icon = "Y" if d["found"] else "N"
            lines.append(f'| {d["rule_id"]} | {d["rule_name"]} | {d.get("command", "")} | {icon} |')
        lines.append("")

    with open(args.output_md, "w") as f:
        f.write("\n".join(lines))

    print(f"Wrote {args.output_md} ({len(lines)} lines)", file=sys.stderr)


if __name__ == "__main__":
    main()
