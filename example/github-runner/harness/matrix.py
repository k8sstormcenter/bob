#!/usr/bin/env python3
# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE.
# All trademarks are expressly reserved.

"""Confusion matrix over a recorded dataset (layout: see README.md), from live alerts and dx KPI rows.

Positives are suite steps run in an attack build. A step is detected when node-agent raised a
non-floor alert tagged to it (collect.py alerts --fire), or when dx scored its suspicion with a
malicious verdict backed by a witness source — verdict=malicious and source in {forest,wire,dc_snoop}
(collect.py kpi). Negatives are clean builds. A clean build is a false positive
when it raised any non-floor alert, or any witnessed malicious KPI verdict.

Floor rules (default R0005,R0011), and any alert the sensor marks arguments.unresolvedPath, are
reported apart and never count. Known residuals passed with
--known RULE:substring (matched against the alert's exe or path) are listed apart as well, so a
known engine defect stays visible without being scored as a profile false positive.
"""
import argparse, glob, json, os, sys

WITNESSED = {"forest", "wire", "dc_snoop"}  # dx evidence sources (the `source` column), not verdicts


def load_jsonl(path):
    out = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    return out


def suite_steps(path):
    names = []
    with open(path) as f:
        for line in f:
            if line.startswith("  - name:"):
                names.append(line.split(":", 1)[1].strip())
    return names


def known_match(known, rule, rec):
    for k_rule, sub in known:
        if k_rule == rule and sub and (sub in (rec.get("exe") or "") or sub in (rec.get("path") or "")):
            return True
    return False


def build(d, floor, known):
    meta = {}
    if os.path.exists(f"{d}/meta.json"):
        meta = json.load(open(f"{d}/meta.json"))
    role = meta.get("role") or meta.get("kind") or "?"
    alerts = {}
    for p in glob.glob(f"{d}/alerts/*.jsonl"):
        rule = os.path.basename(p)[:-6]
        alerts[rule] = load_jsonl(p)
    kpi = load_jsonl(f"{d}/kpi.jsonl")
    fire = json.load(open(f"{d}/fire.json")) if os.path.exists(f"{d}/fire.json") else None
    b = {"id": os.path.basename(d.rstrip("/")), "role": role, "floor": {}, "known": {}, "alerts": {},
         "by_step": {}, "kpi_witnessed": sorted({r["suspicion"] for r in kpi
                                                 if r.get("verdict") == "malicious" and r.get("source") in WITNESSED and r.get("suspicion")}),
         "ran": [s["name"] for s in fire if s.get("t0")] if fire else None}
    for rule, recs in alerts.items():
        for rec in recs:
            if rule in floor or (rec.get("arguments") or {}).get("unresolvedPath"):
                bucket = "floor"  # an open whose path the sensor could not resolve names nothing to allow
            elif known_match(known, rule, rec):
                bucket = "known"
            else:
                bucket = "alerts"
            b[bucket][rule] = b[bucket].get(rule, 0) + 1
            if bucket == "alerts" and rec.get("step") and rec["step"] != "_build":
                b["by_step"].setdefault(rec["step"], set()).add(rule)
    return b


def main():
    g = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dataset")
    p.add_argument("--suite", default=os.path.join(g, "..", "github-runner-attacks.yaml"))
    p.add_argument("--floor", default="R0005,R0011")
    p.add_argument("--known", action="append", default=[], help="RULE:substring of exe or path, repeatable")
    p.add_argument("--subset", help="file with one step name per line (e.g. teampcp-steps.txt)")
    p.add_argument("--json", help="also write the result as JSON here")
    a = p.parse_args()

    floor = {r.strip() for r in a.floor.split(",") if r.strip()}
    known = [tuple(k.split(":", 1)) for k in a.known if ":" in k]
    steps = suite_steps(a.suite)
    subset = None
    if a.subset:
        subset = [l.strip() for l in open(a.subset) if l.strip() and not l.startswith("#")]

    builds = [build(d, floor, known) for d in sorted(glob.glob(f"{a.dataset}/builds/*/"))]
    attacks = [b for b in builds if "attack" in b["role"] or "contrast" in b["role"]]
    cleans = [b for b in builds if b not in attacks]

    rows, tp, fn = [], 0, 0
    for b in attacks:
        ran = b["ran"] if b["ran"] is not None else steps
        for s in (subset or steps):
            if s not in ran:
                continue
            na = sorted(b["by_step"].get(s, ()))
            kp = s in b["kpi_witnessed"]
            hit = bool(na) or kp
            tp += hit
            fn += not hit
            rows.append({"build": b["id"], "step": s, "node_agent": na, "kpi": kp, "detected": hit})

    fp = sum(1 for b in cleans if b["alerts"] or b["kpi_witnessed"])
    tn = len(cleans) - fp

    print(f"# Confusion matrix — {a.dataset}")
    print(f"floor={','.join(sorted(floor))} known={a.known or '-'} subset={a.subset or 'all steps'}\n")
    print("|                    | alerted | quiet |")
    print("|--------------------|---------|-------|")
    print(f"| attack step        | TP {tp:<4} | FN {fn:<3} |")
    print(f"| clean build        | FP {fp:<4} | TN {tn:<3} |\n")
    if tp + fn:
        print(f"detection {tp}/{tp + fn}", end="")
    if cleans:
        print(f"   clean builds quiet {tn}/{len(cleans)}", end="")
    print("\n")
    if rows:
        print("| build | step | node-agent rules | KPI witnessed | detected |")
        print("|---|---|---|---|---|")
        for r in rows:
            print(f"| {r['build']} | {r['step']} | {' '.join(r['node_agent']) or '-'} | "
                  f"{'yes' if r['kpi'] else '-'} | {'**yes**' if r['detected'] else 'no'} |")
        print()
    if cleans:
        print("| clean build | role | non-floor alerts | KPI witnessed | floor | known |")
        print("|---|---|---|---|---|---|")
        for b in cleans:
            fmt = lambda m: " ".join(f"{k}={v}" for k, v in sorted(m.items())) or "-"
            print(f"| {b['id']} | {b['role']} | {fmt(b['alerts'])} | {' '.join(b['kpi_witnessed']) or '-'} | "
                  f"{fmt(b['floor'])} | {fmt(b['known'])} |")
    if a.json:
        out = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "steps": rows,
               "clean": [{k: (v if not isinstance(v, set) else sorted(v)) for k, v in b.items() if k != "by_step"}
                         for b in cleans]}
        with open(a.json, "w") as f:
            json.dump(out, f, indent=1)


if __name__ == "__main__":
    sys.exit(main())
