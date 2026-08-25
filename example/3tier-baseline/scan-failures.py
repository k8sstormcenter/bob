#!/usr/bin/env python3
"""
Read a kubescape scan JSON and show the failures in a form a person can act on.

    ./scan-failures.py /tmp/AllControls-flashy-product.json
    ./scan-failures.py scan.json --summary
    ./scan-failures.py scan.json --sev High
    ./scan-failures.py scan.json --control C-0012
    ./scan-failures.py scan.json --resource db
    ./scan-failures.py scan.json --by-control     # the un-collapsed view

This is the exploration tool. `review.py` is the one that produces the verdict an
agent consumes; this exists because when a scan returns 139 failures you want to
look at them before deciding how to group them.

WHERE THE ACTIONABLE PART LIVES: kubescape puts the fix in
`results[].controls[].rules[].paths[].fixPath`, as `{path, value}` — a YAML path and
the value to set. That is the difference between "C-0013 failed" and
"set spec.template.spec.containers[0].securityContext.runAsNonRoot = true", and it is
the whole reason this output is usable by a coding agent.

A `value` of `YOUR_VALUE` means kubescape knows the field is missing but cannot know
what belongs there. Those need a decision; they are not patchable as-is.
"""
import argparse, collections, json, re, sys

SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def load(path):
    try:
        d = json.load(open(path))
    except FileNotFoundError:
        sys.exit(f"no such scan file: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"{path} is not valid JSON: {e}")
    return d if isinstance(d, list) else d.get("results", [])


def failures(results):
    """Flatten to (severity, controlID, control name, resource, [(path, value)])."""
    for r in results:
        rid = r.get("resourceID", "")
        short = rid.split("/")[-1] or rid
        for c in r.get("controls", []):
            if c.get("status", {}).get("status") != "failed":
                continue
            fixes = []
            for rule in c.get("rules", []):
                for p in (rule.get("paths") or []):
                    fp = p.get("fixPath") or {}
                    if fp.get("path"):
                        fixes.append((fp["path"], str(fp.get("value", ""))))
                    elif p.get("failedPath"):
                        fixes.append((p["failedPath"], "<remove>"))
            yield (c.get("severity", "Low"), c.get("controlID", "?"),
                   c.get("name", ""), short, fixes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scan")
    ap.add_argument("--sev", help="Critical | High | Medium | Low")
    ap.add_argument("--control", help="e.g. C-0012")
    ap.add_argument("--resource", help="e.g. db")
    ap.add_argument("--by-control", action="store_true",
                    help="one row per control per resource, uncollapsed")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()

    rows = list(failures(load(a.scan)))
    if a.sev:
        rows = [r for r in rows if r[0].lower() == a.sev.lower()]
    if a.control:
        rows = [r for r in rows if r[1].lower() == a.control.lower()]
    if a.resource:
        rows = [r for r in rows if r[3] == a.resource]

    if not rows:
        print("no failures matched")
        return

    if a.summary:
        sev = collections.Counter(r[0] for r in rows)
        res = collections.Counter(r[3] for r in rows)
        fixable = sum(1 for r in rows
                      if any(v not in ("YOUR_VALUE", "<remove>", "") for _, v in r[4]))
        print(f"  {len(rows)} failed control instances "
              f"across {len(res)} resources")
        print("  by severity: " + ", ".join(
            f"{k}={sev[k]}" for k in ("Critical", "High", "Medium", "Low") if sev[k]))
        print(f"  carrying a concrete fix value: {fixable}")
        print("  noisiest resources: " + ", ".join(
            f"{k}({v})" for k, v in res.most_common(5)))
        return

    if a.by_control:
        seen = set()
        for sevr, cid, name, res, fixes in sorted(
                rows, key=lambda r: (SEV_RANK.get(r[0], 9), r[1], r[3])):
            if (cid, res) in seen:
                continue
            seen.add((cid, res))
            print(f"{sevr:<8} {cid:<8} {res:<18} {name[:46]}")
            for p, v in list(dict.fromkeys(fixes))[:3]:
                print(f"{'':>9}→ {p} = {v}")
        return

    # default: collapse by the fix, the way review.py does, because several controls
    # routinely demand the same edit and repeating them buries the rest
    grouped = {}
    for sevr, cid, name, res, fixes in rows:
        for p, v in fixes:
            key = re.sub(r"\[\d+\]", "[*]", p)
            g = grouped.setdefault(key, {"vals": set(), "res": set(),
                                         "ctl": set(), "sev": sevr})
            g["vals"].add(v)
            g["res"].add(res)
            g["ctl"].add(cid)
            if SEV_RANK.get(sevr, 9) < SEV_RANK.get(g["sev"], 9):
                g["sev"] = sevr

    print(f"\n{len(rows)} failed control instances → {len(grouped)} distinct fixes\n")
    for key, g in sorted(grouped.items(),
                         key=lambda kv: (SEV_RANK.get(kv[1]["sev"], 9), kv[0])):
        vals = {v for v in g["vals"] if v}
        if vals == {"<remove>"}:
            what = "REMOVE"
        elif "YOUR_VALUE" in vals:
            what = "= <choose a value>"
        else:
            what = "= " + sorted(vals)[0]
        print(f"[{g['sev']:<6}] {key} {what}")
        print(f"{'':>9}{', '.join(sorted(g['res']))}")
        print(f"{'':>9}{', '.join(sorted(g['ctl']))}\n")


if __name__ == "__main__":
    main()
