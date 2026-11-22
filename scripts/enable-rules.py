import json, sys
want = set(sys.argv[1].replace(",", " ").split())
d = json.load(sys.stdin)
for r in d["spec"]["rules"]:
    if r.get("id") in want:
        r["enabled"] = True
        want.discard(r["id"])
if want:
    sys.exit("not in the chart's ruleset: " + " ".join(sorted(want)))
json.dump(d, sys.stdout)
