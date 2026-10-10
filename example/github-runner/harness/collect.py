#!/usr/bin/env python3
"""Pull one runner pod's alerts and learned profile chunks into the replay dataset layout.

alerts: <out>/alerts/<RULE>.jsonl, one line per alert, event fields from the infected process.
        With --fire (bobctl simulate --record), each line is tagged with the suite step whose
        command appears in the alert's process-tree ancestry, else "_build".
chunks: <out>/chunks/{runner,dind}/<name>.json, ready ContainerProfile chunks of the pod.

ClickHouse is reached with kubectl exec; credentials come from CH_USER / CH_PASSWORD.
"""
import argparse, hashlib, json, os, subprocess, sys

CH_NS = os.environ.get("CH_NS", "clickhouse")
CH_POD = os.environ.get("CH_POD", "chi-forensic-soc-db-soc-cluster-0-0-0")
FILE_RULES = {"R0002", "R0006", "R0008", "R0010", "R1010"}


def kubectl(args, timeout=60):
    return subprocess.run(["kubectl"] + args, capture_output=True, text=True, timeout=timeout, check=True).stdout


def clickhouse(query):
    user, pw = os.environ.get("CH_USER"), os.environ.get("CH_PASSWORD")
    if not user or not pw:
        sys.exit("CH_USER and CH_PASSWORD must be set")
    return kubectl(["-n", CH_NS, "exec", CH_POD, "--", "clickhouse-client", "-u", user, "--password", pw, "-q", query], 120)


def find(node, pid):
    if not isinstance(node, dict):
        return None
    if node.get("pid") == pid:
        return node
    for child in (node.get("childrenMap") or {}).values():
        hit = find(child, pid)
        if hit:
            return hit
    return None


def cmdlines(node, acc):
    if isinstance(node, dict):
        if node.get("cmdline"):
            acc.append(node["cmdline"])
        for child in (node.get("childrenMap") or {}).values():
            cmdlines(child, acc)
    return acc


def signatures(fire):
    out = []
    for step in fire:
        cmd = step.get("command") or []
        if not step.get("t0") or not cmd:
            continue
        script = cmd[2] if len(cmd) >= 3 and cmd[0] in ("sh", "bash") and cmd[1] == "-c" else " ".join(cmd)
        out.append((step["name"], script.strip()[:80]))
    return out


def alerts(a):
    where = f"JSONExtractString(RuntimeK8sDetails,'podName')='{a.pod}'"
    if a.since:
        where += f" AND event_time >= {a.since}"
    if a.until:
        where += f" AND event_time <= {a.until}"
    rows = clickhouse("SELECT RuleID, JSONExtractString(RuntimeK8sDetails,'containerName') AS ctr, "
                      "RuntimeProcessDetails, BaseRuntimeMetadata FROM forensic_db.kubescape_logs "
                      f"WHERE {where} FORMAT JSONEachRow")
    sigs = signatures(json.load(open(a.fire))) if a.fire else None
    buf, tagged, ambiguous = {}, 0, 0
    for line in rows.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        rule = d.get("RuleID")
        if not rule:
            continue
        meta = json.loads(d.get("BaseRuntimeMetadata") or "{}")
        tree = (json.loads(d.get("RuntimeProcessDetails") or "{}") or {}).get("processTree") or {}
        args = meta.get("arguments") or {}
        node = find(tree, meta.get("infectedPID")) or {}
        parent = find(tree, node.get("ppid")) if node.get("ppid") else None
        rec = {"ctr": d.get("ctr"), "comm": node.get("comm"), "exe": node.get("path"),
               "pcomm": node.get("pcomm"), "pexe": (parent or {}).get("path"),
               "path": (args.get("path") or args.get("fullPath")) if rule in FILE_RULES else None,
               "arguments": args}
        if sigs is not None:
            blob = " || ".join(cmdlines(tree, []))
            hits = [name for name, sig in sigs if sig and sig in blob]
            rec["step"] = hits[0] if hits else "_build"
            tagged += bool(hits)
            if len(hits) > 1:
                rec["ambiguous"] = True
                ambiguous += 1
        buf.setdefault(rule, []).append(json.dumps(rec))
    os.makedirs(f"{a.out}/alerts", exist_ok=True)
    for rule, lines in buf.items():
        tmp = f"{a.out}/alerts/.{rule}.tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, f"{a.out}/alerts/{rule}.jsonl")
    total = sum(len(v) for v in buf.values())
    print(f"{a.pod}: {total} alerts, rules {sorted(buf)}" + (f", step-tagged {tagged}, ambiguous {ambiguous}" if sigs is not None else ""))


def chunks(a):
    names = [n for n in kubectl(["-n", a.namespace, "get", "containerprofiles", "--no-headers",
                                 "-o", "custom-columns=N:.metadata.name"]).split() if a.pod in n]
    n_out = 0
    for name in names:
        cp = json.loads(kubectl(["-n", a.namespace, "get", "containerprofiles", name, "-o", "json"]))
        if cp["metadata"].get("annotations", {}).get("kubescape.io/status") == "failed":
            continue
        kind = "dind" if "-dind-" in name else "runner"
        os.makedirs(f"{a.out}/chunks/{kind}", exist_ok=True)
        with open(f"{a.out}/chunks/{kind}/{name[-50:]}.json", "w") as f:
            json.dump(cp, f)
        n_out += 1
    print(f"{a.pod}: {n_out} chunks")


def rules_hash(a):
    spec = json.loads(kubectl(["-n", a.rules_namespace, "get", "rules", a.rules_name, "-o", "json"]))["spec"]
    print(hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:12])


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    al = sub.add_parser("alerts")
    al.add_argument("--pod", required=True)
    al.add_argument("--out", required=True)
    al.add_argument("--fire", help="bobctl simulate --record output; tags lines by step ancestry")
    al.add_argument("--since", type=int, help="event_time lower bound (unix ns)")
    al.add_argument("--until", type=int, help="event_time upper bound (unix ns)")
    al.set_defaults(fn=alerts)
    ch = sub.add_parser("chunks")
    ch.add_argument("--pod", required=True)
    ch.add_argument("--out", required=True)
    ch.add_argument("-n", "--namespace", default="arc-systems")
    ch.set_defaults(fn=chunks)
    rh = sub.add_parser("rules-hash", help="sha256[:12] of the live Rules spec, sorted-keys JSON")
    rh.add_argument("--rules-namespace", default="honey")
    rh.add_argument("--rules-name", default="default-rules")
    rh.set_defaults(fn=rules_hash)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
