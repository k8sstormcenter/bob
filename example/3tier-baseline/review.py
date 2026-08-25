#!/usr/bin/env python3
"""
Architecture review for a namespace, as evidence rather than advice.

Reads what actually happened — node-agent runtime alerts and a kubescape compliance
scan — maps each observation onto the platform team's ADRs, and emits a verdict a
coding agent can act on and then re-run to verify its own fix.

    ./review.py flashy-product                     # human-readable
    ./review.py flashy-product --json verdict.json # machine-readable

THE RULE THIS FILE ENFORCES: no observation, no finding. Every entry in the report
carries the event that produced it — container, peer, path, rule ID. Nothing is
emitted because it is generally good practice. If the detector did not see it, the
report does not claim it, and says so explicitly in `not_checked_at_runtime`.
"""
import argparse, collections, json, re, subprocess, sys

KS_NS = "honey"

# Ports that mean "this is the data tier", used to tell a genuine tier skip from a
# frontend calling some external API — both surface as R0011 on tier=frontend.
DB_PORTS = {"5432","3306","27017","6379","9042","9200","8123","5984","8086","7687","26257","11211"}

# Runtime rules that can actually raise an alert. Rules with isTriggerAlert:false are
# evaluated by node-agent but never surface on their own, so an ADR must not depend on
# them. R0004 (capabilities) and R0007 (unexpected API use) are the notable casualties.
SILENT_RULES = {
    "R0004": "Linux Capabilities Anomalies — isTriggerAlert:false, never alerts on its own",
    "R0007": "Workload uses Kubernetes API unexpectedly — isTriggerAlert:false",
    "R1009": "Crypto Mining Related Port Communication — isTriggerAlert:false",
    "R1016": "Signed profile tampered — isTriggerAlert:false",
}

# (rule, tier) -> ADR. tier None means the mapping holds for any tier.
ADR_MAP = {
    ("R0011", "frontend"):    ("ADR-0001", "the presentation tier reached the data tier directly",
                               "route the query through the service labelled tier=backend on 8080/8000/3000"),
    ("R0012", "database"):    ("ADR-0001", "the data tier accepted a connection from outside the application tier",
                               "route the query through the service labelled tier=backend"),
    ("R0011", "database"):    ("ADR-0002", "the data tier initiated an outbound connection",
                               "remove the outbound call; if a database genuinely needs egress, it belongs in a sidecar or job labelled tier=backend"),
    ("R0011", "middleware"):  ("ADR-0002", "the broker reached outside its tier",
                               "check for plugin downloads at startup; bake them into the image"),
    ("R0012", "backend"):     ("ADR-0001", "the application tier was called by something other than the presentation tier",
                               "identify the caller; if it is legitimate give it tier=frontend, otherwise remove it"),
    ("R0011", "backend"):     ("ADR-0001", "the application tier reached an undeclared endpoint",
                               "declare the dependency in the backend profile egress, or drop it"),
    ("R0011", "unclassified"):("ADR-0005", "an unclassified workload made network calls",
                               "label the workload with app.kubernetes.io/tier so it gets a real profile"),
    ("R0012", "unclassified"):("ADR-0005", "an unclassified workload accepted a connection",
                               "label the workload with app.kubernetes.io/tier"),
    ("R0006", None):          ("ADR-0003", "the workload read its Kubernetes ServiceAccount token",
                               "set automountServiceAccountToken: false on the pod spec"),
    ("R0001", None):          ("ADR-0004", "a process ran that is not part of the image's declared behaviour",
                               "if it is a package manager or fetch tool, move the work into the image build"),
    ("R0010", None):          ("ADR-0003", "a sensitive file was read",
                               "no application tier has a legitimate reason to read this path"),
    ("R0005", None):          ("ADR-0004", "a DNS lookup was made for a name outside the learned set",
                               "declare the dependency explicitly, or remove it"),
}

# kubescape control -> ADR, for the checks runtime cannot make.
CONTROL_MAP = {
    "C-0034": ("ADR-0003", "automountServiceAccountToken left at its default"),
    "C-0013": ("ADR-0006", "container may run as root"),
    "C-0017": ("ADR-0006", "root filesystem is writable"),
    "C-0016": ("ADR-0006", "privilege escalation is permitted"),
    "C-0046": ("ADR-0006", "insecure capabilities requested"),
    "C-0038": ("ADR-0006", "host PID/IPC namespace shared"),
    "C-0041": ("ADR-0006", "host network access"),
}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def runtime_findings(ns, alerts):
    """Map alertmanager alerts for this namespace onto ADRs.

    Alertmanager, not `kubectl logs`. Scraping node-agent stdout looks equivalent and
    is not: the log window slides, node-agent restarts truncate it, and a multi-node
    DaemonSet splits the evidence across pods. Verified the hard way — a log-scraping
    version of this function silently missed every R0006 in the namespace while
    alertmanager held three of them.
    """
    pods = {}
    for line in sh(
        f"kubectl -n {ns} get pods -o jsonpath="
        "'{range .items[*]}{.status.podIP}{\" \"}{.metadata.name}{\" \"}"
        "{.metadata.labels.app\\.kubernetes\\.io/tier}{\"\\n\"}{end}'"
    ).splitlines():
        p = line.split()
        if len(p) == 3:
            pods[p[0]] = {"pod": p[1], "tier": p[2]}

    seen, out = set(), []
    for a in alerts:
        l = a.get("labels", {})
        if l.get("namespace") != ns:
            continue
        rid = l.get("rule_id")
        pod = l.get("pod_name", "")
        tier = None
        for meta in pods.values():
            if meta["pod"] == pod:
                tier = meta["tier"]
        # The human-readable event text lives in annotations; labels carry the structure.
        ann = a.get("annotations", {}) or {}
        msg = ann.get("message") or ann.get("description") or l.get("rule_name", "")
        key = (rid, pod, msg)
        if key in seen:
            continue
        seen.add(key)
        adr = ADR_MAP.get((rid, tier)) or ADR_MAP.get((rid, None))
        if not adr:
            continue
        # Refine on the actual peer. (rule, tier) alone cannot tell "the frontend
        # queried Postgres" from "the frontend called an external API" — both are
        # R0011 on tier=frontend, but they break different decisions and have
        # different fixes. Handing an agent the wrong fix is worse than silence.
        if rid == "R0011":
            dst, dport = peer_of(msg)
            in_cluster = dst in pods
            # ADR-0002 already says the data tier must not initiate egress AT ALL, so
            # for those tiers the destination is irrelevant and the mapping stands.
            if not in_cluster and tier not in ("database", "middleware"):
                adr = ("ADR-0004",
                       f"{tier or 'workload'} reached an endpoint outside the cluster "
                       f"that its profile does not declare",
                       "declare the dependency in the tier profile egress, or remove "
                       "the call; an external endpoint reached at runtime that is not "
                       "in the image's declared behaviour is an undeclared dependency")
            elif tier == "frontend" and dport in DB_PORTS:
                pass  # genuine tier skip — keep the ADR-0001 mapping
        out.append({
            "adr": adr[0], "decision_broken": adr[1], "fix": adr[2],
            "source": "runtime", "rule": rid, "rule_name": l.get("rule_name"),
            "evidence_class": "observed", "severity": l.get("severity"),
            "workload": pod, "container": l.get("container_name"),
            "tier": tier, "node": l.get("node_name"),
            "process": l.get("comm"), "pid": l.get("pid"),
            "observed": msg,
            "timestamp": a.get("startsAt"),
        })
    return out, pods


def get_alerts(port):
    """Read alertmanager through a port-forward the caller has already established."""
    import urllib.request
    try:
        return json.load(urllib.request.urlopen(
            f"http://localhost:{port}/api/v2/alerts", timeout=15))
    except Exception as e:
        print(f"could not reach alertmanager on :{port} — {e}", file=sys.stderr)
        print("start one with: kubectl -n honey port-forward svc/alertmanager 9093:9093",
              file=sys.stderr)
        return []


PEER_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")


def peer_of(msg):
    """The address:port the event names. Both R0011 and R0012 messages carry exactly one."""
    m = PEER_RE.search(msg or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def corroborate(findings, pods):
    """Pair each R0011 with the R0012 that saw *the same flow*, and collapse the pair.

    Correctness matters more here than anywhere else in this file: a finding labelled
    CORROBORATED is the one an agent will act on first. Matching must be on the actual
    peer address, not merely "my IP appears somewhere in their message" — that looser
    test paired an unrelated frontend->1.1.1.1:80 egress with a frontend->database
    ingress purely because both mentioned the frontend's IP.

    A confirmed pair becomes ONE finding carrying both ends, not two findings saying
    the same thing from opposite directions.
    """
    ip_of = {m["pod"]: ip for ip, m in pods.items()}
    dropped = set()
    for f in findings:
        if f.get("rule") != "R0011" or id(f) in dropped:
            continue
        f_ip = ip_of.get(f.get("workload") or "")
        dst_ip, dst_port = peer_of(f["observed"])
        if not (f_ip and dst_ip):
            continue
        for g in findings:
            if g.get("rule") != "R0012" or id(g) in dropped:
                continue
            g_ip = ip_of.get(g.get("workload") or "")
            src_ip, _ = peer_of(g["observed"])
            # the sender's destination must BE the receiver, and the receiver must
            # name the sender as its source
            if g_ip == dst_ip and src_ip == f_ip:
                f["corroborated_by"] = {
                    "rule": "R0012", "workload": g["workload"],
                    "container": g.get("container"), "observed": g["observed"],
                    "node": g.get("node"),
                }
                f["confidence"] = "both endpoints observed"
                f["flow"] = f"{f_ip} -> {dst_ip}:{dst_port}"
                dropped.add(id(g))
                break
    return [f for f in findings if id(f) not in dropped]


def dedupe(findings):
    """One finding per (decision, container, peer). Repeats of the same flow are noise."""
    out, seen = [], set()
    for f in findings:
        ip, port = peer_of(f.get("observed", ""))
        key = (f["adr"], f.get("rule"), f.get("container"), ip, port)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def compliance_findings(path, ns):
    """Static controls, COLLAPSED to one entry per control.

    A control that fails on all five workloads is one defect with five instances, not
    five findings. Emitting it per-workload is how a report turns into the generic
    checklist nobody acts on — the same three rows repeated until the observed
    violations are off the top of the screen.
    """
    try:
        data = json.load(open(path))
    except Exception:
        return [], "scan file not readable — compliance section skipped"
    grouped = collections.defaultdict(lambda: {"resources": set()})
    results = data if isinstance(data, list) else data.get("results", [])
    for r in results:
        rid = r.get("resourceID", "")
        if f"/{ns}/" not in rid and ns not in rid:
            continue
        for c in r.get("controls", []):
            cid = c.get("controlID")
            if c.get("status", {}).get("status") != "failed":
                continue
            m = CONTROL_MAP.get(cid)
            if not m:
                continue
            g = grouped[cid]
            g["adr"], g["decision_broken"] = m[0], m[1]
            g["control_name"] = c.get("name", "")
            g["resources"].add(rid.split("/")[-1])
    out = []
    for cid, g in grouped.items():
        res = sorted(g["resources"])
        out.append({
            "adr": g["adr"], "decision_broken": g["decision_broken"],
            "source": "static", "control": cid,
            "evidence_class": "declared",
            "observed": f"{cid} ({g['control_name']}) fails on {len(res)} workloads: {', '.join(res)}",
            "affected": res,
            "fix": g["control_name"],
        })
    return out, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("namespace")
    ap.add_argument("--port", default="9093", help="alertmanager port-forward")
    ap.add_argument("--scan", default="/tmp/nsa.json")
    ap.add_argument("--json")
    a = ap.parse_args()
    a.since = "alertmanager retention"

    rt, pods = runtime_findings(a.namespace, get_alerts(a.port))
    rt = dedupe(corroborate(rt, pods))
    st, scan_note = compliance_findings(a.scan, a.namespace)

    # Rank by what the evidence actually is. An agent should spend its first edit on
    # something that demonstrably happened, not on a field the manifest left at default.
    rt.sort(key=lambda f: (0 if f.get("corroborated_by") else 1, f["adr"]))

    report = {
        "namespace": a.namespace,
        "window": a.since,
        "workloads": [{"pod": m["pod"], "ip": ip, "tier": m["tier"]} for ip, m in pods.items()],
        "act_on_these_first": rt,
        "manifest_defects": sorted(st, key=lambda f: f["adr"]),
        "not_checked_at_runtime": [
            {"rule": k, "why": v} for k, v in SILENT_RULES.items()
        ],
        "how_to_read_this": {
            "observed": "the detector saw this happen. The evidence field is the actual "
                        "event: container, peer address, port, path. Fix these first — "
                        "they are proven, and re-running the review proves the fix.",
            "declared": "nothing was observed. The manifest permits it, which is worth "
                        "fixing but is not evidence that it occurred. Collapsed to one "
                        "entry per control.",
        },
    }
    if scan_note:
        report["compliance_note"] = scan_note

    if a.json:
        json.dump(report, open(a.json, "w"), indent=2)
        print(f"wrote {a.json}")

    print(f"\n╔══ architecture review: {a.namespace} ══╗")
    print(f"   {len(pods)} workloads · {len(rt)} observed · {len(st)} manifest-only "
          f"· window {a.since}\n")

    print("═══ OBSERVED — the detector saw these happen " + "═" * 26)
    if not rt:
        print("\n   Nothing observed in this window.")
        print("   This is NOT a pass. Either the app was not exercised, or the")
        print("   containers are younger than the profile warm-up: network rules")
        print("   were measured silent below ~90s of pod age, partial at ~150s,")
        print("   and reliable from ~206s. File rules (R0002) fire earlier, so")
        print("   'file findings but no network findings' means TOO SOON, not clean.")
        print("   Let the workload reach ~4 minutes, drive it, then re-run.\n")
    for f in rt:
        conf = "CORROBORATED" if f.get("corroborated_by") else "single observation"
        print(f"\n   {f['adr']}  [{conf}]")
        print(f"     broke      {f['decision_broken']}")
        print(f"     evidence   [{f['rule']}] {f.get('container')}: {f['observed']}")
        if f.get("corroborated_by"):
            c = f["corroborated_by"]
            print(f"     confirmed  [{c['rule']}] {c['workload']}: {c['observed']}")
        print(f"     fix        {f['fix']}")

    print(f"\n\n═══ MANIFEST-ONLY — permitted, but not observed " + "═" * 23)
    print("   Lower priority: these are properties of the YAML, not events.\n")
    for f in sorted(st, key=lambda x: x["adr"]):
        print(f"   {f['adr']}  [{f['control']}] {f['decision_broken']}")
        print(f"            {len(f['affected'])} workloads: {', '.join(f['affected'])}")

    print("\n\n═══ BLIND SPOTS — cannot be observed in this configuration " + "═" * 11)
    for k, v in SILENT_RULES.items():
        print(f"   {k}  {v}")
    print()


if __name__ == "__main__":
    main()
