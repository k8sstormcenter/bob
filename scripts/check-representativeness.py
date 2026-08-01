#!/usr/bin/env python3
"""Check that a learned profile shows the workload actually doing its job.

The gap this closes (bob#170): nothing in the pipeline asked whether the learn
window was representative. A profile learned from an idle app is internally
consistent, tunes to score 0, and passes the contrast gate at 0 Blind — while
encoding "this app does nothing" as the definition of normal. Shipped, it then
flags the app's real work as anomalous.

So this asks the one question the other gates do not: did the workload DO its
primary function while node-agent was watching? The expected evidence per
component lives in kubescape/representativeness.yaml, deliberately expressed as
behaviour (which peers, which binaries) rather than size, because size does not
discriminate — 21 opens is correct for argocd-server and catastrophic for
repo-server.

Reads either committed SBoBs or live ContainerProfiles:

  check-representativeness.py --sbob-dir example/argocd/sbobs
  check-representativeness.py --namespace argocd            # live, via kubectl

Exit status is 1 if any component fails, so it can gate a pipeline.
"""
import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

import yaml


def is_public(ip):
    """True for a routable address outside the cluster (a real external dial)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast)


# Mirrors isOverBroadOpen / isWildcardSeg in pkg/pkg/contrast/baseline.go. Kept
# in sync deliberately: a path whose every segment is a wildcard is unanchored,
# so it matches /etc/shadow and makes R0010 Blind. An anchored wildcard like
# /proc/⋯/* is fine — one literal segment is enough to anchor it.
WILDCARD_SEGS = {"*", "**", "⋯", "⋯⋯"}


def is_over_broad_open(path):
    """Unanchored in either sense that matters.

    All-wildcard (`/*`) masks /etc/shadow. A LEADING wildcard (`/*/Chart.yaml`)
    looks anchored because it has a literal segment, but it is worse: storage's
    analyzer short-circuits on a wildcard child at the node it is walking, so a
    `*` in root position captures every subsequent path and the stored profile
    becomes a single `/*`. One such entry annihilates the whole opens list.
    """
    segs = [s for s in path.strip("/").split("/") if s != ""]
    if not segs:
        return False
    return segs[0] in WILDCARD_SEGS or all(s in WILDCARD_SEGS for s in segs)


def profile_facts(spec):
    """Reduce a ContainerProfile spec to the few things the gate reasons about."""
    egress = spec.get("egress") or []
    opens = spec.get("opens") or []
    return {
        "execs": [e.get("path", "") for e in (spec.get("execs") or [])],
        "opens": len(opens),
        "over_broad": [o.get("path", "") for o in opens
                       if is_over_broad_open(o.get("path", ""))],
        "ports": {p.get("name") for e in egress for p in (e.get("ports") or [])},
        "ips": {e.get("ipAddress") for e in egress if e.get("ipAddress")},
        "egress_count": len(egress),
    }


def check(name, rules, facts):
    """Return (failures, notes) for one component."""
    fails, notes = [], []

    for want in rules.get("execs_include") or []:
        if not any(want in p for p in facts["execs"]):
            fails.append(f"never executed {want} — the learn window did not "
                         f"exercise: {rules['function']}")

    want_ports = set(rules.get("egress_ports") or [])
    missing = want_ports - facts["ports"]
    if missing:
        fails.append(f"no egress on {', '.join(sorted(missing))} "
                     f"(saw {', '.join(sorted(facts['ports'])) or 'nothing'})")

    for ip in rules.get("egress_include_ips") or []:
        if ip not in facts["ips"]:
            fails.append(f"never reached {ip}")

    if rules.get("egress_public_ip"):
        pub = [i for i in facts["ips"] if is_public(i)]
        if not pub:
            fails.append("no egress to any public address — nothing was cloned "
                         "from outside the cluster")
        else:
            notes.append(f"public egress: {', '.join(sorted(pub))}")

    # Checked before the count, and it suppresses it: a profile collapsed to a
    # bare /* has few opens BECAUSE it is over-broad, not because the app idled.
    # Reporting "only 1 opens" there sends you to re-learn when the learn window
    # was fine and the collapsing is what broke.
    if facts["over_broad"]:
        ob = facts["over_broad"]
        shown = ", ".join(ob[:4]) + (f" (+{len(ob) - 4} more)" if len(ob) > 4 else "")
        leading = [p for p in ob if p.strip("/") and
                   p.strip("/").split("/")[0] in WILDCARD_SEGS
                   and not all(s in WILDCARD_SEGS for s in p.strip("/").split("/"))]
        if leading:
            fails.append(
                f"{len(ob)} over-broad open(s): {shown}. "
                f"{len(leading)} have a LEADING wildcard, which looks anchored but "
                "is fatal: storage's analyzer short-circuits on a wildcard child "
                "at the root, so ONE such entry absorbs every other path and the "
                "profile is stored as a single /*. Anchor them on their real "
                "prefix (repo-server writes under /tmp, /helm-working-dir and "
                "/app/config) or drop them")
        else:
            fails.append(
                f"{len(ob)} over-broad open(s): {shown} — anchored on nothing, so "
                "this masks /etc/shadow and makes R0010 Blind")
    else:
        floor = rules.get("opens_min")
        if floor is not None and facts["opens"] < floor:
            fails.append(f"only {facts['opens']} opens, expected >= {floor}")

    if rules.get("weak"):
        notes.append("gate is WEAK — see kubescape/representativeness.yaml")

    return fails, notes


def load_sbobs(d):
    out = {}
    for f in sorted(Path(d).glob("cp-*.yaml")):
        doc = yaml.safe_load(f.read_text())
        out[doc["metadata"]["name"]] = doc.get("spec", {})
    return out


CP = "containerprofiles.spdx.softwarecomposition.kubescape.io"


def _kubectl(args):
    try:
        return subprocess.run(["kubectl", *args], capture_output=True, text=True,
                              timeout=60, check=True).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def load_live(ns):
    """Pull ContainerProfiles from the cluster, one Get per profile.

    A List MUST NOT be used here. The storage API server strips spec contents
    from List responses as an optimization, so every profile comes back with
    zero opens/execs/egress — which this gate would read as "the app did
    nothing" and report as a representativeness failure on a perfectly good
    profile. The names come from a List; the contents only ever from a Get.
    """
    listing = _kubectl(["get", CP, "-n", ns, "-o",
                        "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}"])
    if not listing:
        print(f"error: cannot list ContainerProfiles in {ns}", file=sys.stderr)
        return {}

    out = {}
    for name in filter(None, (n.strip() for n in listing.splitlines())):
        raw = _kubectl(["get", CP, "-n", ns, name, "-o", "json"])
        if raw:
            out[name] = json.loads(raw).get("spec", {})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--sbob-dir", help="directory of committed cp-*.yaml SBoBs")
    src.add_argument("--namespace", help="read live ContainerProfiles from this namespace")
    ap.add_argument("--config", default="kubescape/representativeness.yaml")
    ap.add_argument("--match", help="only check components whose name contains this")
    args = ap.parse_args()

    config = yaml.safe_load(Path(args.config).read_text())
    profiles = load_sbobs(args.sbob_dir) if args.sbob_dir else load_live(args.namespace)
    if not profiles:
        print("no profiles found", file=sys.stderr)
        return 2

    failed = ok = skipped = 0
    saw_over_broad = saw_unrepresentative = False
    for name, rules in config.items():
        if args.match and args.match not in name:
            continue
        # Live profile names carry a workload prefix and hash; match loosely.
        spec = profiles.get(name) or next(
            (s for n, s in profiles.items() if name in n), None)
        if spec is None:
            print(f"SKIP  {name}\n        no profile found")
            skipped += 1
            continue

        facts = profile_facts(spec)
        if facts["over_broad"]:
            saw_over_broad = True
        fails, notes = check(name, rules, facts)
        if fails:
            saw_unrepresentative = saw_unrepresentative or not facts["over_broad"]
            print(f"FAIL  {name}")
            for f in fails:
                print(f"        {f}")
            failed += 1
        else:
            print(f"PASS  {name}")
            ok += 1
        for n in notes:
            print(f"        note: {n}")

    print(f"\n{ok} representative, {failed} not, {skipped} missing")
    # The two failure modes need opposite remedies, so do not give one blanket
    # instruction: re-learning an over-broad profile just reproduces it.
    if saw_unrepresentative:
        print("\nUNREPRESENTATIVE: the learn window did not exercise the primary"
              "\nfunction. Re-learn with the app actually working — for Argo CD,"
              "\nexample/argocd/drive-gitops-workload.sh drives real GitOps.")
    if saw_over_broad:
        print("\nOVER-BROAD: the learn window was fine; the paths lost their anchor."
              "\nRe-learning reproduces it. Anchor or drop them instead —"
              "\nscripts/sbob-from-learned.py now rejects both forms.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
