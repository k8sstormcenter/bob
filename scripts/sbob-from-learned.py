#!/usr/bin/env python3
"""Turn a learned ContainerProfile into a shippable SBoB.

Two things have to happen between "node-agent learned it" and "we ship it".

1. DROP over-broad opens. node-agent's own dynamic-path detector collapses
   high-churn directories, and under git-checkout churn it can collapse all the
   way to a bare `/*` — a path with no literal segment, which matches anything
   including /etc/shadow and the SA token. Shipping that blinds R0002 / R0006 /
   R0008 / R0010. It is dropped, not rewritten: an over-broad entry carries no
   information, so there is nothing to preserve. Losing it costs only that the
   paths underneath are no longer baseline, which is the correct posture.

2. Strip learned bookkeeping. A shipped SBoB carries one annotation
   (kubescape.io/managed-by: User) and no workload labels, status annotations or
   resourceVersion.

The output is clean YAML with no commentary — an SBoB is a policy artifact, and
narration hides the parts that were actually chosen.

    sbob-from-learned.py --in learned.json --out release/argocd/cp-repo-server.yaml \
        --name argocd-repo-server --namespace argocd
"""
import argparse
import json
import re
import sys
from pathlib import Path

import yaml


class NoAliasDumper(yaml.SafeDumper):
    """Never emit &id001/*id001 anchors.

    PyYAML back-references any value it sees twice BY IDENTITY. An SBoB is read
    at review time to see what a workload is allowed to do, and an alias hides
    the actual flags behind a pointer. Generators must also avoid sharing list
    objects between entries; this is the backstop for when they slip.
    """

    def ignore_aliases(self, data):
        return True


WILDCARD_SEGMENTS = {"*", "**", "⋯", "⋯⋯"}

# Kubernetes projected volumes (ServiceAccount tokens, ConfigMaps, Secrets) write
# each generation into a "..<timestamp>" directory and atomically re-point ..data
# at it. The timestamp changes on every rotation, so a literal path learned at
# training time stops matching and the workload's OWN token read starts firing
# R0002. Collapsing exactly that one segment to the single-segment wildcard keeps
# the rest of the path literal, so a read of some other secret is still anomalous.
ATOMIC_SWAP_DIR = re.compile(r"^\.\.\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}\.\d+$")


def normalise_rotating(path: str) -> str:
    segs = path.split("/")
    return "/".join("⋯" if ATOMIC_SWAP_DIR.match(s) else s for s in segs)


# The container-runtime init phase touches files and capabilities that no
# workload profile can predict, and it fires on every pod (re)start.
RUNC_INIT = ["runc:[1:INIT]", "runc:[1:CHILD]", "runc:[2:INIT]", "runc:[3:INIT]"]


def workload_comms(execs):
    """Kernel comm values for this container's own processes.

    comm comes from argv[0]'s basename and the kernel truncates it to 15 chars,
    so /usr/local/bin/argocd-application-controller is seen as
    "argocd-applicat" — the exec PATH basename ("argocd") would never match.
    """
    out = []
    for e in execs:
        argv = e.get("args") or []
        if not argv:
            continue
        c = str(argv[0]).split("/")[-1][:15]
        if c and c not in out:
            out.append(c)
    return out


def is_over_broad(path: str) -> bool:
    """True when the path cannot survive a round-trip through the storage API.

    Two distinct cases, and the second is not obvious:

    1. EVERY segment is a wildcard (`/*`). Anchored on nothing, matches
       /etc/shadow, blinds R0002/R0006/R0008/R0010.

    2. The FIRST segment is a wildcard (`/*/Chart.yaml`). This looks anchored —
       it has a literal segment — but it is fatal. storage's dynamic-path
       analyzer keys its trie on the root, and processSegment short-circuits on
       a wildcard child at the node it is walking:

           if wildcardChild, exists := node.Children[WildcardIdentifier]; exists {
               return wildcardChild
           }

       so a `*` in root position captures EVERY subsequent path, and
       processSegments then breaks out ("wildcard absorbs the rest"), emitting
       just `/*`. One such entry therefore annihilates the whole opens list on
       save — verified against the real analyzer: three paths, one of them
       `/*/Chart.yaml`, come back as a single `/*`, regardless of ordering.

       This is exactly how the argocd repo-server SBoB lost its opens. It
       shipped 255 entries, 74 with a leading wildcard and ZERO all-wildcard, so
       the old all-segments test found nothing to drop. Applied to a cluster, it
       stored 1 open: `/*`.
    """
    segs = [s for s in path.strip("/").split("/") if s != ""]
    if not segs:
        return False
    return segs[0] in WILDCARD_SEGMENTS or all(s in WILDCARD_SEGMENTS for s in segs)


def anchor_wildcards(dropped_paths, anchors):
    """Turn unanchored paths into anchored patterns on the workload's real roots.

    Dropping them is safe but expensive: every legitimate read underneath then
    fires R0002. The prefix cannot be recovered per-path — the collapse already
    destroyed it — so the caller supplies the roots the workload is known to
    write to (for argocd-repo-server these are the emptyDir volumeMounts in the
    Deployment: /tmp, /helm-working-dir, /app/config).

    An anchored `/tmp/*` keeps the same breadth under /tmp as the broken
    `/*/Chart.yaml` had, but its first segment is literal, so it cannot swallow
    the rest of the profile on save and it still does not match /etc/shadow.
    """
    flags = sorted({f for o in dropped_paths for f in (o.get("flags") or [])})
    # list(flags) per entry, NOT the shared object: PyYAML emits &id001/*id001
    # anchors for any value it sees twice by identity, which turns a policy file
    # into something nobody can read at review time.
    return [{"path": a.rstrip("/") + "/*", "flags": list(flags)} for a in anchors]


def collapse_exec_args(execs):
    """One entry per binary, args [argv0, ⋯⋯] (zero-or-more).

    Learned args pin values that can never recur — commit SHAs, checkout UUIDs,
    temp filenames, pod names — so the literal entry matches exactly once and is
    dead weight afterwards. A bare [path] is no better: CompareExecArgs shows it
    does NOT match an invocation that has arguments.
    """
    by = {}
    for e in execs:
        argv = e.get("args") or []
        by.setdefault(e["path"], argv[0] if argv else e["path"])
    return [{"path": p, "args": [a, "⋯⋯"]} for p, a in sorted(by.items())]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="src", required=True, help="learned profile as JSON")
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True, help="SBoB name = the bind-label value")
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--keep-syscalls", action="store_true")
    ap.add_argument("--anchor", action="append", default=[], metavar="PREFIX",
                    help="re-anchor unanchored opens onto PREFIX/* instead of "
                         "dropping them; repeatable (e.g. --anchor /tmp)")
    ap.add_argument("--collapse-dir", action="append", default=[], metavar="PREFIX",
                    help="pre-collapse everything under PREFIX to PREFIX/⋯, the "
                         "form storage would produce anyway; repeatable")
    args = ap.parse_args()

    spec = json.loads(Path(args.src).read_text())["spec"]

    opens = spec.get("opens") or []
    for o in opens:
        o["path"] = normalise_rotating(o.get("path", ""))
    bad = [o for o in opens if is_over_broad(o.get("path", ""))]
    kept = [o for o in opens if not is_over_broad(o.get("path", ""))]
    dropped = [o["path"] for o in bad]
    if bad and args.anchor:
        kept.extend(anchor_wildcards(bad, args.anchor))

    # Pre-collapse directories that exceed the analyzer's threshold, so the
    # committed file already equals what storage will store. Otherwise the file
    # and the enforced policy silently disagree.
    for pfx in args.collapse_dir:
        pfx = pfx.rstrip("/") + "/"
        under = [o for o in kept if o["path"].startswith(pfx)]
        if len(under) > 1:
            kept = [o for o in kept if not o["path"].startswith(pfx)]
            kept.append({"path": pfx + "⋯",
                         "flags": sorted({f for o in under for f in (o.get("flags") or [])})})

    # Deduplicate execs by (path, args) — a learned profile repeats an exec once
    # per distinct invocation, which is noise in a shipped artifact.
    seen, execs = set(), []
    for e in spec.get("execs") or []:
        key = (e.get("path"), tuple(e.get("args") or []))
        if key not in seen:
            seen.add(key)
            execs.append(e)
    execs = collapse_exec_args(execs)

    # R0006 is not satisfied by listing the token in `opens` — it is a separate
    # rule that has to name the process allowed to read a ServiceAccount token.
    # Without this a k8s-client workload trips R0006 on its OWN token every time.
    rule_policies = dict(spec.get("rulePolicies") or {})
    rule_policies.setdefault("R0002", {"processAllowed": list(RUNC_INIT)})
    rule_policies.setdefault("R0004", {"processAllowed": list(RUNC_INIT)})
    reads_token = any("serviceaccount" in (o.get("path") or "") for o in kept)
    comms = workload_comms(execs)
    if reads_token and comms:
        rule_policies.setdefault("R0006", {"processAllowed": comms})

    out = {
        "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
        "kind": "ContainerProfile",
        "metadata": {
            "name": args.name,
            "namespace": args.namespace,
            "annotations": {"kubescape.io/managed-by": "User"},
        },
        "spec": {
            "architectures": spec.get("architectures") or ["amd64"],
            "execs": execs,
            "opens": kept,
            "capabilities": spec.get("capabilities") or [],
            "endpoints": spec.get("endpoints") or [],
            "rulePolicies": rule_policies,
        },
    }
    if args.keep_syscalls and spec.get("syscalls"):
        out["spec"]["syscalls"] = spec["syscalls"]
    for k in ("matchLabels", "ingress", "egress"):
        if spec.get(k) is not None:
            out["spec"][k] = spec[k]

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    # Compact flow form — one entry per line. An SBoB is read as a policy
    # document; block style turns 50 entries into 200+ lines and buries the
    # paths among their flags.
    Path(args.out).write_text(yaml.dump(
        out, sort_keys=False, width=4096, allow_unicode=True,
        default_flow_style=None, Dumper=NoAliasDumper))

    print(f"{args.out}: execs={len(execs)} opens={len(kept)} "
          f"egress={len(spec.get('egress') or [])}")
    if dropped:
        print(f"  dropped {len(dropped)} over-broad open(s): {', '.join(sorted(set(dropped)))}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
