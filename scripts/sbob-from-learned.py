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
    """True when every segment is a wildcard, so the path anchors on nothing."""
    segs = [s for s in path.strip("/").split("/") if s != ""]
    return bool(segs) and all(s in WILDCARD_SEGMENTS for s in segs)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="src", required=True, help="learned profile as JSON")
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True, help="SBoB name = the bind-label value")
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--keep-syscalls", action="store_true")
    args = ap.parse_args()

    spec = json.loads(Path(args.src).read_text())["spec"]

    opens = spec.get("opens") or []
    for o in opens:
        o["path"] = normalise_rotating(o.get("path", ""))
    dropped = [o["path"] for o in opens if is_over_broad(o.get("path", ""))]
    kept = [o for o in opens if not is_over_broad(o.get("path", ""))]

    # Deduplicate execs by (path, args) — a learned profile repeats an exec once
    # per distinct invocation, which is noise in a shipped artifact.
    seen, execs = set(), []
    for e in spec.get("execs") or []:
        key = (e.get("path"), tuple(e.get("args") or []))
        if key not in seen:
            seen.add(key)
            execs.append(e)

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
    Path(args.out).write_text(yaml.safe_dump(out, sort_keys=False, width=200, allow_unicode=True))

    print(f"{args.out}: execs={len(execs)} opens={len(kept)} "
          f"egress={len(spec.get('egress') or [])}")
    if dropped:
        print(f"  dropped {len(dropped)} over-broad open(s): {', '.join(sorted(set(dropped)))}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
