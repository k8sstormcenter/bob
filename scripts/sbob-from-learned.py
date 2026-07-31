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
import sys
from pathlib import Path

import yaml

WILDCARD_SEGMENTS = {"*", "**", "⋯", "⋯⋯"}


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
            "rulePolicies": spec.get("rulePolicies") or {},
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
