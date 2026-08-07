#!/usr/bin/env python3
"""Emit a helm values overlay that adds one hostPath mount to node-agent.

node-agent's `host` volume is a NON-recursive bind of "/", so a runc binary on a
separate filesystem (a dedicated /mnt partition, say) is invisible to it even
though the path exists on the node. Fanotify then marks nothing and node-agent
never sees a container start, which shows up as "no ContainerProfile was ever
written" rather than as an error.

The chart exposes nodeAgent.volumes and nodeAgent.volumeMounts, but they are the
COMPLETE lists rather than append-only hooks, and helm replaces lists wholesale.
So the overlay has to restate the chart's own entries alongside the new one; this
reads them straight from `helm show values` at the pinned chart version so they
cannot drift from whatever chart is actually being installed.

This exists so the mount can be applied with a plain `-f`, which behaves
identically under helm 3 and helm 4 — unlike --post-renderer, whose plugin/path
handling differs between them.
"""
import argparse
import json
import subprocess
import sys

import yaml


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chart", default="kubescape/kubescape-operator")
    ap.add_argument("--version", required=True)
    ap.add_argument("--mount", required=True)
    ap.add_argument("--name", default="ks-runc-fs")
    ap.add_argument("-o", "--output", default="-")
    args = ap.parse_args()

    if not args.mount.startswith("/"):
        sys.exit("--mount must be an absolute path on the node, got %r" % args.mount)

    proc = subprocess.run(
        ["helm", "show", "values", args.chart, "--version", args.version],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.exit("helm show values failed: %s" % proc.stderr.strip())

    values = yaml.safe_load(proc.stdout) or {}
    node_agent = values.get("nodeAgent") or {}
    volumes = list(node_agent.get("volumes") or [])
    mounts = list(node_agent.get("volumeMounts") or [])
    if not volumes or not mounts:
        sys.exit("chart %s@%s exposes no nodeAgent volumes to extend" % (args.chart, args.version))

    host_path = "/host" + args.mount
    volumes = [v for v in volumes if v.get("name") != args.name]
    mounts = [m for m in mounts if m.get("name") != args.name]
    volumes.append({"name": args.name, "hostPath": {"path": args.mount, "type": "Directory"}})
    mounts.append({"name": args.name, "mountPath": host_path, "readOnly": True})

    overlay = {"nodeAgent": {"volumes": volumes, "volumeMounts": mounts}}
    text = yaml.safe_dump(overlay, sort_keys=False, width=4096, default_flow_style=None)

    if args.output == "-":
        sys.stdout.write(text)
    else:
        with open(args.output, "w") as fh:
            fh.write(text)
        print("wrote %s: mounts %s into node-agent at %s" % (args.output, args.mount, host_path),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
