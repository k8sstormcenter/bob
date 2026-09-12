#!/usr/bin/env bash
set -euo pipefail

python3 -c '
import os, sys

MNT = os.environ.get("KS_RUNC_MNT", "").strip()
VOL = "ks-runc-fs"

stream = sys.stdin.read()

if not MNT:
    sys.stdout.write(stream)
    sys.exit(0)

if not MNT.startswith("/"):
    sys.exit("post-render: KS_RUNC_MNT must be an absolute path, got %r" % MNT)

try:
    import yaml
except ImportError:
    sys.exit("post-render: KS_RUNC_MNT needs PyYAML (pip install pyyaml)")

def is_node_agent(doc):
    return (isinstance(doc, dict) and doc.get("kind") == "DaemonSet"
            and doc.get("metadata", {}).get("name") == "node-agent")

out, patched = [], 0
for chunk in stream.split("\n---\n"):
    try:
        doc = yaml.safe_load(chunk)
    except yaml.YAMLError:
        out.append(chunk); continue
    if not is_node_agent(doc):
        out.append(chunk); continue

    spec = doc["spec"]["template"]["spec"]
    vols = spec.setdefault("volumes", [])
    if not any(v.get("name") == VOL for v in vols):
        vols.append({"name": VOL,
                     "hostPath": {"path": MNT, "type": "Directory"}})
    for c in spec["containers"]:
        mounts = c.setdefault("volumeMounts", [])
        if not any(m.get("name") == VOL for m in mounts):
            mounts.append({"name": VOL, "mountPath": "/host" + MNT,
                           "readOnly": True})
    out.append(yaml.safe_dump(doc, default_flow_style=False, sort_keys=False))
    patched += 1

if patched != 1:
    sys.exit("post-render: expected exactly 1 node-agent DaemonSet, patched %d" % patched)

sys.stderr.write("post-render: mounted %s into node-agent at /host%s\n" % (MNT, MNT))
sys.stdout.write("\n---\n".join(out))
'
