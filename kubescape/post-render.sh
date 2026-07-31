#!/usr/bin/env bash
# Helm post-renderer for the kubescape-operator chart. Two rewrites:
#
# 1. force node-agent networkStreamingEnabled=true (always)
#
#    The chart ANDs capabilities.networkEventsStreaming with cloud-submit
#    (templates/_common.tpl, "capabilities.gates"): submit is true only when
#    .Values.server is non-empty. On an on-prem stack with no backend the flag
#    therefore renders FALSE no matter what capabilities.networkEventsStreaming
#    says, which leaves the profile's inline network shape inert and makes
#    R0005 (DNS) and R0011 (egress) silently never fire.
#
# 2. mount the filesystem holding a non-stock runc (only when KS_RUNC_MNT is set)
#
#    node-agent's `host` volume is a NON-recursive bind of "/", so a runc on a
#    separate mount is invisible inside the container even with the correct
#    RUNTIME_PATH. The extra hostPath fixes that.
#
#    This cannot be done with --set. The chart ships nodeAgent.volumes as a
#    fully-populated list, so `--set nodeAgent.volumes[0]...` OVERWRITES the
#    first default entry rather than appending — that silently drops /profiles
#    and node-agent CrashLoops. The top-level `volumes` key does append, but it
#    is GLOBAL: it injects the mount into all six chart workloads (kubescape,
#    kubevuln, operator, both schedulers) when only node-agent needs it. So the
#    append is done here, against the rendered DaemonSet, where it can be
#    scoped precisely and needs no index arithmetic against chart internals.
#
# Rewriting the rendered manifest rather than patching the live object matters:
# a post-install patch only reaches node-agent if the DaemonSet is restarted,
# and node-agent must not be restarted on the laptop k3s. Rewriting here means
# the very first node-agent boot already has the correct config.
#
# See docs/portability-spec.md D7a.
set -euo pipefail

python3 -c '
import os, sys

MNT = os.environ.get("KS_RUNC_MNT", "").strip()
VOL = "ks-runc-fs"

stream = sys.stdin.read().replace(
    "\"networkStreamingEnabled\": false", "\"networkStreamingEnabled\": true")

# The default path — rewrite 1 only — is a plain string replace and must stay
# dependency-free: CI and every contributor go through here, and a missing
# PyYAML would otherwise break `make kubescape` for everyone to serve a
# laptop-only feature. yaml is imported below, after the opt-in is confirmed.
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

# Only the node-agent DaemonSet is round-tripped through the YAML parser; every
# other document is emitted byte-for-byte as helm rendered it. Re-serialising
# the whole stream would reflow block scalars such as the embedded config.json.
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
