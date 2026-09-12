#!/usr/bin/env python3
"""
Clean a ContainerProfile YAML for kubectl apply.

Usage: clean-profile.py <input.yaml> <output.yaml>

- Adds apiVersion + kind (server-set in List/Get, required for apply)
- Strips volatile fields (resourceVersion, creationTimestamp, uid, generation, ...)
- Strips kubescape.io/ annotations (server-managed)
- Removes empty metadata maps (annotations, labels)
- Removes status (server-managed)
- Reorders top-level keys: apiVersion, kind, metadata, spec
"""
import sys
import yaml


VOLATILE_META = (
    "resourceVersion", "creationTimestamp", "uid", "generation",
    "ownerReferences", "managedFields", "selfLink", "generateName",
    "deletionTimestamp", "deletionGracePeriodSeconds", "finalizers",
)

KUBESCAPE_ANNOTATION_PREFIXES = (
    "kubescape.io/",
    "spdx.softwarecomposition.kubescape.io/",
)


# Mirrors declareRuncInitAllowed in pkg/autotune/tuner.go. The tuner writes this
# into the profile it emits, but local-ci rebuilds the shipped file from the
# per-iteration snapshot, which predates that step — so the last writer has to
# apply it too or the allowlist silently disappears from what actually ships.
RUNC_INIT_COMMS = ["runc:[1:INIT]", "runc:[1:CHILD]", "runc:[2:INIT]", "runc:[3:INIT]"]


def ensure_runc_init_allowed(spec):
    if not isinstance(spec, dict):
        return
    pol = spec.get("rulePolicies")
    if not isinstance(pol, dict):
        pol = {}
        spec["rulePolicies"] = pol
    for rule_id in ("R0002", "R0004"):
        entry = pol.get(rule_id)
        if not isinstance(entry, dict):
            entry = {}
            pol[rule_id] = entry
        allowed = entry.get("processAllowed")
        if not isinstance(allowed, list):
            allowed = []
            entry["processAllowed"] = allowed
        for comm in RUNC_INIT_COMMS:
            if comm not in allowed:
                allowed.append(comm)


def clean(p):
    p["apiVersion"] = "spdx.softwarecomposition.kubescape.io/v1beta1"
    # CP migration: the tuner emits ContainerProfiles (unified flat spec with
    # inline ingress/egress). This cleaner is spec-agnostic (it only scrubs
    # metadata), so preserve the input's kind and default to ContainerProfile.
    p["kind"] = p.get("kind") or "ContainerProfile"

    m = p.setdefault("metadata", {})
    for k in VOLATILE_META:
        m.pop(k, None)

    if isinstance(m.get("annotations"), dict):
        m["annotations"] = {
            k: v for k, v in m["annotations"].items()
            if not any(k.startswith(pref) for pref in KUBESCAPE_ANNOTATION_PREFIXES)
        }
        if not m["annotations"]:
            m.pop("annotations", None)

    if isinstance(m.get("labels"), dict):
        m["labels"] = {
            k: v for k, v in m["labels"].items()
            if not any(k.startswith(pref) for pref in KUBESCAPE_ANNOTATION_PREFIXES)
        }
        if not m["labels"]:
            m.pop("labels", None)

    p.pop("status", None)
    ensure_runc_init_allowed(p.get("spec"))

    return {k: p[k] for k in ("apiVersion", "kind", "metadata", "spec") if k in p}


def main():
    if len(sys.argv) != 3:
        print("Usage: clean-profile.py <input.yaml> <output.yaml>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        p = yaml.safe_load(f)

    cleaned = clean(p)

    with open(sys.argv[2], "w") as f:
        yaml.safe_dump(cleaned, f, default_flow_style=False, sort_keys=False)


if __name__ == "__main__":
    main()
