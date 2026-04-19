#!/usr/bin/env python3
"""
Clean an ApplicationProfile YAML for kubectl apply.

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


def clean(p):
    p["apiVersion"] = "spdx.softwarecomposition.kubescape.io/v1beta1"
    p["kind"] = "ApplicationProfile"

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
