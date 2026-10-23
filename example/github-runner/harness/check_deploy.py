#!/usr/bin/env python3
"""Guards for deploy/: what Flux applies must be bindable authored profiles.

- every file is a kustomization resource and every resource exists
- each ContainerProfile is authored (managed-by: User) and carries no kubescape.io/status
- no fragment labels: the agent binds one profile per container and composes nothing
- a multi-container workload has one profile per container (<label>-<container>), never the flat <label>
- no exec path whose basename is a wildcard, no exclusion comm the kernel cannot report
"""
import argparse, glob, os, sys
import yaml

MAX_COMM = 15


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("deploy")
    p.add_argument("--workload", action="append", default=[], help="LABEL=ctr1,ctr2: the user-defined-profile label value and its containers")
    a = p.parse_args()
    errs = []
    kust = yaml.safe_load(open(os.path.join(a.deploy, "kustomization.yaml")))
    res = set(kust.get("resources") or [])
    files = {os.path.basename(f) for f in glob.glob(os.path.join(a.deploy, "*.yaml"))} - {"kustomization.yaml"}
    errs += [f"{f}: not in kustomization resources" for f in sorted(files - res)]
    errs += [f"{r}: resource missing" for r in sorted(res - files)]
    names = set()
    for f in sorted(files & res):
        for d in yaml.safe_load_all(open(os.path.join(a.deploy, f))):
            if not d:
                continue
            md = d.get("metadata") or {}
            n = md.get("name", "?")
            names.add(n)
            ann, lab = md.get("annotations") or {}, md.get("labels") or {}
            if d.get("kind") != "ContainerProfile":
                continue
            if ann.get("kubescape.io/managed-by") != "User":
                errs.append(f"{n}: annotation kubescape.io/managed-by must be User")
            if "kubescape.io/status" in ann:
                errs.append(f"{n}: authored profile carries kubescape.io/status")
            errs += [f"{n}: fragment label {k}" for k in lab if k.startswith("kubescape.io/profile-fragment")]
            spec = d.get("spec") or {}
            for e in spec.get("execs") or []:
                base = (e.get("path") or "").rsplit("/", 1)[-1]
                if "⋯" in base or "*" in base:
                    errs.append(f"{n}: wildcard exec name {e.get('path')}")
            for rule, pol in (spec.get("rulePolicies") or {}).items():
                for c in pol.get("processAllowed") or []:
                    if not c or len(c) > MAX_COMM:
                        errs.append(f"{n}: {rule} processAllowed {c!r} can never match a kernel comm")
    for w in a.workload:
        label, ctrs = w.split("=", 1)
        if label in names:
            errs.append(f"{label}: flat profile for a multi-container workload; bind per container")
        errs += [f"{label}-{c}: missing" for c in ctrs.split(",") if f"{label}-{c}" not in names]
    for e in errs:
        print("FAIL", e)
    print(f"{len(names)} profiles checked, {len(errs)} problems")
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
