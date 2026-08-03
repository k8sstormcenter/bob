#!/usr/bin/env python3
"""Fail if any profile ships an open whose FIRST segment is a wildcard.

A leading wildcard is not "a bit broad", it is total. "/*" matches /etc/shadow,
so cp.was_path_opened() returns true for it and every rule that gates on that
predicate — R0010, R1010, R1012 — silently stops firing. The profile still looks
healthy because R0001/R0006/R0008 do not consult it, so the failure shows up as
"three attacks missed" a long way from the cause.

This has now happened twice, on Argo CD and on Flux, both times because a learned
profile collapsed into "/*" and nothing rejected it. Anchored wildcards are fine
(/tmp/*, /proc/⋯/*): the discriminating prefix survives. Only a wildcard in the
first segment is fatal.

Run against shipped SBoBs and against tuner output before it is committed:
    scripts/check-no-overbroad.py example/**/sbobs/*.yaml results/best-profile.yaml
"""
import argparse
import glob
import sys

import yaml

WILDCARDS = {"*", "**", "⋯", "⋯⋯"}
PROFILE_KINDS = {"ContainerProfile", "ApplicationProfile"}


def leading_wildcard(path: str) -> bool:
    segments = [s for s in path.split("/") if s]
    return bool(segments) and segments[0] in WILDCARDS


def check(path: str):
    findings = []
    try:
        with open(path) as fh:
            docs = list(yaml.safe_load_all(fh))
    except Exception as exc:
        return [(path, "<unparseable>", str(exc))]
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") not in PROFILE_KINDS:
            continue
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        spec = doc.get("spec") or {}
        for open_entry in spec.get("opens") or []:
            p = open_entry.get("path", "")
            if leading_wildcard(p):
                findings.append((path, name, p))
        for container in spec.get("containers") or []:
            for open_entry in container.get("opens") or []:
                p = open_entry.get("path", "")
                if leading_wildcard(p):
                    findings.append((path, name, p))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", default=[])
    args = ap.parse_args()

    targets = args.files or sorted(
        set(glob.glob("example/**/sbobs/*.yaml", recursive=True))
        | set(glob.glob("example/**/cp-*.yaml", recursive=True))
    )
    if not targets:
        print("check-no-overbroad: no profiles found to check", file=sys.stderr)
        return 0

    findings = []
    for t in targets:
        findings.extend(check(t))

    for path, name, p in findings:
        print("OVER-BROAD %s [%s]: open path %r begins with a wildcard" % (path, name, p))

    print("check-no-overbroad: %d profile file(s) checked, %d violation(s)"
          % (len(targets), len(findings)))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
