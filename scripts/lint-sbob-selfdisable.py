#!/usr/bin/env python3
"""Fail a ContainerProfile whose wildcard sits above a path a rule protects.

ADR-0007. A profile's `opens` list is an allowlist consulted by `cp.was_path_opened`,
and the matcher treats both `⋯` and `*` as wildcards:

    CompareDynamic("/etc/⋯",        "/etc/shadow") = true
    CompareDynamic("/*",            "/etc/shadow") = true
    CompareDynamic("/etc/hostname", "/etc/shadow") = false

So an entry written to mean "this app reads its config from /etc" also matches
/etc/shadow, which switches R0010 off for that container — silently, permanently,
and while the rule still reads `enabled: true`. The same mechanism turns R0006 off
via /var/run/⋯. The symptom is *fewer* alerts, which reads as success, so nothing
catches it downstream.

`bobctl validate` does not cover this: it rejects wildcards *inside* a segment
(which match nothing), not wildcards *above* a protected path (which match too much).

    ./scripts/lint-sbob-selfdisable.py                 # every SBoB under example/
    ./scripts/lint-sbob-selfdisable.py path/to/cp.yaml # specific files
    ./scripts/lint-sbob-selfdisable.py --list-protected

Exit 0 clean, 1 on any finding, 2 on usage error.
"""
import argparse
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

WILDCARDS = ("⋯", "*")

PROTECTED = {
    "R0006": [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    ],
    "R0010": [
        "/etc/shadow",
        "/etc/gshadow",
        "/root/.ssh/id_rsa",
        "/root/.kube/config",
        "/etc/kubernetes/admin.conf",
        "/var/lib/kubelet/config.yaml",
    ],
}


def segments(path):
    return [s for s in path.strip().split("/") if s]


def is_wildcard(seg):
    return any(w in seg for w in WILDCARDS)


def shadows(entry, protected):
    """True if `entry` (a profile path) can match `protected`.

    A wildcard segment stands for one or more segments, which is what makes
    CompareDynamic("/*", "/etc/shadow") true. Literal segments after a wildcard
    still have to match, so `.../serviceaccount/⋯/ca.crt` cannot reach `.../token`
    and an entry naming the protected file explicitly is an intentional allow
    rather than a wildcard swallowing it.
    """
    es = segments(entry)
    if not any(is_wildcard(s) for s in es):
        return False
    pattern = "".join(
        "/[^/]+(?:/[^/]+)*" if is_wildcard(s) else "/" + re.escape(s) for s in es
    )
    return re.fullmatch(pattern, "/" + "/".join(segments(protected))) is not None


def paths_of(spec, key):
    out = []
    for item in spec.get(key) or []:
        if isinstance(item, dict) and item.get("path"):
            out.append(item["path"])
    return out


def check(path):
    try:
        docs = [d for d in yaml.safe_load_all(open(path)) if d]
    except yaml.YAMLError as exc:
        return [(path, "-", "-", f"unparseable: {exc}")]
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        spec = doc.get("spec") or {}
        name = (doc.get("metadata") or {}).get("name", "?")
        for key in ("opens", "execs"):
            for entry in paths_of(spec, key):
                for rule, targets in PROTECTED.items():
                    for target in targets:
                        if shadows(entry, target):
                            findings.append((path, name, entry, f"{rule} disabled — also matches {target}"))
    return findings


def main():
    ap = argparse.ArgumentParser(description="ADR-0007 self-disabling wildcard lint")
    ap.add_argument("files", nargs="*", help="ContainerProfile YAML (default: example/**/sbobs/*.yaml)")
    ap.add_argument("--list-protected", action="store_true", help="print the protected paths and exit")
    args = ap.parse_args()

    if args.list_protected:
        for rule, targets in PROTECTED.items():
            for target in targets:
                print(f"{rule}\t{target}")
        return 0

    files = args.files or sorted(glob.glob("example/**/sbobs/*.yaml", recursive=True))
    if not files:
        print("no ContainerProfile files found", file=sys.stderr)
        return 2

    findings = []
    for path in files:
        if os.path.isfile(path):
            findings.extend(check(path))

    if not findings:
        print(f"ADR-0007 ok: {len(files)} profile(s), no wildcard above a protected path")
        return 0

    print(f"ADR-0007 VIOLATION: {len(findings)} entr(ies) in {len({f[0] for f in findings})} file(s)\n")
    for path, name, entry, why in findings:
        print(f"  {path}")
        print(f"    profile {name}: {entry}")
        print(f"    {why}\n")
    print("Replace the wildcard with the named files the workload actually opens.")
    print("The symptom of leaving it is FEWER alerts, so this cannot be caught downstream.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
