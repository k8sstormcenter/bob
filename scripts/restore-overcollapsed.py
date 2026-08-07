#!/usr/bin/env python3
"""Put the originally-learned opens back wherever the tuner over-collapsed.

The tuner is allowed to remove paths, and it is allowed to widen a path into an
ANCHORED wildcard (/tmp/*, /proc/⋯/*) where the leading segments still
discriminate. It is never allowed to produce an open whose first segment is a
wildcard: "/*" matches /etc/shadow, which makes cp.was_path_opened() true and
silently kills R0010, R1010 and R1012.

When that happens the fix is not to re-tune, it is to put the originals back. The
raw learned profile is the ground truth for what the workload actually opened;
the collapsed form is a lossy summary of it.

    scripts/restore-overcollapsed.py --raw results/learned-profile-raw-<app>.yaml \
                                     --tuned results/best-profile.yaml
"""
import argparse
import sys

import yaml


WILDCARDS = {"*", "**", "⋯", "⋯⋯"}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def leading_wildcard(path: str) -> bool:
    segments = [s for s in path.split("/") if s]
    return bool(segments) and segments[0] in WILDCARDS


def load_profile(path: str):
    with open(path) as fh:
        docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
    if not docs:
        sys.exit("no YAML documents in %s" % path)
    return docs[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--tuned", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    raw = load_profile(args.raw)
    tuned = load_profile(args.tuned)

    raw_opens = (raw.get("spec") or {}).get("opens") or []
    tuned_opens = (tuned.get("spec") or {}).get("opens") or []

    offending = [o for o in tuned_opens if leading_wildcard(o.get("path", ""))]
    if not offending:
        print("restore-overcollapsed: no leading-wildcard opens in %s, nothing to do" % args.tuned)
        return 0

    bad_raw = [o for o in raw_opens if leading_wildcard(o.get("path", ""))]
    if bad_raw:
        sys.exit("the RAW profile also contains leading-wildcard opens (%s) — collapse happened "
                 "during learning, so there is nothing to restore. Raise openDynamicThreshold."
                 % ", ".join(sorted({o.get("path", "") for o in bad_raw})))

    kept = [o for o in tuned_opens if not leading_wildcard(o.get("path", ""))]
    have = {o.get("path") for o in kept}
    restored = [o for o in raw_opens if o.get("path") not in have]

    print("restore-overcollapsed: dropping %d over-broad open(s): %s"
          % (len(offending), ", ".join(sorted({o.get("path", "") for o in offending}))))
    print("restore-overcollapsed: restoring %d original open(s) from %s" % (len(restored), args.raw))

    merged = kept + restored
    merged.sort(key=lambda o: o.get("path", ""))
    tuned["spec"]["opens"] = merged

    if args.dry_run:
        print("restore-overcollapsed: --dry-run, %s not written" % args.tuned)
        return 0

    with open(args.tuned, "w") as fh:
        yaml.dump(tuned, fh, Dumper=NoAliasDumper, sort_keys=False,
                  width=4096, allow_unicode=True, default_flow_style=None)
    print("restore-overcollapsed: %s now has %d opens" % (args.tuned, len(merged)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
