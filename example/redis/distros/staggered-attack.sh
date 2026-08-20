#!/usr/bin/env bash
# staggered-attack.sh — run each attack in an AttackSuite individually, in the
# suite's declared order, with a fixed sleep between fires so the resulting
# detections land on distinct, well-separated timestamps instead of one
# back-to-back burst.
#
# bobctl runs a whole --attack-suite back-to-back with no gap. This wrapper loads
# each attack on its own (the same target block + one attack, via yq) so the sleep
# can sit between fires without touching bobctl or the attack definitions — every
# attack is byte-identical to the suite, only the pacing changes.
#
# Usage:
#   ./staggered-attack.sh [SUITE] [NAMESPACE]
#
# Env:
#   ATTACK_INTERVAL  seconds to sleep between attacks (default 2) — toggles the
#                    temporal distance between fires.
#   BOBCTL           bobctl binary to invoke (default: bobctl on PATH).
set -euo pipefail

SUITE="${1:-attacks/redis-oss.yaml}"
NAMESPACE="${2:-redis}"
INTERVAL="${ATTACK_INTERVAL:-2}"
BOBCTL="${BOBCTL:-bobctl}"

n=$(yq '.attacks | length' "$SUITE")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "staggered-attack: $n attacks from $SUITE, ${INTERVAL}s between fires (ns=$NAMESPACE)"
for i in $(seq 0 $((n - 1))); do
  single="$work/attack-$i.yaml"
  yq ".attacks = [.attacks[$i]]" "$SUITE" > "$single"
  name=$(yq '.attacks[0].name' "$single")
  echo "### [$((i + 1))/$n] $name"
  "$BOBCTL" attack --attack-suite "$single" -n "$NAMESPACE" --format markdown
  if [ "$i" -lt "$((n - 1))" ]; then
    sleep "$INTERVAL"
  fi
done
