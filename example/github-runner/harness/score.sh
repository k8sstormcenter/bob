#!/usr/bin/env bash
# Scores profiles offline against a dataset of recorded builds (layout: see README.md).
# FP  = attack-distinguishing alerts per clean build (target 0); FLOOR rules are reported apart.
# Detection = suite steps with at least one distinguishing alert, out of every step in the suite.
set -euo pipefail
G=$(cd "$(dirname "$0")/.." && pwd)
DS=${1:?dataset dir}
RUNNER=${RUNNER:-$G/deploy/arc-runner-runner.yaml}
DIND=${DIND:-$G/deploy/arc-runner-dind.yaml}
RULES=${RULES:-$G/rules/default-rules.yaml}
FLOOR=${FLOOR:-R0005,R0011}
SUITE=${SUITE:-$G/../github-runner-attacks.yaml}
B=${BOBCTL:-bobctl}
steps=$(grep -c '^  - name:' "$SUITE")
echo "runner=$RUNNER dind=$DIND rules=$RULES floor=$FLOOR"
printf "%-28s %-12s %13s %6s  %s\n" build role distinguishing floor rules
for d in "$DS"/builds/*/; do
  [ -d "$d/alerts" ] || continue
  b=$(basename "$d")
  role=$(python3 -I -c "import json,sys;m=json.load(open(sys.argv[1]));print(m.get('role') or m.get('kind') or '?')" "$d/meta.json" 2>/dev/null || echo '?')
  out=$($B replay --rules "$RULES" -p runner="$RUNNER" -p dind="$DIND" -a "$d/alerts" --floor "$FLOOR" --top 0)
  case "$role" in
  *attack*|*contrast*)
    echo "$out" | awk -v b="$b" -v n="$steps" '/^  [a-z]/ && /SEPARABLE/{s++} END{printf "%-28s detection %d / %d steps\n", b, s, n}' ;;
  *)
    echo "$out" | awk -v b="$b" -v r="$role" -v fl=",$FLOOR," '/^R[0-9]/ && $8>0 && index(fl, ","$1",")==0 {x=x" "$1"="$8} /still fires:/{printf "%-28s %-12s %13d %6d %s\n", b, r, $4, $6, x}' ;;
  esac
done
