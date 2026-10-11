#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Conformance half of the review: install the kubescape CLI if needed, scan the
# cluster, and leave a JSON file for review.py to turn into agent actions.
#
#   ./scan.sh                        scan flashy-product with AllControls
#   ./scan.sh <namespace>            scan another namespace
#   ./scan.sh <namespace> NSA        pick a different framework
#   ./scan.sh --cluster              whole cluster, no namespace filter
#
# Writes:  /tmp/<framework>-<ns>.json   (path echoed at the end)
#
# WHY AllControls BY DEFAULT: the narrower frameworks (NSA, MITRE, cis-*) each
# omit things the others catch. C-0012 "credentials in configuration files" — the
# control that finds a password sitting in a container's env — is not in NSA. Since
# review.py collapses the output by fix rather than by control, a broader scan costs
# the reader nothing and closes real gaps.
set -euo pipefail

NS="${1:-flashy-product}"
FRAMEWORK="${2:-AllControls}"

if [ "$NS" = "--cluster" ]; then
  NS_ARG=""
  OUT="/tmp/${FRAMEWORK}-cluster.json"
else
  NS_ARG="--include-namespaces $NS"
  OUT="/tmp/${FRAMEWORK}-${NS}.json"
fi

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

log "1/3 kubescape CLI"
export PATH="$PATH:$HOME/.kubescape/bin"
if ! command -v kubescape >/dev/null 2>&1; then
  echo "  installing…"
  curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
  export PATH="$PATH:$HOME/.kubescape/bin"
fi
kubescape version 2>&1 | head -1

log "2/3 scanning ${NS} with ${FRAMEWORK}"
# The scan reads live cluster objects, so it covers running pods and their
# controllers, not just files on disk. A "failed to get cloud provider" warning on a
# local cluster is expected — those controls are for managed control planes.
kubescape scan framework "$FRAMEWORK" $NS_ARG \
  --format json --output "$OUT" 2>&1 | tail -3

log "3/3 what came back"
python3 "$(dirname "$0")/scan-failures.py" "$OUT" --summary

cat <<EOS

Scan written to: $OUT

Turn it into actions an agent can apply:

  kubectl -n honey port-forward svc/alertmanager 9093:9093 &
  ./review.py ${NS} --scan ${OUT} --json verdict.json

Or explore the raw failures first:

  ./scan-failures.py ${OUT}                 # everything, grouped by fix
  ./scan-failures.py ${OUT} --sev High      # only the high-severity ones
  ./scan-failures.py ${OUT} --control C-0012

EOS
