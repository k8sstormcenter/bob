#!/usr/bin/env bash
# Run all Redis attacks sequentially.
# Usage: ./run-all.sh [--kubeconfig PATH] [--context CTX]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"

KUBECONFIG_FLAG=""
CONTEXT_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_FLAG="--kubeconfig $2"; shift 2;;
    --context)    CONTEXT_FLAG="--context $2"; shift 2;;
    *)            echo "Unknown arg: $1"; exit 1;;
  esac
done

PASS=0
FAIL=0
SKIP=0

for attack_file in "${SCRIPT_DIR}"/attack-*.yaml; do
  name="$(basename "${attack_file}" .yaml)"
  echo "=== Running ${name} ==="

  if bobctl attack run ${KUBECONFIG_FLAG} ${CONTEXT_FLAG} "${attack_file}" > "${RESULTS_DIR}/${name}.log" 2>&1; then
    echo "  PASS"
    PASS=$((PASS + 1))
  else
    rc=$?
    if [[ ${rc} -eq 2 ]]; then
      echo "  SKIP (sandbox blocked)"
      SKIP=$((SKIP + 1))
    else
      echo "  FAIL (exit ${rc})"
      FAIL=$((FAIL + 1))
    fi
  fi
done

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ==="
exit ${FAIL}
