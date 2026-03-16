#!/usr/bin/env bash
# Run all Redis attacks in parallel — one per agent/worker.
# Uses GNU parallel if available, otherwise xargs -P.
#
# Usage:
#   ./run-parallel.sh                    # all attacks, max parallelism
#   ./run-parallel.sh -j 4              # limit to 4 concurrent
#   ./run-parallel.sh attack-01 attack-05  # specific attacks only
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"

JOBS=0  # 0 = auto (nproc)
SPECIFIC=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -j)       JOBS="$2"; shift 2;;
    attack-*) SPECIFIC+=("${SCRIPT_DIR}/$1.yaml"); shift;;
    *)        echo "Unknown arg: $1"; exit 1;;
  esac
done

# Determine files to run
if [[ ${#SPECIFIC[@]} -gt 0 ]]; then
  FILES=("${SPECIFIC[@]}")
else
  FILES=("${SCRIPT_DIR}"/attack-*.yaml)
fi

run_one() {
  local f="$1"
  local name
  name="$(basename "$f" .yaml)"
  echo "[START] ${name}"
  if bobctl attack run "$f" > "${RESULTS_DIR}/${name}.log" 2>&1; then
    echo "[PASS]  ${name}"
  else
    echo "[FAIL]  ${name} (exit $?)"
  fi
}
export -f run_one

if command -v parallel &>/dev/null; then
  j_flag=""
  [[ ${JOBS} -gt 0 ]] && j_flag="-j ${JOBS}"
  printf '%s\n' "${FILES[@]}" | parallel ${j_flag} run_one
else
  j_flag="${JOBS}"
  [[ ${j_flag} -eq 0 ]] && j_flag="$(nproc)"
  printf '%s\n' "${FILES[@]}" | xargs -P "${j_flag}" -I{} bash -c 'run_one "$@"' _ {}
fi

# Summary
echo ""
echo "=== Results in ${RESULTS_DIR}/ ==="
PASS=$(grep -l "PASS\|Success" "${RESULTS_DIR}"/*.log 2>/dev/null | wc -l || echo 0)
TOTAL=${#FILES[@]}
echo "  ${PASS}/${TOTAL} attacks succeeded"
