#!/usr/bin/env bash
# run.sh — discover and run every *_test.sh in this directory, tally
# results, exit nonzero if any file failed. This is the entry point for
# CI (`bash scripts/lib/test/run.sh`) and local dev.
#
# Each *_test.sh is self-contained: it sources test_helper.bash, runs
# assertions, prints "<name>: N passed, M failed", and exits 0/1.
# Tier-2 files that need yq self-skip (exit 0) when yq is absent.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

shopt -s nullglob
files=( *_test.sh )
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
  echo "run: no *_test.sh found"
  exit 0
fi

pass_files=0
fail_files=0
failed=()

echo "=== chain-pipeline test harness: ${#files[@]} files ==="
for f in "${files[@]}"; do
  echo "--- $f ---"
  if bash "$f"; then
    pass_files=$((pass_files+1))
  else
    fail_files=$((fail_files+1))
    failed+=("$f")
  fi
done

echo "==============================================="
echo "files: $pass_files ok, $fail_files failed"
if [[ $fail_files -gt 0 ]]; then
  printf '  FAILED: %s\n' "${failed[@]}"
  exit 1
fi
echo "ALL GREEN"
