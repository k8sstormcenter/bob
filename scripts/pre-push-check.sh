#!/usr/bin/env bash
# pre-push-check.sh — fast local mirror of what CI lint+test will run.
#
# Use it manually before `git push`, or install as a git pre-push hook:
#     ln -sf ../../scripts/pre-push-check.sh .git/hooks/pre-push
#     ln -sf ../../../scripts/pre-push-check.sh pkg/.git/hooks/pre-push
#
# Tests run from the pkg submodule directory (where the Go module lives).
# Catches the failure modes that have repeatedly broken CI in the past:
#   - rule-name typos in attack/functional YAML files
#   - missing detection expectations on canonical-sensitive payloads
#   - exec-arg drift between functional and attack suites
#   - lint regressions (gocritic, staticcheck, unparam)
#
# Run time: ~2-3 minutes (mostly the autotune test suite's sleep-based tests).
# Skip via `git push --no-verify` if you ABSOLUTELY know what you're doing.
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
# scripts/ always lives at the outer-bob repo root.
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LINTER="${LINTER:-/mnt/dev-data/bin/golangci-lint}"
if [ ! -x "$LINTER" ]; then
  LINTER="$(command -v golangci-lint || true)"
fi
if [ -z "$LINTER" ] || [ ! -x "$LINTER" ]; then
  echo "ERROR: golangci-lint not found. Install with:" >&2
  echo "  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b /mnt/dev-data/bin v2.12.2" >&2
  exit 1
fi

cd "$REPO_ROOT/pkg"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

echo "═══ pre-push-check ═══"
echo "Repo:   $REPO_ROOT"
echo "Linter: $LINTER ($($LINTER version 2>&1 | head -1))"
echo

FAIL=0

echo "── Step 1: go build ./... ─────────────────────────────────────"
if ! go build ./...; then
  red "BUILD FAILED"; FAIL=1
fi

echo
echo "── Step 2: golangci-lint ──────────────────────────────────────"
if ! "$LINTER" run --timeout=5m; then
  red "LINT FAILED"; FAIL=1
fi

echo
echo "── Step 3: go test (autotune component + rabbit-coverage) ─────"
# These are the tests that have repeatedly broken CI:
#   TestAttackSuite_*Consistency
#   TestRabbit_CoverageSweep_AllPatternsAcrossAllSuites
#   TestDenyList_*
if ! go test -count=1 -timeout 2m \
     -run "TestAttackSuite_|TestRabbit_CoverageSweep|TestDenyList_|TestScore_DetectionMonotonicity|TestCountFalsePositives" \
     ./pkg/autotune/... ./pkg/verify/...; then
  red "COMPONENT TESTS FAILED"; FAIL=1
fi

echo
if [ $FAIL -eq 0 ]; then
  green "═══ ALL CHECKS PASSED — safe to push ═══"
  exit 0
else
  red "═══ CHECKS FAILED — push BLOCKED ═══"
  echo
  yellow "Override with: git push --no-verify  (only if you genuinely know why CI would still be green)"
  exit 1
fi
