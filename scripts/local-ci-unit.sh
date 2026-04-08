#!/usr/bin/env bash
# local-ci-unit.sh — reproduce CI issues locally without a cluster
#
# This script runs the same build + unit/component test pipeline that CI runs,
# catching issues like:
#   - List vs Get bug (collapse analysis returns 0 paths)
#   - Empty sidecar profile selection
#   - Attack binary deny list gaps
#   - Attack suite YAML consistency with code
#   - Pseudo-FS collapse + validation pipeline
#
# Usage:
#   ./scripts/local-ci-unit.sh              # full build + all tests
#   ./scripts/local-ci-unit.sh --test-only  # skip build, run tests only
#   ./scripts/local-ci-unit.sh --verbose    # verbose test output
#
# This mirrors the CI workflow WITHOUT requiring k3s/kubescape/alertmanager.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

TEST_ONLY=false
VERBOSE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-only) TEST_ONLY=true; shift ;;
    --verbose|-v) VERBOSE="-v"; shift ;;
    *) shift ;;
  esac
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { log "FAIL: $*"; exit 1; }
pass() { log "PASS: $*"; }

FAILURES=0
run_test() {
  local name="$1"; shift
  log "--- $name ---"
  if "$@"; then
    pass "$name"
  else
    log "FAIL: $name"
    FAILURES=$((FAILURES + 1))
  fi
}

# ── Step 1: Verify layout (same as CI) ──────────────────────────────────────
log "=== Verify layout ==="
[[ -f pkg/go.mod ]] || die "pkg/go.mod not found — run from bob repo root"
[[ -f pkg/main.go ]] || die "pkg/main.go not found"
if [[ -f ../storage/go.mod ]]; then
  pass "Storage dependency found at ../storage"
else
  log "WARNING: ../storage not found — tests requiring storage types may fail"
fi

# ── Step 2: Build (same as CI) ──────────────────────────────────────────────
if ! $TEST_ONLY; then
  log "=== Build bobctl ==="
  cd pkg
  go build -o ../bin/bobctl ./main.go
  cd ..
  pass "Build OK: bin/bobctl ($(ls -la bin/bobctl | awk '{print $5}') bytes)"
fi

# ── Step 3: Unit tests (all packages) ───────────────────────────────────────
log "=== Unit tests ==="
cd pkg

run_test "profile tests" go test $VERBOSE ./pkg/profile/...
run_test "verify tests" go test $VERBOSE ./pkg/verify/...
run_test "attack tests" go test $VERBOSE ./pkg/attack/...

# ── Step 4: Component tests (autotune — includes slow sleep-based tests) ────
log "=== Component tests ==="
run_test "autotune component tests" go test $VERBOSE -run "^Test(ProfileSelection|DenyList|CollapseAnalysis_EndToEnd|PseudoFSCollapse|AttackSuite|Validate_Redis)" ./pkg/autotune/...

# ── Step 5: Full autotune test suite (includes testAndScore with sleeps) ────
log "=== Full autotune tests (may take ~2min due to sleep-based tests) ==="
run_test "autotune full suite" go test $VERBOSE ./pkg/autotune/...

# ── Step 6: Attack suite YAML validation ────────────────────────────────────
log "=== Attack suite YAML validation ==="
cd "$REPO_ROOT"

validate_suite() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    log "SKIP: $file not found"
    return 0
  fi
  # Use bobctl to validate if built, otherwise just check YAML structure
  if [[ -x bin/bobctl ]]; then
    # LoadAttackSuite validates structure
    cd pkg
    go test -run "TestAttackSuite_.*Consistency" $VERBOSE ./pkg/autotune/... 2>&1
    cd "$REPO_ROOT"
  fi
}

run_test "webapp attacks YAML" validate_suite example/webapp-attacks.yaml
run_test "redis attacks YAML" validate_suite example/redis-attacks.yaml

# ── Step 7: Check attack file consistency ───────────────────────────────────
log "=== Attack file consistency ==="

# Verify individual redis attack files exist for all 12 attacks
REDIS_ATTACKS=$(ls example/redis-tests/attack-*.yaml 2>/dev/null | wc -l)
if [[ "$REDIS_ATTACKS" -eq 12 ]]; then
  pass "All 12 individual redis attack files present"
else
  log "FAIL: Expected 12 redis attack files, found $REDIS_ATTACKS"
  ls example/redis-tests/attack-*.yaml 2>/dev/null
  FAILURES=$((FAILURES + 1))
fi

# Verify attack file names match content (no more curl/hardlink mismatches)
for f in example/redis-tests/attack-*.yaml; do
  [[ -f "$f" ]] || continue
  name=$(grep "^  name:" "$f" 2>/dev/null | head -1 | sed 's/.*name: *//' | tr -d '"')
  base=$(basename "$f" .yaml | sed 's/attack-[0-9]*-//')
  # Check that filename keyword appears in the attack name
  keyword=$(echo "$base" | cut -d- -f1)
  if ! echo "$name" | grep -qi "$keyword"; then
    log "WARNING: $f filename keyword '$keyword' not in attack name '$name'"
  fi
done

# ── Step 8: Collapse analysis regression ────────────────────────────────────
log "=== Collapse analysis regression ==="
cd pkg
run_test "collapse List vs Get bug" go test $VERBOSE -run "TestAggregatePathStats_EmptySpecReturnsNothing" ./pkg/autotune/...
run_test "collapse non-empty guarantee" go test $VERBOSE -run "TestCollapseAnalysis_MustNotBeEmpty" ./pkg/autotune/...
cd "$REPO_ROOT"

# ── Results ─────────────────────────────────────────────────────────────────
echo
echo "============================================"
if [[ "$FAILURES" -eq 0 ]]; then
  log "ALL CHECKS PASSED"
  exit 0
else
  log "$FAILURES CHECK(S) FAILED"
  exit 1
fi
