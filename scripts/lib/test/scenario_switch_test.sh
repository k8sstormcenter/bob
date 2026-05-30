#!/usr/bin/env bash
# Tests for chain-scenario-switch.sh.
# The no-scenarios path is yq-free (runs everywhere). The apply/restart
# paths parse JSON via yq, so they're guarded with have_yq and skip
# locally when yq is absent (they run in CI).
source "$(dirname "${BASH_SOURCE[0]}")/test_helper.bash"
source "$LIB_DIR/chain-scenario-switch.sh"
set +e

have_yq() { command -v yq >/dev/null 2>&1; }

PODS=$'chain-backend\treplicaset-chain-backend\tbackend\tfalse'

# scenarios JSON (one object per line, as manifest_scenarios emits).
SCENARIOS='{"name":"A-vuln","apply":[],"restart":[]}
{"name":"B-distroless","apply":["backend-b.yaml"],"restart":["chain-frontend"]}'

# ── single-shot chain (no scenarios) → rc 2 (yq-free) ─────────────────
test_no_scenarios_returns_2() {
  install_mocks
  stub_manifest "log4j-poc" "$PODS" "" "" ""   # empty scenarios
  chain_scenario_switch "$FIXTURES/dummy.manifest.yaml" "anything" >/dev/null 2>&1
  assert_rc 2 $? "no-scenarios returns 2"
  assert_log_absent "rollout restart" "no restart attempted on single-shot chain"
}

# ── switch to scenario B → applies backend-b + restarts frontend ──────
test_switch_applies_and_restarts() {
  have_yq || { printf '  skip switch-applies-and-restarts (yq absent)\n'; return; }
  install_mocks
  stub_manifest "log4j-poc" "$PODS" "" "$SCENARIOS" ""
  chain_scenario_switch "$FIXTURES/dummy.manifest.yaml" "B-distroless" >/dev/null 2>&1
  assert_rc 0 $? "switch to B returns 0"
  assert_log_contains "apply -f $FIXTURES/backend-b.yaml" "applies scenario B manifest"
  assert_log_contains "-n log4j-poc rollout restart deploy/chain-frontend" "restarts frontend"
  assert_log_order "apply -f $FIXTURES/backend-b.yaml" "rollout restart deploy/chain-frontend" "apply precedes restart"
}

# ── scenario A has empty apply/restart → no-op, rc 0 ──────────────────
test_switch_empty_scenario() {
  have_yq || { printf '  skip switch-empty-scenario (yq absent)\n'; return; }
  install_mocks
  stub_manifest "log4j-poc" "$PODS" "" "$SCENARIOS" ""
  chain_scenario_switch "$FIXTURES/dummy.manifest.yaml" "A-vuln" >/dev/null 2>&1
  assert_rc 0 $? "empty scenario returns 0"
  assert_log_absent "rollout restart" "no restart for empty scenario"
}

# ── unknown scenario name → rc 1 ──────────────────────────────────────
test_unknown_scenario() {
  have_yq || { printf '  skip unknown-scenario (yq absent)\n'; return; }
  install_mocks
  stub_manifest "log4j-poc" "$PODS" "" "$SCENARIOS" ""
  chain_scenario_switch "$FIXTURES/dummy.manifest.yaml" "Z-nonexistent" >/dev/null 2>&1
  assert_rc 1 $? "unknown scenario returns 1"
}

test_no_scenarios_returns_2
test_switch_applies_and_restarts
test_switch_empty_scenario
test_unknown_scenario
finish
