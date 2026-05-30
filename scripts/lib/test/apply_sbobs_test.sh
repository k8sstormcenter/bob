#!/usr/bin/env bash
# Tier-1 orchestration tests for chain-apply-sbobs.sh.
# Hermetic: mocked kubectl + stubbed manifest accessors. No yq/cluster.
source "$(dirname "${BASH_SOURCE[0]}")/test_helper.bash"
source "$LIB_DIR/chain-apply-sbobs.sh"
set +e   # the sourced lib enables `set -e`; tests deliberately exercise nonzero returns

PODS=$'chain-backend\treplicaset-chain-backend\tbackend\tfalse\nchain-frontend\treplicaset-chain-frontend\tnginx\tfalse'

# ── happy path: applies both pods, delete precedes apply (D4) ──────────
test_happy_path() {
  install_mocks
  stub_manifest "log4j-poc" "$PODS" "" "" ""
  chain_apply_sbobs "$FIXTURES/dummy.manifest.yaml" "$FIXTURES/sbobs" >/dev/null 2>&1
  assert_rc 0 $? "happy path returns 0"

  assert_log_contains "delete applicationprofile chain-backend -n log4j-poc --ignore-not-found" "deletes backend AP first"
  assert_log_contains "apply -n log4j-poc -f $FIXTURES/sbobs/ap-chain-backend.yaml" "applies backend AP"
  # The D4 guarantee: every delete happens before any apply.
  assert_log_order "delete applicationprofile chain-backend" "apply -n log4j-poc -f $FIXTURES/sbobs/ap-chain-backend.yaml" "delete precedes apply (D4)"
  assert_log_order "delete networkneighborhood chain-frontend" "apply -n log4j-poc -f $FIXTURES/sbobs/nn-chain-frontend.yaml" "NN delete precedes NN apply"
  # managed-by verification queried for each pod.
  assert_log_contains "get applicationprofile chain-backend -n log4j-poc" "verifies managed-by on backend"
}

# ── managed-by != User aborts (webhook/strip detection) ───────────────
test_managed_by_strip_detected() {
  install_mocks
  export MOCK_MANAGED_BY="Learning"   # simulate node-agent reclaiming it
  stub_manifest "log4j-poc" "$PODS" "" "" ""
  chain_apply_sbobs "$FIXTURES/dummy.manifest.yaml" "$FIXTURES/sbobs" >/dev/null 2>&1
  assert_rc 1 $? "managed-by!=User returns 1"
  unset MOCK_MANAGED_BY
}

# ── missing sbob file aborts BEFORE any kubectl delete/apply ───────────
test_missing_file_aborts_clean() {
  install_mocks
  # Add a third pod whose ap/nn fixtures don't exist.
  local pods="$PODS"$'\nchain-observer\treplicaset-chain-observer\tobserver\ttrue'
  stub_manifest "log4j-poc" "$pods" "" "" ""
  chain_apply_sbobs "$FIXTURES/dummy.manifest.yaml" "$FIXTURES/sbobs" >/dev/null 2>&1
  assert_rc 1 $? "missing file returns 1"
  # Critical: nothing was deleted/applied — fail fast, no partial state.
  assert_log_absent "delete applicationprofile" "no delete on missing-file abort"
  assert_log_absent "apply -n log4j-poc -f" "no apply on missing-file abort"
}

# ── nonexistent sbob_dir returns 2 ────────────────────────────────────
test_bad_sbob_dir() {
  install_mocks
  stub_manifest "log4j-poc" "$PODS" "" "" ""
  chain_apply_sbobs "$FIXTURES/dummy.manifest.yaml" "/no/such/dir" >/dev/null 2>&1
  assert_rc 2 $? "missing sbob_dir returns 2"
}

# ── cache-flush wait calls sleep with the right duration ──────────────
test_cache_flush_wait() {
  install_mocks
  chain_apply_sbobs_wait_for_cache_flush 30 >/dev/null 2>&1
  assert_sleep_contains "30" "default wait sleeps 30s"
  chain_apply_sbobs_wait_for_cache_flush 5 >/dev/null 2>&1
  assert_sleep_contains "5" "override wait sleeps 5s"
}

test_happy_path
test_managed_by_strip_detected
test_missing_file_aborts_clean
test_bad_sbob_dir
test_cache_flush_wait
finish
