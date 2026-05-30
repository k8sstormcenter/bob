#!/usr/bin/env bash
# Tier-1 orchestration tests for chain-deploy.sh.
source "$(dirname "${BASH_SOURCE[0]}")/test_helper.bash"
source "$LIB_DIR/chain-deploy.sh"
set +e

PODS=$'chain-backend\treplicaset-chain-backend\tbackend\tfalse\nchain-postgres\treplicaset-chain-postgres\tpostgres\tfalse'

# Need real files for the deploy[] manifest paths (chain_deploy checks
# -f). Use the fixtures dir with two stand-in manifest files.
mkdir -p "$_TMP/deploydir"
echo 'kind: Namespace' > "$_TMP/deploydir/base.yaml"

# ── applies each deploy step + waits for matching deployments ──────────
test_applies_and_waits() {
  install_mocks
  local deploy=$'$_TMP/deploydir/base.yaml\tfalse'
  # expand $_TMP in the tsv
  deploy=$'\t'; deploy="$_TMP/deploydir/base.yaml"$'\tfalse'
  stub_manifest "log4j-poc" "$PODS" "$deploy" "" ""
  chain_deploy "$FIXTURES/dummy.manifest.yaml" >/dev/null 2>&1
  assert_rc 0 $? "deploy returns 0"
  assert_log_contains "apply -f $_TMP/deploydir/base.yaml" "applies the deploy step"
  assert_log_contains "rollout status deploy/chain-backend -n log4j-poc" "waits for backend rollout"
  assert_log_contains "rollout status deploy/chain-postgres -n log4j-poc" "waits for postgres rollout"
}

# ── required deploy file missing → abort rc=1, no rollout waits ────────
test_required_missing_aborts() {
  install_mocks
  local deploy="/no/such/required.yaml"$'\tfalse'
  stub_manifest "log4j-poc" "$PODS" "$deploy" "" ""
  chain_deploy "$FIXTURES/dummy.manifest.yaml" >/dev/null 2>&1
  assert_rc 1 $? "required-missing returns 1"
  assert_log_absent "rollout status" "no rollout waits after abort"
}

# ── optional deploy file missing → skipped, continues, rc=0 ───────────
test_optional_missing_skips() {
  install_mocks
  local deploy="/no/such/optional.yaml"$'\ttrue'
  stub_manifest "log4j-poc" "$PODS" "$deploy" "" ""
  chain_deploy "$FIXTURES/dummy.manifest.yaml" >/dev/null 2>&1
  assert_rc 0 $? "optional-missing returns 0"
  # still waits for the pods' rollouts
  assert_log_contains "rollout status deploy/chain-backend" "still waits for rollouts after optional skip"
}

# ── deploy that isn't a Deployment object → no rollout wait, no crash ──
test_non_deployment_pod() {
  install_mocks
  export MOCK_DEPLOY_RC=1   # `kubectl get deploy <n>` says not-found
  local deploy="$_TMP/deploydir/base.yaml"$'\tfalse'
  stub_manifest "log4j-poc" "$PODS" "$deploy" "" ""
  chain_deploy "$FIXTURES/dummy.manifest.yaml" >/dev/null 2>&1
  assert_rc 0 $? "non-Deployment pods don't fail deploy"
  assert_log_absent "rollout status deploy/chain-backend" "skips rollout wait when deploy absent"
  unset MOCK_DEPLOY_RC
}

# ── empty namespace → abort rc=1 before any kubectl ──────────────────
test_empty_namespace_aborts() {
  install_mocks
  local deploy="$_TMP/deploydir/base.yaml"$'\tfalse'
  stub_manifest "" "$PODS" "$deploy" "" ""   # empty namespace
  chain_deploy "$FIXTURES/dummy.manifest.yaml" >/dev/null 2>&1
  assert_rc 1 $? "empty namespace returns 1"
  assert_log_absent "apply -f" "no apply with empty namespace"
}

test_applies_and_waits
test_empty_namespace_aborts
test_required_missing_aborts
test_optional_missing_skips
test_non_deployment_pod
finish
