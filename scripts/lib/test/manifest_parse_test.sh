#!/usr/bin/env bash
# Tier-2 tests for chain-manifest-parse.sh — exercise the REAL yq-backed
# accessors against fixture manifests. Skipped when yq is absent.
source "$(dirname "${BASH_SOURCE[0]}")/test_helper.bash"
source "$LIB_DIR/chain-manifest-parse.sh"
set +e

require_yq   # skips the whole file if yq isn't installed

GOOD="$FIXTURES/scenarios.manifest.yaml"

# ── manifest_validate accepts a well-formed manifest ──────────────────
manifest_validate "$GOOD" >/dev/null 2>&1
assert_rc 0 $? "validate accepts good manifest"

# ── manifest_validate rejects a manifest missing required keys ─────────
BAD="$_TMP/bad.yaml"
cat > "$BAD" <<'YAML'
apiVersion: bobctl.k8sstormcenter.io/v1alpha1
kind: ChainManifest
metadata:
  name: incomplete
YAML
manifest_validate "$BAD" >/dev/null 2>&1
assert_rc 1 $? "validate rejects manifest missing namespace/deploy/pods"

# ── manifest_field returns scalar fields ──────────────────────────────
assert_eq "log4j-poc" "$(manifest_field "$GOOD" '.metadata.namespace')" "field: namespace"
assert_eq "sbobs/"    "$(manifest_field "$GOOD" '.sbob_dir')"           "field: sbob_dir"

# ── manifest_pods emits one TSV row per pod with the right columns ─────
pods_out="$(manifest_pods "$GOOD")"
assert_eq "2" "$(printf '%s\n' "$pods_out" | grep -c .)" "pods: 2 rows"
backend_row="$(printf '%s\n' "$pods_out" | grep '^chain-backend')"
assert_eq "chain-backend	replicaset-chain-backend	backend	false" "$backend_row" "pods: backend row columns"
obs_row="$(printf '%s\n' "$pods_out" | grep '^chain-observer')"
assert_eq "chain-observer	replicaset-chain-observer	observer	true" "$obs_row" "pods: observer negative_control=true"

# ── manifest_deploy emits path + optional flag ────────────────────────
deploy_out="$(manifest_deploy "$GOOD")"
assert_eq "2" "$(printf '%s\n' "$deploy_out" | grep -c .)" "deploy: 2 rows"
assert_eq "log4j-chain.yaml	false" "$(printf '%s\n' "$deploy_out" | head -1)" "deploy: first row not optional"
assert_eq "kubescape/rules/R1100_rulespec.yaml	true" "$(printf '%s\n' "$deploy_out" | sed -n 2p)" "deploy: R1100 optional=true"

# ── manifest_scenarios emits one JSON object per scenario ─────────────
scen_out="$(manifest_scenarios "$GOOD")"
assert_eq "2" "$(printf '%s\n' "$scen_out" | grep -c .)" "scenarios: 2 objects"
# first scenario name extractable
first_name="$(printf '%s\n' "$scen_out" | head -1 | yq -p=json '.name')"
assert_eq "A-vuln" "$first_name" "scenarios: first is A-vuln"

# ── manifest_scenarios is empty for a single-shot manifest ────────────
SINGLE="$REPO_ROOT/example/chain/chain.manifest.yaml"
if [[ -f "$SINGLE" ]]; then
  single_scen="$(manifest_scenarios "$SINGLE")"
  assert_eq "" "$single_scen" "scenarios: empty for single-shot chain"
fi

finish
