#!/usr/bin/env bash
# chain-apply-sbobs.sh — apply a user-supplied ContainerProfile to a
# namespace, delete-first to avoid strategic-merge-patch strip (spec D4).
#
# Intended as a sourceable library. Source from local-ci-chain.sh or
# call directly with a manifest path.
#
# Why delete-first: kubectl apply does strategic-merge-patch against
# the on-cluster ContainerProfile. If node-agent already auto-learned a
# ContainerProfile for the workload (which it does on first pod start),
# the patch will be computed against THAT version — and slice fields
# like `execs`, `opens`, `rulePolicies` (and the inline network
# `ingress`/`egress`) without `+patchMergeKey` markers lose newly-added
# entries. PoC-agent's iximiuz lab + PR k8sstormcenter/bob#131 verified
# this end-to-end. delete + apply guarantees a clean write.
#
# Why 30s grace: node-agent caches its per-binding rule policy view.
# Freshly-restarted pods will trigger transient R0002/R0004 fires from
# the JVM JIT comms during the cache-flush window even when the new
# AP correctly suppresses them. PoC-agent's iter-4 verification on
# #131 measured ~30s for the cache to flush in their setup. Run the
# attack AFTER this wait or expect spurious fires.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=./chain-manifest-parse.sh
source "$SCRIPT_DIR/chain-manifest-parse.sh"

# chain_apply_sbobs <manifest.yaml> [sbob-dir]
#   Apply the ContainerProfile file for each pod in the manifest.
#   sbob-dir: directory containing cp-<pod>.yaml files,
#             relative to the manifest's directory. Defaults to the
#             manifest's `sbob_dir` field, else "sbobs/".
#   Exits non-zero if a required file is missing or any apply fails.
chain_apply_sbobs() {
  local manifest=$1
  local sbob_dir=${2:-}

  if [[ ! -f "$manifest" ]]; then
    echo "chain-apply-sbobs: manifest not found: $manifest" >&2
    return 2
  fi

  manifest_validate "$manifest" || return $?

  local manifest_dir
  manifest_dir=$(dirname "$manifest")

  if [[ -z "$sbob_dir" ]]; then
    sbob_dir=$(manifest_field "$manifest" '.sbob_dir')
    [[ -z "$sbob_dir" ]] && sbob_dir="sbobs"
  fi

  # Resolve sbob_dir relative to manifest unless absolute
  if [[ "$sbob_dir" != /* ]]; then
    sbob_dir="$manifest_dir/$sbob_dir"
  fi
  if [[ ! -d "$sbob_dir" ]]; then
    echo "chain-apply-sbobs: sbob_dir not found: $sbob_dir" >&2
    return 2
  fi

  local namespace
  namespace=$(manifest_field "$manifest" '.metadata.namespace')
  [[ -z "$namespace" ]] && { echo "chain-apply-sbobs: metadata.namespace missing" >&2; return 1; }

  # Ensure the namespace exists. Idempotent.
  kubectl create namespace "$namespace" --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null

  # Walk pods. manifest_pods emits TSV: name<TAB>profile_match<TAB>container<TAB>negative_control
  local -a pods=()
  # `|| [[ -n "$pname" ]]` processes a final line lacking a trailing
  # newline (defensive — real yq @tsv emits one, but don't depend on it).
  while IFS=$'\t' read -r pname _ _ _ || [[ -n "$pname" ]]; do
    [[ -n "$pname" ]] && pods+=("$pname")
  done < <(manifest_pods "$manifest")

  if [[ ${#pods[@]} -eq 0 ]]; then
    echo "chain-apply-sbobs: no pods declared in manifest" >&2
    return 1
  fi

  echo "chain-apply-sbobs: applying SBOBs for ${#pods[@]} pods to $namespace"

  local missing=()
  for pname in "${pods[@]}"; do
    local f="$sbob_dir/cp-$pname.yaml"
    [[ -f "$f" ]] || missing+=("$f")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "chain-apply-sbobs: missing files (none applied):" >&2
    printf '  %s\n' "${missing[@]}" >&2
    return 1
  fi

  # D4: delete-first to defeat the strategic-merge-patch strip.
  # --ignore-not-found because the first run won't have a prior CP.
  # We don't --wait on the delete since the ContainerProfile is not
  # namespace-finalized and completes immediately.
  for pname in "${pods[@]}"; do
    kubectl delete containerprofile "$pname" -n "$namespace" --ignore-not-found >/dev/null
  done

  # Apply
  for pname in "${pods[@]}"; do
    kubectl apply -n "$namespace" -f "$sbob_dir/cp-$pname.yaml" >/dev/null
    printf '  applied: %s\n' "$pname"
  done

  # Verify managed-by: User on every applied ContainerProfile. Surfaces
  # schema / webhook strips loudly rather than silently shipping a broken SBOB.
  local bad=()
  for pname in "${pods[@]}"; do
    local mb
    mb=$(kubectl get containerprofile "$pname" -n "$namespace" \
         -o jsonpath='{.metadata.annotations.kubescape\.io/managed-by}' 2>/dev/null || true)
    if [[ "$mb" != "User" ]]; then
      bad+=("$pname (managed-by=${mb:-missing})")
    fi
  done
  if [[ ${#bad[@]} -gt 0 ]]; then
    echo "chain-apply-sbobs: managed-by!=User on some ContainerProfiles (possible webhook strip):" >&2
    printf '  %s\n' "${bad[@]}" >&2
    return 1
  fi

  echo "chain-apply-sbobs: all ${#pods[@]} ContainerProfiles show managed-by: User"
}

# chain_apply_sbobs_wait_for_cache_flush [seconds]
#   Sleep for the node-agent rule policy cache TTL. Default 30s
#   (PoC-agent's measured value on storage sbob-rc1-2026-05-16 +
#   node-agent 1.30.2). Override per-cluster via the arg.
chain_apply_sbobs_wait_for_cache_flush() {
  local secs=${1:-30}
  echo "chain-apply-sbobs: waiting ${secs}s for node-agent per-binding cache flush"
  sleep "$secs"
}

# Allow direct invocation: `bash chain-apply-sbobs.sh <manifest> [sbob-dir]`
# When sourced, the functions are exposed for the caller.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  chain_apply_sbobs "$@"
  chain_apply_sbobs_wait_for_cache_flush
fi
