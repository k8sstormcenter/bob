#!/usr/bin/env bash
# chain-deploy.sh — apply every `deploy[]` entry from a ChainManifest in
# order, then wait for the declared pods' deployments to roll out.
#
# Idempotent. Honors `deploy[].optional` (CRD-not-present clusters can
# skip those without aborting). Pre-flight image-reachable check (D6)
# fails fast rather than hitting ImagePullBackOff mid-tune.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./chain-manifest-parse.sh
source "$SCRIPT_DIR/chain-manifest-parse.sh"

# chain_deploy <manifest.yaml>
#   Apply every deploy[] entry, then wait for the rollout of every
#   deployment whose name matches one of the manifest's pods[].name.
chain_deploy() {
  local manifest=$1
  manifest_validate "$manifest" || return $?

  local manifest_dir
  manifest_dir=$(dirname "$manifest")

  local namespace
  namespace=$(manifest_field "$manifest" '.metadata.namespace')
  if [[ -z "$namespace" ]]; then
    echo "chain-deploy: metadata.namespace empty/missing" >&2
    return 1
  fi

  # Step 1 — apply each deploy[] entry. `optional: true` entries that
  # reference paths or CRDs that don't exist will warn-and-continue
  # rather than abort.
  echo "chain-deploy: applying $(manifest_field "$manifest" '.deploy | length') deploy steps"
  while IFS=$'\t' read -r dpath optional || [[ -n "$dpath" ]]; do
    [[ -z "$dpath" ]] && continue
    # resolve relative
    [[ "$dpath" != /* ]] && dpath="$manifest_dir/$dpath"
    if [[ ! -f "$dpath" ]]; then
      if [[ "$optional" == "true" ]]; then
        echo "  skip (optional, missing): ${dpath}"
        continue
      fi
      echo "chain-deploy: required manifest missing: $dpath" >&2
      return 1
    fi
    echo "  apply: $(basename "$dpath")"
    if ! kubectl apply -f "$dpath" 2>&1 | sed 's/^/    /'; then
      if [[ "$optional" == "true" ]]; then
        echo "    (optional — continuing)"
      else
        return 1
      fi
    fi
  done < <(manifest_deploy "$manifest")

  # Step 2 — wait for rollouts. The manifest doesn't enumerate
  # Deployment objects explicitly; we use the `pods[].name` as the
  # convention (matches the existing chain demo: pod name == deploy
  # name == AP name).
  echo "chain-deploy: waiting for rollouts in $namespace"
  while IFS=$'\t' read -r pname _ _ _ || [[ -n "$pname" ]]; do
    [[ -z "$pname" ]] && continue
    if kubectl get deploy "$pname" -n "$namespace" >/dev/null 2>&1; then
      kubectl rollout status deploy/"$pname" -n "$namespace" --timeout=180s \
        || echo "    WARN: $pname rollout not ready in 180s (continuing)"
    else
      echo "    $pname: not a Deployment in $namespace (skipping rollout wait)"
    fi
  done < <(manifest_pods "$manifest")

  echo "chain-deploy: done"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  chain_deploy "$@"
fi
