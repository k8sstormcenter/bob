#!/usr/bin/env bash
# chain-scenario-switch.sh — execute scenarios[].apply + .restart for a
# named scenario in a ChainManifest. Used by the log4j-chain demo to
# swap the backend image between scenarios A/B/C without re-deploying
# the rest of the topology.
#
# Idempotent within a scenario; running the same scenario twice
# applies the same manifests + restarts the same deployments.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./chain-manifest-parse.sh
source "$SCRIPT_DIR/chain-manifest-parse.sh"

# chain_scenario_switch <manifest.yaml> <scenario-name>
#   Find scenarios[<.name == name>], apply its .apply[] manifests,
#   restart its .restart[] deployments, wait for rollouts.
#
#   Returns 2 if no scenarios in the manifest (single-shot chain).
#   Returns 1 if the named scenario doesn't exist.
chain_scenario_switch() {
  local manifest=$1
  local scenario=$2
  manifest_validate "$manifest" || return $?

  local manifest_dir
  manifest_dir=$(dirname "$manifest")
  local namespace
  namespace=$(manifest_field "$manifest" '.metadata.namespace')

  local scenarios_json
  scenarios_json=$(manifest_scenarios "$manifest")
  if [[ -z "$scenarios_json" ]]; then
    echo "chain-scenario-switch: manifest has no scenarios (single-shot chain)" >&2
    return 2
  fi

  # Extract the matching scenario as JSON
  local sc
  sc=$(echo "$scenarios_json" | yq -p=json -o=json "select(.name == \"$scenario\")")
  if [[ -z "$sc" ]]; then
    local available
    available=$(echo "$scenarios_json" | yq -p=json '.name')
    echo "chain-scenario-switch: scenario '$scenario' not found. Available:" >&2
    echo "$available" | sed 's/^/  /' >&2
    return 1
  fi

  echo "chain-scenario-switch: switching to scenario '$scenario'"

  # apply[]
  while IFS= read -r apath; do
    [[ -z "$apath" || "$apath" == "null" ]] && continue
    [[ "$apath" != /* ]] && apath="$manifest_dir/$apath"
    if [[ ! -f "$apath" ]]; then
      echo "  apply: MISSING $apath" >&2
      return 1
    fi
    echo "  apply: $(basename "$apath")"
    kubectl apply -f "$apath" 2>&1 | sed 's/^/    /'
  done < <(echo "$sc" | yq -p=json '.apply[]?')

  # restart[]
  while IFS= read -r dname; do
    [[ -z "$dname" || "$dname" == "null" ]] && continue
    echo "  restart: deployment/$dname"
    kubectl -n "$namespace" rollout restart deploy/"$dname"
    kubectl -n "$namespace" rollout status  deploy/"$dname" --timeout=120s
  done < <(echo "$sc" | yq -p=json '.restart[]?')

  echo "chain-scenario-switch: scenario '$scenario' active"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  chain_scenario_switch "$@"
fi
