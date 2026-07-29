#!/usr/bin/env bash
# chain-extract-sbobs.sh — read the learned ContainerProfile from the
# cluster for each pod in a ChainManifest and write it to
# `<sbob_dir>/cp-<pod>.yaml`, normalized to the User-managed shape so
# the next consumer can apply it as-is.
#
# Vendor flow: agent A learns sbobs on cluster A, exports via this
# helper, ships to operator B who runs chain-apply-sbobs.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=./chain-manifest-parse.sh
source "$SCRIPT_DIR/chain-manifest-parse.sh"

# chain_extract_sbobs <manifest.yaml> [out-dir]
#   For each pod in the manifest, find its learned ContainerProfile
#   (by `profile_match` prefix) on the cluster, normalize the metadata
#   to the User-managed shape, and write to
#   <out-dir>/cp-<pod-name>.yaml.
#
#   out-dir: defaults to the manifest's `sbob_dir` field, else
#   "<manifest-dir>/sbobs/".
#
#   Normalization:
#     - Strip resourceVersion / uid / creationTimestamp / managedFields
#     - Strip status (storage server re-computes it)
#     - Rename to the pod name (so user-defined-profile labels match)
#     - Add `kubescape.io/managed-by: User` + `status: completed` +
#       `completion: complete` annotations
#     - Add canonical workload-* labels so node-agent's cache picks
#       these up at next pod start
chain_extract_sbobs() {
  local manifest=$1
  local out_dir=${2:-}

  manifest_validate "$manifest" || return $?
  command -v yq >/dev/null || { echo "chain-extract-sbobs: yq required" >&2; return 2; }
  command -v jq >/dev/null || { echo "chain-extract-sbobs: jq required" >&2; return 2; }

  local manifest_dir
  manifest_dir=$(dirname "$manifest")
  if [[ -z "$out_dir" ]]; then
    out_dir=$(manifest_field "$manifest" '.sbob_dir')
    [[ -z "$out_dir" ]] && out_dir="sbobs"
  fi
  [[ "$out_dir" != /* ]] && out_dir="$manifest_dir/$out_dir"
  mkdir -p "$out_dir"

  local namespace
  namespace=$(manifest_field "$manifest" '.metadata.namespace')
  [[ -z "$namespace" ]] && { echo "chain-extract-sbobs: metadata.namespace missing" >&2; return 1; }

  echo "chain-extract-sbobs: extracting from $namespace to $out_dir"

  local errors=0
  while IFS=$'\t' read -r pname pmatch container _ || [[ -n "$pname" ]]; do
    [[ -z "$pname" ]] && continue
    if ! _extract_one_pod "$namespace" "$pname" "$pmatch" "$container" "$out_dir"; then
      errors=$((errors+1))
    fi
  done < <(manifest_pods "$manifest")

  if [[ $errors -gt 0 ]]; then
    echo "chain-extract-sbobs: $errors pod(s) failed extraction" >&2
    return 1
  fi
  echo "chain-extract-sbobs: done"
}

_extract_one_pod() {
  local ns=$1
  local pname=$2
  local pmatch=$3
  local container=$4
  local out_dir=$5

  # Locate the on-cluster ContainerProfile by name-prefix match.
  # node-agent's naming is `replicaset-<deploy>-<hash>` so the manifest's
  # `profile_match` is the prefix `replicaset-<deploy>`. The unified
  # ContainerProfile carries the process view AND the inline network
  # ingress/egress, so a single lookup replaces the former AP+NN pair.
  local cp_name
  cp_name=$(kubectl get containerprofile -n "$ns" -o json 2>/dev/null \
    | jq -r --arg p "$pmatch" '[.items[] | select(.metadata.name | startswith($p))][0].metadata.name // ""')
  if [[ -z "$cp_name" ]]; then
    echo "  $pname: no ContainerProfile found matching prefix $pmatch" >&2
    return 1
  fi

  # Pull the ContainerProfile and rewrite metadata.
  kubectl get containerprofile "$cp_name" -n "$ns" -o yaml \
    | _normalize_metadata "$pname" "$ns" \
    > "$out_dir/cp-$pname.yaml"
  echo "  $pname: cp-$pname.yaml ← $cp_name"
}

_normalize_metadata() {
  local target_name=$1
  local target_ns=$2
  # Drop server-side metadata, rename to the canonical User-managed
  # shape, ensure the managed-by + status annotations carry.
  yq eval '
    del(
      .metadata.resourceVersion,
      .metadata.uid,
      .metadata.creationTimestamp,
      .metadata.managedFields,
      .metadata.generation,
      .metadata.ownerReferences,
      .metadata.annotations["kubescape.io/sync-checksum"],
      .metadata.annotations["kubescape.io/resource-size"],
      .metadata.annotations["kubescape.io/timestamp"],
      .metadata.annotations["kubescape.io/wlid"],
      .metadata.annotations["kubescape.io/image-id"],
      .metadata.annotations["kubescape.io/image-tag"],
      .metadata.annotations["kubescape.io/instance-id"],
      .metadata.annotations["kubescape.io/instance-template-hash"],
      .status,
      .metadata.labels["kubescape.io/instance-template-hash"],
      .metadata.labels["kubescape.io/workload-resource-version"],
      .metadata.labels["kubescape.io/learning-period"]
    ) |
    .metadata.name = "'"$target_name"'" |
    .metadata.namespace = "'"$target_ns"'" |
    .metadata.annotations["kubescape.io/managed-by"] = "User" |
    .metadata.annotations["kubescape.io/status"] = "completed" |
    .metadata.annotations["kubescape.io/completion"] = "complete"
  ' -
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  chain_extract_sbobs "$@"
fi
