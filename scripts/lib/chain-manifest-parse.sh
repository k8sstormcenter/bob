#!/usr/bin/env bash
# chain-manifest-parse.sh — minimal `yq`-based reader for ChainManifest.
#
# This is the STUB that anchors the contract: when the refactor lands,
# scripts/local-ci-chain.sh sources this file and calls the
# manifest_* accessors instead of consulting hardcoded paths.
#
# Today: the accessors below work but no caller uses them yet.
# Tomorrow: the new local-ci-chain.sh driver loops over them.
#
# Schema source of truth: docs/chain-pipeline-refactor.md.

set -euo pipefail

need_yq() {
  command -v yq >/dev/null 2>&1 || {
    echo "chain-manifest-parse.sh: yq not installed (https://github.com/mikefarah/yq)" >&2
    return 1
  }
}

# manifest_pods <manifest.yaml>
#   Emits one line per pod: "name<TAB>profile_match<TAB>container<TAB>negative_control"
#   negative_control is "true"/"false".
manifest_pods() {
  local f=$1
  need_yq
  yq -r '.pods[] | [
    .name,
    .profile_match,
    .container,
    (.negative_control // false | tostring)
  ] | @tsv' "$f"
}

# manifest_deploy <manifest.yaml>
#   Emits one line per deploy step: "path<TAB>optional"
manifest_deploy() {
  local f=$1
  need_yq
  yq -r '.deploy[] | [
    .manifest,
    (.optional // false | tostring)
  ] | @tsv' "$f"
}

# manifest_scenarios <manifest.yaml>
#   Emits the scenarios array as JSON (one line per scenario).
#   Empty output ⇒ no scenarios; caller treats this as single-shot.
manifest_scenarios() {
  local f=$1
  need_yq
  yq -o=json -I=0 '.scenarios[]?' "$f" 2>/dev/null || true
}

# manifest_field <manifest.yaml> <yq-path>
#   Generic accessor for top-level fields. Returns empty on missing.
#   Example: manifest_field foo.yaml '.namespace' → "log4j-poc"
manifest_field() {
  local f=$1
  local path=$2
  need_yq
  yq -r "$path // \"\"" "$f"
}

# manifest_validate <manifest.yaml>
#   Hard-fail if any required field is missing. Returns 0 / 1 / 2:
#     0 — valid
#     1 — required field missing
#     2 — yq error / file unreadable
manifest_validate() {
  local f=$1
  need_yq || return 2
  local errs=""
  for req in '.apiVersion' '.kind' '.metadata.name' '.metadata.namespace' \
             '.deploy' '.pods' '.functional_tests' '.attack_suite'; do
    if [[ "$(yq -r "($req | type) + \"|\" + ($req | tostring)" "$f" 2>/dev/null)" == "!!null|null" ]]; then
      errs="$errs\n  missing: $req"
    fi
  done
  if [[ -n "$errs" ]]; then
    echo -e "chain-manifest-parse: validation failed in $f:$errs" >&2
    return 1
  fi
  return 0
}

# When sourced, this file just exposes the functions. When invoked
# directly with a manifest path, it dumps the parsed view for eyeball
# verification — useful in PR review + bash debugging.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  manifest="${1:?usage: $0 <manifest.yaml>}"
  echo "=== validate ==="
  manifest_validate "$manifest" && echo "OK"
  echo
  echo "=== namespace ==="
  manifest_field "$manifest" '.metadata.namespace'
  echo
  echo "=== deploy ==="
  manifest_deploy "$manifest" | column -t -s $'\t'
  echo
  echo "=== pods (name | profile_match | container | negative_control) ==="
  manifest_pods "$manifest" | column -t -s $'\t'
  echo
  echo "=== scenarios (JSON-per-line, empty = single-shot) ==="
  manifest_scenarios "$manifest"
fi
