#!/usr/bin/env bash
# sbob-pipeline.sh — manifest-driven driver for the SBOB chain pipeline.
#
# Composes scripts/lib/chain-{deploy,apply-sbobs,extract-sbobs,
# scenario-switch}.sh against a ChainManifest. Replaces the apply-loop
# logic from scripts/local-ci-chain.sh with a thin top-level that any
# new chain demo (e.g. example/log4j-chain/) can drive without forking.
#
# Examples (run from repo root):
#
#   # Apply the existing chain's SBOBs onto an existing cluster
#   ./scripts/sbob-pipeline.sh apply  example/chain/chain.manifest.yaml
#
#   # Same, then wait for the node-agent cache flush
#   ./scripts/sbob-pipeline.sh apply  example/chain/chain.manifest.yaml --wait
#
#   # Deploy the chain's pods first
#   ./scripts/sbob-pipeline.sh deploy example/chain/chain.manifest.yaml
#
#   # End-to-end on a manifest with scenarios: deploy, apply SBOBs,
#   # then switch to scenario B
#   ./scripts/sbob-pipeline.sh switch example/log4j-chain/chain.manifest.yaml B-distroless
#
#   # Extract learned SBOBs from a cluster back to the manifest's sbob_dir
#   ./scripts/sbob-pipeline.sh extract example/chain/chain.manifest.yaml
#
#   # Validate the manifest against the schema (CI gate)
#   ./scripts/sbob-pipeline.sh validate example/chain/chain.manifest.yaml
#
# Why a top-level driver instead of extending local-ci-chain.sh: the
# 610-line existing script is hard-coded to the existing chain and
# carries flags for an older workflow. Keeping it untouched while the
# manifest-driven path proves out lets us migrate incrementally; once
# local-ci-chain.sh's behaviors are all reachable via this driver +
# the manifest, we delete it.

set -euo pipefail

# Local var name (avoid clash with the libraries' SCRIPT_DIR — they
# each reassign it on source, leaking into our scope).
PIPELINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PIPELINE_DIR/.." && pwd)"

# shellcheck source=lib/chain-manifest-parse.sh
source "$PIPELINE_DIR/lib/chain-manifest-parse.sh"
# shellcheck source=lib/chain-deploy.sh
source "$PIPELINE_DIR/lib/chain-deploy.sh"
# shellcheck source=lib/chain-apply-sbobs.sh
source "$PIPELINE_DIR/lib/chain-apply-sbobs.sh"
# shellcheck source=lib/chain-extract-sbobs.sh
source "$PIPELINE_DIR/lib/chain-extract-sbobs.sh"
# shellcheck source=lib/chain-scenario-switch.sh
source "$PIPELINE_DIR/lib/chain-scenario-switch.sh"

usage() {
  sed -n '4,30p' "$0" >&2
  exit 64
}

cmd=${1:-}
shift 2>/dev/null || true

case "$cmd" in
  validate)
    # Prefer the python-based schema validator (portable — every dev box
    # has python3, yq is a common-but-not-universal extra). Falls back to
    # the yq-based manifest_validate when python+pyyaml are missing.
    manifest=${1:?usage: $0 validate <manifest.yaml>}
    if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
      python3 - "$manifest" <<'PY' || exit $?
import sys, yaml
from pathlib import Path

REQUIRED_TOP = ["apiVersion", "kind", "metadata", "deploy", "pods",
                "functional_tests", "attack_suite"]
REQUIRED_META = ["name", "namespace"]
REQUIRED_POD = ["name", "profile_match", "container"]
REQUIRED_DEPLOY = ["manifest"]
ALLOWED_KIND = "ChainManifest"
ALLOWED_API = "bobctl.k8sstormcenter.io/v1alpha1"

path = sys.argv[1]
with open(path) as f:
    doc = yaml.safe_load(f)
errs = []
for k in REQUIRED_TOP:
    if k not in doc:
        errs.append(f"missing top-level key: {k}")
if doc.get("kind") != ALLOWED_KIND:
    errs.append(f"kind={doc.get('kind')!r}, want {ALLOWED_KIND!r}")
if doc.get("apiVersion") != ALLOWED_API:
    errs.append(f"apiVersion={doc.get('apiVersion')!r}, want {ALLOWED_API!r}")
meta = doc.get("metadata") or {}
for k in REQUIRED_META:
    if not meta.get(k):
        errs.append(f"metadata.{k} missing or empty")
for i, p in enumerate(doc.get("pods") or []):
    if not isinstance(p, dict):
        errs.append(f"pods[{i}] not a mapping"); continue
    for k in REQUIRED_POD:
        if not p.get(k):
            errs.append(f"pods[{i}].{k} missing")
for i, d in enumerate(doc.get("deploy") or []):
    if not isinstance(d, dict):
        errs.append(f"deploy[{i}] not a mapping"); continue
    for k in REQUIRED_DEPLOY:
        if not d.get(k):
            errs.append(f"deploy[{i}].{k} missing")
if errs:
    print(f"validate: FAIL ({path})", file=sys.stderr)
    for e in errs: print(f"  {e}", file=sys.stderr)
    sys.exit(1)
print(f"validate: OK ({path})")
PY
    else
      manifest_validate "$manifest" && echo "validate: OK"
    fi
    ;;

  deploy)
    manifest=${1:?usage: $0 deploy <manifest.yaml>}
    chain_deploy "$manifest"
    ;;

  apply)
    manifest=${1:?usage: $0 apply <manifest.yaml> [--wait]}
    sbob_dir=""
    wait_flag=false
    shift
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --wait)      wait_flag=true ;;
        --sbob-dir)  sbob_dir=$2; shift ;;
        *)           echo "unknown flag: $1" >&2; usage ;;
      esac
      shift
    done
    chain_apply_sbobs "$manifest" "$sbob_dir"
    if $wait_flag; then
      chain_apply_sbobs_wait_for_cache_flush
    fi
    ;;

  extract)
    manifest=${1:?usage: $0 extract <manifest.yaml> [out-dir]}
    out=${2:-}
    chain_extract_sbobs "$manifest" "$out"
    ;;

  switch)
    manifest=${1:?usage: $0 switch <manifest.yaml> <scenario-name>}
    scenario=${2:?usage: $0 switch <manifest.yaml> <scenario-name>}
    chain_scenario_switch "$manifest" "$scenario"
    ;;

  ""|-h|--help|help)
    usage
    ;;

  *)
    echo "unknown command: $cmd" >&2
    usage
    ;;
esac
