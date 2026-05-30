#!/usr/bin/env bash
# chain-manifest-test.sh — TDD seed: validate every chain.manifest.yaml
# in the repo against the schema documented in
# docs/chain-pipeline-refactor.md. Runs in CI as a gate before the
# pipeline impl lands.
#
# Uses python3 + PyYAML instead of yq because every dev box has
# python3, while yq is a common-but-not-universal extra. Once the
# impl ships, scripts/local-ci-chain.sh will use yq for the live path
# (faster, less indirection); this test stays as the canonical schema
# validator.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Locate every chain.manifest.yaml in the repo. Empty list = nothing
# to test = vacuous pass (no failure, no green claim).
mapfile -t MANIFESTS < <(find example -name chain.manifest.yaml -type f 2>/dev/null | sort)

if [[ ${#MANIFESTS[@]} -eq 0 ]]; then
  echo "chain-manifest-test: no example/**/chain.manifest.yaml present yet — skipping"
  exit 0
fi

echo "chain-manifest-test: checking ${#MANIFESTS[@]} manifest(s)"

python3 - "${MANIFESTS[@]}" <<'PY'
import sys, yaml

REQUIRED_TOP = ["apiVersion", "kind", "metadata", "deploy", "pods",
                "functional_tests", "attack_suite"]
REQUIRED_META = ["name", "namespace"]
REQUIRED_POD = ["name", "profile_match", "container"]
REQUIRED_DEPLOY = ["manifest"]
REQUIRED_SCENARIO = ["name"]
ALLOWED_KIND = "ChainManifest"
ALLOWED_API = "bobctl.k8sstormcenter.io/v1alpha1"

errors = []

def err(file, msg):
    errors.append(f"{file}: {msg}")

for path in sys.argv[1:]:
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as e:
        err(path, f"YAML parse: {e}")
        continue
    if not isinstance(doc, dict):
        err(path, "top-level not a mapping")
        continue

    for k in REQUIRED_TOP:
        if k not in doc:
            err(path, f"missing top-level key: {k}")

    if doc.get("kind") and doc["kind"] != ALLOWED_KIND:
        err(path, f"kind={doc['kind']!r}, want {ALLOWED_KIND!r}")
    if doc.get("apiVersion") and doc["apiVersion"] != ALLOWED_API:
        err(path, f"apiVersion={doc['apiVersion']!r}, want {ALLOWED_API!r}")

    meta = doc.get("metadata") or {}
    for k in REQUIRED_META:
        if not meta.get(k):
            err(path, f"metadata.{k} missing or empty")

    deploy = doc.get("deploy") or []
    if not isinstance(deploy, list) or not deploy:
        err(path, "deploy must be a non-empty list")
    else:
        for i, step in enumerate(deploy):
            if not isinstance(step, dict):
                err(path, f"deploy[{i}] not a mapping"); continue
            for k in REQUIRED_DEPLOY:
                if not step.get(k):
                    err(path, f"deploy[{i}].{k} missing")

    pods = doc.get("pods") or []
    if not isinstance(pods, list) or not pods:
        err(path, "pods must be a non-empty list")
    else:
        names = set()
        for i, pod in enumerate(pods):
            if not isinstance(pod, dict):
                err(path, f"pods[{i}] not a mapping"); continue
            for k in REQUIRED_POD:
                if not pod.get(k):
                    err(path, f"pods[{i}].{k} missing")
            if pod.get("name") in names:
                err(path, f"pods[{i}].name duplicate: {pod['name']!r}")
            names.add(pod.get("name"))

    # scenarios is OPTIONAL; only validate shape when present.
    scenarios = doc.get("scenarios")
    if scenarios is not None:
        if not isinstance(scenarios, list):
            err(path, "scenarios must be a list when present")
        else:
            for i, sc in enumerate(scenarios):
                if not isinstance(sc, dict):
                    err(path, f"scenarios[{i}] not a mapping"); continue
                for k in REQUIRED_SCENARIO:
                    if not sc.get(k):
                        err(path, f"scenarios[{i}].{k} missing")

    print(f"  {path}: OK" if not any(e.startswith(path) for e in errors) else f"  {path}: INVALID")

if errors:
    print("\nERRORS:")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)

print(f"\nchain-manifest-test: all {len(sys.argv)-1} manifests valid")
PY
