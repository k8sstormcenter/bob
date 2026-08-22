#!/usr/bin/env bash
# Flux SBoB demo — deploy Flux and optionally bind ALL component SBoBs.
# Symmetrical to example/redis/distros/deploy-distros.sh.
#
#   ./distro.sh          # deploy only  (make deploy-flux)
#   ./distro.sh sbob     # deploy AND bind every SBoB in sbobs/
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-}"

deploy() { make -C ../.. deploy-flux; }

meta() {  # <sbob> -> "namespace name app"  (Deployment=app, label value=name)
  python3 -c 'import yaml,sys; d=yaml.safe_load(open(sys.argv[1])); print(d["metadata"]["namespace"], d["metadata"]["name"], d["spec"]["matchLabels"]["app"])' "$1"
}

# Bind every sbobs/cp-flux-*.yaml: server-side apply the CP (so it always takes)
# and label the matching Deployment's pod template so node-agent enforces it.
# The operator only stamps the label onto NEWLY created pods, so the patch rolls
# the workload.
bind() {
  local f ns name app
  for f in sbobs/cp-flux-*.yaml; do
    read -r ns name app < <(meta "$f")
    echo ">> $f -> deployment/$app ($ns), profile $name"
    kubectl apply --server-side --force-conflicts -f "$f"
    kubectl -n "$ns" patch deployment "$app" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"kubescape.io/user-defined-profile\":\"$name\"}}}}}"
  done
  for f in sbobs/cp-flux-*.yaml; do
    read -r ns name app < <(meta "$f")
    kubectl -n "$ns" rollout status deploy/"$app" --timeout=180s || true
  done
  echo "bound $(ls sbobs/cp-flux-*.yaml | wc -l) flux component SBoBs"
}

deploy
[ "$MODE" = sbob ] && bind
