#!/usr/bin/env bash
# Flux SBoB demo — deploy Flux and optionally bind ALL component SBoBs.
#   ./distro.sh          # deploy only  (make deploy-flux)
#   ./distro.sh sbob     # deploy AND bind every SBoB in sbobs/
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-}"
LABEL="kubescape.io/user-defined-profile"

deploy() { make -C ../.. deploy-flux; }

meta() {
  python3 -c 'import yaml,sys; d=yaml.safe_load(open(sys.argv[1])); print(d["metadata"].get("namespace") or "default", d["metadata"]["name"], d["spec"]["matchLabels"]["app"])' "$1"
}

bind() {
  local f ns name app bound=0 missing=0 total
  total=$(ls sbobs/cp-flux-*.yaml | wc -l)
  for f in sbobs/cp-flux-*.yaml; do
    read -r ns name app < <(meta "$f")
    if ! kubectl -n "$ns" get deploy "$app" >/dev/null 2>&1; then
      echo "!! skip $name: deployment/$app missing in $ns"; missing=$((missing+1)); continue
    fi
    kubectl apply --server-side --force-conflicts -f "$f" >/dev/null
    kubectl -n "$ns" patch deployment "$app" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"$LABEL\":\"$name\"}}}}}" >/dev/null
    kubectl -n "$ns" rollout restart deploy/"$app" >/dev/null
    echo ">> bound $name -> deployment/$app ($ns)"
    bound=$((bound+1))
  done
  for f in sbobs/cp-flux-*.yaml; do
    read -r ns name app < <(meta "$f")
    kubectl -n "$ns" get deploy "$app" >/dev/null 2>&1 &&
      kubectl -n "$ns" rollout status deploy/"$app" --timeout=180s || true
  done
  echo "-- live pod labels --"
  for f in sbobs/cp-flux-*.yaml; do
    read -r ns name app < <(meta "$f")
    kubectl -n "$ns" get pod -l app="$app" \
      -o 'jsonpath={range .items[*]}{"   "}{.metadata.name}{"  udp="}{.metadata.labels.kubescape\.io/user-defined-profile}{"\n"}{end}' 2>/dev/null || true
  done
  echo "bound=$bound missing=$missing total=$total"
}

deploy
[ "$MODE" = sbob ] && bind
