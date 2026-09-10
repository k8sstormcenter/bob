#!/usr/bin/env bash
# ZITADEL SBoB demo — deploy ZITADEL and optionally bind every component SBoB.
#   ./distro.sh          # deploy only
#   ./distro.sh sbob     # deploy AND bind every SBoB in sbobs/
#   ./distro.sh unbind   # drop the bind label so the components LEARN again
#   ./distro.sh down     # remove everything
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-}"
NS=zitadel
CHART_VERSION="${CHART_VERSION:-10.0.6}"
LABEL="kubescape.io/user-defined-profile"

# Every long-running container ZITADEL leaves behind, and the workload that owns
# it. The init and setup Jobs are deliberately absent: they run once and exit, so
# there is nothing to bind a profile to.
components() {
  cat <<'EOF'
zitadel-postgresql   statefulset/zitadel-postgresql
zitadel              deployment/zitadel
zitadel-login        deployment/zitadel-login
EOF
}

deploy() {
  # A namespace still terminating from a previous `down` accepts the create and
  # then deletes what was just applied, so the rollout fails with "object has
  # been deleted". Wait it out rather than racing it.
  if kubectl get ns "$NS" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Terminating; then
    echo "namespace $NS is terminating; waiting..."
    kubectl wait --for=delete "ns/$NS" --timeout=180s >/dev/null 2>&1 || true
  fi
  kubectl create ns "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  helm repo add zitadel https://charts.zitadel.com >/dev/null 2>&1 || true
  helm repo update zitadel >/dev/null
  # The nulls are load-bearing: they strip the pre-install hook from the init
  # and setup Jobs. Setting the annotations to {} in values.yaml does NOT work —
  # helm merges maps, so the chart's default hook annotations survive.
  helm upgrade --install zitadel zitadel/zitadel \
    --version "$CHART_VERSION" -n "$NS" --values values.yaml \
    --set initJob.annotations=null --set setupJob.annotations=null \
    --wait --timeout 10m

  kubectl -n "$NS" get pods
}

bind() {
  local bound=0 missing=0 total=0
  while read -r name workload; do
    [ -z "$name" ] && continue
    total=$((total + 1))
    if [ ! -f "sbobs/cp-$name.yaml" ]; then
      echo "     $name: no sbobs/cp-$name.yaml — skipped"
      missing=$((missing + 1)); continue
    fi
    if ! kubectl -n "$NS" get "$workload" >/dev/null 2>&1; then
      echo "     $name: no $workload — skipped"
      missing=$((missing + 1)); continue
    fi
    kubectl apply -f "sbobs/cp-$name.yaml" >/dev/null
    # The label goes on the POD TEMPLATE. node-agent binds a profile when the
    # container starts, so the workload has to roll for the bind to take;
    # labelling a running pod does nothing.
    kubectl -n "$NS" patch "$workload" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"$LABEL\":\"$name\"}}}}}" >/dev/null
    bound=$((bound + 1))
  done < <(components)
  echo "bound=$bound missing=$missing total=$total"

  while read -r _ workload; do
    [ -z "$workload" ] && continue
    kubectl -n "$NS" get "$workload" >/dev/null 2>&1 || continue
    kubectl -n "$NS" rollout status "$workload" --timeout=300s >/dev/null 2>&1 || true
  done < <(components)
  kubectl -n "$NS" get pods \
    -o custom-columns=POD:.metadata.name,PROFILE:.metadata.labels."$LABEL" --no-headers
}

# Learning and enforcement are mutually exclusive: while the label is set,
# node-agent applies the supplied profile instead of recording one, so a
# re-learn has to drop it first and roll the workload.
unbind() {
  while read -r _ workload; do
    [ -z "$workload" ] && continue
    kubectl -n "$NS" get "$workload" >/dev/null 2>&1 || continue
    kubectl -n "$NS" patch "$workload" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"$LABEL\":null}}}}}" >/dev/null
  done < <(components)
  kubectl -n "$NS" delete pods --all --wait=true --timeout=180s >/dev/null 2>&1 || true
  kubectl -n "$NS" wait --for=condition=ready pod --all --timeout=300s >/dev/null 2>&1 || true
  echo "unbound; components are recording again"
}

down() {
  helm uninstall zitadel -n "$NS" >/dev/null 2>&1 || true
  kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true
  echo "removed"
}

case "$MODE" in
  sbob)   deploy; bind ;;
  unbind) unbind ;;
  down)   down ;;
  "")     deploy ;;
  *)      echo "usage: $0 [sbob|unbind|down]" >&2; exit 2 ;;
esac
