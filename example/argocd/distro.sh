#!/usr/bin/env bash
# Argo CD SBoB demo — deploy Argo CD and optionally bind every component SBoB.
#   ./distro.sh          # deploy only  (make deploy-argocd)
#   ./distro.sh sbob     # deploy AND bind every SBoB in sbobs/
#   ./distro.sh unbind   # drop the bind label so the components LEARN again
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-}"
NS=argocd
LABEL="kubescape.io/user-defined-profile"

deploy() { make -C ../.. deploy-argocd; }

# The workload that owns each component's pods. argocd-application-controller is
# a StatefulSet; everything else is a Deployment.
workload_for() {
  case "$1" in
    argocd-application-controller) echo "statefulset/$1" ;;
    *)                             echo "deployment/$1" ;;
  esac
}

bind() {
  local bound=0 missing=0 total
  total=$(ls sbobs/cp-argocd-*.yaml | wc -l)
  for f in sbobs/cp-argocd-*.yaml; do
    local name wl
    name=$(basename "$f" .yaml); name="${name#cp-}"
    wl=$(workload_for "$name")
    if ! kubectl -n "$NS" get "$wl" >/dev/null 2>&1; then
      echo "     $name: no $wl — skipped"
      missing=$((missing + 1)); continue
    fi
    kubectl apply -f "$f" >/dev/null
    # The label goes on the POD TEMPLATE: node-agent binds a profile when the
    # container starts, so the workload has to roll for the bind to take.
    kubectl -n "$NS" patch "$wl" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"$LABEL\":\"$name\"}}}}}" >/dev/null
    bound=$((bound + 1))
  done
  echo "bound=$bound missing=$missing total=$total"
  for f in sbobs/cp-argocd-*.yaml; do
    local name wl
    name=$(basename "$f" .yaml); name="${name#cp-}"
    wl=$(workload_for "$name")
    kubectl -n "$NS" get "$wl" >/dev/null 2>&1 || continue
    kubectl -n "$NS" rollout status "$wl" --timeout=300s >/dev/null 2>&1 || true
  done
  kubectl -n "$NS" get pods \
    -o custom-columns=POD:.metadata.name,PROFILE:.metadata.labels."$LABEL" --no-headers
}

# Learning and enforcement are mutually exclusive: while the label is set
# node-agent applies the supplied profile instead of recording one, so a
# re-learn has to drop it first.
unbind() {
  for f in sbobs/cp-argocd-*.yaml; do
    local name wl
    name=$(basename "$f" .yaml); name="${name#cp-}"
    wl=$(workload_for "$name")
    kubectl -n "$NS" get "$wl" >/dev/null 2>&1 || continue
    kubectl -n "$NS" patch "$wl" --type merge \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"$LABEL\":null}}}}}" >/dev/null
  done
  echo "unbound; roll the workloads to start recording"
}

case "$MODE" in
  sbob)   deploy; bind ;;
  unbind) unbind ;;
  "")     deploy ;;
  *)      echo "usage: $0 [sbob|unbind]" >&2; exit 2 ;;
esac
