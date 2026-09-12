#!/usr/bin/env bash
# ZITADEL SBoB demo — deploy ZITADEL and optionally bind every component SBoB.
#   ./distro.sh          # deploy only (components LEARN)
#   ./distro.sh sbob     # reinstall with every SBoB in sbobs/ bound from container start
#   ./distro.sh unbind   # reinstall without the bind labels so the components LEARN again
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
    --version "$CHART_VERSION" -n "$NS" --values values.yaml "$@" \
    --set initJob.annotations=null --set setupJob.annotations=null \
    --wait --timeout 10m

  kubectl -n "$NS" get pods
}

# A fresh install, not a patch-and-roll. node-agent adopts a profile when the
# container STARTS, so the label has to be on the pod template before the pod
# exists — and the database is an emptyDir populated once by the setup Job, so
# rolling the StatefulSet of a running release leaves ZITADEL with no schema
# ("relation system.encryption_keys does not exist") and a CrashLoopBackOff.
bind() {
  kubectl create ns "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  local applied=0 missing=0
  for f in sbobs/cp-*.yaml; do
    [ -e "$f" ] || continue
    kubectl apply -f "$f" >/dev/null
    applied=$((applied + 1))
  done
  while read -r name _; do
    [ -z "$name" ] && continue
    [ -f "sbobs/cp-$name.yaml" ] || { echo "     $name: no sbobs/cp-$name.yaml"; missing=$((missing + 1)); }
  done < <(components)
  echo "profiles applied=$applied missing=$missing"

  deploy --values values-sbob.yaml
  kubectl -n "$NS" get pods \
    -o custom-columns=POD:.metadata.name,PROFILE:".metadata.labels.${LABEL//./\\.}" --no-headers
}

# Learning and enforcement are mutually exclusive: while the label is set,
# node-agent applies the supplied profile instead of recording one. Re-learning
# is a fresh install without the overlay, for the same reason bind is.
unbind() {
  down
  kubectl wait --for=delete "ns/$NS" --timeout=180s >/dev/null 2>&1 || true
  deploy
  echo "reinstalled without the bind labels; components are recording again"
}

down() {
  helm uninstall zitadel -n "$NS" >/dev/null 2>&1 || true
  kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true
  echo "removed"
}

case "$MODE" in
  sbob)   down; kubectl wait --for=delete "ns/$NS" --timeout=180s >/dev/null 2>&1 || true; bind ;;
  unbind) unbind ;;
  down)   down ;;
  "")     deploy ;;
  *)      echo "usage: $0 [sbob|unbind|down]" >&2; exit 2 ;;
esac
