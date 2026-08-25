#!/usr/bin/env bash
# Deploy UPSTREAM Pixie (vizier in-cluster components only — no Pixie Cloud, no px CLI)
# and optionally bind the generalised SBoBs in sbobs/ by labelling each workload.
#
# Pixie is operator-managed: px-operator reconciles the Vizier CR into the pl namespace.
# Vizier.spec.pod.labels applies ONE shared label map to every vizier pod, which cannot
# express a different profile per component, so each workload is labelled individually.
#
#   component                 container    profile (metadata.name)
#   vizier-pem (DaemonSet)    pem          vizier-pem-pem
#   kelvin                    app          kelvin
#   vizier-query-broker       app          vizier-query-broker
#   vizier-metadata (STS)     app          vizier-metadata
#   vizier-cloud-connector    app          vizier-cloud-connector
#   pl-nats (STS)             pl-nats      pl-nats-pl-nats
#   ...plus the *-wait init containers, see sbobs/
#
# Usage:
#   ./distros.sh [deploy|sbob|all|status]
#     deploy  - install olm + px-operator + Vizier CR, wait for the mesh
#     sbob    - apply sbobs/ and label the workloads (requires an existing deploy)
#     all     - deploy, then sbob
#     status  - show vizier pods and which profile each is bound to
#
# Env:
#   PL_NS            vizier namespace                 (default: pl)
#   OPERATOR_NS      operator namespace               (default: px-operator)
#   PX_CLOUD_ADDR    cloud address for the Vizier CR  (default: withpixie.ai:443)
#   PX_DEPLOY_KEY    deploy key secret value          (required for a cloud-connected vizier)
#   RECREATE         1 = roll workloads after labelling (default: 1)
set -euo pipefail
cd "$(dirname "$0")"

PL_NS="${PL_NS:-pl}"
OPERATOR_NS="${OPERATOR_NS:-px-operator}"
PX_CLOUD_ADDR="${PX_CLOUD_ADDR:-withpixie.ai:443}"
RECREATE="${RECREATE:-1}"
OLM_VERSION="${OLM_VERSION:-v0.28.0}"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- deploy ----

deploy_olm() {
  if kubectl get crd catalogsources.operators.coreos.com >/dev/null 2>&1; then
    log "OLM already present"
    return
  fi
  log "installing OLM ${OLM_VERSION}"
  kubectl apply --server-side -f \
    "https://github.com/operator-framework/operator-lifecycle-manager/releases/download/${OLM_VERSION}/crds.yaml"
  kubectl apply -f \
    "https://github.com/operator-framework/operator-lifecycle-manager/releases/download/${OLM_VERSION}/olm.yaml"
  kubectl -n olm rollout status deploy/olm-operator --timeout=300s
  kubectl -n olm rollout status deploy/catalog-operator --timeout=300s
}

deploy_operator() {
  log "installing px-operator into ${OPERATOR_NS}"
  kubectl create namespace "${OPERATOR_NS}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: pixie-operator-index
  namespace: ${OPERATOR_NS}
spec:
  sourceType: grpc
  image: gcr.io/pixie-oss/pixie-prod/operator/bundle_index:0.0.4
  displayName: Pixie Operator
  publisher: px.dev
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: global-operators
  namespace: ${OPERATOR_NS}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: pixie-operator-subscription
  namespace: ${OPERATOR_NS}
spec:
  channel: stable
  name: pixie-operator
  source: pixie-operator-index
  sourceNamespace: ${OPERATOR_NS}
  installPlanApproval: Automatic
EOF
  log "waiting for the operator to become available"
  for _ in $(seq 1 60); do
    kubectl -n "${OPERATOR_NS}" get deploy vizier-operator >/dev/null 2>&1 && break
    sleep 5
  done
  kubectl -n "${OPERATOR_NS}" rollout status deploy/vizier-operator --timeout=300s
}

deploy_vizier() {
  log "creating Vizier CR in ${PL_NS}"
  kubectl create namespace "${PL_NS}" --dry-run=client -o yaml | kubectl apply -f -

  if [ -n "${PX_DEPLOY_KEY:-}" ]; then
    kubectl -n "${PL_NS}" create secret generic pl-deploy-secrets \
      --from-literal=deploy-key="${PX_DEPLOY_KEY}" \
      --dry-run=client -o yaml | kubectl apply -f -
  else
    echo "WARNING: PX_DEPLOY_KEY is unset — vizier will come up but cannot register with Pixie Cloud." >&2
    echo "         That is fine for SBoB work: the in-cluster components still run and are profiled." >&2
  fi

  kubectl apply -f - <<EOF
apiVersion: px.dev/v1alpha1
kind: Vizier
metadata:
  name: pixie
  namespace: ${PL_NS}
spec:
  version: ${PX_VIZIER_VERSION:-0.14.20}
  cloudAddr: ${PX_CLOUD_ADDR}
  deployKey: ""
  disableAutoUpdate: true
  pemMemoryLimit: 1Gi
EOF

  log "waiting for the vizier mesh"
  for _ in $(seq 1 90); do
    running=$(kubectl -n "${PL_NS}" get pods --no-headers 2>/dev/null | grep -c ' Running ' || true)
    [ "${running:-0}" -ge 5 ] && break
    sleep 10
  done
  kubectl -n "${PL_NS}" get pods -o wide
}

# ------------------------------------------------------------------ sbob ----

apply_cp() {  # cp-file
  sed "0,/^  namespace:/{s/^  namespace: .*/  namespace: ${PL_NS}/}" "sbobs/$1" | kubectl apply -f -
}

label_workload() {  # kind  name  profile
  kubectl -n "${PL_NS}" patch "$1" "$2" --type merge \
    -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"kubescape.io/user-defined-profile\":\"$3\"}}}}}"
}

bind_sbobs() {
  log "applying SBoBs to ${PL_NS}"
  for f in sbobs/cp-*.yaml; do
    apply_cp "$(basename "$f")"
  done

  log "labelling workloads so node-agent binds the profiles"
  # node-agent binds a user-defined profile at CONTAINER START, so the label must be on
  # the pod template before the pod is (re)created — hence the roll below.
  label_workload daemonset   vizier-pem             vizier-pem-pem
  label_workload deployment  kelvin                 kelvin
  label_workload deployment  vizier-query-broker    vizier-query-broker
  label_workload deployment  vizier-cloud-connector vizier-cloud-connector
  label_workload statefulset vizier-metadata        vizier-metadata
  label_workload statefulset pl-nats                pl-nats-pl-nats

  if [ "${RECREATE}" = "1" ]; then
    log "rolling workloads so pods are born with the label"
    kubectl -n "${PL_NS}" rollout restart daemonset/vizier-pem \
      deployment/kelvin deployment/vizier-query-broker deployment/vizier-cloud-connector \
      statefulset/vizier-metadata statefulset/pl-nats
    kubectl -n "${PL_NS}" rollout status daemonset/vizier-pem --timeout=300s
    kubectl -n "${PL_NS}" rollout status deployment/kelvin --timeout=300s
  fi

  log "NOTE: px-operator reconciles the Vizier CR. A vizier version change or an operator"
  echo   "      resync can drop these pod-template labels — re-run './distros.sh sbob' after"
  echo   "      any vizier upgrade, and re-check with './distros.sh status'."
}

# ---------------------------------------------------------------- status ----

status() {
  log "vizier pods and bound profiles (${PL_NS})"
  kubectl -n "${PL_NS}" get pods \
    -o custom-columns='POD:.metadata.name,NODE:.spec.nodeName,PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,STATUS:.status.phase'
  log "user-defined ContainerProfiles"
  kubectl -n "${PL_NS}" get containerprofiles \
    -o custom-columns='NAME:.metadata.name,MANAGED-BY:.metadata.annotations.kubescape\.io/managed-by' 2>/dev/null || true
}

case "${1:-all}" in
  deploy) deploy_olm; deploy_operator; deploy_vizier ;;
  sbob)   bind_sbobs ;;
  all)    deploy_olm; deploy_operator; deploy_vizier; bind_sbobs; status ;;
  status) status ;;
  *)
    echo "usage: $0 [deploy|sbob|all|status]" >&2
    exit 2
    ;;
esac
