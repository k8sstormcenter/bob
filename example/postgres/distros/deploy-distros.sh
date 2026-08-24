#!/usr/bin/env bash
# Deploy the PostgreSQL packaging distros via their most-popular native installer,
# EXACTLY PINNED so the learned SBoBs in sbobs/ are reproducible. One namespace
# each. Every distro runs the SAME postgres:17 pg-client pod, so a SINGLE portable
# client SBoB (sbobs/cp-pg-client.yaml) is the contrast leg across all three
# backends; each backend also gets its own server SBoB (sbobs/cp-postgres-<fork>.yaml).
#
#   distro     installer                         server image
#   oss        plain Deployment (this manifest)  postgres:17
#   bitnami    helm bitnami/postgresql 16.x       bitnami/postgresql
#   cnpg       CloudNativePG operator 1.24.1      ghcr.io/cloudnative-pg/postgresql:17.5
#
# Usage:
#   ./deploy-distros.sh [oss|bitnami|cnpg|all] [sbob]
#   (no first argument = all; pass "sbob" as the second argument to bind the
#    matching server + client ContainerProfiles from sbobs/ at deploy time)
set -euo pipefail
cd "$(dirname "$0")"

SBOB="${2:-}"

deploy_oss() {
  kubectl apply -f postgres-oss.yaml
  kubectl -n postgres-oss rollout status deploy/postgres --timeout=180s
  kubectl -n postgres-oss wait --for=condition=ready pod/pg-client --timeout=60s
}

deploy_bitnami() {
  helm install pg-bitnami oci://registry-1.docker.io/bitnamicharts/postgresql \
    --set auth.database=app --set auth.username=app \
    --set auth.password=bobtest --set auth.postgresPassword=bobtest \
    --set primary.persistence.enabled=false \
    -n postgres-bitnami --create-namespace
  kubectl apply -f postgres-bitnami.yaml
  kubectl -n postgres-bitnami rollout status statefulset/pg-bitnami-postgresql --timeout=180s
  kubectl -n postgres-bitnami wait --for=condition=ready pod/pg-client --timeout=60s
}

deploy_cnpg() {
  kubectl apply --server-side \
    -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.1.yaml
  kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager --timeout=180s
  kubectl apply -f postgres-cnpg.yaml
  kubectl -n postgres-cnpg wait --for=condition=ready pod -l cnpg.io/cluster=pg --timeout=240s
  kubectl -n postgres-cnpg wait --for=condition=ready pod/pg-client --timeout=60s
}

# --- SBoB binding (only when the "sbob" toggle is passed) -------------------
# Apply a ContainerProfile into the install namespace (committed namespace is
# overridden at apply time, not in the file) and label the workload's pod so
# node-agent enforces it. The client profile is shared; the server profile is
# per-fork.
apply_cp() {  # ns  cp-file  profile-name
  sed "0,/^  namespace:/{s/^  namespace: .*/  namespace: $1/}" "sbobs/$2" | kubectl apply -f -
}
# pg-client is a bare Pod, so node-agent only enforces the shared profile if the
# pod is BORN with the label — recreate it from its manifest with the label injected.
bind_client() {  # ns  manifest
  apply_cp "$1" cp-pg-client.yaml pg-client
  kubectl -n "$1" delete pod pg-client --ignore-not-found
  sed '/app.kubernetes.io\/name: pg-client/a\    kubescape.io/user-defined-profile: pg-client' "$2" \
    | kubectl apply -f -
  kubectl -n "$1" wait --for=condition=ready pod/pg-client --timeout=60s
}

bind_oss() {
  apply_cp postgres-oss cp-postgres-oss.yaml postgres-oss
  kubectl -n postgres-oss patch deploy postgres --type merge \
    -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"postgres-oss"}}}}}'
  bind_client postgres-oss postgres-oss.yaml
}
bind_bitnami() {
  apply_cp postgres-bitnami cp-postgres-bitnami.yaml postgres-bitnami
  kubectl -n postgres-bitnami patch statefulset pg-bitnami-postgresql --type merge \
    -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"postgres-bitnami"}}}}}'
  bind_client postgres-bitnami postgres-bitnami.yaml
}
bind_cnpg() {
  apply_cp postgres-cnpg cp-postgres-cnpg.yaml postgres-cnpg
  # node-agent only switches to a user-defined profile when the label is present
  # at pod birth. A live `kubectl label` on the running pod does NOT rebind. CNPG's
  # inheritedMetadata propagates the label to instance pods AND survives operator
  # reconciles; recreate the instance pod so it is born with the label enforced.
  kubectl -n postgres-cnpg patch cluster pg --type merge \
    -p '{"spec":{"inheritedMetadata":{"labels":{"kubescape.io/user-defined-profile":"postgres-cnpg"}}}}'
  kubectl -n postgres-cnpg delete pod -l cnpg.io/cluster=pg --wait=false
  kubectl -n postgres-cnpg wait --for=condition=ready pod -l cnpg.io/cluster=pg --timeout=180s
  bind_client postgres-cnpg postgres-cnpg.yaml
}

do_distro() {  # deploy-fn  bind-fn
  "$1"
  [ "$SBOB" = sbob ] && "$2" || true
}

distro="${1:-all}"
case "$distro" in
  oss)     do_distro deploy_oss     bind_oss ;;
  bitnami) do_distro deploy_bitnami bind_bitnami ;;
  cnpg)    do_distro deploy_cnpg    bind_cnpg ;;
  all)     do_distro deploy_oss bind_oss; do_distro deploy_bitnami bind_bitnami; do_distro deploy_cnpg bind_cnpg ;;
  *)
    echo "unknown distro: $distro" >&2
    echo "usage: $0 [oss|bitnami|cnpg|all] [sbob]" >&2
    exit 2
    ;;
esac
