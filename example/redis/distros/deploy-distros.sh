#!/usr/bin/env bash
# Deploy the redis-protocol distros via their most-popular native installer,
# EXACTLY PINNED (chart version + image digest) so the learned SBoBs in sbobs/
# are strongly versioned and reproducible. One namespace each.
#
#   distro     chart / operator          app ver   image (pinned by digest/tag)
#   redis      bitnami/redis 27.0.18     8.8.1     bitnami/redis@sha256:08863c2c…
#   valkey     bitnami/valkey 6.2.5      9.1.1     bitnami/valkey@sha256:4a1c16ea…
#   keydb      enapter/keydb 0.48.0      6.3.2     eqalpha/keydb:x86_64_v6.3.2
#   dragonfly  dragonfly-operator 1.6.1  1.39.0    dragonflydb/dragonfly:v1.39.0
#
# Usage:
#   ./deploy-distros.sh [redis|valkey|keydb|dragonfly|all] [sbob]
#   (no first argument = all; pass "sbob" as the second argument to bind the
#    matching ContainerProfile from sbobs/ at deploy time)
set -euo pipefail
cd "$(dirname "$0")"

SBOB="${2:-}"

deploy_redis() {
  helm install redis oci://registry-1.docker.io/bitnamicharts/redis --version 27.0.18 \
    --set architecture=standalone --set auth.enabled=false \
    --set image.repository=bitnami/redis \
    --set image.digest=sha256:08863c2c3f4e051fb6139b38fa223e9c13be5033326a59bead182860d899bf98 \
    -n redis --create-namespace
}

deploy_valkey() {
  helm install valkey oci://registry-1.docker.io/bitnamicharts/valkey --version 6.2.5 \
    --set architecture=standalone --set auth.enabled=false \
    --set image.repository=bitnami/valkey \
    --set image.digest=sha256:4a1c16ea2ece2baea6c1d7a116c00060f5bfbf1d2807b703a552ba840c87956e \
    -n valkey --create-namespace
}

deploy_keydb() {
  helm repo add enapter https://enapter.github.io/charts/ >/dev/null
  helm repo update >/dev/null
  helm install keydb enapter/keydb --version 0.48.0 \
    --set image.repository=eqalpha/keydb --set image.tag=x86_64_v6.3.2 \
    -n keydb --create-namespace
}

deploy_dragonfly() {
  kubectl apply --server-side \
    -f https://raw.githubusercontent.com/dragonflydb/dragonfly-operator/v1.6.1/manifests/dragonfly-operator.yaml
  kubectl -n dragonfly-operator-system rollout status \
    deploy/dragonfly-operator-controller-manager --timeout=150s
  kubectl create namespace dragonfly
  kubectl apply -f - <<'CR'
apiVersion: dragonflydb.io/v1alpha1
kind: Dragonfly
metadata:
  name: dragonfly
  namespace: dragonfly
spec:
  replicas: 1
  image: docker.dragonflydb.io/dragonflydb/dragonfly:v1.39.0
CR
}

# --- SBoB binding (only when the "sbob" toggle is passed) -------------------
# Apply the ContainerProfile into the install namespace (its committed namespace
# is overridden at apply time, not in the file) and label the workload's pod so
# node-agent enforces it. StatefulSet pods for redis/valkey/keydb; the operator
# CR for dragonfly (patching the StatefulSet there is reverted by the operator).
apply_cp() {  # ns  cp-file
  sed "0,/^  namespace:/{s/^  namespace: .*/  namespace: $1/}" "sbobs/$2" | kubectl apply -f -
}
label_sts() {  # ns  statefulset  profile
  kubectl -n "$1" patch statefulset "$2" --type merge \
    -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"kubescape.io/user-defined-profile\":\"$3\"}}}}}"
}

bind_redis()  { apply_cp redis  cp-redis.yaml;  label_sts redis  redis-master   redis; }
bind_valkey() { apply_cp valkey cp-valkey.yaml; label_sts valkey valkey-primary valkey; }
bind_keydb()  { apply_cp keydb  cp-keydb.yaml;  label_sts keydb  keydb          keydb; }
bind_dragonfly() {
  apply_cp dragonfly cp-dragonfly.yaml
  kubectl -n dragonfly patch dragonfly dragonfly --type merge \
    -p '{"spec":{"podMetadata":{"labels":{"kubescape.io/user-defined-profile":"dragonfly"}}}}'
}

do_distro() {  # deploy-fn  bind-fn
  "$1"
  [ "$SBOB" = sbob ] && "$2" || true
}

distro="${1:-all}"
case "$distro" in
  redis)     do_distro deploy_redis     bind_redis ;;
  valkey)    do_distro deploy_valkey    bind_valkey ;;
  keydb)     do_distro deploy_keydb     bind_keydb ;;
  dragonfly) do_distro deploy_dragonfly bind_dragonfly ;;
  all)       do_distro deploy_redis bind_redis; do_distro deploy_valkey bind_valkey; do_distro deploy_keydb bind_keydb; do_distro deploy_dragonfly bind_dragonfly ;;
  *)
    echo "unknown distro: $distro" >&2
    echo "usage: $0 [redis|valkey|keydb|dragonfly|all] [sbob]" >&2
    exit 2
    ;;
esac
