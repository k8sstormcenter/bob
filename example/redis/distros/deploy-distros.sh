#!/usr/bin/env bash
# Deploy a redis-protocol distro via its most-popular native installer AND bind
# its SBoB in one shot: the pod carries the kubescape.io/user-defined-profile
# label (baked into the helm values / operator CR) and the matching
# ContainerProfile from sbobs/ is applied, so node-agent enforces the SBoB from
# the moment the pod starts — no post-deploy patching.
#
#   distro     installer                       ns          bound profile
#   redis-oss  bitnami/redis 27.0.18           redis-oss   sbobs/cp-redis.yaml
#   valkey     bitnami/valkey 6.2.5            valkey      sbobs/cp-valkey.yaml
#   keydb      enapter/keydb 0.48.0            keydb       sbobs/cp-keydb.yaml
#   dragonfly  dragonfly-operator 1.6.1        dragonfly   sbobs/cp-dragonfly.yaml
#
# Usage:
#   ./deploy-distros.sh [redis|valkey|keydb|dragonfly|all]   (no arg = all)
set -euo pipefail
cd "$(dirname "$0")"

deploy_redis() {
  helm install redis oci://registry-1.docker.io/bitnamicharts/redis --version 27.0.18 \
    -n redis-oss --create-namespace -f helm-values/redis-oss.yaml
  kubectl apply -f sbobs/cp-redis.yaml
}

deploy_valkey() {
  helm install valkey oci://registry-1.docker.io/bitnamicharts/valkey --version 6.2.5 \
    -n valkey --create-namespace -f helm-values/valkey.yaml
  kubectl apply -f sbobs/cp-valkey.yaml
}

deploy_keydb() {
  helm repo add enapter https://enapter.github.io/charts/ >/dev/null
  helm repo update >/dev/null
  helm install keydb enapter/keydb --version 0.48.0 \
    -n keydb --create-namespace -f helm-values/keydb.yaml
  kubectl apply -f sbobs/cp-keydb.yaml
}

deploy_dragonfly() {
  kubectl apply --server-side \
    -f https://raw.githubusercontent.com/dragonflydb/dragonfly-operator/v1.6.1/manifests/dragonfly-operator.yaml
  kubectl -n dragonfly-operator-system rollout status \
    deploy/dragonfly-operator-controller-manager --timeout=150s
  kubectl create namespace dragonfly
  # podMetadata.labels is the operator-supported way to label the managed pod;
  # patching the StatefulSet directly is reverted by the operator.
  kubectl apply -f - <<'CR'
apiVersion: dragonflydb.io/v1alpha1
kind: Dragonfly
metadata:
  name: dragonfly
  namespace: dragonfly
spec:
  replicas: 1
  image: docker.dragonflydb.io/dragonflydb/dragonfly:v1.39.0
  podMetadata:
    labels:
      kubescape.io/user-defined-profile: dragonfly
CR
  kubectl apply -f sbobs/cp-dragonfly.yaml
}

distro="${1:-all}"
case "$distro" in
  redis|redis-oss) deploy_redis ;;
  valkey)          deploy_valkey ;;
  keydb)           deploy_keydb ;;
  dragonfly)       deploy_dragonfly ;;
  all)             deploy_redis; deploy_valkey; deploy_keydb; deploy_dragonfly ;;
  *)
    echo "unknown distro: $distro" >&2
    echo "usage: $0 [redis|valkey|keydb|dragonfly|all]" >&2
    exit 2
    ;;
esac
