#!/usr/bin/env bash
# Deploys the php2shell-wordpress example from the published image, without a preset profile label, so it is learned.
set -euo pipefail
IMG="ghcr.io/${GITHUB_REPOSITORY_OWNER}/php2shell-wordpress"
TAG="$(git rev-parse HEAD:example/php2shell-wordpress | cut -c1-12)-$(git hash-object example/php2shell-wordpress/Dockerfile | cut -c1-6)"
echo "${GH_TOKEN}" | docker login ghcr.io -u "${GITHUB_ACTOR}" --password-stdin
docker pull -q "$IMG:$TAG"
docker tag "$IMG:$TAG" php2shell-wordpress:demo
docker save php2shell-wordpress:demo | sudo k3s ctr images import -
for f in mariadb wordpress loadgen; do
  sed -e 's#ghcr.io/k8sstormcenter/php2shell-wordpress:latest#php2shell-wordpress:demo#' -e '/kubescape.io\/user-defined-profile/d' \
    "example/php2shell-wordpress/$f.yaml" | kubectl apply -f -
done
kubectl label namespace wordpress bobctl.k8sstormcenter.io/simulation=allowed --overwrite
kubectl -n wordpress-db rollout status deployment/mariadb --timeout=300s
kubectl -n wordpress rollout status deployment/wordpress --timeout=300s
kubectl -n wordpress-loadgen rollout status deployment/loadgen --timeout=420s
