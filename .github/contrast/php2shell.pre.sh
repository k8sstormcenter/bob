#!/usr/bin/env bash
# Deploys the php2shell example from the published image, without a preset profile label, so it is learned.
set -euo pipefail
IMG="ghcr.io/${GITHUB_REPOSITORY_OWNER}/php2shell-vulnerable"
TAG="$(git rev-parse HEAD:example/php2shell | cut -c1-12)-$(git hash-object example/php2shell/Dockerfile | cut -c1-6)"
echo "${GH_TOKEN}" | docker login ghcr.io -u "${GITHUB_ACTOR}" --password-stdin
docker pull -q "$IMG:$TAG"
docker tag "$IMG:$TAG" php2shell-vulnerable:demo
docker save php2shell-vulnerable:demo | sudo k3s ctr images import -
sed -e 's#ghcr.io/k8sstormcenter/php2shell-vulnerable:latest#php2shell-vulnerable:demo#' -e '/kubescape.io\/user-defined-profile/d' \
  example/php2shell/php2shell.yaml | kubectl apply -f -
sed -e '/kubescape.io\/user-defined-profile/d' example/php2shell/loadgen.yaml | kubectl apply -f -
kubectl label namespace php2shell bobctl.k8sstormcenter.io/simulation=allowed --overwrite
kubectl -n php2shell rollout status deployment/php2shell --timeout=300s
kubectl -n php2shell-loadgen rollout status deployment/loadgen --timeout=300s
