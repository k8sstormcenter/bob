#!/usr/bin/env bash
# Deploy the four redis-protocol distros via their most-popular native installer,
# EXACTLY PINNED (chart version + image digest) so the learned SBoBs in sbobs/
# are strongly versioned and reproducible. One namespace each.
#
#   distro     chart / operator          app ver   image (pinned by digest/tag)
#   redis      bitnami/redis 27.0.18     8.8.1     bitnami/redis@sha256:08863c2c…
#   valkey     bitnami/valkey 6.2.5      9.1.1     bitnami/valkey@sha256:4a1c16ea…
#   keydb      enapter/keydb 0.48.0      6.3.2     eqalpha/keydb:x86_64_v6.3.2
#   dragonfly  dragonfly-operator 1.6.1  1.39.0    dragonflydb/dragonfly:v1.39.0
set -euo pipefail

helm install redis oci://registry-1.docker.io/bitnamicharts/redis --version 27.0.18 \
  --set architecture=standalone --set auth.enabled=false \
  --set image.repository=bitnami/redis \
  --set image.digest=sha256:08863c2c3f4e051fb6139b38fa223e9c13be5033326a59bead182860d899bf98 \
  -n redis --create-namespace

helm install valkey oci://registry-1.docker.io/bitnamicharts/valkey --version 6.2.5 \
  --set architecture=standalone --set auth.enabled=false \
  --set image.repository=bitnami/valkey \
  --set image.digest=sha256:4a1c16ea2ece2baea6c1d7a116c00060f5bfbf1d2807b703a552ba840c87956e \
  -n valkey --create-namespace

helm repo add enapter https://enapter.github.io/charts/ >/dev/null
helm repo update >/dev/null
helm install keydb enapter/keydb --version 0.48.0 \
  --set image.repository=eqalpha/keydb --set image.tag=x86_64_v6.3.2 \
  -n keydb --create-namespace

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
