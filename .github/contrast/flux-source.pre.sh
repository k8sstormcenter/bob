#!/usr/bin/env bash
# Installs upstream Flux with all six controllers and starts the GitOps load driver for the whole job.
set -euo pipefail
VER=2.10.1
SUM=967365ff84aabc97871827ff33713ef0c09f62dd83c18759e3a5e39adcea9285
BIN="$GITHUB_WORKSPACE/bin"
mkdir -p "$BIN"
if [ ! -x "$BIN/flux" ]; then
  curl -fsSL -o /tmp/flux.tgz "https://github.com/fluxcd/flux2/releases/download/v$VER/flux_${VER}_linux_amd64.tar.gz"
  echo "$SUM  /tmp/flux.tgz" | sha256sum -c -
  tar -xzf /tmp/flux.tgz -C "$BIN" flux
fi
"$BIN/flux" install --namespace=flux-system --components-extra=image-reflector-controller,image-automation-controller --export | kubectl apply -f -
kubectl apply -f example/flux/metrics-services.yaml
kubectl label namespace flux-system bobctl.k8sstormcenter.io/simulation=allowed --overwrite
for c in source kustomize helm notification image-reflector image-automation; do
  kubectl -n flux-system rollout status "deployment/$c-controller" --timeout=300s
done
FLUX="$BIN/flux" nohup bash -c 'example/flux/drive-gitops-workload.sh 4200 2>&1 | tee "$GITHUB_WORKSPACE/out/flux-driver.log" | sed -un "s/.*round \([0-9]*\) .*/workload-cycle-ok \1/p" > "$GITHUB_WORKSPACE/out/usual-traffic.log"' > /dev/null 2>&1 &
echo "flux $VER installed; load driver started"
