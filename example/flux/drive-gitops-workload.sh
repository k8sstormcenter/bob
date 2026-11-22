#!/usr/bin/env bash
set -uo pipefail
DURATION="${1:-900}"
NS=flux-system
APP_NS=flux-demo
REPO=https://github.com/fluxcd/flux2-kustomize-helm-example
PODINFO=https://github.com/stefanprodan/podinfo
FLUX="${FLUX:-$(command -v flux 2>/dev/null || echo /mnt/dev-data/bin/flux)}"

log() { echo "[$(date +%H:%M:%S)] $*"; }
kap() { kubectl apply -f - >/dev/null 2>&1; }

kubectl create ns "$APP_NS" --dry-run=client -o yaml | kap

seed_sources() {
  kap <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: {name: podinfo, namespace: $NS}
spec:
  interval: 1m
  url: $PODINFO
  ref: {branch: master}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: {name: flux-example, namespace: $NS}
spec:
  interval: 1m
  url: $REPO
  ref: {branch: main}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: {name: podinfo-tag, namespace: $NS}
spec:
  interval: 2m
  url: $PODINFO
  ref: {tag: 6.5.4}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata: {name: podinfo-helm, namespace: $NS}
spec:
  interval: 2m
  url: https://stefanprodan.github.io/podinfo
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata: {name: podinfo-oci, namespace: $NS}
spec:
  interval: 2m
  type: oci
  url: oci://ghcr.io/stefanprodan/charts
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata: {name: podinfo-oci-artifact, namespace: $NS}
spec:
  interval: 2m
  url: oci://ghcr.io/stefanprodan/manifests/podinfo
  ref: {tag: latest}
EOF
}

seed_kustomizations() {
  kap <<EOF
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: podinfo-kustomize, namespace: $NS}
spec:
  interval: 1m
  path: ./kustomize
  prune: true
  sourceRef: {kind: GitRepository, name: podinfo}
  targetNamespace: $APP_NS
  timeout: 2m
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: podinfo-oci-kustomize, namespace: $NS}
spec:
  interval: 2m
  path: ./
  prune: true
  sourceRef: {kind: OCIRepository, name: podinfo-oci-artifact}
  targetNamespace: $APP_NS
  timeout: 2m
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: podinfo-substitute, namespace: $NS}
spec:
  interval: 2m
  path: ./kustomize
  prune: true
  sourceRef: {kind: GitRepository, name: podinfo-tag}
  targetNamespace: $APP_NS
  timeout: 2m
  postBuild:
    substitute: {bob_marker: "driven"}
  healthChecks:
    - {apiVersion: apps/v1, kind: Deployment, name: podinfo, namespace: $APP_NS}
EOF
}

seed_helmreleases() {
  kap <<EOF
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: podinfo-http, namespace: $NS}
spec:
  interval: 2m
  targetNamespace: $APP_NS
  chart:
    spec:
      chart: podinfo
      version: '>=6.0.0'
      sourceRef: {kind: HelmRepository, name: podinfo-helm}
  install: {createNamespace: true, remediation: {retries: 1}}
  upgrade: {remediation: {retries: 1}}
  values: {replicaCount: 1, resources: {limits: {cpu: 100m, memory: 64Mi}}}
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: podinfo-oci-release, namespace: $NS}
spec:
  interval: 2m
  targetNamespace: $APP_NS
  releaseName: podinfo-oci
  chart:
    spec:
      chart: podinfo
      sourceRef: {kind: HelmRepository, name: podinfo-oci}
  install: {createNamespace: true}
  values: {replicaCount: 1, resources: {limits: {cpu: 100m, memory: 64Mi}}}
EOF
}

seed_notification() {
  kap <<EOF
apiVersion: notification.toolkit.fluxcd.io/v1beta3
kind: Provider
metadata: {name: bob-generic, namespace: $NS}
spec:
  type: generic
  address: http://alertmanager.honey.svc.cluster.local:9093/api/v2/alerts
---
apiVersion: notification.toolkit.fluxcd.io/v1beta3
kind: Alert
metadata: {name: bob-alert, namespace: $NS}
spec:
  providerRef: {name: bob-generic}
  eventSeverity: info
  eventSources:
    - {kind: GitRepository, name: '*'}
    - {kind: Kustomization, name: '*'}
    - {kind: HelmRelease, name: '*'}
---
apiVersion: notification.toolkit.fluxcd.io/v1
kind: Receiver
metadata: {name: bob-receiver, namespace: $NS}
spec:
  type: generic
  secretRef: {name: bob-receiver-token}
  resources:
    - {kind: GitRepository, name: podinfo}
EOF
  kubectl -n $NS create secret generic bob-receiver-token \
    --from-literal=token=bobtoken --dry-run=client -o yaml | kap
}

seed_image_automation() {
  kap <<EOF
apiVersion: image.toolkit.fluxcd.io/v1beta2
kind: ImageRepository
metadata: {name: podinfo-image, namespace: $NS}
spec:
  interval: 2m
  image: ghcr.io/stefanprodan/podinfo
---
apiVersion: image.toolkit.fluxcd.io/v1beta2
kind: ImagePolicy
metadata: {name: podinfo-semver, namespace: $NS}
spec:
  imageRepositoryRef: {name: podinfo-image}
  policy: {semver: {range: '>=6.0.0'}}
---
apiVersion: image.toolkit.fluxcd.io/v1beta2
kind: ImagePolicy
metadata: {name: podinfo-numeric, namespace: $NS}
spec:
  imageRepositoryRef: {name: podinfo-image}
  filterTags: {pattern: '^6\\.(?P<minor>[0-9]+)\\.[0-9]+$', extract: '\$minor'}
  policy: {numerical: {order: asc}}
EOF
}

log "seeding sources (git branch/tag, helm http, helm oci, oci artifact)"
seed_sources
log "seeding kustomizations (git, oci, postBuild substitute + healthChecks)"
seed_kustomizations
log "seeding helmreleases (http chart, oci chart)"
seed_helmreleases
log "seeding notification (provider, alert, receiver)"
seed_notification
log "seeding image automation (repository, semver + numeric policies)"
seed_image_automation

END=$((SECONDS + DURATION))
round=0
while [ $SECONDS -lt $END ]; do
  round=$((round + 1))

  for k in gitrepository/podinfo gitrepository/flux-example gitrepository/podinfo-tag \
           helmrepository/podinfo-helm helmrepository/podinfo-oci \
           ocirepository/podinfo-oci-artifact imagerepository/podinfo-image; do
    kubectl -n $NS annotate "$k" reconcile.fluxcd.io/requestedAt="$(date +%s%N)" --overwrite >/dev/null 2>&1
  done
  for k in kustomization/podinfo-kustomize kustomization/podinfo-oci-kustomize \
           kustomization/podinfo-substitute helmrelease/podinfo-http helmrelease/podinfo-oci-release; do
    kubectl -n $NS annotate "$k" reconcile.fluxcd.io/requestedAt="$(date +%s%N)" --overwrite >/dev/null 2>&1
  done

  if [ $((round % 3)) -eq 0 ]; then
    R=$(( (round / 3 % 2) + 1 ))
    kubectl -n $NS patch helmrelease podinfo-http --type=merge \
      -p "{\"spec\":{\"values\":{\"replicaCount\":$R}}}" >/dev/null 2>&1
  fi

  if [ $((round % 4)) -eq 0 ]; then
    $FLUX suspend kustomization podinfo-kustomize -n $NS >/dev/null 2>&1
    $FLUX resume  kustomization podinfo-kustomize -n $NS >/dev/null 2>&1
  fi

  if [ $((round % 5)) -eq 0 ]; then
    kap <<EOF
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: transient-$((round % 3)), namespace: $NS}
spec:
  interval: 1m
  path: ./kustomize
  prune: true
  sourceRef: {kind: GitRepository, name: podinfo}
  targetNamespace: $APP_NS
  timeout: 1m
EOF
    kubectl -n $NS delete kustomization "transient-$(((round + 2) % 3))" --ignore-not-found >/dev/null 2>&1
  fi

  $FLUX get all -n $NS >/dev/null 2>&1
  $FLUX events -n $NS --for GitRepository/podinfo >/dev/null 2>&1
  $FLUX stats -n $NS >/dev/null 2>&1
  $FLUX trace kustomization podinfo-kustomize -n $NS >/dev/null 2>&1

  for svc in source-controller:80 notification-controller:80 kustomize-controller:8080 \
             helm-controller:8080 image-reflector-controller:8080 image-automation-controller:8080; do
    kubectl get --raw "/api/v1/namespaces/$NS/services/$svc/proxy/metrics" >/dev/null 2>&1
  done

  log "round $round  ($((END - SECONDS))s left)  reconcile+patch+suspend/resume+cli+metrics"
  sleep 20
done

log "workload complete after $round rounds"
$FLUX get all -n $NS 2>/dev/null | head -30
