#!/usr/bin/env bash
# Drive a full Argo CD workload for the duration of the node-agent learn window.
#
# WHY THIS EXISTS: bob#170. The argocd SBoBs were learned from an Argo CD with
# ZERO Applications, so they captured the control plane idling — no git clone,
# no render, no reconcile. Applied to a working install they produced thousands
# of false positives, because the profile had never seen the app do its job
# (5 execs vs 10, 51 opens vs 517, egress null vs github.com:443).
#
# A learn window is only as good as the load running through it. This drives the
# DEFAULT actions a real Argo CD performs, so every component contributes to its
# own baseline:
#
#   argocd-repo-server           git clone + helm render + kustomize render
#   argocd-application-controller reconcile, sync, self-heal, prune
#   argocd-applicationset-controller  generates Applications from a generator
#   argocd-server                API read + write path
#   argocd-redis                 cache traffic from server and controller
#   argocd-notifications-controller  trigger evaluation on app state change
#
# Run it for AT LEAST the learn window (kubescape/values.yaml learningPeriod).
#
#   ./drive-gitops-workload.sh 900     # seconds
set -uo pipefail
DURATION="${1:-900}"
NS=argocd
REPO="https://github.com/argoproj/argocd-example-apps.git"
DEST_NS=gitops-demo

log() { echo "[$(date +%H:%M:%S)] $*"; }

apply_apps() {
  for p in guestbook helm-guestbook kustomize-guestbook; do
    kubectl apply -f - >/dev/null 2>&1 <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: $p, namespace: $NS}
spec:
  project: default
  source: {repoURL: "$REPO", path: $p, targetRevision: HEAD}
  destination: {server: "https://kubernetes.default.svc", namespace: $DEST_NS}
  syncPolicy: {automated: {prune: true, selfHeal: true}, syncOptions: ["CreateNamespace=true"]}
EOF
  done
}

apply_appset() {
  # Exercises argocd-applicationset-controller, which otherwise never runs: it
  # generates Applications, which in turn drive repo-server and the controller.
  kubectl apply -f - >/dev/null 2>&1 <<EOF
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata: {name: bob-generated, namespace: $NS}
spec:
  generators:
    - list:
        elements:
          - {name: gen-guestbook, path: guestbook}
          - {name: gen-kustomize, path: kustomize-guestbook}
  template:
    metadata: {name: '{{name}}'}
    spec:
      project: default
      source: {repoURL: "$REPO", path: '{{path}}', targetRevision: HEAD}
      destination: {server: "https://kubernetes.default.svc", namespace: $DEST_NS}
      syncPolicy: {automated: {prune: true, selfHeal: true}, syncOptions: ["CreateNamespace=true"]}
EOF
}

log "seeding Applications + ApplicationSet"
apply_apps
apply_appset

END=$((SECONDS + DURATION))
round=0
while [ $SECONDS -lt $END ]; do
  round=$((round + 1))

  # Hard refresh bypasses the manifest cache, forcing repo-server to re-clone
  # and re-render. Without this the render toolchain runs once and the rest of
  # the window is cache hits.
  for a in guestbook helm-guestbook kustomize-guestbook gen-guestbook gen-kustomize; do
    kubectl -n $NS annotate application "$a" argocd.argoproj.io/refresh=hard --overwrite >/dev/null 2>&1
  done

  # A transient app exercises the create -> render -> sync -> delete lifecycle
  # (and the controller's prune path) rather than only steady-state reconcile.
  kubectl apply -f - >/dev/null 2>&1 <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: transient-$((round % 3)), namespace: $NS}
spec:
  project: default
  source: {repoURL: "$REPO", path: guestbook, targetRevision: HEAD}
  destination: {server: "https://kubernetes.default.svc", namespace: $DEST_NS}
  syncPolicy: {automated: {prune: true}, syncOptions: ["CreateNamespace=true"]}
EOF

  # API read path on argocd-server (also warms argocd-redis).
  for ep in version settings applications projects clusters repositories certificates gpgkeys applicationsets; do
    kubectl get --raw \
      "/api/v1/namespaces/$NS/services/https:argocd-server:443/proxy/api/v1/$ep" >/dev/null 2>&1
  done
  kubectl get --raw "/api/v1/namespaces/$NS/services/https:argocd-server:443/proxy/api/version" >/dev/null 2>&1

  # Metrics endpoints — what Prometheus scrapes in a normal install.
  for svc in argocd-metrics:8082 argocd-repo-server:8084 argocd-applicationset-controller:8080 argocd-notifications-controller-metrics:9001; do
    kubectl get --raw "/api/v1/namespaces/$NS/services/$svc/proxy/metrics" >/dev/null 2>&1
  done

  if [ $((round % 4)) -eq 0 ]; then
    kubectl -n $NS delete application "transient-$(((round - 1) % 3))" --ignore-not-found >/dev/null 2>&1
  fi

  log "round $round  ($((END - SECONDS))s left)  refresh+lifecycle+api+metrics"
  sleep 20
done

log "workload complete after $round rounds"
kubectl get applications -n $NS -o custom-columns=NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status --no-headers 2>/dev/null
