#!/usr/bin/env bash
# Drive a full Argo CD workload for the duration of the node-agent learn window.
#
# WHY THIS EXISTS: bob#170. The argocd SBoBs were learned from an Argo CD with
# ZERO Applications, so they captured the control plane idling — no git clone,
# no render, no reconcile. Applied to a working install they produced thousands
# of false positives, because the profile had never seen the app do its job
# (5 execs vs 10, 51 opens vs 517, egress null vs github.com:443).
#
# A learn window is only as good as the load running through it. The first
# version of this script drove three Applications through one render path each.
# That was enough to prove the point but not enough to be a baseline: it never
# ran jsonnet, never resolved a Helm dependency (so repo-server never dialled a
# chart repo), never ran a sync hook, and never touched rollback. A profile
# learned from it calls all of those anomalous.
#
# So this exercises Argo CD's four NATIVE render paths and the operations built
# on top of them:
#
#   RENDER   plain directory · Helm · Kustomize · Jsonnet (incl. top-level args)
#            Helm dependency resolution -> EXTERNAL chart-repo egress
#            directory recursion over a many-manifest tree
#   SYNC     automated sync, self-heal, prune, manual sync, selective refresh
#            PreSync/PostSync hooks and Helm hooks (both create Jobs)
#            sync waves (ordered application)
#   HISTORY  parameter change -> new revision -> rollback
#   FANOUT   ApplicationSet via list AND git-directory generators
#            app-of-apps (an Application whose manifests are Applications)
#   API      argocd-server read+write path, metrics scrape, redis cache traffic
#
# Component coverage:
#   argocd-repo-server            git clone/fetch, helm, kustomize, jsonnet, gpg
#   argocd-application-controller reconcile, sync, hooks, prune, self-heal
#   argocd-applicationset-controller  two generator types
#   argocd-server                 API read + write
#   argocd-redis                  cache traffic
#   argocd-notifications-controller trigger evaluation on state change
#
# HEAVY APPS ARE RENDER-ONLY. sock-shop and blue-green are left on manual sync:
# repo-server still clones and renders them on every refresh, which is what we
# want for the baseline, but nothing is deployed — syncing sock-shop would put
# ~10 services on the laptop for no extra profile coverage.
#
# Run it for AT LEAST the learn window. The live value is
# maxSniffingTimePerContainer in the node-agent ConfigMap.
#
#   ./drive-gitops-workload.sh 900     # seconds
set -uo pipefail
DURATION="${1:-900}"
NS=argocd
REPO="https://github.com/argoproj/argocd-example-apps.git"
DEST_NS=gitops-demo

log() { echo "[$(date +%H:%M:%S)] $*"; }
api() { kubectl get --raw "/api/v1/namespaces/$NS/services/https:argocd-server:443/proxy/$1" 2>/dev/null; }

# app <name> <path> <sync-policy-block> [extra source yaml]
app() {
  local name=$1 path=$2 policy=$3 extra=${4:-}
  kubectl apply -f - >/dev/null 2>&1 <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: $name, namespace: $NS}
spec:
  project: default
  source:
    repoURL: "$REPO"
    path: $path
    targetRevision: HEAD
$extra
  destination: {server: "https://kubernetes.default.svc", namespace: $DEST_NS}
  syncPolicy: $policy
EOF
}

AUTO='{automated: {prune: true, selfHeal: true}, syncOptions: ["CreateNamespace=true"]}'
MANUAL='{syncOptions: ["CreateNamespace=true"]}'

seed_render_paths() {
  # One Application per native config-management tool. These are the render
  # paths repo-server forks a different binary for; without each of them the
  # corresponding binary never appears in the profile.
  app guestbook            guestbook            "$AUTO"    # plain directory
  app helm-guestbook       helm-guestbook       "$AUTO"    # helm template
  app kustomize-guestbook  kustomize-guestbook  "$AUTO"    # kustomize build
  app jsonnet-guestbook    jsonnet-guestbook    "$AUTO"    # jsonnet

  # Jsonnet with top-level arguments — a distinct code path from plain jsonnet.
  app jsonnet-tla jsonnet-guestbook-tla "$AUTO" \
'    directory:
      jsonnet:
        tlas:
          - {name: replicas, value: "1"}'

  # Helm chart with a dependency. Resolving it makes repo-server fetch from an
  # EXTERNAL chart repository, which is the only thing here that produces
  # non-github egress. Without it the profile learns github:443 and nothing else.
  app helm-dependency helm-dependency "$MANUAL"

  # Helm parameter override — exercises the parameter path rather than plain
  # `helm template`, and gives the app a second revision to roll back to.
  app helm-params helm-guestbook "$AUTO" \
'    helm:
      parameters:
        - {name: replicaCount, value: "1"}'

  # Directory recursion over a many-manifest tree. Render-only (see header).
  app sock-shop sock-shop "$MANUAL" \
'    directory: {recurse: true}'
}

seed_hooks_and_waves() {
  # Hooks and waves make the CONTROLLER do work it otherwise never does: it
  # creates hook Jobs, waits for them, and orders resources across waves.
  app pre-post-sync pre-post-sync "$AUTO"   # PreSync + PostSync Jobs
  app sync-waves    sync-waves    "$AUTO"   # wave-ordered apply + hooks
  app helm-hooks    helm-hooks    "$MANUAL" # helm-native hooks, render-only
}

seed_app_of_apps() {
  # An Application whose rendered manifests are themselves Applications. Drives
  # a second reconcile generation through the controller.
  app bob-app-of-apps apps "$MANUAL"
}

seed_appsets() {
  # Two generator types. The list generator is static; the git-directory
  # generator makes the applicationset-controller itself clone the repo and
  # enumerate directories — a different code path with its own git traffic.
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
---
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata: {name: bob-gitgen, namespace: $NS}
spec:
  generators:
    - git:
        repoURL: "$REPO"
        revision: HEAD
        directories:
          - path: guestbook
          - path: jsonnet-guestbook
  template:
    metadata: {name: 'git-{{path.basename}}'}
    spec:
      project: default
      source: {repoURL: "$REPO", path: '{{path}}', targetRevision: HEAD}
      destination: {server: "https://kubernetes.default.svc", namespace: $DEST_NS}
      syncPolicy: {automated: {prune: true}, syncOptions: ["CreateNamespace=true"]}
EOF
}

ALL_APPS="guestbook helm-guestbook kustomize-guestbook jsonnet-guestbook jsonnet-tla
          helm-dependency helm-params sock-shop pre-post-sync sync-waves helm-hooks
          bob-app-of-apps gen-guestbook gen-kustomize git-guestbook git-jsonnet-guestbook"

log "seeding render paths (directory/helm/kustomize/jsonnet/dependency/recurse)"
seed_render_paths
log "seeding hooks + sync waves"
seed_hooks_and_waves
log "seeding app-of-apps"
seed_app_of_apps
log "seeding ApplicationSets (list + git-directory generators)"
seed_appsets

END=$((SECONDS + DURATION))
round=0
while [ $SECONDS -lt $END ]; do
  round=$((round + 1))

  # Hard refresh bypasses the manifest cache, forcing repo-server to re-clone
  # and re-render. Without this the render toolchain runs once and the rest of
  # the window is cache hits. Alternate with a normal refresh, which is the
  # cheaper path a real install spends most of its time in.
  REFRESH=hard; [ $((round % 2)) -eq 0 ] && REFRESH=normal
  for a in $ALL_APPS; do
    kubectl -n $NS annotate application "$a" \
      "argocd.argoproj.io/refresh=$REFRESH" --overwrite >/dev/null 2>&1
  done

  # A transient app exercises the create -> render -> sync -> delete lifecycle
  # (and the controller's prune path) rather than only steady-state reconcile.
  app "transient-$((round % 3))" guestbook "{automated: {prune: true}, syncOptions: [\"CreateNamespace=true\"]}"

  # Manual sync through the API — the write path, distinct from the controller's
  # own automated sync loop.
  for a in helm-dependency helm-hooks bob-app-of-apps sock-shop; do
    api "api/v1/applications/$a/sync" >/dev/null 2>&1
  done

  # Rollback: flip a Helm parameter so the app gains a new revision, then ask
  # for history. Exercises the controller's revision bookkeeping and makes
  # repo-server re-render the previous revision.
  if [ $((round % 3)) -eq 0 ]; then
    REPL=$(( (round / 3 % 2) + 1 ))
    kubectl -n $NS patch application helm-params --type=merge >/dev/null 2>&1 \
      -p "{\"spec\":{\"source\":{\"helm\":{\"parameters\":[{\"name\":\"replicaCount\",\"value\":\"$REPL\"}]}}}}"
    api "api/v1/applications/helm-params/revisions/HEAD/metadata" >/dev/null 2>&1
  fi

  # A resource action on a live workload (restart), which the controller applies
  # through its own action machinery rather than a plain sync.
  if [ $((round % 4)) -eq 0 ]; then
    kubectl -n $DEST_NS rollout restart deploy/guestbook-ui >/dev/null 2>&1
  fi

  # API read path on argocd-server (also warms argocd-redis).
  for ep in version settings applications projects clusters repositories certificates gpgkeys applicationsets; do
    api "api/v1/$ep" >/dev/null 2>&1
  done
  api "api/version" >/dev/null 2>&1

  # Metrics endpoints — what Prometheus scrapes in a normal install.
  for svc in argocd-metrics:8082 argocd-repo-server:8084 argocd-applicationset-controller:8080 argocd-notifications-controller-metrics:9001; do
    kubectl get --raw "/api/v1/namespaces/$NS/services/$svc/proxy/metrics" >/dev/null 2>&1
  done

  if [ $((round % 4)) -eq 0 ]; then
    kubectl -n $NS delete application "transient-$(((round - 1) % 3))" --ignore-not-found >/dev/null 2>&1
  fi

  log "round $round  ($((END - SECONDS))s left)  refresh=$REFRESH +sync +rollback +api +metrics"
  sleep 20
done

log "workload complete after $round rounds"
kubectl get applications -n $NS \
  -o custom-columns=NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status \
  --no-headers 2>/dev/null
