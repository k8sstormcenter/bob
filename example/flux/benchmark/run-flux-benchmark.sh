#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_REPO="${UPSTREAM_REPO:-https://github.com/fluxcd/flux-benchmark}"
UPSTREAM_SHA="${UPSTREAM_SHA:-e09c5330d7f8edd3be0c8b47a12655ff30ef8848}"
CACHE_DIR="${CACHE_DIR:-${TMPDIR:-/tmp}/flux-benchmark-${UPSTREAM_SHA:0:12}}"

KS="${KS:-20}"
HR="${HR:-10}"
PODS="${PODS:-0}"
MCPU_INSTALL="${MCPU_INSTALL:-1}"
MCPU_UPGRADE="${MCPU_UPGRADE:-2}"
ROUNDS="${ROUNDS:-1}"
TIMEOUT="${TIMEOUT:-10m}"
REG_PORT="${REG_PORT:-5555}"
CHART_SRC="${CHART_SRC:-ghcr.io/stefanprodan/charts/podinfo:6.5.3}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="${BUNDLE:-$HERE/flux-benchmark.cue}"

PATH="/mnt/dev-data/bin:$HOME/go/bin:$PATH"
for t in kubectl timoni crane; do
  command -v "$t" >/dev/null || { echo "missing required tool: $t" >&2; exit 1; }
done

log() { printf '[bench] %s\n' "$*"; }

PF_PID=""
cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

fetch_upstream() {
  if [ ! -d "$CACHE_DIR/.git" ]; then
    log "cloning $UPSTREAM_REPO @ ${UPSTREAM_SHA:0:12}"
    rm -rf "$CACHE_DIR"
    git clone -q "$UPSTREAM_REPO" "$CACHE_DIR"
  fi
  git -C "$CACHE_DIR" fetch -q origin
  git -C "$CACHE_DIR" checkout -q "$UPSTREAM_SHA"
}

start_registry() {
  kubectl apply -f "$HERE/registry.yaml" >/dev/null
  kubectl -n flux-registry rollout status deploy/flux-registry --timeout=3m >/dev/null
  kubectl -n flux-registry port-forward svc/flux-registry "$REG_PORT:5000" >/dev/null 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "http://localhost:$REG_PORT/v2/" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "registry did not become reachable on localhost:$REG_PORT" >&2
  exit 1
}

push_artifacts() {
  log "pushing timoni modules and podinfo artifacts to localhost:$REG_PORT"
  timoni mod push "$CACHE_DIR/timoni/modules/flux-ks-bench" \
    "oci://localhost:$REG_PORT/modules/flux-ks-bench" -v 1.0.0 >/dev/null
  timoni mod push "$CACHE_DIR/timoni/modules/flux-hr-bench" \
    "oci://localhost:$REG_PORT/modules/flux-hr-bench" -v 1.0.0 >/dev/null
  timoni artifact push "oci://localhost:$REG_PORT/manifests/podinfo" \
    -f "$CACHE_DIR/manifests/podinfo" -t 1.0.0 -t latest >/dev/null
  crane copy "$CHART_SRC" "localhost:$REG_PORT/charts/podinfo:6.5.3" >/dev/null
}

phase() {
  local name="$1"; shift
  log "phase: $name"
  env "$@" PODS="$PODS" timoni bundle apply -f "$BUNDLE" \
    --runtime-from-env --timeout="$TIMEOUT" 2>&1 | sed 's/^/       /'
  kubectl -n flux-system top pods 2>/dev/null | sed 's/^/       /' || true
}

teardown() {
  log "tearing down benchmark instances"
  timoni bundle delete flux-benchmark --wait=false >/dev/null 2>&1 || true
  kubectl delete ns kustomize-benchmark helm-benchmark --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete -f "$HERE/registry.yaml" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

case "${1:-}" in
  --teardown)
    teardown
    exit 0
    ;;
  --prepare)
    fetch_upstream
    start_registry
    push_artifacts
    log "prepared: registry up, modules and artifacts pushed"
    exit 0
    ;;
  --load)
    fetch_upstream
    start_registry
    ;;
  *)
    fetch_upstream
    start_registry
    push_artifacts
    ;;
esac

for r in $(seq 1 "$ROUNDS"); do
  log "round $r/$ROUNDS  (KS=$KS HR=$HR PODS=$PODS)"
  phase "kustomize install"  KS="$KS" MCPU="$MCPU_INSTALL"
  phase "kustomize upgrade"  KS="$KS" MCPU="$MCPU_UPGRADE"
  phase "helm install"       HR="$HR" MCPU="$MCPU_INSTALL"
  phase "helm upgrade"       HR="$HR" MCPU="$MCPU_UPGRADE"
done

log "reconciler state"
flux get all --all-namespaces 2>/dev/null | tail -20 | sed 's/^/       /' || true
log "done"
