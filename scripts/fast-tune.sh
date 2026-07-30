#!/usr/bin/env bash
# fast-tune.sh — fastest possible iteration loop for verifying YAML/code
# changes locally before pushing to CI.
#
# Assumes the cluster + kubescape + alertmanager + the target app are
# ALREADY DEPLOYED and the app's profile has been LEARNED. Only re-runs
# the tune against the existing baseline. Skips:
#   - kind/k3s setup
#   - kubescape install
#   - alertmanager install
#   - app deploy
#   - learning phase (uses the existing completed profile)
#   - collapse analysis (use local-ci.sh --tune-only for that)
#
# Typical wall-clock: ~3-5 min per iteration vs ~15-18 min for full CI.
#
# Usage:
#   ./scripts/fast-tune.sh                    # webapp (default)
#   ./scripts/fast-tune.sh redis              # different app
#   ./scripts/fast-tune.sh webapp --no-build  # skip Go rebuild (binary fresh)
#
# Exit code is the bobctl tune score (0 = perfect, >0 = miss + FP count).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

APP="${1:-webapp}"
SKIP_BUILD=false
[[ "${2:-}" == "--no-build" ]] && SKIP_BUILD=true

# App-specific config — keep in sync with .github/workflows/ci-bobctl-autotune.yaml.
case "$APP" in
  webapp)
    NS=webapp
    SUITE=example/webapp-attacks.yaml
    FUNCTESTS=example/webapp-functional-tests.yaml
    PROFILE_MATCH=replicaset-webapp
    ;;
  redis)
    NS=redis
    SUITE=example/redis-attacks.yaml
    FUNCTESTS=example/redis-functional-tests.yaml
    PROFILE_MATCH=replicaset-redis
    ;;
  postgres)
    NS=postgres
    SUITE=example/postgres-attacks.yaml
    FUNCTESTS=example/postgres-functional-tests.yaml
    PROFILE_MATCH=pg-client
    ;;
  postgres-vuln)
    NS=postgres-vuln
    SUITE=example/postgres-vuln-attacks.yaml
    FUNCTESTS=example/postgres-vuln-functional-tests.yaml
    PROFILE_MATCH=replicaset-pg-vuln
    ;;
  mariadb)
    NS=mariadb
    SUITE=example/mariadb-attacks.yaml
    FUNCTESTS=example/mariadb-functional-tests.yaml
    # Pin the CLIENT profile. Every expectedDetection in the suite is
    # containerName: client, because exec attacks all land on the pod behind
    # target.service (mariadb-client) — there is no per-attack target override.
    # A bare "replicaset-mariadb" substring-matches the server profile AND
    # replicaset-mariadb-client-<hash>, so which one got tuned depended on API
    # listing order.
    PROFILE_MATCH=replicaset-mariadb-client
    ;;
  argocd-server)
    NS=argocd
    SUITE=example/argocd-server-attacks.yaml
    FUNCTESTS=example/argocd-server-functional-tests.yaml
    PROFILE_MATCH=argocd-server-.*-argocd-server
    SERVICE_SCHEME=https
    NEEDS_ARGOCD_TOKEN=true
    ;;
  argocd-repo-server)
    NS=argocd
    SUITE=example/argocd-repo-server-attacks.yaml
    FUNCTESTS=example/argocd-repo-server-functional-tests.yaml
    PROFILE_MATCH=argocd-repo-server-.*-argocd-repo-server
    ;;
  argocd-application-controller)
    NS=argocd
    SUITE=example/argocd-application-controller-attacks.yaml
    FUNCTESTS=example/argocd-application-controller-functional-tests.yaml
    PROFILE_MATCH=argocd-application-controller-.*-argocd-application-controller
    ;;
  argocd-applicationset-controller)
    NS=argocd
    SUITE=example/argocd-applicationset-controller-attacks.yaml
    FUNCTESTS=example/argocd-applicationset-controller-functional-tests.yaml
    PROFILE_MATCH=argocd-applicationset-controller-.*-argocd-applicationset-controller
    ;;
  argocd-notifications-controller)
    NS=argocd
    SUITE=example/argocd-notifications-controller-attacks.yaml
    FUNCTESTS=example/argocd-notifications-controller-functional-tests.yaml
    PROFILE_MATCH=argocd-notifications-controller-.*-argocd-notifications-controller
    ;;
  argocd-dex-server)
    NS=argocd
    SUITE=example/argocd-dex-server-attacks.yaml
    FUNCTESTS=
    PROFILE_MATCH=argocd-dex-server-.*-dex
    ;;
  argocd-redis)
    NS=argocd
    SUITE=example/argocd-redis-attacks.yaml
    FUNCTESTS=example/argocd-redis-functional-tests.yaml
    PROFILE_MATCH=argocd-redis-.*-redis
    ;;
  *)
    echo "Unknown app: $APP. Supported: webapp redis postgres postgres-vuln mariadb" >&2
    echo "  argocd legs: argocd-server argocd-repo-server argocd-application-controller" >&2
    echo "               argocd-applicationset-controller argocd-notifications-controller" >&2
    echo "               argocd-dex-server argocd-redis" >&2
    exit 2
    ;;
esac

# Argo CD authenticated functional tests carry __ARGOCD_TOKEN__, substituted from
# the environment by LoadFunctionalTests. Mint a session token from the
# admin secret so the read-path suite exercises the real API instead of 401ing.
if [[ "${NEEDS_ARGOCD_TOKEN:-false}" == "true" && -z "${ARGOCD_TOKEN:-}" ]]; then
  ARGOCD_PW="$(kubectl -n argocd get secret argocd-initial-admin-secret \
    -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)"
  if [[ -n "$ARGOCD_PW" ]]; then
    # POST /api/v1/session through the K8s API service proxy — no port-forward,
    # and no `argocd account generate-token` (that needs the apiKey capability,
    # which the admin account does not have by default).
    _sess="$(mktemp)"
    printf '{"username":"admin","password":"%s"}' "$ARGOCD_PW" > "$_sess"
    ARGOCD_TOKEN="$(kubectl create --raw \
      "/api/v1/namespaces/argocd/services/https:argocd-server:443/proxy/api/v1/session" \
      -f "$_sess" 2>/dev/null | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
    rm -f "$_sess"
    export ARGOCD_TOKEN
  fi
  if [[ -z "${ARGOCD_TOKEN:-}" ]]; then
    echo "WARN: could not mint ARGOCD_TOKEN; authenticated functional tests will fail to load." >&2
  fi
fi

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Sanity: cluster reachable + the app profile exists.
log "=== Sanity ==="
if ! kubectl get ns "$NS" >/dev/null 2>&1; then
  echo "FAIL: namespace $NS not found. Did you deploy $APP? Run local-ci.sh --setup-only --app $APP first." >&2
  exit 2
fi
# `head -1` causes SIGPIPE upstream which trips `set -o pipefail`. Use awk's
# `exit` instead — it consumes all input but stops processing after first match.
# Match PROFILE_MATCH as a substring anywhere in the line (so `pg-client`
# matches `pod-pg-client`, `replicaset-mariadb` matches `replicaset-mariadb-app`, etc.)
# but exclude bobctl-managed iteration profiles (ug- prefix) so we don't
# discover yesterday's tune output as the "learned" profile.
PROFILE_NAME="$(kubectl get containerprofiles.spdx.softwarecomposition.kubescape.io -n "$NS" -o name 2>/dev/null \
  | awk -v match_re="$PROFILE_MATCH" '$0 ~ match_re && $0 !~ /\/ug-/ { sub(/^[^\/]*\//, ""); print; exit }')"
if [[ -z "$PROFILE_NAME" ]]; then
  echo "FAIL: no learned profile matching '$PROFILE_MATCH' in $NS. Run learning first." >&2
  kubectl get containerprofiles.spdx.softwarecomposition.kubescape.io -n "$NS" -o name >&2
  exit 2
fi
log "  Cluster:  reachable"
log "  Profile:  $NS/$PROFILE_NAME"
log "  Suite:    $SUITE"

# Build bobctl (incremental).
if ! $SKIP_BUILD; then
  log "=== Build bobctl (incremental) ==="
  GOPATH="${GOPATH:-/mnt/dev-data/go}" \
  GOMODCACHE="${GOMODCACHE:-/mnt/dev-data/go/pkg/mod}" \
  GOCACHE="${GOCACHE:-/mnt/dev-data/go-cache}" \
    make build >/dev/null
fi
log "  bobctl:   bin/bobctl ($(stat -c%s bin/bobctl 2>/dev/null || stat -f%z bin/bobctl) bytes)"

# Wipe prior iteration profiles so the tune starts clean. CRITICAL: use the
# `ug-` name prefix, NEVER the kubescape.io/managed-by=bobctl label —
# learned profiles also carry that label in some kubescape versions and a
# label-based delete wipes the source profile too. Iteration profiles always
# get the `ug-` prefix from applyProfile (see tuner.go), so name-based
# matching is safe.
log "=== Cleanup prior iterations (ug-* only) ==="
ITER_PROFILES="$(kubectl get containerprofiles.spdx.softwarecomposition.kubescape.io \
  -n "$NS" -o name 2>/dev/null \
  | awk '/\/ug-/ { sub(/^[^\/]*\//, ""); print }')"
if [[ -n "$ITER_PROFILES" ]]; then
  echo "$ITER_PROFILES" | xargs -r kubectl delete containerprofiles.spdx.softwarecomposition.kubescape.io \
    -n "$NS" --ignore-not-found 2>&1 | tail -5
fi

# Wipe prior results.
mkdir -p results
rm -f results/iteration*.yaml results/metrics.json results/best-profile.yaml 2>/dev/null || true

# Run the tune.
log "=== Tune $APP ==="
START=$(date +%s)
set +e
bin/bobctl tune \
  --profile "$PROFILE_NAME" \
  --namespace "$NS" \
  --ks-namespace honey \
  ${SERVICE_SCHEME:+--service-scheme "$SERVICE_SCHEME"} \
  --attack-suite "$SUITE" \
  ${FUNCTESTS:+--functional-tests "$FUNCTESTS"} \
  --output-dir results \
  --max-rounds 3 2>&1 | tee results/fast-tune.log
TUNE_EC=$?
set -e
END=$(date +%s)
log "  tune wall: $((END-START))s, exit code: $TUNE_EC"

# Extract best score from metrics.
if [[ -f results/metrics.json ]]; then
  BEST_SCORE=$(jq '[to_entries[] | select(.value.phase != "raw-baseline")] | min_by(.value.score) | .value.score' results/metrics.json 2>/dev/null || echo "?")
  RAW_SCORE=$(jq '[to_entries[] | select(.value.phase == "raw-baseline")] | .[0].value.score' results/metrics.json 2>/dev/null || echo "?")
  log "  best score: $BEST_SCORE   (raw-baseline: $RAW_SCORE)"
  jq '[to_entries[] | select(.value.phase != "raw-baseline")] | min_by(.value.score) | .value | {score, missed_detections, false_positives, phase, iteration}' results/metrics.json
fi

exit $TUNE_EC
