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
  elk)
    NS=elk
    SUITE=example/elk-attacks.yaml
    FUNCTESTS=example/elk-functional-tests.yaml
    PROFILE_MATCH=el-es
    ;;
  misp)
    NS=honey
    SUITE=example/misp-attacks.yaml
    FUNCTESTS=example/misp-functional-tests.yaml
    PROFILE_MATCH=replicaset-misp
    ;;
  *)
    echo "Unknown app: $APP. Supported: webapp redis postgres postgres-vuln elk misp" >&2
    exit 2
    ;;
esac

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
# matches `pod-pg-client`, `replicaset-misp` matches `replicaset-misp-app`, etc.)
# but exclude bobctl-managed iteration profiles (ug- prefix) so we don't
# discover yesterday's tune output as the "learned" profile.
PROFILE_NAME="$(kubectl get applicationprofiles.spdx.softwarecomposition.kubescape.io -n "$NS" -o name 2>/dev/null \
  | awk -v match_re="$PROFILE_MATCH" '$0 ~ match_re && $0 !~ /\/ug-/ { sub(/^[^\/]*\//, ""); print; exit }')"
if [[ -z "$PROFILE_NAME" ]]; then
  echo "FAIL: no learned profile matching '$PROFILE_MATCH' in $NS. Run learning first." >&2
  kubectl get applicationprofiles.spdx.softwarecomposition.kubescape.io -n "$NS" -o name >&2
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
ITER_PROFILES="$(kubectl get applicationprofiles.spdx.softwarecomposition.kubescape.io \
  -n "$NS" -o name 2>/dev/null \
  | awk '/\/ug-/ { sub(/^[^\/]*\//, ""); print }')"
if [[ -n "$ITER_PROFILES" ]]; then
  echo "$ITER_PROFILES" | xargs -r kubectl delete applicationprofiles.spdx.softwarecomposition.kubescape.io \
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
  --kubescape-namespace honey \
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
