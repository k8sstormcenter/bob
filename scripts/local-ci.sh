#!/usr/bin/env bash
# local-ci.sh — local mirror of .github/workflows/ci-bobctl-autotune.yaml
#
# Usage:
#   ./scripts/local-ci.sh                    # full run (setup + install + collapse + tune)
#   ./scripts/local-ci.sh --tune-only        # skip infra setup, re-run collapse + tune on existing profile
#   ./scripts/local-ci.sh --setup-only       # only set up infra (kubescape + alertmanager + webapp)
#   ./scripts/local-ci.sh --app redis        # tune redis instead of webapp (default: webapp)
#
# Differences from CI:
#   - learn timeout is 3m (kubescape values.yaml sets maxLearningPeriod: 2m)
#   - uses kubeconfig from env or ~/.kube/config
#   - uses K8s API service proxy (no port-forwarding needed)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ── defaults ────────────────────────────────────────────────────────────────
TUNE_ONLY=false
SETUP_ONLY=false
APP=webapp
KS_NS=honey

for arg in "$@"; do
  case "$arg" in
    --tune-only)  TUNE_ONLY=true ;;
    --setup-only) SETUP_ONLY=true ;;
    --app)        shift; APP="${1:-webapp}" ;;
  esac
done
# Handle --app <value> form
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) APP="${2:-webapp}"; shift 2 ;;
    *)     shift ;;
  esac
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { log "ERROR: $*"; exit 1; }

# ── app-specific config ────────────────────────────────────────────────────
case "$APP" in
  webapp)
    APP_NS=webapp
    APP_MANIFEST=example/webapp-manifest.yaml
    APP_FUNC_TESTS=example/webapp-functional-tests.yaml
    APP_ATTACKS=example/webapp-attacks.yaml
    APP_SERVICE=webapp-mywebapp
    APP_PORT=8080
    ;;
  redis)
    APP_NS=redis
    APP_MANIFEST=example/redis-vulnerable.yaml
    APP_FUNC_TESTS=example/redis-functional-tests.yaml
    APP_ATTACKS=example/redis-attacks.yaml
    APP_SERVICE=redis
    APP_PORT=6379
    ;;
  *)
    die "Unknown app: $APP (use webapp or redis)"
    ;;
esac

# ── build ────────────────────────────────────────────────────────────────────
log "=== Build bobctl ==="
cd pkg
go build -o ../bin/bobctl ./main.go
cd ..
log "Build OK: bin/bobctl"

if $SETUP_ONLY || ! $TUNE_ONLY; then
  # ── install kubescape ──────────────────────────────────────────────────────
  log "=== Install kubescape (namespace: $KS_NS) ==="
  make kubescape

  # ── install alertmanager ───────────────────────────────────────────────────
  log "=== Install alertmanager ==="
  make alertmanager

  # ── wait for kubescape components ──────────────────────────────────────────
  log "=== Wait for kubescape components ==="
  kubectl wait --for=condition=ready pod -l app=node-agent   -n "$KS_NS" --timeout=180s
  kubectl wait --for=condition=ready pod -l app=storage      -n "$KS_NS" --timeout=180s
  kubectl wait --for=condition=ready pod -l app=alertmanager -n "$KS_NS" --timeout=120s
  log "All kubescape components ready"

  if $SETUP_ONLY; then
    log "=== Setup complete (--setup-only). Deploy app and run --tune-only next. ==="
    exit 0
  fi
fi

# ── install and learn app ────────────────────────────────────────────────────
if ! $TUNE_ONLY; then
  log "=== Install and learn $APP ==="
  PROFILE=$(bin/bobctl install \
    --manifest "$APP_MANIFEST" \
    --functional-tests "$APP_FUNC_TESTS" \
    -n "$APP_NS" \
    --timeout 3m \
    -v 2>&1 | tee /dev/stderr | tail -1)
  [[ -n "$PROFILE" ]] || die "bobctl install did not return a profile name"
  log "Learned profile: $PROFILE"
  # Save for --tune-only reruns
  echo "$PROFILE" > /tmp/bobctl-last-profile-$APP
else
  # Re-use last learned profile
  if [[ -f /tmp/bobctl-last-profile-$APP ]]; then
    PROFILE=$(cat /tmp/bobctl-last-profile-$APP)
    log "Re-using saved profile: $PROFILE"
  else
    # Discover from cluster
    log "Discovering completed profiles in $APP_NS..."
    PROFILE=$(kubectl get applicationprofiles -n "$APP_NS" \
      -o jsonpath='{range .items[?(@.metadata.annotations.kubescape\.io/status=="completed")]}{.metadata.name}{"\n"}{end}' \
      2>/dev/null | grep -v "^ug-" | head -1)
    [[ -n "$PROFILE" ]] || die "No completed learned profile found in $APP_NS. Run without --tune-only first."
    log "Discovered profile: $PROFILE"
  fi
fi

# ── run collapse analysis ────────────────────────────────────────────────────
log "=== Run collapse analysis ==="
mkdir -p results
set +e
bin/bobctl collapse \
  --namespaces "$APP_NS" \
  --noisy-threshold 10 \
  --apply \
  -v 2>&1 | tee results/collapse-analysis.txt
COLLAPSE_EXIT=${PIPESTATUS[0]}
set -e
if [[ "$COLLAPSE_EXIT" -eq 0 ]]; then
  log "Collapse analysis: OK"
else
  log "Collapse analysis: finished with exit $COLLAPSE_EXIT (continuing)"
fi

# ── run tune ─────────────────────────────────────────────────────────────────
log "=== Run tune ==="
set +e
bin/bobctl tune \
  --profile "$PROFILE" \
  -n "$APP_NS" \
  --ks-namespace "$KS_NS" \
  --service "$APP_SERVICE" \
  --service-port "$APP_PORT" \
  --alertmanager-service alertmanager \
  --alertmanager-port 9093 \
  --functional-tests "$APP_FUNC_TESTS" \
  --attack-suite "$APP_ATTACKS" \
  --output-dir results \
  --max-rounds 3 \
  --debug \
  -v 2>&1 | tee /tmp/tune-output.txt
TUNE_EXIT=${PIPESTATUS[0]}
set -e

# ── run attacks (separate pass for detection report) ─────────────────────────
log "=== Run attacks ==="
set +e
bin/bobctl attack \
  --attack-suite "$APP_ATTACKS" \
  -n "$APP_NS" \
  --ks-namespace "$KS_NS" \
  --service "$APP_SERVICE" \
  --service-port "$APP_PORT" \
  --format markdown 2>&1 | tee results/attack-results.md
set -e

# ── detection report ─────────────────────────────────────────────────────────
log "=== Detection report ==="
set +e
bin/bobctl report \
  --alertmanager-service alertmanager \
  --alertmanager-port 9093 \
  --ks-namespace "$KS_NS" \
  -n "$APP_NS" \
  --format markdown 2>&1 | tee results/detection-report.md
set -e

# ── collect diagnostics ──────────────────────────────────────────────────────
log "=== Diagnostics ==="
echo "--- Node-agent logs (last 100) ---"
kubectl logs -n "$KS_NS" -l app=node-agent --tail=100 2>/dev/null || echo "(no node-agent logs)"
echo "--- Storage logs (last 50) ---"
kubectl logs -n "$KS_NS" -l app=storage --tail=50 2>/dev/null || echo "(no storage logs)"
echo "--- Alertmanager alerts ---"
kubectl get --raw \
  "/api/v1/namespaces/$KS_NS/services/alertmanager:9093/proxy/api/v2/alerts?active=true" \
  2>/dev/null | python3 -c "
import json,sys
for a in json.load(sys.stdin):
  l=a.get('labels',{})
  print(f\"  rule={l.get('rule_name','?')} comm={l.get('comm','?')} ns={l.get('namespace','?')}\")
" 2>/dev/null || echo "  (no alerts or alertmanager unreachable)"

# ── result files ─────────────────────────────────────────────────────────────
echo
log "=== Results ==="
ls -la results/ 2>/dev/null || true

echo
if [[ "$TUNE_EXIT" -eq 0 ]]; then
  log "RESULT: tune converged (perfect score)"
else
  log "RESULT: tune finished without perfect score (exit $TUNE_EXIT)"
  log "  This matches CI continue-on-error: true — review results/ for details"
fi
