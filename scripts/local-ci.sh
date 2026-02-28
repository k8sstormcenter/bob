#!/usr/bin/env bash
# local-ci.sh — exact local mirror of .github/workflows/ci-bobctl-autotune.yaml
#
# Usage:
#   ./scripts/local-ci.sh                    # full run (install + autotune)
#   ./scripts/local-ci.sh --autotune-only    # skip install steps, just run autotune
#
# The only difference from CI:
#   - learn timeout is 3m (kubescape values.yaml sets maxLearningPeriod: 2m, so 10m is wasteful)
#   - kubeconfig from env or ~/.kube/config instead of /home/runner/.kube/config
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

AUTOTUNE_ONLY=false
for arg in "$@"; do
  [[ "$arg" == "--autotune-only" ]] && AUTOTUNE_ONLY=true
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }

# ── build ────────────────────────────────────────────────────────────────────
log "=== Build bobctl ==="
cd pkg
go build -o ../bin/bobctl ./main.go
cd ..
log "Build OK"

if ! $AUTOTUNE_ONLY; then
  # ── install kubescape (exact CI command) ──────────────────────────────────
  log "=== Install kubescape ==="
  make kubescape

  # ── install alertmanager (exact CI command) ───────────────────────────────
  log "=== Install alertmanager ==="
  make alertmanager

  # ── install webapp (exact CI commands) ───────────────────────────────────
  log "=== Install webapp ==="
  make helm-install-no-bob
  kubectl wait --for=condition=available --timeout=120s deployment/webapp-mywebapp -n webapp

  # ── wait for kubescape components (exact CI commands) ────────────────────
  log "=== Wait for kubescape components ==="
  kubectl wait --for=condition=ready pod -l app=node-agent   -n honey --timeout=180s
  kubectl wait --for=condition=ready pod -l app=storage      -n honey --timeout=180s
  kubectl wait --for=condition=ready pod -l app=alertmanager -n honey --timeout=120s

  # ── wait for profile learning ─────────────────────────────────────────────
  # CI uses 10m but maxLearningPeriod in values.yaml is 2m — use 3m locally
  log "=== Wait for profile learning ==="
  bin/bobctl learn -n webapp --timeout 3m -v
fi

# ── discover profile name (exact CI command) ─────────────────────────────────
log "=== Discover profile ==="
PROFILE=$(kubectl get applicationprofiles -n webapp -o jsonpath='{.items[0].metadata.name}')
[[ -n "$PROFILE" ]] || { log "ERROR: no applicationprofile in namespace webapp"; exit 1; }
log "Profile: $PROFILE"

# ── run autotune (exact CI command) ──────────────────────────────────────────
log "=== Run autotune ==="
mkdir -p results
set +e
bin/bobctl autotune \
  --profile "$PROFILE" \
  -n webapp \
  --ks-namespace honey \
  --service webapp-mywebapp \
  --service-port 8080 \
  --alertmanager-service alertmanager \
  --alertmanager-port 9093 \
  --max-iterations 10 \
  --learn-timeout 5m \
  --output-dir results \
  --debug \
  -v 2>&1 | tee /tmp/autotune-output.txt
AUTOTUNE_EXIT=${PIPESTATUS[0]}
set -e

# ── collect diagnostics (mirrors CI "Collect diagnostics" step) ──────────────
log "=== Diagnostics ==="
echo "--- Node-agent logs ---"
kubectl logs -n honey -l app=node-agent --tail=100 || true
echo "--- Storage logs ---"
kubectl logs -n honey -l app=storage --tail=50 || true
echo "--- Alertmanager alerts ---"
kubectl get --raw \
  "/api/v1/namespaces/honey/services/alertmanager:9093/proxy/api/v2/alerts?active=true" \
  2>/dev/null | jq '.[].labels' 2>/dev/null \
  || echo "No alerts or alertmanager unreachable"

echo
# CI uses continue-on-error: true on the autotune step — non-convergence is
# expected behaviour, not a hard failure. We report the outcome but don't exit 1.
if [[ "$AUTOTUNE_EXIT" -eq 0 ]]; then
  log "✓ autotune converged (perfect score)"
else
  log "~ autotune finished without perfect score (exit $AUTOTUNE_EXIT) — matches CI continue-on-error: true"
fi
