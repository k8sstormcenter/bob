#!/usr/bin/env bash
# run-iktlinz-e2e.sh — one-shot IKT-Linz attack path, start to finish.
#
# Produces ONE tight, repeatable MALICIOUS window on whatever cluster kubectl
# points at, with machine-readable boundaries and a list of the events any
# detection stack must not miss.
#
# It configures no detection stack of its own — point yours at the cluster
# first, then run this to get a labelled window to evaluate it against.
#
#   ./run-iktlinz-e2e.sh --out results/run1
#   ./run-iktlinz-e2e.sh --pre 180 --post 180 --out results/run2
#   ./run-iktlinz-e2e.sh --benign-only --out results/baseline   # no attack
#
# Requires on PATH: kubectl, python3, curl. Ran must be reachable at --ran-url
# (default http://localhost:8080) with its armory loaded.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

PRE=180; POST=180; OUT="$HERE/results"; RAN_URL="${RAN_URL:-http://localhost:8080}"
DEPLOY=1; BENIGN_ONLY=0; BENIGN=1
while [ $# -gt 0 ]; do
  case "$1" in
    --pre) PRE="$2"; shift 2;;
    --post) POST="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --ran-url) RAN_URL="$2"; shift 2;;
    --no-deploy) DEPLOY=0; shift;;
    --no-benign) BENIGN=0; shift;;
    --benign-only) BENIGN_ONLY=1; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
mkdir -p "$OUT"
say(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
now(){ date -u +%Y-%m-%dT%H:%M:%SZ; }

RAW=https://raw.githubusercontent.com
OOPS=$RAW/Magier/Oopserability/main/manifests
IKT=$RAW/Magier/ikt26/main/k8s

# ── preflight ───────────────────────────────────────────────────────────────
kubectl get nodes >/dev/null 2>&1 || { say "FAIL: kubectl cannot reach a cluster"; exit 2; }
curl -sf "$RAN_URL/api/armory" -o /dev/null || { say "FAIL: Ran not reachable at $RAN_URL"; exit 2; }
say "preflight ok — cluster reachable, Ran up at $RAN_URL"

# ── target platform (idempotent) ────────────────────────────────────────────
if [ "$DEPLOY" = 1 ]; then
  say "deploying target platform + CVE-2026-47701 prerequisites"
  kubectl apply -f $RAW/prometheus-operator/prometheus-operator/v0.91.0/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml >/dev/null 2>&1
  kubectl wait --for=condition=Established crd/servicemonitors.monitoring.coreos.com --timeout=90s >/dev/null 2>&1
  # Namespaces first: 14-sidecar-config.yaml is a ConfigMap in agent-system, and
  # orchestrator.yaml is what creates that namespace. Applied the other way round
  # the ConfigMap is rejected, and agent-orchestrator then wedges on FailedMount
  # for orchestrator-otel-sidecar-config with the CVE leak having nothing to leak.
  for ns in agent-system oopservability; do
    kubectl create namespace "$ns" --dry-run=client -o yaml 2>/dev/null | kubectl apply -f - >/dev/null 2>&1
  done

  # SBoBs before the workloads: node-agent binds a User profile at pod attach, so
  # a pod that starts first gets a learnt sibling instead and never rebinds.
  if [ -d "$HERE/sbobs" ]; then
    kubectl apply -n agent-system -f "$HERE/sbobs/cp-agent-orchestrator-orchestrator.yaml" \
      -f "$HERE/sbobs/cp-agent-orchestrator-otel-collector.yaml" \
      -f "$HERE/sbobs/cp-agent-worker.yaml" >/dev/null 2>&1
    kubectl apply -n oopservability -f "$HERE/sbobs/cp-oopservability-redis-redis.yaml" \
      -f "$HERE/sbobs/cp-oopservability-redis-metric-receiver.yaml" \
      -f "$HERE/sbobs/cp-spog-dashboard.yaml" \
      -f "$HERE/sbobs/cp-target-allocator.yaml" >/dev/null 2>&1
    say "applied $(ls "$HERE"/sbobs/cp-*.yaml | wc -l) SBoBs"
  fi

  for m in spog.yaml rbac.yaml cve-2026-47701/22-redis-with-metric-receiver.yaml \
           cve-2026-47701/10-target-allocator.yaml cve-2026-47701/14-sidecar-config.yaml; do
    kubectl apply -f "$OOPS/$m" >/dev/null 2>&1 || say "WARN: apply failed: $m"
  done
  kubectl apply -f "$IKT/orchestrator.yaml" >/dev/null 2>&1

  # Bind: node-agent resolves <label>-<containerName>, then the bare label.
  kubectl -n agent-system patch deploy agent-orchestrator --type=strategic \
    -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"agent-orchestrator"}}}}}' >/dev/null 2>&1
  for d in oopservability-redis spog target-allocator; do
    kubectl -n oopservability patch deploy "$d" --type=strategic \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"kubescape.io/user-defined-profile\":\"$d\"}}}}}" >/dev/null 2>&1
  done

  # The otel sidecar must be injected into agent-orchestrator or the CVE chain
  # has nothing to leak: no sidecar -> the redis key stays empty -> no token.
  curl -sfL "$OOPS/cve-2026-47701/20-sidecar-patch.yaml" -o "$OUT/sidecar-patch.yaml" &&
    kubectl patch deployment agent-orchestrator -n agent-system --type=strategic \
      --patch-file "$OUT/sidecar-patch.yaml" >/dev/null 2>&1

  for d in oopservability/oopservability-redis oopservability/target-allocator \
           oopservability/spog agent-system/agent-orchestrator; do
    kubectl -n "${d%%/*}" rollout status "deployment/${d##*/}" --timeout=240s >/dev/null 2>&1 \
      || say "WARN: ${d} not ready"
  done
  # confirm the sidecar actually landed — silent failure here voids unit-5 part 2
  if kubectl -n agent-system get pod -l app=agent-orchestrator \
       -o jsonpath='{.items[*].spec.containers[*].name}' 2>/dev/null | grep -q otel; then
    say "otel sidecar present on agent-orchestrator"
  else
    say "WARN: otel sidecar NOT on agent-orchestrator — the CVE leak will not fire"
  fi

  # confirm the SBoBs actually bound, rather than assuming the labels took
  BOUND=$(kubectl -n honey logs -l app.kubernetes.io/component=node-agent --tail=2000 2>/dev/null \
          | grep -c 'adopted user-authored ContainerProfile' || true)
  say "node-agent adopted ${BOUND:-0} user-authored profile(s)"
fi

# ── reset prior disease artefacts ───────────────────────────────────────────
# Without this a second run collides with the pods the first run created, and
# the windows stop being comparable.
say "clearing prior disease artefacts"
kubectl -n agent-system delete pod ran-privileged --ignore-not-found >/dev/null 2>&1
# delete ALL worker pods, not just callback-1: benign twins accumulate and then
# `.items[0]` picks an arbitrary one, making foothold + scan CIDR nondeterministic
kubectl -n agent-system delete pod -l task=callback-1 --ignore-not-found >/dev/null 2>&1
for wp in $(kubectl -n agent-system get pods -o name 2>/dev/null | grep 'pod/agent-worker'); do
  kubectl -n agent-system delete "$wp" --ignore-not-found >/dev/null 2>&1
done
kubectl -n oopservability delete servicemonitor redis-metrics --ignore-not-found >/dev/null 2>&1
RPOD=$(kubectl -n oopservability get pod -l app.kubernetes.io/name=oopservability-redis \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -n "$RPOD" ] && kubectl -n oopservability exec "$RPOD" -c redis -- \
  redis-cli DEL 'oopservability:receiver:last-authorization' >/dev/null 2>&1
curl -sf -X POST "$RAN_URL/api/campaign/reset" -H 'Content-Type: application/json' -d '{}' >/dev/null 2>&1
sleep 5

# ── benign twin ─────────────────────────────────────────────────────────────
if [ "$BENIGN" = 1 ]; then
  # The agent platform hums on its own; add explicit benign worker tasks so the
  # baseline is not just idle control-plane chatter.
  say "starting benign twin (periodic benign worker tasks)"
  NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' | awk '{print $1}')
  ( while :; do
      curl -sS -X POST "http://${NODE_IP}:30080/tasks" -H 'Content-Type: application/json' \
        -d "{\"id\":\"benign-$(date +%s)\",\"repo\":\"https://github.com/Magier/ikt26\",\"cmd\":\"echo benign; ls /app; sleep 20\"}" \
        >/dev/null 2>&1 || true
      sleep 45
    done ) & BENIGN_PID=$!
  trap '[ -n "${BENIGN_PID:-}" ] && kill "$BENIGN_PID" 2>/dev/null' EXIT
fi

# ── window ──────────────────────────────────────────────────────────────────
T0="$(now)"; say "T0=$T0 — PRE ${PRE}s (benign only)"; sleep "$PRE"

FIRE_START="$(now)"
if [ "$BENIGN_ONLY" = 1 ]; then
  say "benign-only run: no disease fired"
  FIRE_END="$FIRE_START"
else
  say "FIRE: IKT-Linz disease path (20 steps, units 2-7)"
  ( cd "$HERE" && RAN_URL="$RAN_URL" python3 demo_chain.py --reset --from 1 --to 20 --no-frames ) \
    2>&1 | tee "$OUT/chain.log"
  FIRE_END="$(now)"
fi
say "fire window $FIRE_START -> $FIRE_END ; POST ${POST}s"; sleep "$POST"
T1="$(now)"; say "T1=$T1"

GREEN=$(grep -c ' OK$' "$OUT/chain.log" 2>/dev/null || echo 0)

# ── machine-readable window + silent-miss gate ──────────────────────────────
cat > "$OUT/window.json" <<JSON
{
  "scenario": "iktlinz-2027",
  "pre_start": "$T0",
  "fire_start": "$FIRE_START",
  "fire_end": "$FIRE_END",
  "post_end": "$T1",
  "pre_seconds": $PRE,
  "post_seconds": $POST,
  "benign_only": $BENIGN_ONLY,
  "steps_green": $GREEN,
  "silent_miss_gate": [
    {"id":"worker-callback","ns":"agent-system","pod_prefix":"agent-worker",
     "what":"socat TCP to the Ran listener on :1337 (initial foothold)"},
    {"id":"sa-token-read","ns":"agent-system","pod_prefix":"agent-worker",
     "what":"read /var/run/secrets/kubernetes.io/serviceaccount/token"},
    {"id":"nmap-sweep","ns":"agent-system","pod_prefix":"agent-worker",
     "what":"nmap -sT -F across the pod /27 — many unique destinations from one process"},
    {"id":"redis-rce","ns":"oopservability","pod_prefix":"oopservability-redis",
     "what":"CVE-2022-0543 Lua escape: /bin/sh -c executed inside redis"},
    {"id":"cve-2026-47701-extract","ns":"oopservability","pod_prefix":"oopservability-redis",
     "what":"redis GET oopservability:receiver:last-authorization (leaked agent-orchestrator token)"},
    {"id":"privileged-pod","ns":"agent-system","pod_prefix":"ran-privileged",
     "what":"attacker-created pod, hostPath / + hostPID, socat callback to :1337"},
    {"id":"host-escape","ns":"agent-system","pod_prefix":"ran-privileged",
     "what":"nsenter --target 1 into the host namespaces"},
    {"id":"k3s-credential-read","ns":"agent-system","pod_prefix":"ran-privileged",
     "what":"read /host/etc/rancher/k3s/k3s.yaml (cluster credentials)"}
  ]
}
JSON

# Fold in the values this run resolved. The suite states them as variables on
# purpose: the listener is the node IP and the scan CIDR derives from the redis
# pod, so both move per cluster and per run. A scorer needs the literals; the
# shipped suite must not carry them.
if [ -f "$HERE/resolved.json" ]; then
  python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); w["resolved"]=json.load(open(sys.argv[2])); json.dump(w,open(sys.argv[1],"w"),indent=2,sort_keys=True)' \
    "$OUT/window.json" "$HERE/resolved.json" \
    && say "folded resolved runtime values into window.json"
fi

say "wrote $OUT/window.json (steps green: $GREEN/20)"
[ "$BENIGN_ONLY" = 1 ] || [ "$GREEN" = 20 ] || say "WARN: only $GREEN/20 steps green — check $OUT/chain.log before trusting this window"
say "done"
