#!/usr/bin/env bash
# run-iktlinz2-e2e.sh — one-shot IKT-Linz chain-2 attack path, start to finish.
#
# Chain 2 is chain 1 over different protocols: dig reverse lookups instead of
# nmap, postgres instead of redis, CVE-2019-9193 (COPY .. FROM PROGRAM) instead
# of the redis Lua escape, and CVE-2026-47702 instead of -47701. Everything else
# is identical, deliberately, so a measurement taken on chain 1 can be repeated
# without changing what is being measured.
#
# Diff this against ../iktlinz/run-iktlinz-e2e.sh: the differences are the
# specimen it applies, the artefacts it resets, the driver it fires, and the
# gate it writes. Nothing else should differ.
#
#   ./run-iktlinz2-e2e.sh --out results/run1
#   ./run-iktlinz2-e2e.sh --benign-only --out results/baseline   # no attack
#
# Requires on PATH: kubectl, python3, curl. Ran must be reachable at --ran-url
# (default http://localhost:8080) with its armory loaded.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

PRE=180; POST=180; OUT="$HERE/results"; RAN_URL="${RAN_URL:-http://localhost:8080}"
DEPLOY=${DEPLOY:-1}; BENIGN_ONLY=${BENIGN_ONLY:-0}; BENIGN=${BENIGN:-1}
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
# Chain 2's specimen and leak arm live in THIS repo, not in Magier's, so the
# lesion and the manifests that produce it version together.
SPEC="$HERE/specimens/cve-2026-47702"

PG_SELECTOR='app.kubernetes.io/name=oopservability-postgres'
CACHE_KEY='oopservability:receiver:last-authorization'

# ── preflight ───────────────────────────────────────────────────────────────
kubectl get nodes >/dev/null 2>&1 || { say "FAIL: kubectl cannot reach a cluster"; exit 2; }
curl -sf "$RAN_URL/api/armory" -o /dev/null || { say "FAIL: Ran not reachable at $RAN_URL"; exit 2; }
[ -d "$SPEC" ] || { say "FAIL: chain-2 specimens missing at $SPEC"; exit 2; }
say "preflight ok — cluster reachable, Ran up at $RAN_URL"

# ── target platform (idempotent) ────────────────────────────────────────────
if [ "$DEPLOY" = 1 ]; then
  say "deploying target platform + CVE-2026-47702 prerequisites"
  kubectl apply -f $RAW/prometheus-operator/prometheus-operator/v0.91.0/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml >/dev/null 2>&1
  kubectl wait --for=condition=Established crd/servicemonitors.monitoring.coreos.com --timeout=90s >/dev/null 2>&1
  for ns in agent-system oopservability; do
    kubectl create namespace "$ns" --dry-run=client -o yaml 2>/dev/null | kubectl apply -f - >/dev/null 2>&1
  done

  # SBoBs before the workloads: node-agent binds a User profile at pod attach, so
  # a pod that starts first comes up on a learnt sibling until it is rebound.
  if [ -d "$HERE/sbobs" ]; then
    AGENT_SBOBS="cp-agent-orchestrator-orchestrator.yaml cp-agent-orchestrator-otel-collector.yaml"
    OOPS_SBOBS="cp-oopservability-postgres-postgres.yaml cp-oopservability-postgres-metric-receiver.yaml \
                cp-spog-dashboard.yaml cp-target-allocator.yaml"
    N=0
    # A refused profile must not look like a clean deploy. Discarding the error
    # leaves the pod labelled with a profile name that nothing matches: it reads
    # as governed, no rule can fire on it, and a quiet alert gate is then
    # indistinguishable from working governance.
    FAILED=""
    for f in $AGENT_SBOBS; do
      [ -f "$HERE/sbobs/$f" ] || continue
      if MSG=$(kubectl apply -n agent-system -f "$HERE/sbobs/$f" 2>&1); then
        N=$((N+1))
      else
        FAILED="$FAILED $f"; say "PROFILE APPLY FAILED: $f -- $MSG"
      fi
    done
    for f in $OOPS_SBOBS; do
      [ -f "$HERE/sbobs/$f" ] || continue
      if MSG=$(kubectl apply -n oopservability -f "$HERE/sbobs/$f" 2>&1); then
        N=$((N+1))
      else
        FAILED="$FAILED $f"; say "PROFILE APPLY FAILED: $f -- $MSG"
      fi
    done
    if [ -n "$FAILED" ]; then
      say "ABORT: profiles refused:$FAILED"
      say "the target would be labelled for a profile that does not exist, so it"
      say "would look governed while nothing governs it and no rule could fire"
      exit 1
    fi
    for f in $OOPS_SBOBS; do
      [ -f "$HERE/sbobs/$f" ] || continue
      NAME=$(awk '/^  name:/{print $2; exit}' "$HERE/sbobs/$f")
      kubectl -n oopservability get containerprofiles "$NAME" >/dev/null 2>&1 || {
        say "ABORT: profile $NAME is not present after apply"; exit 1; }
    done
    say "applied $N SBoB(s) (agent-worker and ran-privileged are rogue pods, they get none)"
    [ -f "$HERE/sbobs/cp-oopservability-postgres-postgres.yaml" ] || \
      say "WARN: no postgres SBoB — learn one first, or the specimen runs unprofiled and the governed-pod case is not exercised"
  fi

  # Reused from chain 1 unchanged: spog, RBAC and the orchestrator-side collector
  # config. The CVE primitive is not protocol-specific.
  for m in spog.yaml rbac.yaml cve-2026-47701/14-sidecar-config.yaml; do
    kubectl apply -f "$OOPS/$m" >/dev/null 2>&1 || say "WARN: apply failed: $m"
  done
  # The allocator is NOT reused. Chain 1's selects its ServiceMonitor by
  # app.kubernetes.io/component: redis-metrics, so chain 2's was never selected,
  # /collect was never scraped and the leak could not fire. Chain 2 ships its own
  # copy differing in that one line.
  kubectl apply -f "$SPEC/10-target-allocator.yaml" >/dev/null 2>&1 || say "WARN: apply failed: 10-target-allocator"
  # Chain 2's own specimen, from this repo. Its pod template already carries
  # kubescape.io/user-defined-profile, so unlike chain 1 there is no post-apply
  # patch and therefore no rollout at stamp time — which on chain 1 put the
  # attack on a pod the tracer never saw (entlein/dx#179).
  kubectl apply -f "$SPEC/11-metric-receiver.yaml" >/dev/null 2>&1 || say "WARN: apply failed: 11-metric-receiver"
  kubectl apply -f "$SPEC/22-postgres-with-metric-receiver.yaml" >/dev/null 2>&1 || say "WARN: apply failed: 22-postgres"

  if curl -sfL "$IKT/orchestrator.yaml" -o "$OUT/orchestrator.yaml"; then
    python3 - "$OUT/orchestrator.yaml" <<'PYEOF' && kubectl apply -f "$OUT/orchestrator.yaml" >/dev/null 2>&1
import sys, yaml
path = sys.argv[1]
docs = [d for d in yaml.safe_load_all(open(path)) if d]
stamped = 0
for d in docs:
    if d.get("kind") == "Deployment" and d["metadata"]["name"] == "agent-orchestrator":
        meta = d.setdefault("spec", {}).setdefault("template", {}).setdefault("metadata", {})
        meta.setdefault("labels", {})["kubescape.io/user-defined-profile"] = "agent-orchestrator"
        stamped += 1
if not stamped:
    sys.exit("no agent-orchestrator Deployment in orchestrator.yaml to stamp")
yaml.safe_dump_all(docs, open(path, "w"), default_flow_style=False, sort_keys=False)
PYEOF
    say "applied orchestrator with the binding label in its pod template"
  else
    say "WARN: could not fetch orchestrator.yaml for stamping — falling back to apply + patch"
    kubectl apply -f "$IKT/orchestrator.yaml" >/dev/null 2>&1
    kubectl -n agent-system patch deploy agent-orchestrator --type=strategic \
      -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"agent-orchestrator"}}}}}' >/dev/null 2>&1
  fi
  # postgres is NOT in this loop: it is born bound. Patching it here would roll it.
  for d in spog target-allocator; do
    kubectl -n oopservability patch deploy "$d" --type=strategic \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"kubescape.io/user-defined-profile\":\"$d\"}}}}}" >/dev/null 2>&1
  done

  # The otel sidecar must be injected into agent-orchestrator or the CVE chain
  # has nothing to leak: no sidecar -> the postgres row stays empty -> no token.
  curl -sfL "$OOPS/cve-2026-47701/20-sidecar-patch.yaml" -o "$OUT/sidecar-patch.yaml" &&
    kubectl patch deployment agent-orchestrator -n agent-system --type=strategic \
      --patch-file "$OUT/sidecar-patch.yaml" >/dev/null 2>&1

  for d in oopservability/oopservability-postgres oopservability/target-allocator \
           oopservability/spog agent-system/agent-orchestrator; do
    kubectl -n "${d%%/*}" rollout status "deployment/${d##*/}" --timeout=240s >/dev/null 2>&1 \
      || say "WARN: ${d} not ready"
  done
  if kubectl -n agent-system get pod -l app=agent-orchestrator \
       -o jsonpath='{.items[*].spec.containers[*].name}' 2>/dev/null | grep -q otel; then
    say "otel sidecar present on agent-orchestrator"
  else
    say "WARN: otel sidecar NOT on agent-orchestrator — the CVE leak will not fire"
  fi

  BOUND=$(kubectl -n honey logs -l app.kubernetes.io/component=node-agent --tail=2000 2>/dev/null \
          | grep -c 'adopted user-authored ContainerProfile' || true)
  say "node-agent adopted ${BOUND:-0} user-authored profile(s)"
fi

# ── reset prior disease artefacts ───────────────────────────────────────────
say "clearing prior disease artefacts"
kubectl -n agent-system delete pod ran-privileged --ignore-not-found >/dev/null 2>&1
kubectl -n agent-system delete pod -l task=callback-1 --ignore-not-found >/dev/null 2>&1
for wp in $(kubectl -n agent-system get pods -o name 2>/dev/null | grep 'pod/agent-worker'); do
  kubectl -n agent-system delete "$wp" --ignore-not-found >/dev/null 2>&1
done
kubectl -n oopservability delete servicemonitor postgres-metrics --ignore-not-found >/dev/null 2>&1
PGPOD=$(kubectl -n oopservability get pod -l "$PG_SELECTOR" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -n "$PGPOD" ] && kubectl -n oopservability exec "$PGPOD" -c postgres -- \
  psql -U oops -d oops -c "DELETE FROM oopservability.receiver WHERE key = '$CACHE_KEY';" >/dev/null 2>&1
curl -sf -X POST "$RAN_URL/api/campaign/reset" -H 'Content-Type: application/json' -d '{}' >/dev/null 2>&1
sleep 5

# ── benign twin ─────────────────────────────────────────────────────────────
if [ "$BENIGN" = 1 ]; then
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
  say "FIRE: IKT-Linz chain-2 disease path (20 steps, units 2-7)"
  ( cd "$HERE" && RAN_URL="$RAN_URL" python3 demo_chain2.py --reset --from 1 --to 20 --no-frames ) \
    2>&1 | tee "$OUT/chain.log"
  FIRE_END="$(now)"
fi
say "fire window $FIRE_START -> $FIRE_END ; POST ${POST}s"; sleep "$POST"
T1="$(now)"; say "T1=$T1"

GREEN=$(grep -c ' OK$' "$OUT/chain.log" 2>/dev/null || echo 0)

# ── machine-readable window + silent-miss gate ──────────────────────────────
cat > "$OUT/window.json" <<JSON
{
  "scenario": "iktlinz-2027-chain2",
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
    {"id":"dns-reverse-sweep","ns":"agent-system","pod_prefix":"agent-worker",
     "what":"dig -x across the pod /24 — many in-addr.arpa queries from one process"},
    {"id":"postgres-rce","ns":"oopservability","pod_prefix":"oopservability-postgres",
     "what":"CVE-2019-9193: COPY .. FROM PROGRAM executes a shell command inside postgres"},
    {"id":"cve-2026-47702-extract","ns":"oopservability","pod_prefix":"oopservability-postgres",
     "what":"SELECT of $CACHE_KEY (leaked agent-orchestrator token)"},
    {"id":"privileged-pod","ns":"agent-system","pod_prefix":"ran-privileged",
     "what":"attacker-created pod, hostPath / + hostPID, socat callback to :1337"},
    {"id":"host-escape","ns":"agent-system","pod_prefix":"ran-privileged",
     "what":"nsenter --target 1 into the host namespaces"},
    {"id":"k3s-credential-read","ns":"agent-system","pod_prefix":"ran-privileged",
     "what":"read /host/etc/rancher/k3s/k3s.yaml (cluster credentials)"}
  ]
}
JSON

if [ -f "$HERE/resolved.json" ]; then
  python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); w["resolved"]=json.load(open(sys.argv[2])); json.dump(w,open(sys.argv[1],"w"),indent=2,sort_keys=True)' \
    "$OUT/window.json" "$HERE/resolved.json" \
    && say "folded resolved runtime values into window.json"
fi

say "wrote $OUT/window.json (steps green: $GREEN/20)"
[ "$BENIGN_ONLY" = 1 ] || [ "$GREEN" = 20 ] || say "WARN: only $GREEN/20 steps green — check $OUT/chain.log before trusting this window"
say "done"
