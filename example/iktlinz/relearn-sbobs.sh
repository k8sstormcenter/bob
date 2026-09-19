#!/usr/bin/env bash
# relearn-sbobs.sh — learn CLEAN (benign-only) ContainerProfiles for every
# IKT-Linz component, then generalise them into shippable SBoBs.
#
# Why this exists: profiles learned while the disease ran are contaminated —
# redis's contained the CVE-2022-0543 RCE (`/bin/sh -c id`) and the worker's
# contained apt/nmap/kubectl from the attack. Generalising those would allowlist
# the attack, so the malignant path would raise no referral at all.
#
# Re-learn needs a NEW pod identity: node-agent tombstones the profile name, so
# deleting the CP alone is not enough — the workloads must be restarted.
#
#   ./relearn-sbobs.sh [--learn-seconds 240] [--out sbobs]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BOBCTL="${BOBCTL:-bobctl}"
command -v "$BOBCTL" >/dev/null || { echo "need bobctl on PATH (or set BOBCTL=/path/to/bobctl)"; exit 2; }
LEARN=240; OUT="$HERE/sbobs"
while [ $# -gt 0 ]; do
  case "$1" in
    --learn-seconds) LEARN="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
mkdir -p "$OUT/recorded"
say(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
CP=containerprofiles.spdx.softwarecomposition.kubescape.io

# ── 1. remove attacker artefacts so they are never learned ──────────────────
say "removing attacker artefacts"
kubectl -n agent-system delete pod ran-privileged --ignore-not-found >/dev/null 2>&1
for wp in $(kubectl -n agent-system get pods -o name 2>/dev/null | grep 'pod/agent-worker'); do
  kubectl -n agent-system delete "$wp" --ignore-not-found >/dev/null 2>&1
done
kubectl -n oopservability delete servicemonitor redis-metrics --ignore-not-found >/dev/null 2>&1
RPOD=$(kubectl -n oopservability get pod -l app.kubernetes.io/name=oopservability-redis \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -n "$RPOD" ] && kubectl -n oopservability exec "$RPOD" -c redis -- \
  redis-cli DEL 'oopservability:receiver:last-authorization' >/dev/null 2>&1

# ── 2. wipe contaminated profiles ───────────────────────────────────────────
say "deleting contaminated ContainerProfiles"
for ns in agent-system oopservability; do
  kubectl -n "$ns" delete "$CP" --all --ignore-not-found >/dev/null 2>&1
done

# ── 3. restart workloads => new pod identity => fresh learn ─────────────────
say "restarting workloads for a new learn window"
kubectl -n oopservability rollout restart deploy/oopservability-redis deploy/target-allocator deploy/spog >/dev/null 2>&1
kubectl -n agent-system  rollout restart deploy/agent-orchestrator >/dev/null 2>&1
for d in oopservability/oopservability-redis oopservability/target-allocator \
         oopservability/spog agent-system/agent-orchestrator; do
  kubectl -n "${d%%/*}" rollout status "deployment/${d##*/}" --timeout=240s >/dev/null 2>&1 \
    || say "WARN: ${d} not ready"
done

# ── 4. benign traffic ONLY for the whole learn window ───────────────────────
say "driving benign-only workload for ${LEARN}s (NO disease)"
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' | awk '{print $1}')
( END=$(( $(date +%s) + LEARN ))
  while [ "$(date +%s)" -lt "$END" ]; do
    curl -sS -X POST "http://${NODE_IP}:30080/tasks" -H 'Content-Type: application/json' \
      -d "{\"id\":\"benign-$(date +%s)\",\"repo\":\"https://github.com/Magier/ikt26\",\"cmd\":\"echo benign; ls /app; cat /etc/hostname; sleep 15\"}" \
      >/dev/null 2>&1 || true
    sleep 30
  done ) & BPID=$!
sleep "$LEARN"
kill "$BPID" 2>/dev/null

# ── 5. wait for profiles to complete ────────────────────────────────────────
say "waiting for profiles to reach completed"
for i in $(seq 1 30); do
  TOTAL=0; DONE=0
  for ns in agent-system oopservability; do
    while read -r n st; do
      [ -z "$n" ] && continue
      TOTAL=$((TOTAL+1)); [ "$st" = "completed" ] && DONE=$((DONE+1))
    done < <(kubectl -n "$ns" get "$CP" -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.annotations.kubescape\.io/status}{"\n"}{end}' 2>/dev/null)
  done
  say "  profiles completed: $DONE/$TOTAL"
  [ "$TOTAL" -gt 0 ] && [ "$DONE" = "$TOTAL" ] && break
  sleep 20
done

# ── 6. export + verify NOT contaminated, then generalise ────────────────────
say "exporting recorded profiles"
for ns in agent-system oopservability; do
  for n in $(kubectl -n "$ns" get "$CP" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    kubectl -n "$ns" get "$CP" "$n" -o yaml > "$OUT/recorded/${ns}__${n}.yaml" 2>/dev/null
  done
done
say "recorded: $(ls "$OUT/recorded" | wc -l) profiles"

say "contamination check (attack markers must be absent)"
# NB: word-boundary the markers. A bare `nmap` also matches the *syscall*
# `munmap`, which every profile legitimately contains -> false CONTAMINATED.
if grep -rlE '(^|[ /"])nmap([ "]|$)|/usr/bin/nmap|redis-cli .{0,40}EVAL|(^|[ /"])nsenter|/host/etc/rancher|/tmp/kubectl|(^|[ /"])socat|redis-tools' "$OUT/recorded" 2>/dev/null | head; then
  say "  !! CONTAMINATED — the above profiles still contain attack activity"
else
  say "  clean — no attack markers in any recorded profile"
fi

say "generalising into SBoBs"
for f in "$OUT/recorded"/*.yaml; do
  b=$(basename "$f" .yaml); ns="${b%%__*}"; name="${b#*__}"
  d=$(mktemp -d); cp "$f" "$d/"
  "$BOBCTL" generalize -d "$d" --collapse --sbob "$name" -n "$ns" \
    -o "$OUT/cp-${name}.yaml" 2>/dev/null \
    && say "  SBoB: cp-${name}.yaml" || say "  WARN: generalize failed for $name"
  rm -rf "$d"
done
say "done — SBoBs in $OUT"
