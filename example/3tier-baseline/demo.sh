#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# "Let an AI build it, let kubescape review it"
#
#   ./demo.sh setup     kubescape + alertmanager + kyverno + the tier SBoBs
#   ./demo.sh deploy <file.yaml> [ns]
#                       apply an AI-generated manifest; kyverno classifies and
#                       binds a profile at admission time
#   ./demo.sh attack [ns]
#                       drive the anti-patterns: frontend->database directly
#                       (R0011 + R0012) and database->internet
#   ./demo.sh alerts [ns]
#                       the review: alerts grouped by tier, each mapped to the
#                       architectural finding it represents
#   ./demo.sh show [ns] what kyverno decided for each pod
#   ./demo.sh reset [ns]
#
# NOTE ON NAMESPACES: ContainerProfiles are namespaced and node-agent resolves the
# user-defined-profile label in the POD'S OWN namespace. The SBoBs therefore live
# in `sbob-library` and Kyverno clones them into every new namespace. Without that
# clone a workload silently ends up with no profile at all.
set -euo pipefail
cd "$(dirname "$0")"

LIB_NS="${LIB_NS:-sbob-library}"
KS_NS="${KS_NS:-honey}"
# repo root, so the demo installs the kubescape it ships next to
BOB_DIR="${BOB_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

setup() {
  log "1/4 kubescape (fork defaults)"
  echo "  bob: $(cd "$BOB_DIR" && git log --oneline -1 2>/dev/null || echo 'not a git checkout')"
  echo "  images: $(grep -A1 'repository: ghcr.io/k8sstormcenter/node-agent' "$BOB_DIR/kubescape/values.yaml" | grep tag: | tr -d ' ')"
  ( cd "$BOB_DIR" && make kubescape && make alertmanager )
  # make kubescape takes client-side field ownership of .spec.rules, so a repeat run
  # can leave stale severities behind. Force the rules to match the checkout.
  kubectl apply --server-side --force-conflicts -f "$BOB_DIR/kubescape/default-rules.yaml" >/dev/null
  kubectl -n "$KS_NS" rollout status ds/node-agent --timeout=300s

  log "  network rules must be armed before anything is deployed"
  kubectl get rules.kubescape.io -n "$KS_NS" default-rules -o json |
    python3 -c "
import sys, json
rules = json.load(sys.stdin)['spec']['rules']
ok = True
for r in rules:
    if r.get('id') in ('R0011', 'R0012'):
        print('   %s enabled=%s severity=%s' % (r['id'], r.get('enabled'), r.get('severity')))
        ok = ok and r.get('enabled')
if not ok:
    raise SystemExit('   R0011/R0012 are not enabled — the demo cannot detect the tier skip')
"

  log "2/4 kyverno"
  helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
  helm repo update >/dev/null
  helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait

  log "3/4 SBoB library namespace + profiles"
  kubectl create namespace "$LIB_NS" --dry-run=client -o yaml | kubectl apply -f -
  for f in sbobs/cp-tier-*.yaml; do
    sed "0,/^  namespace:/{s/^  namespace: .*/  namespace: $LIB_NS/}" "$f" | kubectl apply -f -
  done
  kubectl -n "$LIB_NS" get containerprofiles

  log "4/4 policies (clone + classify)"
  kubectl apply -f kyverno/00-kyverno-rbac.yaml
  kubectl apply -f kyverno/01-clone-profiles.yaml
  kubectl apply -f kyverno/02-label-tiers.yaml
  kubectl get clusterpolicy

  cat <<'EOS'

Ready. Now go and ask an AI for an app — do not sanitise what it gives you:

  "Build me a flashy 3-tier web app for Kubernetes: a React frontend, a Python
   API, and a Postgres database. Give me the complete deployment YAML, ready to
   kubectl apply. Make it look good."

Save the reply as app.yaml, then:

  ./demo.sh deploy app.yaml
  # exercise the app for a few minutes (click around, hit the API)
  ./demo.sh alerts

EOS
}

deploy() {
  local f="${1:?usage: demo.sh deploy <file.yaml> [ns]}" ns="${2:-vibe-app}"
  # Profiles attach when a container STARTS. A pod that was already running when
  # node-agent came up reports file activity but no network activity, which looks
  # exactly like a broken demo. Never deploy into a rolling node-agent.
  kubectl -n "$KS_NS" rollout status ds/node-agent --timeout=300s
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
  log "waiting for the profile clones to land in $ns"
  for _ in $(seq 1 30); do
    n=$(kubectl -n "$ns" get containerprofiles --no-headers 2>/dev/null | wc -l)
    [ "${n:-0}" -ge 5 ] && break
    sleep 2
  done
  kubectl -n "$ns" get containerprofiles 2>/dev/null || echo "  WARNING: no clones yet"
  log "applying the AI's manifest (unmodified)"
  kubectl -n "$ns" apply -f "$f"
  sleep 5
  show "$ns"
}

# The developer shortcut this demo exists to catch: the browser-facing pod talks
# straight to Postgres. Produces R0011 on the frontend (connection leaves) and
# R0012 on the database (connection arrives) — the same TCP flow from both ends.
attack() {
  local ns="${1:-vibe-app}"
  local dbip fe db
  dbip=$(kubectl -n "$ns" get pod -l app=db -o jsonpath='{.items[0].status.podIP}')
  fe=$(kubectl -n "$ns" get pod -l app=frontend -o name | head -1)
  db=$(kubectl -n "$ns" get pod -l app=db -o name | head -1)

  log "frontend -> $dbip:5432 (the tier skip)"
  for _ in $(seq 1 6); do
    kubectl -n "$ns" exec "$fe" -- bash -c "exec 3<>/dev/tcp/$dbip/5432 && echo connected" || true
    sleep 3
  done

  log "database -> 1.1.1.1:443 (the exfil shape)"
  for _ in $(seq 1 3); do
    kubectl -n "$ns" exec "$db" -- bash -c 'exec 3<>/dev/tcp/1.1.1.1/443 && echo connected' || true
    sleep 3
  done

  log "give node-agent ~90s, then: ./demo.sh alerts $ns"
}

show() {
  local ns="${1:-vibe-app}"
  log "what kyverno decided ($ns)"
  kubectl -n "$ns" get pods -o custom-columns=\
'POD:.metadata.name,TIER:.metadata.labels.app\.kubernetes\.io/tier,PROFILE:.metadata.labels.kubescape\.io/user-defined-profile,IMAGE:.spec.containers[0].image,STATUS:.status.phase'
}

alerts() {
  local ns="${1:-vibe-app}"
  log "architecture review for $ns"
  kubectl -n "$KS_NS" port-forward svc/alertmanager 9093:9093 >/dev/null 2>&1 &
  local pf=$!; sleep 3
  NS="$ns" python3 - <<'PY'
import json, os, urllib.request, collections
ns = os.environ["NS"]
try:
    data = json.load(urllib.request.urlopen("http://localhost:9093/api/v2/alerts", timeout=10))
except Exception as e:
    raise SystemExit(f"could not read alertmanager: {e}")

FINDING = {
 ("frontend","R0011"): "frontend opened a connection it should not — if the peer is a DB port, the backend tier was skipped and the browser-facing pod holds DB credentials",
 ("database","R0011"): "DATABASE INITIATED AN OUTBOUND CONNECTION — the shape of data exfiltration; nothing legitimate needs this",
 ("backend","R0011"):  "backend reached an undeclared external endpoint — an undocumented third-party dependency, or a library phoning home",
 ("middleware","R0011"):"broker reached outside its tier — check for plugin downloads or exfil",
 ("unclassified","R0011"):"unclassified workload made network calls — tell the demo what tier it is",
 ("database","R0012"): "DATABASE ACCEPTED A CONNECTION FROM OUTSIDE THE BACKEND TIER — if the peer is the frontend, the middle tier was skipped. This is the same violation as the frontend R0011, seen from the receiving end",
 ("backend","R0012"):  "backend accepted a connection from something other than the frontend — check who is calling the API directly",
 ("middleware","R0012"):"broker accepted a connection from outside the backend tier",
 (None,"R0004"): "container needed a Linux capability — it runs as root and drops privileges; use the rootless/distroless image variant",
 (None,"R0001"): "unexpected process — package manager at runtime (unpinned supply chain), a shell, or a network client that should not be in the image",
 (None,"R0006"): "service-account token read — this workload has cluster credentials it probably does not need",
 (None,"R0010"): "sensitive file access (/etc/shadow or cluster credentials) — never legitimate in an app container",
 (None,"R0005"): "DNS lookup for a name outside the learned set — check for an undeclared dependency",
}
by = collections.defaultdict(lambda: collections.defaultdict(set))
for a in data:
    l = a.get("labels", {})
    if l.get("namespace") != ns: continue
    by[l.get("app_kubernetes_io_tier") or l.get("tier") or "?"][l.get("rule_id","?")].add(
        (l.get("container_name") or l.get("pod_name") or "?"))

if not by:
    print("  no alerts yet — exercise the app for a few minutes, profiles bind at container start")
for tier in sorted(by):
    print(f"\n─── {tier.upper()} " + "─"*(60-len(tier)))
    for rid in sorted(by[tier]):
        who = ", ".join(sorted(by[tier][rid])[:3])
        msg = FINDING.get((tier, rid)) or FINDING.get((None, rid)) or "see rule definition"
        print(f"  {rid:6s} [{who}]\n         → {msg}")
PY
  kill $pf 2>/dev/null || true
}

reset() {
  local ns="${1:-vibe-app}"
  kubectl delete namespace "$ns" --ignore-not-found
}

case "${1:-}" in
  setup)  setup ;;
  deploy) shift; deploy "$@" ;;
  attack) shift; attack "${1:-vibe-app}" ;;
  alerts) shift; alerts "${1:-vibe-app}" ;;
  show)   shift; show "${1:-vibe-app}" ;;
  reset)  shift; reset "${1:-vibe-app}" ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
