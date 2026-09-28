#!/usr/bin/env bash
# Drive benign controller work: admission validation, a reload, and served requests.
set -euo pipefail
NS=ingress-nginx
DEMO=ing-demo

kubectl create ns "$DEMO" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$DEMO" create deployment echo --image=hashicorp/http-echo \
  -- /http-echo -text=hello -listen=:5678 >/dev/null 2>&1 || true
kubectl -n "$DEMO" expose deployment echo --port=5678 >/dev/null 2>&1 || true
kubectl -n "$DEMO" rollout status deploy/echo --timeout=120s >/dev/null

kubectl apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: echo, namespace: $DEMO}
spec:
  ingressClassName: nginx
  rules:
  - host: echo.local
    http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: echo, port: {number: 5678}}}}]}
EOF

IP=$(kubectl -n "$NS" get svc ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
[ -n "$IP" ] || IP=$(kubectl -n "$NS" get svc ingress-nginx-controller -o jsonpath='{.spec.clusterIP}')

for _ in $(seq 1 60); do curl -s -o /dev/null -m 3 -H "Host: echo.local" "http://$IP/" || true; done
kubectl -n "$DEMO" annotate ingress echo nginx.ingress.kubernetes.io/enable-cors=true --overwrite >/dev/null
sleep 3
for _ in $(seq 1 30); do curl -s -o /dev/null -m 3 -H "Host: echo.local" "http://$IP/" || true; done
