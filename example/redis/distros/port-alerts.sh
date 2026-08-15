#!/usr/bin/env bash
# issue #80 — egress port alerting, internal + external.
# A user-defined ContainerProfile allows a client to reach:
#   - an external IP on TCP/80  (fusioncore.ai 162.0.217.171)
#   - the in-cluster redis pod on TCP/6379
# The same peer on any other port is a port violation and must fire R0011,
# even though the address itself is allowlisted.
#
# Usage: ./port-alerts.sh [namespace]   (default: portdemo)
set -euo pipefail

NS="${1:-portdemo}"
EXT_IP=162.0.217.171
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NS" run redis --image=redis:7-alpine --port=6379
kubectl -n "$NS" wait --for=condition=ready pod/redis --timeout=120s
RIP="$(kubectl -n "$NS" get pod redis -o jsonpath='{.status.podIP}')"
echo "redis pod IP: $RIP"

kubectl -n "$NS" apply -f - <<YAML
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ContainerProfile
metadata:
  name: portclient-overlay
  labels:
    kubescape.io/context: user-defined
spec:
  architectures: [amd64]
  containers: []
  matchLabels:
    app: portclient
  egress:
  - identifier: redis-internal
    type: internal
    ipAddresses: ["$RIP"]
    ports:
    - {name: TCP-6379, protocol: TCP, port: 6379}
  - identifier: fusioncore-external
    type: external
    ipAddress: $EXT_IP
    ports:
    - {name: TCP-80, protocol: TCP, port: 80}
YAML

kubectl -n "$NS" run portclient --image=curlimages/curl \
  --labels="app=portclient,kubescape.io/user-defined-profile=portclient-overlay" \
  --command -- sleep 3600
kubectl -n "$NS" wait --for=condition=ready pod/portclient --timeout=120s
echo "waiting for node-agent to bind the profile..."
sleep 30

echo "== allowed ports (silent) =="
kubectl -n "$NS" exec portclient -- curl -sm3 "http://$RIP:6379" -o /dev/null || true
kubectl -n "$NS" exec portclient -- curl -sm3 "http://$EXT_IP:80" -o /dev/null || true

echo "== port violations (R0011) =="
kubectl -n "$NS" exec portclient -- curl -sm3 "http://$RIP:6380" -o /dev/null || true
kubectl -n "$NS" exec portclient -- curl -sm3 -k "https://$EXT_IP:443" -o /dev/null || true

echo "waiting for alerts..."
sleep 25
echo "== R0011 egress port alerts =="
kubectl -n honey logs -l app=node-agent -c node-agent --tail=3000 --max-log-requests=10 \
  | grep -aoE "Unexpected egress network communication to: ($RIP|$EXT_IP):[0-9]+ using TCP" | sort -u
