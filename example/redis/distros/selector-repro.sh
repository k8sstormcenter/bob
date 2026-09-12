#!/usr/bin/env bash
set -euo pipefail

NS=${NS:-redis}
NA_NS=${NA_NS:-honey}
WARMUP=${WARMUP:-30}
DURATION=${DURATION:-60}

kubectl -n "$NS" get pod redis-master-0 >/dev/null

master_node=$(kubectl -n "$NS" get pod redis-master-0 -o jsonpath='{.spec.nodeName}')
other_node=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep -vx "$master_node" | head -1)
[ -n "$other_node" ] || { echo "need a second node for the inter-node case" >&2; exit 1; }

emit() {
  local name=$1 kp=$2 node=$3 key=$4 val=$5
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $name
  namespace: $NS
  labels: { repro: $name }
spec:
  replicas: 1
  selector: { matchLabels: { repro: $name } }
  template:
    metadata:
      labels: { repro: $name, $key: $val }
    spec:
      nodeName: $node
      containers:
        - name: client
          image: redis:7-alpine
          command: ["/bin/sh","-c"]
          args: ["i=0; while true; do redis-cli -h redis-master -p 6379 SET \"$kp:\$i\" v >/dev/null; i=\$((i+1)); sleep 2; done"]
YAML
}

for d in sel-allow-intra sel-rogue-intra sel-allow-inter sel-rogue-inter; do
  kubectl -n "$NS" delete deploy "$d" --ignore-not-found >/dev/null
done

{
  emit sel-allow-intra ai "$master_node" app.kubernetes.io/name redis-client; echo ---
  emit sel-rogue-intra ri "$master_node" app rogue;                          echo ---
  emit sel-allow-inter ao "$other_node"  app.kubernetes.io/name redis-client; echo ---
  emit sel-rogue-inter ro "$other_node"  app rogue
} | kubectl apply -f -

kubectl -n "$NS" rollout status deploy/sel-allow-intra --timeout=90s
kubectl -n "$NS" rollout status deploy/sel-rogue-inter --timeout=90s
sleep "$WARMUP"
sleep "$DURATION"

na=$(kubectl -n "$NA_NS" get pods -o wide --field-selector spec.nodeName="$master_node" --no-headers | awk '/node-agent/{print $1; exit}')
logs=$(kubectl -n "$NA_NS" logs "$na" --since="${DURATION}s")

ipof() { kubectl -n "$NS" get pod -l "repro=$1" -o jsonpath='{.items[0].status.podIP}'; }
count() { printf '%s\n' "$logs" | grep -c "ingress network communication from: $1" || true; }

printf '\n%-18s %-12s %-11s %-6s %-8s\n' client node allowlisted R0012 verdict
for row in "sel-allow-intra|app.kubernetes.io/name=redis-client|$master_node|yes|0" \
           "sel-rogue-intra|app=rogue|$master_node|no|>0" \
           "sel-allow-inter|app.kubernetes.io/name=redis-client|$other_node|yes|0" \
           "sel-rogue-inter|app=rogue|$other_node|no|>0"; do
  IFS='|' read -r name sel node allow want <<<"$row"
  ip=$(ipof "$name"); n=$(count "$ip")
  if { [ "$want" = 0 ] && [ "$n" -eq 0 ]; } || { [ "$want" = ">0" ] && [ "$n" -gt 0 ]; }; then verdict=PASS; else verdict=FAIL; fi
  printf '%-18s %-12s %-11s %-6s %-8s\n' "$name" "$node" "$allow" "$n" "$verdict"
done