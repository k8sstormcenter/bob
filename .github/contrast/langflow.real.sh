#!/usr/bin/env bash
# The real run for this example: the public proof of concept against the bound pod. Writes the window to out/real-from and out/real-to.
set -uo pipefail
POD=$(kubectl -n sim-langflow get pod -l app=langflow-service,langflow-scope=backend --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -n "$POD" ] || { echo "no running pod in sim-langflow"; exit 1; }
POD_IP=$(kubectl -n sim-langflow get pod "$POD" -o jsonpath='{.status.podIP}')
echo "target pod=$POD ip=$POD_IP"
WORK=/tmp/langflow-poc
mkdir -p "$WORK" out/langflow
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" -q install requests==2.32.3
date -u +%FT%TZ > out/real-from
PYTHON="$WORK/venv/bin/python" bash pkg/attack/langflow/private/run-langflow.sh "http://$POD_IP:7860" steps "$WORK/steps.txt" "$WORK" || true
sleep 30
date -u +%FT%TZ > out/real-to
sleep 20
landed=$(grep -c ' VULNERABLE$' "$WORK/steps.txt" 2>/dev/null || true)
if [ "${landed:-0}" -ge 6 ]; then echo "landed: 6 of 6 steps" > out/langflow/real-result.txt; else echo "${landed:-0} of 6 steps landed; nothing can be concluded from this run" > out/langflow/real-result.txt; echo "::warning::the real run did not land completely"; fi
cat out/langflow/real-result.txt
