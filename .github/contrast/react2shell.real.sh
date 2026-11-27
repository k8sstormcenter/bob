#!/usr/bin/env bash
# The real run for this example: the public proof of concept against the bound pod. Writes the window to out/real-from and out/real-to.
set -uo pipefail
POD=$(kubectl -n sim-react2shell get pod -l app=next --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
POD_IP=$(kubectl -n sim-react2shell get pod "$POD" -o jsonpath='{.status.podIP}')
echo "target pod=$POD ip=$POD_IP"
WORK=/tmp/react2shell-poc
mkdir -p "$WORK" out/react2shell
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" -q install requests==2.32.3
date -u +%FT%TZ > out/real-from
PYTHON="$WORK/venv/bin/python" bash pkg/attack/react2shell/private/run-react2shell.sh "http://$POD_IP:3000" steps "$WORK/steps.txt" "$WORK" || true
sleep 30
date -u +%FT%TZ > out/real-to
sleep 20
landed=$(grep -c ' \(sim-\|uid=\)' "$WORK/steps.txt" 2>/dev/null || true)
if [ "${landed:-0}" = 6 ]; then echo "landed: 6 of 6 steps" > out/react2shell/real-result.txt; else echo "${landed:-0} of 6 steps landed; nothing can be concluded from this run" > out/react2shell/real-result.txt; echo "::warning::the real run did not land completely"; fi
cat out/react2shell/real-result.txt
