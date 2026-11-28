#!/usr/bin/env bash
# The real run for this example: the public proof of concept against the bound pod. Writes the window to out/real-from and out/real-to.
set -uo pipefail
POD=$(kubectl -n sim-geoserver get pod -l app=geoserver --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -n "$POD" ] || { echo "no running pod in sim-geoserver"; exit 1; }
POD_IP=$(kubectl -n sim-geoserver get pod "$POD" -o jsonpath='{.status.podIP}')
echo "target pod=$POD ip=$POD_IP"
WORK=/tmp/geoserver-poc
mkdir -p "$WORK" out/geoserver
date -u +%FT%TZ > out/real-from
bash pkg/attack/geoserver/private/run-geoserver.sh "http://$POD_IP:8080/geoserver" steps "$WORK/steps.txt" "$WORK" || true
sleep 30
date -u +%FT%TZ > out/real-to
sleep 20
awk '{print "step", NR, ($3 == "VULNERABLE" ? "landed" : "failed"), ($5 ~ /^[0-9][0-9][0-9]$/ ? $5 : ""), ($6 ~ /^[A-Za-z0-9_.]+(Exception|Error)$/ ? $6 : "")}' "$WORK/steps.txt" 2>/dev/null
landed=$(grep -c ' VULNERABLE$' "$WORK/steps.txt" 2>/dev/null || true)
if [ "${landed:-0}" -ge 6 ]; then echo "landed: 6 of 6 steps" > out/geoserver/real-result.txt; else echo "${landed:-0} of 6 steps landed; nothing can be concluded from this run" > out/geoserver/real-result.txt; echo "::warning::the real run did not land completely"; fi
cat out/geoserver/real-result.txt
