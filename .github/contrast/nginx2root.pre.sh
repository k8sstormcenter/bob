#!/usr/bin/env bash
# Prepares the nginx2root target: the published reproduction is cloned, and its reference nginx configuration becomes the target's ConfigMap.
set -euo pipefail
WORK=/tmp/nginx2root-poc
[ -d "$WORK" ] || git clone --depth 1 https://github.com/sfewer-r7/CVE-2026-123007 "$WORK"
awk "/cat > nginx.conf <<'NGINX_CONF'/{f=1;next} /^[[:space:]]*NGINX_CONF/{f=0} f" "$WORK/NGINX_HTTP2_STANDALONE_REPRODUCTION.md" | sed 's/^  //' > /tmp/nginx2root.conf
test -s /tmp/nginx2root.conf
kubectl create namespace sim-nginx2root --dry-run=client -o yaml | kubectl apply -f -
kubectl -n sim-nginx2root create configmap nginx2root-conf --from-file=nginx.conf=/tmp/nginx2root.conf --dry-run=client -o yaml | kubectl apply -f -
