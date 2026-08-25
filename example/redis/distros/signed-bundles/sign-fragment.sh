#!/usr/bin/env bash
# Vendor-side signing + cluster ingestion of a bundle fragment.
#
#   1. SIGN OFFLINE: sign-object --embed-content signs the fragment and embeds
#      the exact signed content in the signature.kubescape.io/content
#      annotation. The resulting *-signed.yaml is the shippable artifact — the
#      cluster is not involved, and the signature stays valid no matter how the
#      storage server normalises the spec on save (annotations are never
#      touched).
#   2. INGEST: apply the SIGNED artifact. The cluster never sees an unsigned
#      fragment. Re-runs replace the object (delete+create).
#
# Usage: ./sign-fragment.sh <fragment.yaml> <private-key.pem>
# Requires: kubectl and SIGN_OBJECT pointing at the sign-object binary
# (default: ./sign-object).
set -euo pipefail
FRAGMENT="$1"; KEY="$2"
SIGN_OBJECT="${SIGN_OBJECT:-./sign-object}"
CPRES=containerprofiles.spdx.softwarecomposition.kubescape.io

ARTIFACT="${FRAGMENT%.yaml}-signed.yaml"
"$SIGN_OBJECT" sign --file "$FRAGMENT" --output "$ARTIFACT" --key "$KEY" --type containerprofile >/dev/null
echo "signed artifact: $ARTIFACT ($(basename "$KEY"))"

# identity via client-side dry-run (no YAML parser needed on this machine)
OUT=$(kubectl create --dry-run=client -f "$ARTIFACT" -o jsonpath='{.metadata.name} {.metadata.namespace}')
NAME=${OUT% *}
NS=${OUT#* }
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS" >/dev/null
if kubectl -n "$NS" get "$CPRES" "$NAME" >/dev/null 2>&1; then
  kubectl -n "$NS" delete "$CPRES" "$NAME" >/dev/null
fi
kubectl create -f "$ARTIFACT" >/dev/null
echo "OK: $NS/$NAME ingested (signed at rest from the first byte)"
