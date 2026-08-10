#!/usr/bin/env bash
# Sign a bundle fragment with the sign-after-roundtrip pattern:
#   1. apply the fragment UNSIGNED
#   2. read back the storage-normalised form (storage deflates specs on save —
#      signing the local file instead would make the signature invalid on load)
#   3. sign the normalised form with the given key and replace the object
#   4. VERIFY the re-fetched in-cluster object; if the save normalised the spec
#      further (deflate reaches its fixed point after an extra pass on large
#      learned profiles), sign again over the new form — loop until the stored
#      object verifies (bounded).
#
# Usage: ./sign-fragment.sh <fragment.yaml> <private-key.pem>
# Requires: kubectl and SIGN_OBJECT pointing at the sign-object binary
# (default: ./sign-object).
set -euo pipefail
FRAGMENT="$1"; KEY="$2"
SIGN_OBJECT="${SIGN_OBJECT:-./sign-object}"
CPRES=containerprofiles.spdx.softwarecomposition.kubescape.io

# identity via client-side dry-run (no YAML parser needed on this machine);
# create only if absent — re-running against an existing (already signed)
# fragment goes straight to the sign loop over the stored form
OUT=$(kubectl create --dry-run=client -f "$FRAGMENT" -o jsonpath='{.metadata.name} {.metadata.namespace}')
NAME=${OUT% *}
NS=${OUT#* }
if kubectl -n "$NS" get "$CPRES" "$NAME" >/dev/null 2>&1; then
  echo "fragment $NS/$NAME already exists — re-signing the stored object"
else
  kubectl create -f "$FRAGMENT" >/dev/null
  echo "created fragment $NS/$NAME (unsigned)"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

for attempt in 1 2 3; do
  kubectl -n "$NS" get "$CPRES" "$NAME" -o yaml > "$TMP/normalised.yaml"
  "$SIGN_OBJECT" sign --file "$TMP/normalised.yaml" --output "$TMP/signed.yaml" --key "$KEY" --type containerprofile >/dev/null
  kubectl -n "$NS" replace -f "$TMP/signed.yaml" >/dev/null
  # verify the object AS STORED — that is what node-agent will hash
  kubectl -n "$NS" get "$CPRES" "$NAME" -o yaml > "$TMP/stored.yaml"
  if "$SIGN_OBJECT" verify --file "$TMP/stored.yaml" --strict=false >/dev/null 2>&1; then
    echo "OK: $NAME signed ($(basename "$KEY")), stored object verifies (attempt $attempt)"
    exit 0
  fi
  echo "attempt $attempt: stored object does not verify yet (storage normalised the spec further); re-signing over the stored form"
done
echo "ERROR: $NAME still does not verify after 3 sign/replace rounds"; exit 1
