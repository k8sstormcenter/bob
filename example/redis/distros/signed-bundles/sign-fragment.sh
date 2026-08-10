#!/usr/bin/env bash
# Sign a bundle fragment with the sign-after-roundtrip pattern:
#   1. apply the fragment UNSIGNED
#   2. read back the storage-normalised form (storage deflates specs on save —
#      signing the local file instead would make the signature invalid on load)
#   3. sign the normalised form with the given key
#   4. replace the in-cluster object with the signed version
#
# Usage: ./sign-fragment.sh <fragment.yaml> <private-key.pem>
# Requires: kubectl, python3, and SIGN_OBJECT pointing at the sign-object binary
# (default: ./sign-object).
set -euo pipefail
FRAGMENT="$1"; KEY="$2"
SIGN_OBJECT="${SIGN_OBJECT:-./sign-object}"

NAME=$(python3 -c "import yaml,sys; d=yaml.safe_load(open('$FRAGMENT')); print(d['metadata']['name'])")
NS=$(python3 -c "import yaml,sys; d=yaml.safe_load(open('$FRAGMENT')); print(d['metadata']['namespace'])")

kubectl apply -f "$FRAGMENT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
kubectl -n "$NS" get containerprofiles.spdx.softwarecomposition.kubescape.io "$NAME" -o yaml > "$TMP/normalised.yaml"

"$SIGN_OBJECT" sign --file "$TMP/normalised.yaml" --output "$TMP/signed.yaml" --key "$KEY" --type containerprofile

kubectl -n "$NS" replace -f "$TMP/signed.yaml"
echo "OK: $NAME signed ($(basename "$KEY")) and replaced in-cluster"
