#!/usr/bin/env bash
# Sign a Rules object offline and ingest the signed artifact.
#
# Same model as sign-fragment.sh, for rules instead of profiles: the class
# label and the namespace are part of the signed content, so a signed rules
# fragment cannot be re-classed or moved to another namespace without breaking
# its signature.
#
#   cluster   class -> the rules apply cluster-wide (the vendor baseline)
#   namespace class -> the rules apply ONLY in the object's own namespace, and
#                      override the cluster rule with the same ID there
#
# Usage: ./sign-rules.sh <rules.yaml> <private-key.pem>
# The class comes from the object's signature.kubescape.io/rule-class label.
# Requires: kubectl and SIGN_OBJECT pointing at the sign-object binary
# (default: ./sign-object).
set -euo pipefail
RULES="$1"; KEY="$2"
SIGN_OBJECT="${SIGN_OBJECT:-./sign-object}"
RULERES=rules.kubescape.io

ARTIFACT="${RULES%.yaml}-signed.yaml"
"$SIGN_OBJECT" sign --file "$RULES" --output "$ARTIFACT" --key "$KEY" --type rules >/dev/null
echo "signed artifact: $ARTIFACT ($(basename "$KEY"))"

# identity via client-side dry-run (no YAML parser needed on this machine)
OUT=$(kubectl create --dry-run=client -f "$ARTIFACT" -o jsonpath='{.metadata.name} {.metadata.namespace}')
NAME=${OUT% *}
NS=${OUT#* }
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS" >/dev/null
if kubectl -n "$NS" get "$RULERES" "$NAME" >/dev/null 2>&1; then
  kubectl -n "$NS" delete "$RULERES" "$NAME" >/dev/null
fi
kubectl create -f "$ARTIFACT" >/dev/null
echo "OK: $NS/$NAME ingested (signed at rest from the first byte)"
