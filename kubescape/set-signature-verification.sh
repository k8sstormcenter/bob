#!/usr/bin/env bash
# Toggle node-agent ContainerProfile signature verification.
#
# bobctl emits UNSIGNED user-defined ContainerProfiles (SBoBs). With signature
# verification ON, node-agent silently refuses to enforce them and falls back to
# learning mode — no detection, no error. This repo's demos rely on applying
# those SBoBs, so the default is OFF (production should instead `bobctl sign` and
# turn it ON).
#
# The upstream kubescape-operator chart does not template this config key, and
# --post-renderer is not helm-4 safe, so the value is applied to the node-agent
# ConfigMap after helm. node-agent reads config only at start, so a single roll
# is needed to pick it up; the roll is skipped when the value is already correct.
#
# Usage: set-signature-verification.sh <on|off>   (env: KS_NAMESPACE, default honey)
set -euo pipefail

MODE="${1:-off}"
NS="${KS_NAMESPACE:-honey}"
CM="${KS_NODE_AGENT_CM:-node-agent}"

case "$MODE" in
  on)  WANT=true ;;
  off) WANT=false ;;
  *)   echo "usage: $(basename "$0") <on|off>" >&2; exit 2 ;;
esac

cur="$(kubectl -n "$NS" get configmap "$CM" -o jsonpath='{.data.config\.json}' 2>/dev/null || true)"
if [ -z "$cur" ]; then
  echo "set-signature-verification: configmap $NS/$CM not found; skipping" >&2
  exit 0
fi

have="$(printf '%s' "$cur" | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("enableSignatureVerification", False)).lower())')"
if [ "$have" = "$WANT" ]; then
  echo "set-signature-verification: already enableSignatureVerification=$WANT in $NS/$CM"
  exit 0
fi

new="$(WANT="$WANT" python3 - "$cur" <<'PY'
import json, os, sys
d = json.loads(sys.argv[1])
d["enableSignatureVerification"] = (os.environ["WANT"] == "true")
print(json.dumps(d))
PY
)"

kubectl -n "$NS" patch configmap "$CM" --type merge -p "$(python3 - "$new" <<'PY'
import json, sys
print(json.dumps({"data": {"config.json": sys.argv[1]}}))
PY
)"

echo "set-signature-verification: enableSignatureVerification=$WANT in $NS/$CM ; rolling node-agent to apply"
kubectl -n "$NS" rollout restart daemonset/node-agent
kubectl -n "$NS" rollout status daemonset/node-agent --timeout=300s
