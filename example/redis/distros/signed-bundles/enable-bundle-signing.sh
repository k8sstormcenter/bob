#!/usr/bin/env bash
# Enable signed-bundle overlays on an installed kubescape (ns honey):
#  1. apply the root-signed trust-policy ConfigMap
#  2. add bundleTrustPolicyPath to node-agent's config.json
#  3. mount the policy at /etc/bundle in the node-agent DaemonSet
#  4. restart node-agent so it picks the config up
#
# No signing key is deployed: node-agent only verifies. It checks the policy
# against the root public key compiled into its image, so a policy that is
# unsigned or signed by another key leaves bundles disabled (fail closed).
#
# Run this BEFORE deploying workloads: the restart discards any learning in
# progress. Requires: kubectl, python3.
set -euo pipefail
cd "$(dirname "$0")"
NS=honey

kubectl apply -f bundle-signing.yaml

# 2. patch config.json inside the node-agent ConfigMap
kubectl -n "$NS" get configmap node-agent -o json | python3 -c '
import json, sys
cm = json.load(sys.stdin)
cfg = json.loads(cm["data"]["config.json"])
cfg["bundleTrustPolicyPath"] = "/etc/bundle/trust-policy.json"
cfg.pop("bundleSigningKeyPath", None)  # removed: node-agent no longer signs
cm["data"]["config.json"] = json.dumps(cfg, indent=4)
json.dump(cm, sys.stdout)
' | kubectl apply -f -

# 3. add the volumes + mounts to the DaemonSet (strategic merge is idempotent)
kubectl -n "$NS" patch daemonset node-agent --type strategic -p '{
  "spec": {"template": {"spec": {
    "volumes": [
      {"name": "bundle-policy", "configMap": {"name": "node-agent-bundle-policy"}}
    ],
    "containers": [{
      "name": "node-agent",
      "volumeMounts": [
        {"name": "bundle-policy", "mountPath": "/etc/bundle/trust-policy.json", "subPath": "trust-policy.json", "readOnly": true}
      ]
    }]
  }}}
}'

# 4. restart + wait (root transitions are logged at info level — no debug
# logging needed)
kubectl -n "$NS" rollout restart daemonset node-agent
kubectl -n "$NS" rollout status daemonset node-agent --timeout=300s

# confirm (capture first: pipefail + grep -m1 would SIGPIPE kubectl and fail
# the pipeline even on a match). On an idempotent re-run nothing restarts, so
# the startup line may be far back — search the full pod log and also accept
# recent bundle-assembly activity as proof the feature is live.
# NB: kubectl logs on a workload reference (daemonset/...) silently defaults
# to --tail=10 — iterate the pods to get full logs
LOGS=$(for p in $(kubectl -n "$NS" get pods -l app.kubernetes.io/component=node-agent -o name); do
  kubectl -n "$NS" logs "$p" -c node-agent 2>/dev/null
done)
# pure-bash match: echo|grep -q under pipefail SIGPIPEs once the log outgrows
# the pipe buffer (grep exits on first match while echo is still writing)
if [[ "$LOGS" == *"signed bundle overlays enabled"* || "$LOGS" == *"assembled signed bundle overlay"* ]]; then
  echo "OK: signed bundle overlays enabled"
else
  echo "ERROR: node-agent did not report bundle overlays enabled — check the logs"; exit 1
fi
