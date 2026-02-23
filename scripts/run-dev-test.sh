#!/bin/bash
set -e


read -p "Please enter the image tag for storage : " IMAGE_TAG
read -p "Please enter the image tag for node-agent: " NIMAGE_TAG
echo


VALUES_FILE="kubescape/values.yaml"
echo "Updating $VALUES_FILE..."

NEW_CONTENT=$(cat <<EOF
storage:
  image:
    repository: ghcr.io/k8sstormcenter/storage
    tag: ${IMAGE_TAG}

nodeAgent:
  image:
    repository: ghcr.io/k8sstormcenter/node-agent
    tag: ${NIMAGE_TAG}
  config:
    maxLearningPeriod: 10m
    learningPeriod: 5m
    updatePeriod: 10000m
    ruleCooldown:
      ruleCooldownDuration: 0h
      ruleCooldownAfterCount: 1000000000
      ruleCooldownOnProfileFailure: false
      ruleCooldownMaxSize: 20000
capabilities:
  runtimeDetection: enable
  networkEventsStreaming: disable
alertCRD:
  installDefault: true
  scopeClustered: true
clusterName: bobexample
ksNamespace: honey
excludeNamespaces: "kubescape,kube-system,kube-public,kube-node-lease,kubeconfig,gmp-system,gmp-public,storm,lightening,cert-manager,kube-flannel,ingress-nginx,olm,px-operator,honey"
linuxAudit:
  enabled: true
EOF
)

awk -v new_content="$NEW_CONTENT" '
  BEGIN {p=1}
  /^storage:/ {print new_content; p=0}
  {if(p)print}
' "$VALUES_FILE" > "${VALUES_FILE}.tmp" && mv "${VALUES_FILE}.tmp" "$VALUES_FILE"

echo "$VALUES_FILE has been updated successfully."
echo


echo "Running 'make kubescape'..."
make kubescape
echo "'make kubescape' finished."
echo


echo "Running 'make helm-install-no-bob'..."
make helm-install-no-bob

make fwd

echo "Waiting for ApplicationProfiles to reach completed status..."
bobctl learn -n webapp --timeout 10m

echo "ApplicationProfile is ready. Exporting to webapp-profile.yaml..."
kubectl get applicationprofiles.spdx.softwarecomposition.kubescape.io replicaset-webapp-mywebapp-c8bdd6944 -n webapp -o yaml > webapp-profile.yaml
echo "ApplicationProfile exported successfully to webapp-profile.yaml"
echo

# Optional: run automated iterative tuning
# bobctl autotune \
#   --profile replicaset-webapp-mywebapp-c8bdd6944 \
#   -n webapp \
#   --url http://localhost:8081 \
#   --alertmanager-url http://localhost:9093 \
#   --ks-namespace honey \
#   --max-iterations 10 \
#   -v
