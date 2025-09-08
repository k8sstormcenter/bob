#!/bin/bash


set -e 
set -o pipefail 


NAMESPACES_TO_CHECK=(
  "olm:2"
  "px-operator:5"
  "pl:8"
  "openebs:5"
)

TIMEOUT_SECONDS=1000 
SLEEP_INTERVAL=15   

for ns_info in "${NAMESPACES_TO_CHECK[@]}"; do
  NAMESPACE=$(echo "$ns_info" | cut -d: -f1)
  EXPECTED_COUNT=$(echo "$ns_info" | cut -d: -f2)
  timed_out=false

  echo "---"
  echo "Waiting for $EXPECTED_COUNT ApplicationProfiles in namespace '$NAMESPACE' to have status 'completed'..."

  SECONDS=0
  while true; do
    COMPLETED_COUNT=$(kubectl get applicationprofile.spdx.softwarecomposition.kubescape.io -n "$NAMESPACE" -o json 2>/dev/null | jq '[.items[] | select(.metadata.annotations."kubescape.io/status" == "completed")] | length')

    if [[ "$COMPLETED_COUNT" -ge "$EXPECTED_COUNT" ]]; then
      echo "✅ Found $COMPLETED_COUNT completed ApplicationProfiles in '$NAMESPACE'. Proceeding to export."
      break
    fi

    if [ $SECONDS -ge $TIMEOUT_SECONDS ]; then
      echo "❌ Timed out after $TIMEOUT_SECONDS seconds waiting for ApplicationProfiles in namespace '$NAMESPACE'."
      echo "   Found $COMPLETED_COUNT completed profiles, but expected $EXPECTED_COUNT."
      timed_out=true
      break
    fi

    echo "Waiting... Found $COMPLETED_COUNT/$EXPECTED_COUNT completed profiles in '$NAMESPACE'. Will check again in $SLEEP_INTERVAL seconds."
    sleep $SLEEP_INTERVAL
    SECONDS=$((SECONDS + SLEEP_INTERVAL))
  done

  if [ "$timed_out" = true ]; then
    continue
  fi


  PROFILE_NAMES=$(kubectl get applicationprofile.spdx.softwarecomposition.kubescape.io -n "$NAMESPACE" -o json | jq -r '.items[] | select(.metadata.annotations."kubescape.io/status" == "completed") | .metadata.name')


  EXPORT_DIR="$NAMESPACE-profiles"
  mkdir -p "$EXPORT_DIR"
  echo "Exporting profiles to directory: '$EXPORT_DIR'"

  for profile_name in $PROFILE_NAMES; do
    OUTPUT_FILE="${EXPORT_DIR}/${profile_name}.yaml"
    echo "-> Exporting profile '$profile_name' to '$OUTPUT_FILE'..."
    kubectl get applicationprofile -n "$NAMESPACE" "$profile_name" -o yaml > "$OUTPUT_FILE"
    echo "   Successfully exported '$OUTPUT_FILE'."
  done
done

