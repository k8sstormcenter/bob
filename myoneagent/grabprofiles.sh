#!/bin/bash

# This script waits for a specified number of ApplicationProfiles to reach
# the 'completed' status in a given namespace and then exports them to YAML files.

set -e # Exit immediately if a command exits with a non-zero status.
set -o pipefail # The return value of a pipeline is the status of the last command to exit with a non-zero status.

NAMESPACE="dynatrace"
EXPECTED_COUNT=3
TIMEOUT_SECONDS=1000 # 10 minutes
SLEEP_INTERVAL=15   # 15 seconds

echo "Waiting for $EXPECTED_COUNT ApplicationProfiles in namespace '$NAMESPACE' to have status 'completed'..."

SECONDS=0
while true; do
  # Get the count of completed ApplicationProfiles using jq.
  # The "2>/dev/null" suppresses errors if no profiles exist yet.
  COMPLETED_COUNT=$(kubectl get applicationprofile.spdx.softwarecomposition.kubescape.io -n "$NAMESPACE" -o json 2>/dev/null | jq '[.items[] | select(.metadata.annotations."kubescape.io/status" == "completed")] | length')

  if [[ "$COMPLETED_COUNT" -ge "$EXPECTED_COUNT" ]]; then
    echo "✅ Found $COMPLETED_COUNT completed ApplicationProfiles. Proceeding to export."
    break
  fi

  if [ $SECONDS -ge $TIMEOUT_SECONDS ]; then
    echo "❌ Timed out after $TIMEOUT_SECONDS seconds waiting for ApplicationProfiles."
    echo "Found $COMPLETED_COUNT completed profiles, but expected $EXPECTED_COUNT."
    exit 1
  fi

  echo "Waiting... Found $COMPLETED_COUNT/$EXPECTED_COUNT completed profiles. Will check again in $SLEEP_INTERVAL seconds."
  sleep $SLEEP_INTERVAL
  SECONDS=$((SECONDS + SLEEP_INTERVAL))
done

# Get the names of the completed profiles
# The -r flag for jq outputs the raw string without quotes.
PROFILE_NAMES=$(kubectl get applicationprofile.spdx.softwarecomposition.kubescape.io -n "$NAMESPACE" -o json | jq -r '.items[] | select(.metadata.annotations."kubescape.io/status" == "completed") | .metadata.name')

# Create a directory to store the profiles
EXPORT_DIR="$NAMESPACE-profiles"
mkdir -p "$EXPORT_DIR"
echo "Exporting profiles to directory: '$EXPORT_DIR'"

# Loop through the names and export each to its own file
for profile_name in $PROFILE_NAMES; do
  OUTPUT_FILE="${EXPORT_DIR}/${profile_name}.yaml"
  echo "-> Exporting profile '$profile_name' to '$OUTPUT_FILE'..."
  kubectl get applicationprofile -n "$NAMESPACE" "$profile_name" -o yaml > "$OUTPUT_FILE"
  echo "   Successfully exported '$OUTPUT_FILE'."
done

echo "✅ All completed profiles have been exported."
