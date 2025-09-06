#!/bin/bash

# A script to compare two directories of Bill of Behavior (BoB) YAML files,
# ignoring volatile fields that change between runs.

# --- Configuration ---
DIR1="$1"
DIR2="$2"

# --- Pre-flight checks ---
if [ -z "$DIR1" ] || [ -z "$DIR2" ]; then
  echo "Usage: $0 <directory1> <directory2>"
  exit 1
fi

if ! command -v yq &> /dev/null; then
    echo "Error: yq is not installed. Please install it to continue."
    echo "See: https://github.com/mikefarah/yq/#install"
    exit 1
fi

if [ ! -d "$DIR1" ]; then
    echo "Error: Directory not found: $DIR1"
    exit 1
fi

if [ ! -d "$DIR2" ]; then
    echo "Error: Directory not found: $DIR2"
    exit 1
fi

# --- Main Logic ---
echo "Comparing BoB files in '$DIR1' with '$DIR2'..."
DIFF_FOUND=0

# Function to normalize a BoB file for comparison.
# It removes metadata that is expected to change with every run.
normalize_bob() {
  # Use yq to remove volatile metadata and sort arrays to ensure consistent order.
  # Then use sed to normalize timestamped paths in `opens`.
  yq eval '
    del(
      .metadata.creationTimestamp,
      .metadata.resourceVersion,
      .metadata.uid,
      .metadata.labels."kubescape.io/workload-resource-version",
      .metadata.annotations."kubescape.io/resource-size"
    ) |
    .spec.containers[0].capabilities |= (. // [] | sort | unique) |
    .spec.containers[0].syscalls |= (. // [] | sort | unique) |
    .spec.containers[0].execs |= (. // [] | sort_by(.path, .args | join(" ")) | unique) |
    .spec.containers[0].opens |= (. // [] | map(.flags |= (. // [] | sort | unique)) | sort_by(.path, .flags | join(" ")) | unique) |
    .spec.containers[0].endpoints |= (
        . // []
        | map(select(. != null))
        | map(
            (.methods |= (. // [] | sort | unique))
            | (.headers.Host |= (. // [] | sort | unique))
          )
        | sort_by(.endpoint, .methods | join(" "), .headers.Host | join(" "))
        | unique
      )
  ' "$1" | sed -E 's|(\.\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\.[0-9]+)|..TIMESTAMPED_DIR|g'
}

# Loop through all YAML files in the first directory
for file1 in "$DIR1"/*.yaml; do
  [ -e "$file1" ] || continue # Skip if no files match

  filename=$(basename "$file1")
  file2="$DIR2/$filename"

  if [ -f "$file2" ]; then
    echo "--- Comparing $filename ---"
    if ! diff -u <(normalize_bob "$file1") <(normalize_bob "$file2"); then
      echo "❌ BoB file $filename has changed between directories."
      DIFF_FOUND=1
    else
      echo "✅ $filename is identical."
    fi
  else
    echo "⚠️ Corresponding file not found for $filename in $DIR2. Skipping."
  fi
  echo "" # Add a newline for better readability
done

# --- Summary ---
if [ "$DIFF_FOUND" -ne 0 ]; then
  echo "Comparison finished. One or more BoB files have changed."
  exit 1
else
  echo "Comparison finished. All corresponding BoB files are identical."
  exit 0
fi
