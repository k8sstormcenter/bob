#!/bin/bash

INPUT_DIR="$1"
OUTPUT_FILE="$2"

if [ -z "$INPUT_DIR" ] || [ -z "$OUTPUT_FILE" ]; then
  echo "Usage: $0 <directory_with_bobs> <output_superset_file.yaml>"
  exit 1
fi

if ! command -v yq &> /dev/null || ! command -v jq &> /dev/null; then
    echo "Error: yq and jq are required."
    exit 1
fi

if [ ! -d "$INPUT_DIR" ]; then
    echo "Error: Directory not found: $INPUT_DIR"
    exit 1
fi

FILES=("$INPUT_DIR"/*.yaml)
if [ ${#FILES[@]} -eq 0 ]; then
  echo "No YAML files found in $INPUT_DIR"
  exit 1
fi

all_syscalls=()
all_capabilities=()
all_execs_json="[]"
all_opens_json="[]"
all_endpoints_json="[]"

for file in "${FILES[@]}"; do
  norm_file=$(mktemp)
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
    .spec.containers[0].execs |= (. // [] | unique_by(.path)) |
    .spec.containers[0].opens |= (. // [] | unique_by(.path)) |
    .spec.containers[0].endpoints |= (. // [] | sort | unique)
  ' "$file" > "$norm_file"

  syscalls=$(yq '.spec.containers[0].syscalls[]' "$norm_file" 2>/dev/null || true)
  capabilities=$(yq '.spec.containers[0].capabilities[]' "$norm_file" 2>/dev/null || true)

  execs_json=$(yq -o=json '.spec.containers[0].execs' "$norm_file" 2>/dev/null || echo "[]")
  opens_json=$(yq -o=json '.spec.containers[0].opens' "$norm_file" 2>/dev/null || echo "[]")
  endpoints_json=$(yq -o=json '.spec.containers[0].endpoints' "$norm_file" 2>/dev/null || echo "[]")

  # Merge execs
  all_execs_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_execs_json") <(echo "$execs_json"))
  # Merge opens
  all_opens_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_opens_json") <(echo "$opens_json"))
  # Merge endpoints
  all_endpoints_json=$(jq -s 'add | unique' <(echo "$all_endpoints_json") <(echo "$endpoints_json"))

  all_syscalls+=($syscalls)
  all_capabilities+=($capabilities)

  rm "$norm_file"
done

superset_syscalls=($(printf "%s\n" "${all_syscalls[@]}" | sort -u))
superset_capabilities=($(printf "%s\n" "${all_capabilities[@]}" | sort -u))

superset_execs=$(echo "$all_execs_json" | yq -P '.')
superset_opens=$(echo "$all_opens_json" | yq -P '.')
superset_endpoints=$(echo "$all_endpoints_json" | yq -P '.')

# Todo: make it formatted and idented like a real application profile
cat <<EOF > "$OUTPUT_FILE"
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: superset-bob
  namespace: bob
  annotations:
    kubescape.io/completion: complete
    kubescape.io/status: ready
spec:
  architectures:
    - amd64
  containers:
    - name: redis
      syscalls:
$(for s in "${superset_syscalls[@]}"; do echo "        - $s"; done)
      capabilities:
$(for c in "${superset_capabilities[@]}"; do echo "        - $c"; done)
      endpoints:
$(echo "$superset_endpoints" | sed 's/^/        /')
      execs:
$(echo "$superset_execs" | sed 's/^/        /')
      opens:
$(echo "$superset_opens" | sed 's/^/        /')
EOF

echo "Superset arrays written to '$OUTPUT_FILE'" 