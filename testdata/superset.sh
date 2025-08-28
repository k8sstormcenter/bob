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
all_rules_json="[]"


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
    .spec.containers[0].opens |= (
      . // []
      | map(.path |= sub("pod[0-9a-fA-F_\\-]+", "⋯"))   # normalize pod UID
      | map(.path |= sub("cri-containerd-[0-9a-f]{64}\\.scope", "⋯.scope")) # normalize container ID
      | map(.path |= sub("\\.\\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\\.[0-9]+", "⋯"))
      | unique_by(.path)
    ) |
    .spec.containers[0].endpoints |= (. // [] | sort | unique)|
    .spec.containers[0].rules |= (. // [] | sort | unique)
  ' "$file" > "$norm_file"

  syscalls=$(yq '.spec.containers[0].syscalls[]' "$norm_file" 2>/dev/null || true)
  capabilities=$(yq '.spec.containers[0].capabilities[]' "$norm_file" 2>/dev/null || true)
  imageID=$(yq '.spec.containers[0].imageID' "$norm_file" 2>/dev/null || true)
  imageID=$(echo "$imageID" | sed 's|^docker-pullable://|docker.io/|')
  imageTag=$(yq '.spec.containers[0].imageTag' "$norm_file" 2>/dev/null || true)
  containerName=$(yq '.spec.containers[0].name' "$norm_file" 2>/dev/null || true)
  architecture=$(yq '.spec.architectures[0]' "$norm_file" 2>/dev/null || true)
  identifiedCallStacks=$(yq '.spec.containers[0].identifiedCallStacks' "$norm_file" 2>/dev/null || true)
  apiGroup=$(yq '.metadata.labels."kubescape.io/workload-api-group"' "$norm_file" 2>/dev/null || true)
  apiVersion=$(yq '.metadata.labels."kubescape.io/workload-api-version"' "$norm_file" 2>/dev/null || true)
  kind=$(yq '.metadata.labels."kubescape.io/workload-kind"' "$norm_file" 2>/dev/null || true)
  workloadname=$(yq '.metadata.labels."kubescape.io/workload-name"' "$norm_file" 2>/dev/null || true)
  namespace=$(yq '.metadata.labels."kubescape.io/workload-namespace"' "$norm_file" 2>/dev/null || true)
  instanceid=$(yq '.metadata.annotations."kubescape.io/instance-id"' "$norm_file" 2>/dev/null || true)
  wlid=$(yq '.metadata.annotations."kubescape.io/wlid"' "$norm_file" 2>/dev/null || true)
  name=$(yq '.metadata.name' "$norm_file" 2>/dev/null || true)


  execs_json=$(yq -o=json '.spec.containers[0].execs' "$norm_file" 2>/dev/null || echo "[]")
  opens_json=$(yq -o=json '.spec.containers[0].opens' "$norm_file" 2>/dev/null || echo "[]")
  endpoints_json=$(yq -o=json '.spec.containers[0].endpoints' "$norm_file" 2>/dev/null || echo "[]")
  rules_json=$(yq -o=json '.spec.containers[0].rulePolicies | select(. != null) | to_entries' "$norm_file" 2>/dev/null || echo "[]")



  # Merge execs
  all_execs_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_execs_json") <(echo "$execs_json"))
  # Merge opens
  all_opens_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_opens_json") <(echo "$opens_json"))
  # Merge endpoints
  all_endpoints_json=$(jq -s 'add | unique' <(echo "$all_endpoints_json") <(echo "$endpoints_json"))
  # Merge rules -> for each rule, we need to sort and unique them
  all_rules_json=$(jq -s 'add' <(echo "$all_rules_json") <(echo "$rules_json"))



  all_syscalls+=($syscalls)
  all_capabilities+=($capabilities)

  rm "$norm_file"
done

superset_syscalls=($(printf "%s\n" "${all_syscalls[@]}" | sort -u))
superset_capabilities=($(printf "%s\n" "${all_capabilities[@]}" | sort -u))

superset_execs=$(echo "$all_execs_json" | yq -P '.')
superset_opens=$(echo "$all_opens_json" | yq -P '.')
nullflag=""
if [ "$(echo "$all_endpoints_json" | jq 'length')" -eq 0 ]; then
  nullflag="null"
else
  superset_endpoints=$(echo "$all_endpoints_json" | yq -P '.' )
fi
superset_rules=$(echo "$all_rules_json" | jq '
  group_by(.key) |
  map({
    key: .[0].key,
    value: (map(.value.processAllowed // []) | add | unique | if length > 0 then {processAllowed: .} else {} end)
  }) | from_entries
' | yq -P '.')


indent_endpoints() {

  while IFS= read -r line; do 
    if [[ "$line" =~ ^- ]]; then   
      echo "    $line"
    elif  [[ "$line" = "null" ]]; then
      :
    else
      echo "    $line"
    fi
  done
}



indent_execs() {
  while IFS= read -r line; do
    if [[ "$line" =~ "- args" ]]; then
      echo "    $line"
    elif [[ "$line" =~ "path" ]]; then
      echo "    $line"  
    else
      echo "  $line"
    fi
  done
}

indent_opens() {
  while IFS= read -r line; do
    if [[ "$line" =~ "- flags" ]]; then
      echo "    $line"
    elif [[ "$line" =~ "path" ]]; then
      echo "    $line"  
    else
      echo "  $line"
    fi
  done      
}

indent_rules() {
  while IFS= read -r line; do
    if [[ "$line" =~ ":" ]]; then
      echo "      $line"
    else
      echo "    $line"
    fi
  done
}




cat <<EOF > "$OUTPUT_FILE"
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: $name
  namespace: $namespace
  annotations:
    kubescape.io/completion: complete
    kubescape.io/status: completed
    kubescape.io/instance-id: $instanceid
    kubescape.io/wlid: $wlid
  labels:
    kubescape.io/workload-api-group: $apiGroup
    kubescape.io/workload-api-version: $apiVersion
    kubescape.io/workload-kind: $kind
    kubescape.io/workload-name: $workloadname
    kubescape.io/workload-namespace: $namespace
spec:
  architectures:
  - $architecture
  containers:
  - capabilities:
$(for c in "${superset_capabilities[@]}"; do echo "    - $c"; done)
    endpoints: $nullflag
$(echo "$superset_endpoints" |indent_endpoints)
    execs:
$(echo "$superset_execs" | indent_execs)
    identifiedCallStacks: $identifiedCallStacks
    imageID: $imageID
    imageTag: $imageTag
    name: $containerName
    opens:
$(echo "$superset_opens" | indent_opens)
    rulePolicies:
$(echo "$superset_rules" | indent_rules)
    seccompProfile:
      spec:
        defaultAction: ""
    syscalls:
$(for s in "${superset_syscalls[@]}"; do echo "    - $s"; done)
EOF

OUTPUT_FILE="$OUTPUT_FILE".helm

cat << EOF >> "$OUTPUT_FILE"
{{- if .Values.bob.create }}
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  annotations:
    kubescape.io/completion: complete
    kubescape.io/instance-id: apiVersion-apps/v1/namespace-{{ .Release.Namespace }}/kind-StatefulSet/name-bob-redis-master-{{ .Values.bob.templateHash }}
    kubescape.io/status: completed
    kubescape.io/wlid: wlid://cluster-{{ .Values.bob.clusterName }}/namespace-{{ .Release.Namespace }}/statefulset-bob-redis-master 
  labels:
    kubescape.io/ignore: {{ .Values.bob.ignore | quote }}
    kubescape.io/workload-api-group: apps
    kubescape.io/workload-api-version: v1
    kubescape.io/workload-kind: StatefulSet
    kubescape.io/workload-name: bob-redis-master                      
    kubescape.io/workload-namespace: {{ .Release.Namespace }}                                                               
  name: statefulset-bob-redis-master-{{ .Values.bob.templateHash }}                                  
  namespace: {{ .Release.Namespace }}                                                             
  resourceVersion: "1" 
spec:
  architectures:
  - $architecture
  containers:
  - capabilities:
$(for c in "${superset_capabilities[@]}"; do echo "    - $c"; done)
    endpoints: $nullflag
$(echo "$superset_endpoints" |indent_endpoints)
    execs: 
$(echo "$superset_execs" | indent_execs)
    identifiedCallStacks: $identifiedCallStacks
    imageID: {{ .Values.bob.imageID }}
    imageTag: {{ .Values.bob.imageTag }}
    name: $containerName
    opens:
$(echo "$superset_opens" | indent_opens)
    rulePolicies:
$(echo "$superset_rules" | indent_rules)
    seccompProfile:
      spec:
        defaultAction: ""
    syscalls:
$(for s in "${superset_syscalls[@]}"; do echo "    - $s"; done)
{{- end }}
EOF


echo "Superset arrays written to '$OUTPUT_FILE'"
#    rulePolicies:
#$(for r in "${rules_json[@]}"; do echo "     $r"; done)
