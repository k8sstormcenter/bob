#!/usr/local/bin/bash

INPUT_DIR="$1"
OUTPUT_DIR="$1"

if [ -z "$INPUT_DIR" ] || [ -z "$OUTPUT_DIR" ]; then
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


declare -A GROUPSS

for file in "$INPUT_DIR"/*.yaml; do
  [ -f "$file" ] || continue
  [[ "$file" == *_bob.yaml ]] && continue
  name=$(yq '.metadata.name' "$file")
  echo $name
  shortname=$(echo "$name" | sed -E 's/-[0-9a-f]{6,}$//')   
  echo $shortname
  GROUPSS["$shortname"]+="$file "
done


for shortname in "${!GROUPSS[@]}"; do
  echo "Processing group: $shortname"

  FILES=(${GROUPSS[$shortname]})

all_syscalls=()
all_capabilities=()
all_execs_json="[]"
all_opens_json="[]"
all_endpoints_json="[]"
all_rules_json="[]"

normalize_opens() {
  jq 'map(
    .path |= (
      # normalize hashes / pod ids
      gsub("[0-9a-f]{32,}"; "⋯") |
      gsub("pod[0-9a-fA-F_\\-]+"; "⋯") |
      gsub("cri-containerd-[0-9a-f]{64}\\.scope"; "⋯.scope") |
      gsub("[0-9]+"; "⋯") |
      gsub("/[^/]+\\.service"; "/*.service") |
      gsub("/[^/]+\\.socket"; "/*.socket")
    )
  )
  | unique_by(.path + ( .flags | tostring ))'
}


collapse_opens_with_globs() {
  jq '
    group_by(.path | split("/")[:-1] | join("/")) |
    map(
      if length > 3 then
        (map(.path | split("/")[-1] | capture("\\.(?<ext>[^./]+)$")?.ext) | unique) as $exts
        |
        if ($exts | length) == 1 then
          [{ flags: (.[0].flags),
             path: ((.[0].path | split("/")[:-1] | join("/")) + "/*." + ($exts[0])) }]
        else
          [{ flags: (.[0].flags),
             path: ((.[0].path | split("/")[:-1] | join("/")) + "/*") }]
        end
      else
        .
      end
    )
    | add
  '
}

collapse_opens_events() {
  jq '
    group_by(.path | split("/")[:-1] | join("/")) |
    map(
      if length > 1 then
        [{ flags: (.[0].flags),
           path: (.[0].path | split("/")[:-1] | join("/") + "/*") }]
      else
        .
      end
    )
    | add
  '
}


for file in "${FILES[@]}"; do
  norm_file=$(mktemp)
  yq eval '
    del(
      .metadata.creationTimestamp,
      .metadata.resourceVersion,
      .metadata.uid,
      .metadata.labels."kubescape.io/workload-resource-version",
      .metadata.annotations."kubescape.io/resource-size"
    )'  "$file" > "$norm_file"

  yq eval '
    .spec.containers[0]? |= (
    .capabilities |= (. // [] | sort | unique) |
    .syscalls |= (. // [] | sort | unique) |
    .execs |= (. // [] | unique_by(.path)) |
    .opens |= (
      . // []
      | map(.path |= sub("pod[0-9a-fA-F_\\-]+", "⋯"))   
      | map(.path |= sub("cri-containerd-[0-9a-f]{64}\\.scope", "⋯.scope")) 
      | map(.path |= sub("\\.\\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\\.[0-9]+", "⋯"))
      | unique_by(.path)
    ) |
    .endpoints |= (. // [] | sort | unique)|
    .rules |= (. // [] | sort | unique)
    )
  ' -i "$norm_file"

  apiGroup=$(yq '.metadata.labels."kubescape.io/workload-api-group"' "$norm_file" 2>/dev/null || true)
  apiVersion=$(yq '.metadata.labels."kubescape.io/workload-api-version"' "$norm_file" 2>/dev/null || true)
  kind=$(yq '.metadata.labels."kubescape.io/workload-kind"' "$norm_file" 2>/dev/null || true)
  workloadname=$(yq '.metadata.labels."kubescape.io/workload-name"' "$norm_file" 2>/dev/null || true)
  namespace=$(yq '.metadata.labels."kubescape.io/workload-namespace"' "$norm_file" 2>/dev/null || true)
  instanceid=$(yq '.metadata.annotations."kubescape.io/instance-id"' "$norm_file" 2>/dev/null || true)
  wlid=$(yq '.metadata.annotations."kubescape.io/wlid"' "$norm_file" 2>/dev/null || true)


  name=$(yq '.metadata.name' "$norm_file" 2>/dev/null || true)
  imageID=$(yq '.spec.containers[0].imageID' "$norm_file" 2>/dev/null || true)
  imageID=$(echo "$imageID" | sed 's|^docker-pullable://|docker.io/|')
  imageTag=$(yq '.spec.containers[0].imageTag' "$norm_file" 2>/dev/null || true)
  containerName=$(yq '.spec.containers[0].name' "$norm_file" 2>/dev/null || true)
  architecture=$(yq '.spec.architectures[0]' "$norm_file" 2>/dev/null || true)
  identifiedCallStacks=$(yq '.spec.containers[0].identifiedCallStacks' "$norm_file" 2>/dev/null || true)


  syscalls=$(yq '.spec.containers[0].syscalls[]' "$norm_file" 2>/dev/null || true)
  capabilities=$(yq '.spec.containers[0].capabilities[]' "$norm_file" 2>/dev/null || true)

  execs_json=$(yq -o=json '.spec.containers[].execs' "$norm_file" 2>/dev/null || echo "[]")
  opens_json=$(yq -o=json '.spec.containers[].opens' "$norm_file" 2>/dev/null || echo "[]")
  endpoints_json=$(yq -o=json '.spec.containers[].endpoints' "$norm_file" 2>/dev/null || echo "[]")
  rules_json=$(yq -o=json '.spec.containers[].rulePolicies | select(. != null) | to_entries' "$norm_file" 2>/dev/null || echo "[]")


  all_execs_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_execs_json") <(echo "$execs_json"))
  all_opens_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_opens_json") <(echo "$opens_json"))
  all_opens_json=$(echo "$all_opens_json" | normalize_opens)
  all_opens_json=$(echo "$all_opens_json" | collapse_opens_with_globs|collapse_opens_events)
  all_endpoints_json=$(jq -s 'add | unique' <(echo "$all_endpoints_json") <(echo "$endpoints_json"))
  all_rules_json=$(jq -s 'add' <(echo "$all_rules_json") <(echo "$rules_json"))

  all_syscalls+=($syscalls)
  all_capabilities+=($capabilities)

 ## TODO: add for multiple containers AND multiple initContainers
 ## init_count=$(yq '.spec.initContainers | length' "$norm_file" 2>/dev/null || echo 0)
 # for i in $(seq 0 $((init_count-1))); do
has_init=$(yq e '.spec.initContainers | length' "$norm_file" 2>/dev/null || echo 0)

if [ "$has_init" -gt 0 ]; then
  yq eval '
    .spec.initContainers? |= (
    .capabilities |= (. // [] | sort | unique) |
    .syscalls |= (. // [] | sort | unique) |
    .execs |= (. // [] | unique_by(.path)) |
    .opens |= (
      . // []
      | map(.path |= sub("pod[0-9a-fA-F_\\-]+", "⋯"))   
      | map(.path |= sub("cri-containerd-[0-9a-f]{64}\\.scope", "⋯.scope")) 
      | map(.path |= sub("\\.\\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\\.[0-9]+", "⋯"))
      | unique_by(.path)
    ) |
    .endpoints |= (. // [] | sort | unique)|
    .rules |= (. // [] | sort | unique)
    )
  ' -i "$norm_file"

  init_imageID=$(yq '.spec.initContainers[].imageID' "$norm_file" 2>/dev/null || true)
  init_imageID=$(echo "$init_imageID" | sed 's|^docker-pullable://|docker.io/|')
  init_imageTag=$(yq '.spec.initContainers[].imageTag' "$norm_file" 2>/dev/null || true)
  init_containerName=$(yq '.spec.initContainers[].name' "$norm_file" 2>/dev/null || true)
  init_identifiedCallStacks=$(yq '.spec.initContainers[].identifiedCallStacks' "$norm_file" 2>/dev/null || true)

  init_syscalls=$(yq '.spec.initContainers[].syscalls[]' "$norm_file" 2>/dev/null || true)
  init_capabilities=$(yq '.spec.initContainers[].capabilities[]' "$norm_file" 2>/dev/null || true)

  all_init_syscalls+=($init_syscalls)
  all_init_capabilities+=($init_capabilities)
  init_execs_json=$(yq -o=json '.spec.initContainers[].execs' "$norm_file" 2>/dev/null || echo "[]")
  init_opens_json=$(yq -o=json '.spec.initContainers[].opens' "$norm_file" 2>/dev/null || echo "[]")
  init_endpoints_json=$(yq -o=json '.spec.initContainers[].endpoints' "$norm_file" 2>/dev/null || echo "[]")
  init_rules_json=$(yq -o=json '.spec.initContainers[].rulePolicies | select(. != null) | to_entries' "$norm_file" 2>/dev/null || echo "[]")


  all_init_execs_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_init_execs_json") <(echo "$init_execs_json"))
  all_init_opens_json=$(jq -s 'add | unique_by(.path)' <(echo "$all_init_opens_json") <(echo "$init_opens_json"))
  all_init_opens_json=$(echo "$all_init_opens_json" | normalize_opens)
  all_init_opens_json=$(echo "$all_init_opens_json" | collapse_opens_with_globs|collapse_opens_events)
  all_init_endpoints_json=$(jq -s 'add | unique' <(echo "$all_init_endpoints_json") <(echo "$init_endpoints_json"))
  all_init_rules_json=$(jq -s 'map(. // []) | add' <(echo "$all_init_rules_json") <(echo "$init_rules_json"))

  all_init_syscalls+=($init_syscalls)
  all_init_capabilities+=($init_capabilities)
fi

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



superset_init_syscalls=($(printf "%s\n" "${all_init_syscalls[@]}" | sort -u))
superset_init_capabilities=($(printf "%s\n" "${all_init_capabilities[@]}" | sort -u))

superset_init_execs=$(echo "$all_init_execs_json" | yq -P '.')
superset_init_opens=$(echo "$all_init_opens_json" | yq -P '.')
init_nullflag=""
if [ "$(echo "$all_init_endpoints_json" | jq 'length')" -eq 0 ]; then
  init_nullflag="null"
else
  superset_init_endpoints=$(echo "$all_init_endpoints_json" | yq -P '.' )
fi
superset_init_rules=$(echo "$all_init_rules_json" | jq '
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
    if [[ "$line" =~ "- args" || "$line" =~ "- flags" ]]; then
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


OUTPUT_FILE="$OUTPUT_DIR/${shortname}_bob.yaml"

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
  initContainers:
  - capabilities:
$(for c in "${superset_init_capabilities[@]}"; do echo "    - $c"; done)
    endpoints: $nullflag
$(echo "$superset_init_endpoints" |indent_endpoints)
    execs:
$(echo "$superset_init_execs" | indent_execs)
    identifiedCallStacks: $init_identifiedCallStacks
    imageID: $init_imageID
    imageTag: $init_imageTag
    name: $init_containerName
    opens:
$(echo "$superset_init_opens" | indent_opens)
    rulePolicies:
$(echo "$superset_init_rules" | indent_rules)
    seccompProfile:
      spec:
        defaultAction: ""
    syscalls:
$(for s in "${superset_init_syscalls[@]}"; do echo "    - $s"; done)
EOF

OUTPUT_FILE="$OUTPUT_DIR/${shortname}_bob.helm"

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
done