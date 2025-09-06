#!/usr/local/bin/bash 

bla= ###!/usr/bin/env bash
set -u

INPUT_DIR="$1"
OUTPUT_DIR="$1"

if [ -z "$INPUT_DIR" ] ; then
  echo "You supplied $1"
  echo "Usage: $0 <directory_with_bobs> "
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

# Print a YAML key as a list or null, inline
print_yaml_list_or_null_inline() {
  local key="$1"
  shift
  local arr=("$@")
  if [ "${#arr[@]}" -eq 0 ] || [ -z "${arr[*]// }" ]; then
    echo "$key: null"
  else
    echo "$key:"
    printf "%s\n" "${arr[@]}" | sed 's/^/    - /'
  fi
}

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


## this is the most outer loop - the grouploop

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


declare -A keys
declare -A imageID
declare -A imageTag
declare -A containerName
declare -A identifiedCallStacks
declare -A nullflag
declare -A all_execs_json        
declare -A all_opens_json
declare -A all_endpoints_json
declare -A all_rules_json
declare -A all_syscalls     
declare -A all_capabilities 

declare -A superset_execs        
declare -A superset_open
declare -A superset_endpoints
declare -A superset_rules
declare -A superset_syscalls     
declare -A superset_capabilities 

declare -A initkeys
declare -A initimageID
declare -A initimageTag
declare -A initcontainerName
declare -A initidentifiedCallStacks
declare -A initnullflag
declare -A init_execs_json
declare -A init_opens_json
declare -A init_endpoints_json
declare -A init_rules_json
declare -A init_syscalls
declare -A init_capabilities

declare -A superset_init_execs
declare -A superset_init_open
declare -A superset_init_endpoints
declare -A superset_init_rules
declare -A superset_init_syscalls
declare -A superset_init_capabilities


# second outer loop, the mainloop over files

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

  # the static header
    apiGroup=$(yq '.metadata.labels."kubescape.io/workload-api-group"' "$norm_file" 2>/dev/null || true)
    apiVersion=$(yq '.metadata.labels."kubescape.io/workload-api-version"' "$norm_file" 2>/dev/null || true)
    kind=$(yq '.metadata.labels."kubescape.io/workload-kind"' "$norm_file" 2>/dev/null || true)
    workloadname=$(yq '.metadata.labels."kubescape.io/workload-name"' "$norm_file" 2>/dev/null || true)
    namespace=$(yq '.metadata.labels."kubescape.io/workload-namespace"' "$norm_file" 2>/dev/null || true)
    instanceid=$(yq '.metadata.annotations."kubescape.io/instance-id"' "$norm_file" 2>/dev/null || true)
    wlid=$(yq '.metadata.annotations."kubescape.io/wlid"' "$norm_file" 2>/dev/null || true)
    name=$(yq '.metadata.name' "$norm_file" 2>/dev/null || true)
    architecture=$(yq '.spec.architectures[0]' "$norm_file" 2>/dev/null || true)
       

  container_count=$(yq '.spec.containers | length' "$norm_file")
      for i in $(seq 0 $((container_count-1))); do
      

        yq eval '.spec.containers[$i] |= (
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

        #Assumption: containerName is hopefully unique across a deploymentspec
        containerName=$(yq -r ".spec.containers[$i].name // \"\" " "$norm_file" 2>/dev/null || true)
        key="${containerName//-/_}" 
        keys["$key"]="${key}"
        echo "Taking on container $i $workloadname $key"

        : "${imageID["$key"]:=""}"
        : "${imageTag["$key"]:=""}"
        : "${containerName["$key"]:=""}"
        : "${identifiedCallStacks["$key"]:=""}"
        : "${nullflag["$key"]:=""}"
        : "${all_execs_json["$key"]:="[]"}"
        : "${all_opens_json["$key"]:="[]"}"
        : "${all_endpoints_json["$key"]:="[]"}"
        : "${all_rules_json["$key"]:="[]"}"
        : "${all_syscalls["$key"]:=""}"
        : "${all_capabilities["$key"]:=""}"
        : "${superset_syscalls["$key"]:=""}"
        : "${superset_capabilities["$key"]:=""}"
        : "${superset_execs["$key"]:=""}"
        : "${superset_open["$key"]:=""}"

        imageID["$key"]=$(yq ".spec.containers[$i].imageID" "$norm_file" 2>/dev/null || true)
        imageID["$key"]=$(echo "${imageID["$key"]}" | sed 's|^docker-pullable://|docker.io/|')
        imageTag["$key"]=$(yq ".spec.containers[$i].imageTag" "$norm_file" 2>/dev/null || true)
        containerName["$key"]=$(yq ".spec.containers[$i].name" "$norm_file" 2>/dev/null || true)
        identifiedCallStacks["$key"]=$(yq ".spec.containers[$i].identifiedCallStacks" "$norm_file" 2>/dev/null || true)

        syscalls=$(yq ".spec.containers[$i].syscalls[]" "$norm_file" 2>/dev/null || true)
        capabilities=$(yq ".spec.containers[$i].capabilities[]" "$norm_file" 2>/dev/null || true)

        execs_json=$(yq -o=json ".spec.containers[$i].execs" "$norm_file" 2>/dev/null || echo "[]")
        opens_json=$(yq -o=json ".spec.containers[$i].opens" "$norm_file" 2>/dev/null || echo "[]")
        endpoints_json=$(yq -o=json ".spec.containers[$i].endpoints" "$norm_file" 2>/dev/null || echo "[]")
        rules_json=$(yq -o=json ".spec.containers[$i].rulePolicies | select(. != null) | to_entries" "$norm_file" 2>/dev/null || echo "[]")


        all_execs_json["$key"]=$(jq -s 'add | unique_by(.path)' <(echo "${all_execs_json["$key"]}") <(echo "$execs_json"))
        all_opens_json["$key"]=$(jq -s 'add | unique_by(.path)' <(echo "${all_opens_json["$key"]}")  <(echo "$opens_json") | normalize_opens  | collapse_opens_with_globs | collapse_opens_events)
        all_endpoints_json["$key"]=$(jq -s 'add | unique' <(echo "${all_endpoints_json["$key"]}") <(echo "${endpoints_json:-"[]"}"))
        all_rules_json["$key"]=$(jq -s 'add' <(echo "${all_rules_json["$key"]}") <(echo "$rules_json"))

        all_syscalls["$key"]="${all_syscalls["$key"]} $syscalls"
        all_capabilities["$key"]="${all_capabilities["$key"]} $capabilities"

    superset_syscalls["$key"]=$(printf "%s\n" ${all_syscalls["$key"]} | sort -u)
    superset_capabilities["$key"]=$(printf "%s\n" ${all_capabilities["$key"]} | sort -u)


    superset_execs["$key"]=$(echo "${all_execs_json["$key"]}" | yq -P '.')
    superset_open["$key"]=$(echo "${all_opens_json["$key"]}" | yq -P '.')
    nullflag["$key"]=""
    if [ "$(echo "${all_endpoints_json["$key"]}" | jq -r 'length')" -eq 0 ]; then
      nullflag["$key"]="null"
    else
      superset_endpoints["$key"]=$(echo "${all_endpoints_json["$key"]}" | yq -P '.' )
    fi
    superset_rules["$key"]=$(echo "${all_rules_json["$key"]}" | jq '
      group_by(.key) | map({
        key: .[0].key, value: (map(.value.processAllowed // []) | add | unique | if length > 0 then {processAllowed: .} else {} end)
      }) | from_entries ' | yq -P '.')
  done #end of container(key)

  init_container_count=$(yq '.spec.initContainers // [] | length' "$norm_file")
      for i in $(seq 0 $((init_container_count-1))); do
      echo "Taking on initContainer $i" $(yq ".spec.initContainers[$i].imageID" "$norm_file" 2>/dev/null)
        if [ "$init_container_count" -eq 0 ]; then
          continue
        fi
          yq eval '
            .spec.initContainers[$i] |= (
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
        initcontainerName=$(yq -r ".spec.initContainers[$i].name // \"\" " "$norm_file" 2>/dev/null || true)
        echo $initcontainerName
        key="${initcontainerName//-/}" 
        echo $key "for initContainer"
        : "${init_imageID["$key"]:=""}"
        : "${init_imageTag["$key"]:=""}"
        : "${init_containerName["$key"]:=""}"
        : "${init_identifiedCallStacks["$key"]:=""}"
        : "${init_nullflag["$key"]:=""}"
        : "${all_init_execs_json["$key"]:="[]"}"
        : "${all_init_opens_json["$key"]:="[]"}"
        : "${all_init_endpoints_json["$key"]:="[]"}"
        : "${all_init_rules_json["$key"]:="[]"}"
        : "${all_init_syscalls["$key"]:=""}"
        : "${all_init_capabilities["$key"]:=""}"
        : "${superset_init_syscalls["$key"]:=[]}"
        : "${superset_init_capabilities["$key"]:=""}"
        : "${superset_init_execs["$key"]:=""}"
        : "${superset_init_opens["$key"]:=""}"
        : "${superset_init_endpoints["$key"]:=""}"
        : "${superset_init_rules["$key"]:=""}"
        : "${initkeys["$key"]:=""}"
        initkeys["$key"]="${key}"
          init_imageID["$key"]=$(yq ".spec.initContainers[$i].imageID" "$norm_file" 2>/dev/null || true)
          init_imageID["$key"]=$(echo "${init_imageID["$key"]}" | sed 's|^docker-pullable://|docker.io/|')
          init_imageTag["$key"]=$(yq ".spec.initContainers[$i].imageTag" "$norm_file" 2>/dev/null || true)
          init_containerName["$key"]=$(yq ".spec.initContainers[$i].name" "$norm_file" 2>/dev/null || true)
          init_identifiedCallStacks["$key"]=$(yq ".spec.initContainers[$i].identifiedCallStacks" "$norm_file" 2>/dev/null || true)

          init_syscalls=$(yq ".spec.initContainers[$i].syscalls[]" "$norm_file" 2>/dev/null || true)
          init_capabilities=$(yq ".spec.initContainers[$i].capabilities[]" "$norm_file" 2>/dev/null || true)

          init_execs_json=$(yq -o=json ".spec.initContainers[$i].execs" "$norm_file" 2>/dev/null || echo "[]")
          init_opens_json=$(yq -o=json ".spec.initContainers[$i].opens" "$norm_file" 2>/dev/null || echo "[]")
          init_endpoints_json=$(yq -o=json ".spec.initContainers[$i].endpoints" "$norm_file" 2>/dev/null || echo "[]")
          init_rules_json=$(yq -o=json ".spec.initContainers[$i].rulePolicies | select(. != null) | to_entries" "$norm_file" 2>/dev/null || echo "[]")

          all_init_execs_json["$key"]=$(jq -s 'add | unique_by(.path)' <(echo "$all_init_execs_json") <(echo "$init_execs_json"))
          all_init_opens_json["$key"]=$(jq -s 'add | unique_by(.path)' <(echo "${all_init_opens_json["$key"]}")  <(echo "$init_opens_json") | normalize_opens  | collapse_opens_with_globs | collapse_opens_events)
          all_init_endpoints_json["$key"]=$(jq -s 'add | unique' <(echo "$all_init_endpoints_json") <(echo "$init_endpoints_json"))
          all_init_rules_json["$key"]=$(jq -s 'map(. // []) | add' <(echo "$all_init_rules_json") <(echo "$init_rules_json"))

        all_init_syscalls["$key"]="${all_init_syscalls["$key"]} $init_syscalls"
        all_init_capabilities["$key"]="${all_init_capabilities["$key"]} $init_capabilities"

    superset_init_syscalls["$key"]=($(printf "%s\n" "${all_init_syscalls["$key"]}" | sort -u))
    superset_init_capabilities["$key"]=($(printf "%s\n" "${all_init_capabilities["$key"]}" | sort -u))

    superset_init_execs["$key"]=$(echo "$all_init_execs_json["$key"]" | yq -P '.')
    superset_init_open["$key"]=$(echo "$all_init_opens_json["$key"]" | yq -P '.')
    init_nullflag["$key"]=""
    if [ "$(echo "$all_init_endpoints_json["$key"]" | jq 'length')" -eq 0 ]; then
      init_nullflag["$key"]="null"
    else
      superset_init_endpoints=$(echo "$all_init_endpoints_json" | yq -P '.' )
    fi
    superset_init_rules=$(echo "$all_init_rules_json" | jq '
      group_by(.key) | map({
        key: .[0].key, value: (map(.value.processAllowed // []) | add | unique | if length > 0 then {processAllowed: .} else {} end)
      }) | from_entries' | yq -P '.')
    done #end of initContainer(key)

  rm "$norm_file"
  done # end of the main loop, where all the same files are aggregated


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
EOF
## Now loop over all container keys
for key in "${!keys[@]}"; do
cat <<EOF >> "$OUTPUT_FILE"
  - $(print_yaml_list_or_null_inline "capabilities" ${superset_capabilities["$key"]})
$(if [ "${nullflag["$key"]}" = "null" ]; then
    echo "    endpoints: null"
  else
    echo "    endpoints:"
    echo "${superset_endpoints["$key"]}" | indent_endpoints | sed -E '/^[[:space:]]*$/d'
  fi)
    execs:
$(echo "${superset_execs["$key"]}" | indent_execs)
    identifiedCallStacks: ${identifiedCallStacks["$key"]}
    imageID: ${imageID["$key"]}
    imageTag: ${imageTag["$key"]}
    name: ${containerName["$key"]}
    opens:
$(echo "${superset_open["$key"]}" | indent_opens)
    rulePolicies:
$(echo "${superset_rules["$key"]}" | indent_rules)
    seccompProfile:
      spec:
        defaultAction: ""
$(print_yaml_list_or_null_inline "    syscalls" ${superset_syscalls["$key"]})
EOF
done
## Now loop over all initContainer keys
# only add initContainers block if data exists
for key in "${!initkeys[@]}"; do
if [ "${#superset_init_capabilities["$key"]}" -gt 0 ] || [ "${#superset_init_syscalls["$key"]}" -gt 0 ]  ; then
cat <<EOF >> "$OUTPUT_FILE"
  initContainers:
  - capabilities: print_yaml_list_or_null ${superset_capabilities["$key"]}
    endpoints: ${init_nullflag["$key"]}
$(echo "${superset_init_endpoints["$key"]}" | indent_endpoints)
    execs:
$(echo "${superset_init_execs["$key"]}" | indent_execs)
    identifiedCallStacks: ${init_identifiedCallStacks["$key"]}
    imageID: ${init_imageID["$key"]}
    imageTag: ${init_imageTag["$key"]}
    name: ${init_containerName["$key"]}
    opens:
$(echo "${superset_init_opens["$key"]}" | indent_opens)
    rulePolicies:
$(echo "${superset_init_rules["$key"]}" | indent_rules)
    seccompProfile:
      spec:
        defaultAction: ""
    syscalls:
$(printf "%s\n" ${superset_init_syscalls["$key"]} | sed 's/^/    - /')s
EOF
fi
done

echo "Superset arrays written to '$OUTPUT_FILE'"

done