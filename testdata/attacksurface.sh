#!/usr/local/bin/bash


#set -xe
set -euo pipefail

INPUT_DIR="${1:-}"
if [ -z "$INPUT_DIR" ] || [ ! -d "$INPUT_DIR" ]; then
  echo "Usage: $0 <directory_with_bob_yamls>"
  exit 1
fi

if ! command -v yq &> /dev/null; then
    echo "Error: yq is required."
    exit 1
fi

print_header() {
  echo "| Component                   | Container         | Type          | Capabilities                        | Net    | Opens  | Execs  | Syscalls |"
  echo "|-----------------------------|------------------|--------------|-------------------------------------|--------|--------|--------|----------|"
}


shorten_name() {
  local name="$1"
  name=$(echo "$name" | sed -E 's/\b(replica|stateful|daemon|deployment|job|cronjob)set\b/rs/g; s/\bdaemonset\b/ds/g; s/\bstatefulset\b/sts/g; s/\bdeployment\b/deploy/g; s/\bcronjob\b/cj/g; s/\bjob\b/job/g')
  name=$(echo "$name" | sed -E 's/-other-k8s-[0-9\-]+//g; s/-[0-9a-f]{6,}$//')
  echo "$name"
}
format_caps() {
  local caps="$1"
  if [ -z "$caps" ]; then
    echo "none"
    return
  fi
  echo "$caps" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | awk 'ORS="<br>" {print}' | sed 's/<br>$//'
}
summarize_profile() {
  local file="$1"
  local component="$2"

  # Containers
  local container_count
  container_count=$(yq '.spec.containers | length' "$file")
  for ((i=0; i<container_count; i++)); do
    local name type capabilities network opens execs syscalls
    name=$(yq -r ".spec.containers[$i].name // \"\"" "$file" | tr -d '\n')
    type="container"
    capabilities=$(yq -r ".spec.containers[$i].capabilities // [] | join(\", \")" "$file")
    network=$(yq ".spec.containers[$i].endpoints // [] | length" "$file" | xargs)
    opens=$(yq ".spec.containers[$i].opens // [] | length" "$file" | xargs)
    execs=$(yq ".spec.containers[$i].execs // [] | length" "$file" | xargs)
    syscalls=$(yq ".spec.containers[$i].syscalls // [] | length" "$file" | xargs)
    printf "| %-27s | %-16s | %-12s | %-35s | %-6s | %-6s | %-6s | %-8s |\n" \
      "$component" "$name" "$type" "$(format_caps "$capabilities")" "$network" "$opens" "$execs" "$syscalls"
  done

  # InitContainers
  local init_count
  init_count=$(yq '.spec.initContainers // [] | length' "$file")
  for ((j=0; j<init_count; j++)); do
    local name type capabilities network opens execs syscalls
    name=$(yq -r ".spec.initContainers[$j].name // \"\"" "$file" | tr -d '\n')
    type="initContainer"
    capabilities=$(yq -r ".spec.initContainers[$j].capabilities // [] | join(\", \")" "$file")
    network=$(yq '.spec.initContainers[$j].endpoints // [] | length' "$file")
    opens=$(yq '.spec.initContainers[$j].opens // [] | length' "$file")
    execs=$(yq '.spec.initContainers[$j].execs // [] | length' "$file")
    syscalls=$(yq '.spec.initContainers[$j].syscalls // [] | length' "$file")
    printf "| %-27s | %-16s | %-12s | %-35s | %-6s | %-6s | %-6s | %-8s |\n" \
      "$component" "$name" "$type" "$(format_caps "$capabilities")" "$network" "$opens" "$execs" "$syscalls"
  done
}
unset GROUPSS
declare -A GROUPSS

# Group files by shortname (component)
for file in "$INPUT_DIR"/*_bob.yaml; do
  [ -f "$file" ] || continue
  name=$(yq '.metadata.name' "$file")
  shortname=$(shorten_name "$name")
  GROUPSS["$shortname"]+="$file "
done

print_header
for shortname in "${!GROUPSS[@]}"; do
  for file in ${GROUPSS[$shortname]}; do
    summarize_profile "$file" "$shortname"
  done
done