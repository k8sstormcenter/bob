#!/usr/bin/env bash
set -euo pipefail


BASELINE_FILE="../src/fixtures/containerdseccomp.yaml"


BASELINE_SYSCALL_COUNT=$(yq '.allowedSyscalls | length' "$BASELINE_FILE")

summarize_profile() {
  local file="$1"
  local label="$2"


  capabilities=$(yq '.spec.containers[0].capabilities // [] | join(",")' "$file")
  syscalls=$(yq '.spec.containers[0].syscalls // [] | length' "$file")
  network=$(yq '.spec.containers[0].endpoints  // [] | length' "$file")
  opens=$(yq '.spec.containers[0].opens // [] | length' "$file")
  execs=$(yq '.spec.containers[0].execs // [] | length' "$file")
  seccomp=$(yq '.spec.containers[0].seccompProfile.spec.defaultAction' "$file")

  echo "$label|${capabilities:-none}|$network|$opens|$execs|$syscalls"
}

print_header() {
  echo "Profile|Capabilities|Network|Opens (#)|Execs (#)|Allowed Syscalls (#)"
  echo "-------|------------|-------|---------|---------|-------------------"
  echo "Kubernetes Default (v1.33)|unconfined|CNI|unconfined|unconfined|$BASELINE_SYSCALL_COUNT"
}

{
  print_header
for bfile in parameterstudy/pixie/super/*.yaml; do
  bname=$(basename "$bfile" .yaml)

  # Try to find corresponding C (bau) profile by matching core name
  core=$(echo "$bname" | sed -E 's/(catalogoperator|catalogsource|certman|initjob|kelvin|olmoperator|pem|pletcd|plnats|query|cloud|meta|vizieroperator).*/\1/')

  cfile=$(ls parameterstudy/pixie/bau/*"$core"*.yaml 2>/dev/null || true)

  if [[ -n "$cfile" ]]; then
    echo "-----"
    summarize_profile "$bfile" "$bname"
    summarize_profile "$cfile" "BAU :$bname"
    
  else
    summarize_profile "$bfile" "FULL:$bname"
    echo "-----"
  fi
done
}| column -t -s '|'




