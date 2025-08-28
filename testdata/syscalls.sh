#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./compare_attack_surface.sh <profile-b.yaml> <profile-c.yaml> [seccomp-default-json-url]
#
# Defaults:
#   seccomp-default-json-url -> https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json
#
# Prereqs: curl, jq, yq (mikefarah), awk, sort, comm

PROFILE_B="$1"
PROFILE_C="$2"
SECCOMP_URL="${3:-https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json}"
KERNEL_SYSCALL_URL="${4:-https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl}"

tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT

echo "Fetching kernel syscall table (x86_64)..."
curl -sSf "$KERNEL_SYSCALL_URL" -o "$tmpd/syscall_64.tbl"

# Extract syscall names robustly: skip comments/blank lines, prefer 3rd column.
awk '!/^#/ && NF>=3 {print $3}' "$tmpd/syscall_64.tbl" | sed '/^\s*$/d' | sort -u > "$tmpd/all_syscalls.txt"

echo "Downloading runtime default seccomp profile (as representative runtime default)..."
curl -sSfL "$SECCOMP_URL" -o "$tmpd/seccomp.json"

# Determine baseline allowed syscalls from runtime default profile:
defaultAction=$(jq -r '.defaultAction // ""' "$tmpd/seccomp.json")

if [ "$defaultAction" = "SCMP_ACT_ALLOW" ]; then
  # profile is allow-by-default, so syscalls listed with action != ALLOW are blocked
  jq -r '.syscalls[]? | select(.action != "SCMP_ACT_ALLOW") | .names[]' "$tmpd/seccomp.json" \
    | sort -u > "$tmpd/blocked_by_runtime.txt"
  # allowed = all - blocked
  comm -23 "$tmpd/all_syscalls.txt" "$tmpd/blocked_by_runtime.txt" > "$tmpd/allowed_baseline.txt"
else
  # profile is deny-by-default (e.g., defaultAction == SCMP_ACT_ERRNO/SCMP_ACT_KILL),
  # so allowed = names explicitly allowed
  jq -r '.syscalls[]? | select(.action == "SCMP_ACT_ALLOW") | .names[]' "$tmpd/seccomp.json" \
    | sort -u > "$tmpd/allowed_baseline.txt"
fi

# Helper: extract profile syscalls (unique, sorted)
extract_syscalls () {
  local file="$1" out="$2"
  # yq -> json -> jq to get flat list (handles null -> [])
  yq eval -o=json '.spec.containers[0].syscalls // []' "$file" \
    | jq -r '.[]' 2>/dev/null | sed '/^$/d' | sort -u > "$out" || true
}

# Helper: extract normalized opens list (replace pod/container timestamps & long hex ids)
extract_opens_normalized() {
  local file="$1" out="$2"
  # get .spec.containers[0].opens[].path
  yq eval -o=json '.spec.containers[0].opens // [] | .[].path' "$file" 2>/dev/null \
    | jq -r '. // empty' \
    | sed 's/\\x2d/-/g' \
    | sed -E 's/pod[0-9a-fA-F_\\-]+/pod⋯/g; s/cri-containerd-[0-9a-f]{64}\.scope/cri-containerd-⋯.scope/g; s/[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\.[0-9]+/⋯/g' \
    | sort -u > "$out" || true
}

# Extract profile syscall sets
extract_syscalls "$PROFILE_B" "$tmpd/profile_b_syscalls.txt"
extract_syscalls "$PROFILE_C" "$tmpd/profile_c_syscalls.txt"

# If a profile has no syscall lines (empty file), treat as empty set (observed none).
# (If you prefer to interpret "null" as "unconfined", adjust below.)

# Baseline counts
baseline_count=$(wc -l < "$tmpd/allowed_baseline.txt" | tr -d ' ')
# Profile counts
b_count=$(wc -l < "$tmpd/profile_b_syscalls.txt" | tr -d ' ')
c_count=$(wc -l < "$tmpd/profile_c_syscalls.txt" | tr -d ' ')

# Diffs (profile - baseline and baseline - profile)
b_added=$(comm -23 "$tmpd/profile_b_syscalls.txt" "$tmpd/allowed_baseline.txt" | wc -l | tr -d ' ')
b_removed=$(comm -23 "$tmpd/allowed_baseline.txt" "$tmpd/profile_b_syscalls.txt" | wc -l | tr -d ' ')
c_added=$(comm -23 "$tmpd/profile_c_syscalls.txt" "$tmpd/allowed_baseline.txt" | wc -l | tr -d ' ')
c_removed=$(comm -23 "$tmpd/allowed_baseline.txt" "$tmpd/profile_c_syscalls.txt" | wc -l | tr -d ' ')

# Extract opens and execs counts and capabilities
extract_opens_normalized "$PROFILE_B" "$tmpd/profile_b_opens.txt"
extract_opens_normalized "$PROFILE_C" "$tmpd/profile_c_opens.txt"

b_opens=$(wc -l < "$tmpd/profile_b_opens.txt" | tr -d ' ')
c_opens=$(wc -l < "$tmpd/profile_c_opens.txt" | tr -d ' ')

b_execs=$(yq eval '.spec.containers[0].execs // [] | length' "$PROFILE_B" 2>/dev/null || echo 0)
c_execs=$(yq eval '.spec.containers[0].execs // [] | length' "$PROFILE_C" 2>/dev/null || echo 0)

b_caps=$(yq eval -o=json '.spec.containers[0].capabilities // []' "$PROFILE_B" 2>/dev/null | jq -r '.[]' 2>/dev/null | paste -sd "," - || echo "none")
c_caps=$(yq eval -o=json '.spec.containers[0].capabilities // []' "$PROFILE_C" 2>/dev/null | jq -r '.[]' 2>/dev/null | paste -sd "," - || echo "none")

# Print compact markdown table suitable for PowerPoint
echo
echo "| Profile | # Allowed syscalls | Δ vs baseline | # Opens (normalized) | # Execs | Capabilities |"
echo "|---:|---:|:---:|---:|---:|:---|"
printf "| %s | %d | %s | %d | %s | %s |\n" "Runtime default (baseline)" "$baseline_count" "(–)" 0 0 "runtime-default"
printf "| %s | %d | %s | %d | %s | %s |\n" "Profile B ($(basename "$PROFILE_B"))" "$b_count" "$(printf '%+d / -%d' "$b_added" "$b_removed")" "$b_opens" "$b_execs" "$b_caps"
printf "| %s | %d | %s | %d | %s | %s |\n" "Profile C ($(basename "$PROFILE_C"))" "$c_count" "$(printf '%+d / -%d' "$c_added" "$c_removed")" "$c_opens" "$c_execs" "$c_caps"

echo
echo "Notes:"
echo "- Baseline computed as (all x86_64 kernel syscalls) minus (syscalls blocked by the runtime default seccomp profile)."
echo "- The script uses the provided seccomp profile URL (default: moby/moby default.json) as a representative runtime default; container runtimes may vary."
echo "- Opens are normalized (pod/container ids, timestamps replaced with ⋯) before counting unique entries."
