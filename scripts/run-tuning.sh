#!/usr/bin/env bash
# ============================================================================
# demo-hot-reload-collapse-config.sh
#
# Demonstrates hot-reloading of CollapseConfig via the storage ConfigMap.
# Designed for k3s on iximiuz labs — only needs kubectl and jq.
#
# What it does:
#   1. Shows the current storage ConfigMap (no collapseConfig.json key)
#   2. Creates a profile with 4 /var/run paths — default threshold=3 → collapses
#   3. Patches the ConfigMap to raise /var/run threshold to 10
#   4. Waits for the informer to pick up the change (~5s)
#   5. Creates a second profile with the same 4 paths — now below threshold → NOT collapsed
#   6. Side-by-side comparison proves the hot-reload worked
#   7. Cleans up
#
# Usage:
#   chmod +x demo-hot-reload-collapse-config.sh
#   ./demo-hot-reload-collapse-config.sh
# ============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
KS_NS="kubescape"
CM_NAME="storage"
TEST_NS="demo-collapse-$$"
API_GROUP="spdx.softwarecomposition.kubescape.io"
API_VERSION="v1beta1"
INFORMER_WAIT=6  # seconds to let the informer pick up changes

# --- Colors ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# --- Helpers -----------------------------------------------------------------
banner() { echo -e "\n${CYAN}${BOLD}=== $1 ===${RESET}\n"; }
info()   { echo -e "${GREEN}[+]${RESET} $1"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $1"; }
fail()   { echo -e "${RED}[x]${RESET} $1"; exit 1; }

check_deps() {
    for cmd in kubectl jq; do
        command -v "$cmd" &>/dev/null || fail "Required command not found: $cmd"
    done
}

cleanup() {
    banner "Cleanup"

    # Remove collapseConfig.json key from ConfigMap
    info "Removing collapseConfig.json from ConfigMap ${CM_NAME}..."
    kubectl patch configmap "$CM_NAME" -n "$KS_NS" \
        --type merge -p '{"data":{"collapseConfig.json":null}}' 2>/dev/null || true

    # Delete test profiles
    for name in demo-default-threshold demo-raised-threshold; do
        kubectl delete applicationprofiles.${API_GROUP} "$name" -n "$TEST_NS" 2>/dev/null || true
    done

    # Delete test namespace
    kubectl delete namespace "$TEST_NS" --wait=false 2>/dev/null || true

    info "Cleanup complete."
}
trap cleanup EXIT

# Creates an ApplicationProfile YAML with N unique opens under a given prefix
generate_profile_yaml() {
    local name="$1"
    local prefix="$2"
    local count="$3"

    local opens=""
    for i in $(seq 1 "$count"); do
        opens="${opens}
        - path: \"${prefix}/file${i}.pid\"
          flags: [\"O_RDONLY\"]"
    done

    cat <<EOF
apiVersion: ${API_GROUP}/${API_VERSION}
kind: ApplicationProfile
metadata:
  name: ${name}
  namespace: ${TEST_NS}
  labels:
    kubescape.io/managed-by: "User"
  annotations:
    kubescape.io/status: "completed"
    kubescape.io/completion: "complete"
spec:
  containers:
    - name: demo-container
      syscalls: ["read", "open"]
      opens:${opens}
      capabilities: []
      execs: []
      endpoints: []
EOF
}

# Retrieves opens from a stored profile and prints them
get_stored_opens() {
    local name="$1"
    kubectl get applicationprofiles.${API_GROUP} "$name" -n "$TEST_NS" -o json \
        | jq -r '.spec.containers[0].opens[] | .path'
}

# --- Main --------------------------------------------------------------------
check_deps

banner "Hot-Reload CollapseConfig Demo"
echo -e "This demo proves that storage collapse thresholds can be changed at"
echo -e "runtime via the ${BOLD}${CM_NAME}${RESET} ConfigMap — no pod restart needed.\n"
echo -e "Default /var/run threshold: ${BOLD}3${RESET}  (paths > 3 get collapsed)"
echo -e "We'll create 4 files under /var/run, then raise the threshold to 10.\n"

# --- Step 0: Prerequisites ---------------------------------------------------
banner "Step 0: Prerequisites"

info "Creating test namespace: ${TEST_NS}"
kubectl create namespace "$TEST_NS"

info "Verifying storage pod is running..."
kubectl get pods -n "$KS_NS" -l app=storage --no-headers \
    | grep -q Running || fail "Storage pod not running in ${KS_NS}"
info "Storage pod is healthy."

# --- Step 1: Show current ConfigMap ------------------------------------------
banner "Step 1: Current ConfigMap state"

info "ConfigMap ${CM_NAME} in ${KS_NS}:"
echo ""
kubectl get configmap "$CM_NAME" -n "$KS_NS" -o jsonpath='{.data}' | jq .
echo ""
warn "Note: No 'collapseConfig.json' key — defaults are active."
echo -e "  Default collapse configs:"
echo -e "    /etc           threshold=100"
echo -e "    /etc/apache2   threshold=5"
echo -e "    /opt           threshold=5"
echo -e "    ${BOLD}/var/run       threshold=3${RESET}"
echo -e "    /app           threshold=1"

# --- Step 2: Create profile with defaults ------------------------------------
banner "Step 2: Create profile with 4 /var/run paths (default threshold=3)"

info "Generating ApplicationProfile 'demo-default-threshold' with 4 /var/run opens..."
generate_profile_yaml "demo-default-threshold" "/var/run" 4 | kubectl apply -f -

sleep 1
info "Stored opens:"
echo ""
OPENS_BEFORE=$(get_stored_opens "demo-default-threshold")
echo "$OPENS_BEFORE" | while read -r path; do
    echo -e "  ${path}"
done
echo ""

COUNT_BEFORE=$(echo "$OPENS_BEFORE" | wc -l)
if [ "$COUNT_BEFORE" -lt 4 ]; then
    info "${GREEN}4 paths collapsed to ${COUNT_BEFORE} (4 > threshold 3) — expected!${RESET}"
else
    warn "Paths did NOT collapse (count=${COUNT_BEFORE}). Threshold may already be raised."
fi

# --- Step 3: Patch ConfigMap to raise threshold ------------------------------
banner "Step 3: Hot-reload — raise /var/run threshold to 10"

COLLAPSE_CONFIG='{"openDynamicThreshold":50,"endpointDynamicThreshold":100,"collapseConfigs":[{"prefix":"/etc","threshold":100},{"prefix":"/etc/apache2","threshold":5},{"prefix":"/opt","threshold":5},{"prefix":"/var/run","threshold":10},{"prefix":"/app","threshold":1}]}'

info "Patching ConfigMap with collapseConfig.json..."
kubectl patch configmap "$CM_NAME" -n "$KS_NS" \
    --type merge \
    -p "{\"data\":{\"collapseConfig.json\":$(echo "$COLLAPSE_CONFIG" | jq -Rs .)}}"

info "Updated ConfigMap:"
echo ""
kubectl get configmap "$CM_NAME" -n "$KS_NS" -o jsonpath='{.data}' | jq .
echo ""

info "Waiting ${INFORMER_WAIT}s for informer to pick up the change..."
sleep "$INFORMER_WAIT"
info "Informer should have updated the provider by now."

# --- Step 4: Create second profile with raised threshold ---------------------
banner "Step 4: Create profile with same 4 /var/run paths (threshold now 10)"

info "Generating ApplicationProfile 'demo-raised-threshold' with 4 /var/run opens..."
generate_profile_yaml "demo-raised-threshold" "/var/run" 4 | kubectl apply -f -

sleep 1
info "Stored opens:"
echo ""
OPENS_AFTER=$(get_stored_opens "demo-raised-threshold")
echo "$OPENS_AFTER" | while read -r path; do
    echo -e "  ${path}"
done
echo ""

COUNT_AFTER=$(echo "$OPENS_AFTER" | wc -l)
if [ "$COUNT_AFTER" -eq 4 ]; then
    info "${GREEN}4 paths remain individual (4 < threshold 10) — hot-reload worked!${RESET}"
else
    warn "Paths were collapsed (count=${COUNT_AFTER}). Hot-reload may not have taken effect."
fi

# --- Step 5: Side-by-side comparison ----------------------------------------
banner "Step 5: Side-by-side comparison"

echo -e "${BOLD}BEFORE (default threshold=3):${RESET}"
echo "$OPENS_BEFORE" | while read -r path; do echo "  $path"; done
echo -e "  Total paths: ${BOLD}${COUNT_BEFORE}${RESET}"
echo ""

echo -e "${BOLD}AFTER (threshold raised to 10):${RESET}"
echo "$OPENS_AFTER" | while read -r path; do echo "  $path"; done
echo -e "  Total paths: ${BOLD}${COUNT_AFTER}${RESET}"
echo ""

if [ "$COUNT_BEFORE" -lt 4 ] && [ "$COUNT_AFTER" -eq 4 ]; then
    echo -e "${GREEN}${BOLD}SUCCESS: Hot-reload changed collapse behavior without restarting storage!${RESET}"
else
    echo -e "${YELLOW}${BOLD}INCONCLUSIVE: Results don't match expected pattern. Check storage logs:${RESET}"
    echo -e "  kubectl logs -n ${KS_NS} -l app=storage --tail=50 | grep 'collapse config'"
fi

echo ""
info "Demo complete. Cleanup will run automatically."