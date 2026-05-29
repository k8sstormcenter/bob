# test_helper.bash — hermetic test scaffolding for scripts/lib/chain-*.sh.
#
# Source this at the top of every *_test.sh. Provides:
#   - a mock `kubectl` (and `sleep`) on PATH that records every
#     invocation to $KUBECTL_LOG and returns canned, configurable output
#   - assertion helpers (assert_eq / assert_rc / assert_log_* / ...)
#   - a pass/fail tally + finish() that sets the file's exit code
#
# Design: the chain-* helpers source chain-manifest-parse.sh and reach
# the cluster via kubectl. Tests mock kubectl (the side-effect seam) and
# stub the manifest_* accessors (the input seam) so orchestration logic
# is exercised with zero external deps — no yq, no jq, no live cluster.
# Tier-2 tests that DO want real yq parsing guard with require_yq.

set -uo pipefail

TEST_NAME="$(basename "${BASH_SOURCE[1]:-test}" .sh)"
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/../.." && pwd)"
FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fixtures"

_PASS=0
_FAIL=0
_TMP="$(mktemp -d)"
trap '_cleanup' EXIT

_cleanup() { rm -rf "$_TMP"; }

# ── mock kubectl ──────────────────────────────────────────────────────
# Writes a kubectl shim to $_TMP/bin and prepends it to PATH. Every call
# is appended (argv space-joined) to $KUBECTL_LOG. Behavior is tuned by
# env vars the test sets BEFORE calling the function under test:
#   MOCK_MANAGED_BY       value returned for the managed-by jsonpath
#                         query (default "User")
#   MOCK_DEPLOY_RC        exit code for `kubectl get deploy <n>`
#                         (default 0 = exists)
#   MOCK_AP_LIST_JSON     file whose contents are returned for
#                         `kubectl get applicationprofile -n <ns> -o json`
#   MOCK_NN_LIST_JSON     same for networkneighborhood list
install_mocks() {
  export KUBECTL_LOG="$_TMP/kubectl.log"
  export SLEEP_LOG="$_TMP/sleep.log"
  : > "$KUBECTL_LOG"
  : > "$SLEEP_LOG"
  mkdir -p "$_TMP/bin"

  cat > "$_TMP/bin/kubectl" <<'MOCK'
#!/usr/bin/env bash
echo "$*" >> "$KUBECTL_LOG"
# Drain stdin for `kubectl apply -f -` so upstream pipes don't SIGPIPE.
case " $* " in *" -f - "*) cat >/dev/null 2>&1 || true ;; esac

verb=$1; kind=${2:-}
case "$verb $kind" in
  "get applicationprofile"|"get networkneighborhood")
    # List form: `get <kind> -n <ns> -o json` (3rd arg starts with -).
    if [[ "${3:-}" == -* ]]; then
      if [[ "$kind" == applicationprofile && -n "${MOCK_AP_LIST_JSON:-}" ]]; then
        cat "$MOCK_AP_LIST_JSON"; exit 0
      fi
      if [[ "$kind" == networkneighborhood && -n "${MOCK_NN_LIST_JSON:-}" ]]; then
        cat "$MOCK_NN_LIST_JSON"; exit 0
      fi
      echo '{"items":[]}'; exit 0
    fi
    # Named form: the managed-by jsonpath query.
    echo "${MOCK_MANAGED_BY-User}"
    exit 0
    ;;
  "get deploy")
    exit "${MOCK_DEPLOY_RC:-0}"
    ;;
  *)
    exit 0
    ;;
esac
MOCK
  chmod +x "$_TMP/bin/kubectl"

  # sleep shim — record requested seconds, return instantly so the
  # cache-flush wait test doesn't actually block.
  cat > "$_TMP/bin/sleep" <<'MOCK'
#!/usr/bin/env bash
echo "$*" >> "$SLEEP_LOG"
exit 0
MOCK
  chmod +x "$_TMP/bin/sleep"

  export PATH="$_TMP/bin:$PATH"
}

# ── manifest accessor stubs ───────────────────────────────────────────
# Replace the yq-backed accessors with fixture-returning functions so
# orchestration tests need no yq. Call AFTER sourcing the helper under
# test (sourcing pulls in the real chain-manifest-parse.sh; these
# redefinitions win).
#
# stub_manifest <namespace> <pods-tsv> [deploy-tsv] [scenarios-json] [sbob_dir]
#   pods-tsv:   newline-separated "name<TAB>profile_match<TAB>container<TAB>negctl"
#   deploy-tsv: newline-separated "path<TAB>optional"
stub_manifest() {
  local ns=$1 pods=$2 deploy=${3:-} scenarios=${4:-} sbobdir=${5:-sbobs}
  eval "manifest_validate() { return 0; }"
  eval "manifest_field() { case \"\$2\" in
    *.namespace) echo '$ns' ;;
    *.sbob_dir)  echo '$sbobdir' ;;
    *) echo '' ;;
  esac; }"
  # Use printf into the function bodies via temp files to preserve tabs.
  printf '%s' "$pods"      > "$_TMP/pods.tsv"
  printf '%s' "$deploy"    > "$_TMP/deploy.tsv"
  printf '%s' "$scenarios" > "$_TMP/scenarios.json"
  eval "manifest_pods()      { cat '$_TMP/pods.tsv'; }"
  eval "manifest_deploy()    { cat '$_TMP/deploy.tsv'; }"
  eval "manifest_scenarios() { cat '$_TMP/scenarios.json'; }"
}

# ── assertions ────────────────────────────────────────────────────────
_ok()   { _PASS=$((_PASS+1)); printf '  ok   %s\n' "$1"; }
_bad()  { _FAIL=$((_FAIL+1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '       %s\n' "$2"; }

assert_eq() { # expected actual msg
  if [[ "$1" == "$2" ]]; then _ok "$3"; else _bad "$3" "expected [$1] got [$2]"; fi
}
assert_rc() { # expected_rc actual_rc msg
  if [[ "$1" == "$2" ]]; then _ok "$3"; else _bad "$3" "expected rc=$1 got rc=$2"; fi
}
assert_log_contains() { # pattern msg
  if grep -qF -- "$1" "$KUBECTL_LOG"; then _ok "$2"; else _bad "$2" "pattern not in kubectl log: $1"; fi
}
assert_log_absent() { # pattern msg
  if grep -qF -- "$1" "$KUBECTL_LOG"; then _bad "$2" "pattern unexpectedly in log: $1"; else _ok "$2"; fi
}
# assert_log_order FIRST SECOND msg — first matching line precedes second
assert_log_order() {
  local a b
  a=$(grep -nF -- "$1" "$KUBECTL_LOG" | head -1 | cut -d: -f1)
  b=$(grep -nF -- "$2" "$KUBECTL_LOG" | head -1 | cut -d: -f1)
  if [[ -n "$a" && -n "$b" && "$a" -lt "$b" ]]; then
    _ok "$3"
  else
    _bad "$3" "expected [$1]@$a before [$2]@$b"
  fi
}
assert_sleep_contains() { # pattern msg
  if grep -qF -- "$1" "$SLEEP_LOG"; then _ok "$2"; else _bad "$2" "sleep not called with: $1"; fi
}

# require_yq — tier-2 guard. Skips (exits 0) the file when yq is absent.
require_yq() {
  if ! command -v yq >/dev/null 2>&1; then
    printf '  skip %s (yq not installed)\n' "$TEST_NAME"
    exit 0
  fi
}

finish() {
  printf '%s: %d passed, %d failed\n' "$TEST_NAME" "$_PASS" "$_FAIL"
  [[ "$_FAIL" -eq 0 ]]
}
