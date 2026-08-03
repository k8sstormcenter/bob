#!/usr/bin/env bash
# Schema-validate every AttackSuite and FunctionalTestSuite under example/.
#
# Why this exists: a suite is only exercised if its app is in the CI tune matrix
# (.github/workflows/ci-bobctl-autotune.yaml). Argo CD is not, so
# example/argocd/attacks.yaml and example/argocd/functional-tests.yaml drifted
# out of schema and nobody noticed until an outside user tried to run them and
# filed bob#171. Every suite is checked here, matrix membership or not.
#
# No cluster required. bobctl parses and validates the suite BEFORE it touches
# kubernetes, so KUBECONFIG is pointed at a nonexistent path and the resulting
# error is classified:
#
#   "validating ... suite"  -> schema is wrong                    FAIL
#   "unresolved placeholder" -> schema unknown, env not set       FAIL (see below)
#   "connecting to cluster"  -> parsed and validated cleanly      PASS
#
# Placeholders (__NAME__, for run-time secrets that must never be committed) are
# satisfied with dummy values so a suite that uses them is still fully validated
# rather than skipped — otherwise the one suite carrying a credential would be
# the one suite nobody checks.
#
# Usage: scripts/validate-suites.sh [bobctl-path]
set -uo pipefail

BOBCTL="${1:-bin/bobctl}"
if [ ! -x "$BOBCTL" ]; then
  echo "error: $BOBCTL not found or not executable (run: make build)" >&2
  exit 2
fi

# Collect every placeholder any suite references and give each a dummy value.
mapfile -t NAMES < <(grep -ohE '__[A-Z][A-Z0-9_]*__' example/*-attacks.yaml \
                        example/*-functional-tests.yaml example/*/attacks.yaml \
                        example/*/functional-tests.yaml 2>/dev/null \
                     | sed 's/^__//; s/__$//' | sort -u)
for n in "${NAMES[@]:-}"; do
  [ -n "$n" ] && export "$n=dummy-value-for-validation"
done

pass=0; fail=0; failed=()

check() {
  local file="$1" kind="$2" out
  if [ "$kind" = attack ]; then
    out=$(KUBECONFIG=/nonexistent "$BOBCTL" attack --attack-suite "$file" -n validate 2>&1)
  else
    out=$(KUBECONFIG=/nonexistent "$BOBCTL" test --functional-tests "$file" -n validate 2>&1)
  fi

  if grep -q 'connecting to cluster' <<<"$out"; then
    printf '  PASS  %s\n' "$file"; pass=$((pass + 1)); return
  fi

  # Anything else that reached the cluster step is also fine — the point is that
  # loading and validating succeeded, not what happened afterwards.
  if ! grep -qE 'loading (attack suite|functional tests)' <<<"$out"; then
    printf '  PASS  %s\n' "$file"; pass=$((pass + 1)); return
  fi

  printf '  FAIL  %s\n        %s\n' "$file" \
    "$(grep -m1 '^Error:' <<<"$out" | cut -c1-160)"
  fail=$((fail + 1)); failed+=("$file")
}

echo "Validating attack suites..."
for f in example/*-attacks.yaml example/*/attacks.yaml; do
  [ -e "$f" ] && check "$f" attack
done

echo "Validating functional test suites..."
for f in example/*-functional-tests.yaml example/*/functional-tests.yaml; do
  [ -e "$f" ] && check "$f" functional
done

echo
echo "$pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  echo
  echo "These suites cannot be run by bobctl as shipped:"
  printf '  - %s\n' "${failed[@]}"
  echo "Fix the schema, or delete the file if it has been superseded."
  exit 1
fi

# A leading-wildcard open annihilates R0010/R1010/R1012. Never ship one.
python3 "$(dirname "$0")/check-no-overbroad.py" || exit 1
