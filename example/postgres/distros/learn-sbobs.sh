#!/usr/bin/env bash
# Re-learn the distro SBoBs. Run after ./deploy-distros.sh.
#
#   ./learn-sbobs.sh [oss|bitnami|cnpg|all]
set -euo pipefail
cd "$(dirname "$0")"

CP=containerprofiles.spdx.softwarecomposition.kubescape.io
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

declare -A NS=(  [oss]=postgres-oss     [bitnami]=postgres-bitnami [cnpg]=postgres-cnpg )
declare -A SRV=( [oss]=postgres         [bitnami]=postgresql       [cnpg]=pg-1          )
declare -A OUT=( [oss]=postgres-oss     [bitnami]=postgres-bitnami [cnpg]=postgres-cnpg )

drive_benign() {
  local ns=$1 suite=$2
  bobctl test -n "$ns" --functional-tests "$suite" >/dev/null 2>&1 || \
    bobctl test -n "$ns" --functional-tests "$suite"
}

wait_for_entries() {
  local ns=$1 obj=$2 n
  for _ in $(seq 1 40); do
    n=$(bobctl get "$obj" -n "$ns" -o wide 2>/dev/null | awk '/^  (Execs|Opens):/ {t+=$2} END {print t+0}')
    [ "${n:-0}" -gt 0 ] && return 0
    sleep 10
  done
  echo "  $obj: no entries after 400s — was the benign suite driven inside the window?" >&2
  return 1
}

sbob_for() {
  local ns=$1 obj=$2 name=$3 out=$4
  local d="$WORK/$name"; mkdir -p "$d"
  bobctl get "$obj" -n "$ns" -o yaml > "$d/learned.yaml"
  bobctl generalize -d "$d" --sbob "$name" -o "$WORK/$name.sbob.yaml" >/dev/null
  bobctl portable --file "$WORK/$name.sbob.yaml" --out "$out"
  bobctl validate --file "$out"
}

learn_one() {
  local fork=$1 ns=${NS[$1]} obj
  echo "=== $fork ($ns)"
  drive_benign "$ns" "functional/$fork.yaml"

  obj=$(kubectl get $CP -n "$ns" -o name 2>/dev/null | sed 's|.*/||' | grep -- "${SRV[$fork]}" | grep -v initdb | head -1)
  [ -n "$obj" ] || { echo "  no server profile matching '${SRV[$fork]}' in $ns" >&2; return 1; }
  wait_for_entries "$ns" "$obj"
  sbob_for "$ns" "$obj" "${OUT[$fork]}" "sbobs/cp-${OUT[$fork]}.yaml"

  if [ "$fork" = oss ]; then
    obj=$(kubectl get $CP -n "$ns" -o name 2>/dev/null | sed 's|.*/||' | grep pg-client | head -1)
    [ -n "$obj" ] || { echo "  no pg-client profile in $ns" >&2; return 1; }
    wait_for_entries "$ns" "$obj"
    sbob_for "$ns" "$obj" pg-client sbobs/cp-pg-client.yaml
  fi
}

case "${1:-all}" in
  all) for f in oss bitnami cnpg; do learn_one "$f"; done ;;
  *)   learn_one "$1" ;;
esac
