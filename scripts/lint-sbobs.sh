#!/usr/bin/env bash
# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE.
# All trademarks are expressly reserved.

set -euo pipefail

BOBCTL=${BOBCTL:-bobctl}
BASELINE=${BASELINE:-.github/sbob-lint-baseline.txt}
ROOTS=${ROOTS:-example kubescape}
EXCLUDE=${EXCLUDE:-example/deprecated/}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

declare -A known=()
if [[ -f $BASELINE ]]; then
  while read -r id; do [[ -n $id ]] && known[$id]=1; done < "$BASELINE"
fi

checked=0 failed=0 new=0
declare -A seen=()

while IFS= read -r -d '' f; do
  [[ $f == $EXCLUDE* ]] && continue
  grep -q '^kind: ContainerProfile' "$f" || continue
  rm -f "$tmp"/doc.*
  awk -v out="$tmp/doc." 'BEGIN{n=0} /^---[[:space:]]*$/{n++; next} {print > (out n)}' "$f"
  for d in $(ls "$tmp"/doc.* | sort -t. -k2 -n); do
    grep -q '^kind: ContainerProfile' "$d" || continue
    idx=${d##*.}
    id="$f#$idx"
    checked=$((checked + 1))
    if out=$("$BOBCTL" validate --file "$d" 2>&1); then
      if [[ -n ${known[$id]:-} ]]; then
        echo "::warning file=$f::$id now passes validate; drop it from $BASELINE"
      fi
      continue
    fi
    failed=$((failed + 1))
    seen[$id]=1
    if [[ -n ${known[$id]:-} ]]; then
      echo "known  $id"
      continue
    fi
    new=$((new + 1))
    echo "::error file=$f::$id fails bobctl validate"
    echo "$out" | sed 's/^/    /'
  done
done < <(find $ROOTS -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 | sort -z)

for id in "${!known[@]}"; do
  [[ -n ${seen[$id]:-} ]] && continue
  f=${id%#*}
  [[ -f $f ]] || echo "::warning::$id is in $BASELINE but the file is gone"
done

echo "checked=$checked failed=$failed baseline=${#known[@]} new=$new"
[[ $new -eq 0 ]]
