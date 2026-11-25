#!/usr/bin/env bash
# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE.
# All trademarks are expressly reserved.
#
# Copies the SBoBs of a Contrast run into example/, but only those whose gate passed in that run.
# A file is the run's artifact with the licence header in front; nothing else is changed.
# Each SBoB is placed in both exec forms: the regex form at its place, the legacy args grammar in legacy/ beside it.
# usage: place-example-sbobs.sh <directory with the downloaded sbob-* artifacts> [mapping file] [report file]
set -euo pipefail
SRC=${1:?directory with the downloaded sbob-* artifacts}
MAP=${2:-.github/contrast/examples.txt}
REPORT=${3:-/dev/stdout}
placed=0 held=0
{
  echo "| Application | Gate | Example file | Why |"
  echo "|---|---|---|---|"
} > "$REPORT"
while IFS= read -r f; do
  app=$(basename "$f" -sbob.yaml)
  dest=$(awk -F'|' -v a="$app" '$1 == a {print $2}' "$MAP" | head -1)
  [ -n "$dest" ] || dest="example/contrast/cp-$app.yaml"
  gate="$(dirname "$f")/$app-gate.json"
  if [ ! -f "$gate" ]; then
    echo "| $app | no verdict | $dest left as it is | the run produced no gate verdict |" >> "$REPORT"
    held=$((held + 1))
    continue
  fi
  if [ "$(jq -r .pass "$gate")" != true ] || ! grep -q '^kind: ContainerProfile' "$f"; then
    why=$(jq -r '[.checks[] | select(.pass == false) | .name + ": " + .value] | join("; ")' "$gate")
    echo "| $app | held back | $dest left as it is | ${why//|/ } |" >> "$REPORT"
    held=$((held + 1))
    continue
  fi
  legacy="$(dirname "$f")/$app-legacy.yaml"
  if [ ! -f "$legacy" ] || grep -q 'argsRegex' "$legacy"; then
    echo "| $app | held back | $dest left as it is | the run did not write the legacy exec form beside the regex form |" >> "$REPORT"
    held=$((held + 1))
    continue
  fi
  mkdir -p "$(dirname "$dest")/legacy"
  for pair in "$f|$dest" "$legacy|$(dirname "$dest")/legacy/$(basename "$dest")"; do
    {
      echo '# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>'
      echo '# SPDX-License-Identifier: Apache-2.0'
      echo '# Licensed under the Apache License, Version 2.0; see LICENSE.'
      echo '# All trademarks are expressly reserved.'
      cat "${pair%%|*}"
    } > "${pair##*|}"
  done
  echo "| $app | pass | $dest | $(jq -r '"\(.steps_detected) of \(.steps_ran) simulated steps detected, \(.benign_causes) alert causes under usual traffic"' "$gate") |" >> "$REPORT"
  placed=$((placed + 1))
done < <(find "$SRC" -type f -name '*-sbob.yaml' | sort)
{
  echo
  echo "**Applications bobctl was not prepared for** (no step, path or trait is written for them; only the type is given)"
  echo
  echo "| Application | Ecosystem expected | Found from behaviour | Simulated steps detected | Alert causes under usual traffic | Gate |"
  echo "|---|---|---|---|---|---|"
  n=0 ok=0
  while IFS= read -r g; do
    [ "$(jq -r '.corpus // "known"' "$g")" = unknown ] || continue
    n=$((n + 1))
    [ "$(jq -r .pass "$g")" = true ] && ok=$((ok + 1))
    jq -r '"| \(.app) | \(.ecosystem_expected) | \(.traits_found | join(", ")) \(if .ecosystem_recognised then "(recognised)" else "(**not recognised**)" end) | \(.steps_detected) of \(.steps_ran) | \(.benign_causes) | \(if .pass then "pass" else "held back" end) |"' "$g"
  done < <(find "$SRC" -type f -name '*-gate.json' | sort)
  echo
  echo "$ok of $n unknown applications pass the gate."
} >> "$REPORT"
echo "placed $placed, held back $held" >&2
