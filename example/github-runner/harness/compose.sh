#!/usr/bin/env bash
# Regenerates the runner ContainerProfiles in deploy/ from sbobs/runner-family (shared base + one overlay per profile); git diff shows any drift.
set -euo pipefail
G=$(cd "$(dirname "$0")/.." && pwd)
F="$G/sbobs/runner-family"
for ov in "$F"/runner-overlay-*.yaml; do
  name=$(basename "$ov" .yaml); name=${name#runner-overlay-}
  ${BOBCTL:-bobctl} compose --name "$name" -o "$G/deploy/$name.yaml" "$F/runner.yaml" "$ov"
done
