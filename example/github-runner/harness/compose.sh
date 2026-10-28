#!/usr/bin/env bash
# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE.
# All trademarks are expressly reserved.

# Regenerates the runner ContainerProfiles in deploy/ from sbobs/runner-family (shared base + one overlay per profile + the pkg-maintenance overlay), minus every ioc-overlays subtract fragment; git diff shows any drift.
set -euo pipefail
G=$(cd "$(dirname "$0")/.." && pwd)
F="$G/sbobs/runner-family"
for ov in "$F"/runner-overlay-*.yaml; do
  name=$(basename "$ov" .yaml); name=${name#runner-overlay-}
  [ "$name" = pkg-maintenance ] && continue
  ${BOBCTL:-bobctl} compose --name "$name" -n arc-systems -o "$G/deploy/$name.yaml" "$F/runner.yaml" "$ov" "$F/runner-overlay-pkg-maintenance.yaml" "$G"/ioc-overlays/*.yaml
done
