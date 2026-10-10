#!/usr/bin/env bash
# Regenerates deploy/arc-runner-runner.yaml from sbobs/runner (base + every overlay); git diff shows any drift.
set -euo pipefail
G=$(cd "$(dirname "$0")/.." && pwd)
${BOBCTL:-bobctl} compose --name arc-runner-runner -o "$G/deploy/arc-runner-runner.yaml" "$G/sbobs/runner/base.yaml" "$G"/sbobs/runner/overlays/*.yaml
