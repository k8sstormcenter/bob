#!/usr/bin/env bash
# render-gif.sh — render metrics.json into an animated GIF using containerized Python.
#
# Usage:
#   ./scripts/render-gif.sh results/metrics.json results/tune.gif
#   ./scripts/render-gif.sh results/metrics.json results/tune.gif --title "webapp (ubuntu-24.04)"
#
# Works on both local Docker and GitHub Actions runners.
# Falls back to native Python if Docker is unavailable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
METRICS_JSON="${1:?Usage: render-gif.sh <metrics.json> <output.gif> [--title TITLE]}"
OUTPUT_GIF="${2:?Usage: render-gif.sh <metrics.json> <output.gif> [--title TITLE]}"
shift 2

# Resolve to absolute paths
METRICS_JSON="$(cd "$(dirname "$METRICS_JSON")" && pwd)/$(basename "$METRICS_JSON")"
OUTPUT_DIR="$(cd "$(dirname "$OUTPUT_GIF")" && pwd)"
OUTPUT_NAME="$(basename "$OUTPUT_GIF")"

if ! [ -f "$METRICS_JSON" ]; then
  echo "ERROR: $METRICS_JSON not found" >&2
  exit 1
fi

# Check if metrics.json has any iterations
ITER_COUNT=$(python3 -c "import json; print(len(json.load(open('$METRICS_JSON'))))" 2>/dev/null || echo "0")
if [ "$ITER_COUNT" = "0" ]; then
  echo "SKIP: metrics.json is empty or unreadable — no GIF to render" >&2
  exit 0
fi

render_native() {
  echo "Rendering GIF natively (Python3 + matplotlib + Pillow)..." >&2
  python3 "$SCRIPT_DIR/render-metrics-gif.py" "$METRICS_JSON" "$OUTPUT_DIR/$OUTPUT_NAME" "$@"
}

render_docker() {
  echo "Rendering GIF in container (python:3.12-slim + matplotlib + Pillow)..." >&2
  # Build extra args array for proper quoting through docker
  local -a extra_args=()
  for arg in "$@"; do
    extra_args+=("$arg")
  done
  docker run --rm \
    -v "$SCRIPT_DIR/render-metrics-gif.py:/app/render-metrics-gif.py:ro" \
    -v "$METRICS_JSON:/data/metrics.json:ro" \
    -v "$OUTPUT_DIR:/output" \
    python:3.12-slim \
    bash -c 'pip install --quiet matplotlib pillow && python3 /app/render-metrics-gif.py /data/metrics.json "/output/'"$OUTPUT_NAME"'" "$@"' _ "${extra_args[@]}"
}

# Prefer native Python if matplotlib+Pillow are available (faster, no Docker pull).
# Fall back to Docker container.
if python3 -c "import matplotlib; import PIL" 2>/dev/null; then
  render_native "$@"
elif command -v docker &>/dev/null; then
  render_docker "$@"
else
  echo "ERROR: Neither Python3+matplotlib+Pillow nor Docker available." >&2
  echo "  Install: pip install matplotlib pillow" >&2
  echo "  Or: install Docker" >&2
  exit 1
fi
