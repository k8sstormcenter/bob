#!/usr/bin/env bash
# md-to-pdf.sh — Convert markdown files to PDF on standard Linux
#
# Requires: Node.js (uses npx md-to-pdf — no sudo needed)
#
# Usage:
#   ./scripts/md-to-pdf.sh                          # converts pkg/README.md → pkg/README.pdf
#   ./scripts/md-to-pdf.sh path/to/file.md          # converts specific file
#   ./scripts/md-to-pdf.sh file.md -o output.pdf    # custom output path
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INPUT="${1:-$REPO_ROOT/pkg/README.md}"
OUTPUT=""

# Parse -o flag
shift 2>/dev/null || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUTPUT="$2"; shift 2 ;;
    *)  shift ;;
  esac
done

[[ -f "$INPUT" ]] || { echo "File not found: $INPUT" >&2; exit 1; }

# Default output: same path with .pdf extension
if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${INPUT%.md}.pdf"
fi

echo "Input:  $INPUT"
echo "Output: $OUTPUT"

# ── Check node is available ──────────────────────────────────────────────────
if ! command -v npx &>/dev/null; then
  echo "npx not found. Install Node.js (https://nodejs.org) or use nvm." >&2
  exit 1
fi

# ── Convert using md-to-pdf (Chromium-based, GitHub-flavored markdown) ───────
# md-to-pdf outputs to the same directory by default; we use --as-html=false
# and a config for styling.
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Copy input to tmpdir so md-to-pdf writes output there
cp "$INPUT" "$TMPDIR/doc.md"

cat > "$TMPDIR/.md-to-pdf.js" <<'EOF'
module.exports = {
  stylesheet: [],
  css: `
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      max-width: 900px;
      margin: 0 auto;
      padding: 1.5em;
      color: #24292e;
    }
    h1, h2, h3 { border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
    h1 { font-size: 1.8em; }
    h2 { font-size: 1.4em; }
    code { background: #f6f8fa; padding: 0.2em 0.4em; border-radius: 3px; font-size: 85%; }
    pre { background: #f6f8fa; padding: 0.8em; border-radius: 6px; overflow-x: auto; font-size: 12px; }
    pre code { background: none; padding: 0; }
    table { border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 12px; }
    th, td { border: 1px solid #dfe2e5; padding: 4px 10px; }
    th { background: #f6f8fa; font-weight: 600; }
    tr:nth-child(even) { background: #f6f8fa; }
  `,
  pdf_options: {
    format: 'A4',
    margin: { top: '15mm', bottom: '15mm', left: '15mm', right: '15mm' },
    printBackground: true,
  },
  marked_options: {
    gfm: true,
    breaks: false,
  },
};
EOF

npx --yes md-to-pdf "$TMPDIR/doc.md" --config-file "$TMPDIR/.md-to-pdf.js" 2>&1

# Move to requested output path
mv "$TMPDIR/doc.pdf" "$OUTPUT"

echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
