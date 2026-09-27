#!/usr/bin/env bash
# compose-split.sh — build the final side-by-side demo video.
#
#   left  = RanUI, the disease path        (ran-attack-left.webm,  960x1080)
#   right = Pixie/dx, the detection        (pixie-detect-right.webm, 960x1080)
#   out   = 1920x1080, exactly the laptop screen
#
# Both panels are recorded natively at half-screen width, so this is a pure
# hstack: no cropping (nothing of either UI is lost) and no rescaling.
#
#   ./compose-split.sh [left.webm] [right.webm] [out.mp4]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FFMPEG="${FFMPEG:-$(command -v ffmpeg || true)}"
[ -x "$FFMPEG" ] || { echo "need ffmpeg on PATH (or set FFMPEG=/path/to/ffmpeg)"; exit 2; }
L="${1:-$HERE/iktlinz-demo.webm}"
R="${2:-$HERE/pixie-detect-right.webm}"
OUT="${3:-$HERE/iktlinz-split.mp4}"

[ -f "$L" ] || { echo "missing left panel: $L"; exit 1; }
if [ ! -f "$R" ]; then
  echo "no right panel yet ($R) — emitting the left panel alone."
  "$FFMPEG" -y -i "$L" -c:v libx264 -pix_fmt yuv420p -crf 20 "$OUT"
  echo "wrote $OUT (left only)"; exit 0
fi

# Pad the shorter panel so both run the full length (tpad clones the last frame).
"$FFMPEG" -y -i "$L" -i "$R" -filter_complex "\
[0:v]scale=960:1080:force_original_aspect_ratio=decrease,pad=960:1080:(ow-iw)/2:(oh-ih)/2,tpad=stop_mode=clone:stop_duration=600[l];\
[1:v]scale=960:1080:force_original_aspect_ratio=decrease,pad=960:1080:(ow-iw)/2:(oh-ih)/2,tpad=stop_mode=clone:stop_duration=600[r];\
[l][r]hstack=inputs=2,trim=duration=$( "$FFMPEG" -i "$L" 2>&1 | awk -F'[:,]' '/Duration/{print ($2*3600)+($3*60)+$4; exit}' || echo 600 )[v]" \
  -map "[v]" -c:v libx264 -pix_fmt yuv420p -crf 20 "$OUT"

echo "wrote $OUT (1920x1080 split: attack | detection)"
