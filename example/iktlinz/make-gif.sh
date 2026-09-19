#!/usr/bin/env bash
# make-gif.sh — turn a RanUI screencast into a GIF of ONLY the fully-rendered states.
#
# The screencast contains reload flashes (blank/partial paints) and long runs of
# identical stills. Selecting by brightness/"ink" would wrongly drop the early
# steps, whose graph is legitimately near-empty — so we select by STABILITY:
# a settled state persists for many frames, a reload transient does not.
#
#   ./make-gif.sh [video] [out.gif] [seconds-per-state]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FFMPEG="$HERE/bin/ffmpeg"
VID="${1:-$HERE/ran-attack-left.webm}"
OUT="${2:-$HERE/iktlinz-attack.gif}"
SPF="${3:-1.4}"

WORK="$HERE/.gifwork"; rm -rf "$WORK"; mkdir -p "$WORK/all" "$WORK/keep"
"$FFMPEG" -y -i "$VID" -vsync 0 "$WORK/all/f%05d.png" >/dev/null 2>&1
echo "  extracted $(ls "$WORK"/all/*.png | wc -l) frames"

python3 - "$WORK" <<'PY'
from PIL import Image
import numpy as np, glob, sys, shutil, os
work = sys.argv[1]
def dhash(im, s=12):
    a = np.asarray(im.convert('L').resize((s+1, s)), dtype=np.int16)
    return (a[:, 1:] > a[:, :-1]).flatten()
files = sorted(glob.glob(f'{work}/all/*.png'))
hs, sd = [], []
for f in files:
    im = Image.open(f); hs.append(dhash(im))
    sd.append(float(np.asarray(im.convert('L'), dtype=np.float32).std()))
d = lambda a, b: int(np.count_nonzero(a != b))
runs, start = [], 0
for i in range(1, len(files)):
    if d(hs[i], hs[start]) > 6:
        runs.append((start, i-1)); start = i
runs.append((start, len(files)-1))
MIN_RUN = 8                      # >=0.32s at 25fps == a real settled state
keep = []
for a, b in runs:
    if b - a + 1 < MIN_RUN: continue
    rep = b                      # last frame of the run is the most settled
    if sd[rep] < 5: continue     # fully blank (mid-reload)
    if keep and d(hs[rep], hs[keep[-1]]) <= 6: continue
    keep.append(rep)
for n, i in enumerate(keep, 1):
    shutil.copy(files[i], f'{work}/keep/g{n:03d}.png')
print(f"  {len(files)} frames -> {len(runs)} runs -> {len(keep)} settled states")
PY

"$FFMPEG" -y -framerate "1/$SPF" -i "$WORK/keep/g%03d.png" \
  -vf "scale=800:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=3" \
  -loop 0 "$OUT" >/dev/null 2>&1
echo "  wrote $OUT ($(stat -c%s "$OUT") bytes)"
rm -rf "$WORK"
