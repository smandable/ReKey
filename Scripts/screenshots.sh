#!/bin/bash
#
# Capture a Mac App Store screenshot of the ReKey window.
#
# Each run: a camera cursor appears — click the ReKey window. The grab (no window
# shadow) is scaled to fit, padded to an EXACT App Store size, and flattened to
# remove the alpha channel (Apple rejects screenshots with transparency). Saved
# auto-numbered to ./screenshots/. Run it once per screen you want (Import,
# Findings, Fix Queue, Help, …); the store needs 1–10.
#
#   SIZE=1440x900    force a specific canvas. Default: AUTO — the smallest valid
#                    App Store size (1280x800 / 1440x900 / 2560x1600 / 2880x1800)
#                    that contains the window, so it's padded, never upscaled.
#   BG=ffffff        background/pad color, hex (default white).
#
# The window is captured at its NORMAL size and never resized up — the script only
# adds a margin to reach a legal dimension, so the app sits at natural size on a
# clean backdrop. Capture all your shots without resizing the window and they'll
# come out the same size (consistent in the listing).
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="$ROOT/screenshots"
mkdir -p "$OUTDIR"

BG="${BG:-ffffff}"

n=1
while [[ -e "$OUTDIR/$(printf 'rekey-%02d.png' "$n")" ]]; do ((n++)); done
OUT="$OUTDIR/$(printf 'rekey-%02d.png' "$n")"

TMP="$(mktemp -d)"; RAW="$TMP/raw.png"; trap 'rm -rf "$TMP"' EXIT
echo "Click the ReKey window to capture it (Esc to cancel)…"
screencapture -o -w "$RAW"
[[ -s "$RAW" ]] || { echo "Cancelled — nothing captured."; exit 1; }

# Window's natural pixel size (2x on Retina).
read OW OH < <(sips -g pixelWidth -g pixelHeight "$RAW" | awk '/pixelWidth/{w=$2}/pixelHeight/{h=$2}END{print w, h}')

# Choose the target canvas: an explicit SIZE, else the smallest legal App Store
# size that fully contains the window (so we pad, never upscale).
if [[ -n "${SIZE:-}" ]]; then
    W="${SIZE%x*}"; H="${SIZE#*x}"
else
    W=""; H=""
    for cand in 1280x800 1440x900 2560x1600 2880x1800; do
        cw="${cand%x*}"; ch="${cand#*x}"
        if (( cw >= OW && ch >= OH )); then W="$cw"; H="$ch"; break; fi
    done
    [[ -n "$W" ]] || { W=2880; H=1800; }   # window bigger than the largest size → scale down to fit
fi

# Only ever scale DOWN (if the window exceeds the target); never up.
if (( OW > W || OH > H )); then
    scale=$(awk -v W="$W" -v H="$H" -v ow="$OW" -v oh="$OH" 'BEGIN{a=W/ow;b=H/oh;print (a<b)?a:b}')
    sips --resampleHeightWidth \
        "$(awk -v s="$scale" -v d="$OH" 'BEGIN{printf "%d", d*s}')" \
        "$(awk -v s="$scale" -v d="$OW" 'BEGIN{printf "%d", d*s}')" "$RAW" >/dev/null
fi

# Center the window on the exact-size canvas (margin in BG), then drop alpha.
sips --padToHeightWidth "$H" "$W" --padColor "$BG" "$RAW" >/dev/null
sips -s format jpeg "$RAW" --out "$TMP/flat.jpg" >/dev/null   # jpeg has no alpha
sips -s format png "$TMP/flat.jpg" --out "$OUT" >/dev/null    # back to crisp png, now opaque

echo "Saved $OUT  ($(sips -g pixelWidth -g pixelHeight "$OUT" | awk '/pixelWidth/{w=$2}/pixelHeight/{h=$2}END{print w"x"h}'), no alpha)"
