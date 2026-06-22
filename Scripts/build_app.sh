#!/bin/bash
#
# Assemble and codesign a sandboxed ReKey.app from the SwiftPM executable.
#
# This produces a real App-Sandboxed .app (ad-hoc signed, with the network-client
# and user-selected-file entitlements) without an Xcode project. Notarization and
# Sparkle are deliberately out of scope here.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${1:-release}"
APP="$ROOT/ReKey.app"
ENTITLEMENTS="$ROOT/App/ReKey.entitlements"
INFO_PLIST="$ROOT/App/Info.plist"

echo "==> Building ReKey ($CONFIG)…"
swift build -c "$CONFIG" --product ReKey
BIN_PATH="$(swift build -c "$CONFIG" --product ReKey --show-bin-path)"

echo "==> Assembling $APP …"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN_PATH/ReKey" "$APP/Contents/MacOS/ReKey"
cp "$INFO_PLIST" "$APP/Contents/Info.plist"

# Copy SwiftPM resource bundles (PSL, EFF wordlist, FallbackMap) into
# Contents/Resources — the standard, codesign-sealable location. ReKey's
# ReKeyResources resolver looks here first, so Bundle.module's app-root
# expectation is irrelevant for the packaged app.
shopt -s nullglob
for bundle in "$BIN_PATH"/*.bundle; do
    cp -R "$bundle" "$APP/Contents/Resources/"
    echo "    bundled $(basename "$bundle") in Contents/Resources"
done
shopt -u nullglob

# App icon (Info.plist references AppIcon via CFBundleIconFile).
if [[ -f "$ROOT/App/AppIcon.icns" ]]; then
    cp "$ROOT/App/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
    echo "    bundled AppIcon.icns in Contents/Resources"
fi

# Privacy manifest (no data collected; declares required-reason API usage).
if [[ -f "$ROOT/App/PrivacyInfo.xcprivacy" ]]; then
    cp "$ROOT/App/PrivacyInfo.xcprivacy" "$APP/Contents/Resources/PrivacyInfo.xcprivacy"
    echo "    bundled PrivacyInfo.xcprivacy in Contents/Resources"
fi

# PkgInfo (optional but conventional).
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> Codesigning (ad-hoc) with sandbox entitlements…"
codesign --force --sign - --entitlements "$ENTITLEMENTS" --timestamp=none "$APP"

echo "==> Verifying signature + entitlements:"
codesign --verify --verbose=2 "$APP"
codesign --display --entitlements - --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null || \
    codesign --display --entitlements - "$APP"

echo ""
echo "Built: $APP"
echo "Run with:  open \"$APP\"   (or)   \"$APP/Contents/MacOS/ReKey\""
