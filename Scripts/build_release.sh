#!/bin/bash
#
# Build a notarized, Developer-ID-signed ReKey.dmg for direct (GitHub) download.
#
# This is the FULL app — Cull, Clean Up, the rekey-cleanup workflow, and free
# fixing (no MAS_BUILD flag, so no paywall). It's signed for distribution OUTSIDE
# the App Store (Developer ID + notarization), so a downloaded copy runs without a
# Gatekeeper warning. Counterpart to build_mas.sh (the App Store .pkg).
#
# REQUIRED environment:
#   SIGN_APP        Developer ID Application identity, e.g.
#                   "Developer ID Application: Sean Mandable (7VP76365KX)"
#   NOTARY_PROFILE  A notarytool keychain profile you set up ONCE with:
#                     xcrun notarytool store-credentials "rekey-notary" \
#                       --apple-id you@example.com --team-id 7VP76365KX \
#                       --password <app-specific-password>
#                   (create the app-specific password at appleid.apple.com)
#
# Optional:
#   MARKETING_VERSION=1.1  Set CFBundleShortVersionString (the user-visible version)
#                          in App/Info.plist — the single source of truth, also read
#                          by build_mas.sh. Commit the change as part of the release.
#                          Omit to keep whatever's already in the plist.
#   BUILD_NUMBER=…         Override the auto date-time CFBundleVersion.
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${SIGN_APP:?Set SIGN_APP to your Developer ID Application identity}"
: "${NOTARY_PROFILE:?Set NOTARY_PROFILE to your notarytool keychain profile name}"

APP="$ROOT/build/ReKey.app"
DMG="$ROOT/build/ReKey.dmg"
ZIP="$ROOT/build/ReKey-notarize.zip"
ENTITLEMENTS="$ROOT/App/ReKey.entitlements"
INFO_PLIST="$ROOT/App/Info.plist"

# Marketing version (the user-visible "1.1"). When MARKETING_VERSION is set, write
# it into the source Info.plist so it's the single source of truth shared with
# build_mas.sh; the bundle copy below inherits it. (CFBundleVersion is the separate
# auto date-time build number, stamped further down.)
if [[ -n "${MARKETING_VERSION:-}" ]]; then
    if [[ ! "$MARKETING_VERSION" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
        echo "MARKETING_VERSION must look like 1, 1.1, or 1.2.3 (got '$MARKETING_VERSION')." >&2
        exit 1
    fi
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $MARKETING_VERSION" "$INFO_PLIST"
    echo "==> Set marketing version → $MARKETING_VERSION in App/Info.plist (remember to commit it)."
fi
echo "    marketing version: $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$INFO_PLIST")"

echo "==> Building universal FULL app (release, arm64 + x86_64)…"
swift build -c release --arch arm64 --arch x86_64 --product ReKey
BIN_PATH="$(swift build -c release --arch arm64 --arch x86_64 --product ReKey --show-bin-path)"

echo "==> Assembling $APP …"
rm -rf "$APP" "$DMG" "$ZIP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_PATH/ReKey" "$APP/Contents/MacOS/ReKey"
cp "$INFO_PLIST" "$APP/Contents/Info.plist"

BUILD_NUMBER="${BUILD_NUMBER:-$(date +%Y%m%d.%H%M%S)}"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP/Contents/Info.plist"
echo "    build number: $BUILD_NUMBER"

shopt -s nullglob
for bundle in "$BIN_PATH"/*.bundle; do cp -R "$bundle" "$APP/Contents/Resources/"; done
shopt -u nullglob
cp "$ROOT/App/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/App/PrivacyInfo.xcprivacy" "$APP/Contents/Resources/PrivacyInfo.xcprivacy"
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> Compiling asset catalog…"
ACTOOL_OUT="$(mktemp -d)"
xcrun actool "$ROOT/App/Assets.xcassets" --compile "$ACTOOL_OUT" --platform macosx \
    --minimum-deployment-target 15.0 --app-icon AppIcon \
    --output-partial-info-plist "$ACTOOL_OUT/partial.plist" --errors --warnings >/dev/null
cp "$ACTOOL_OUT/Assets.car" "$APP/Contents/Resources/Assets.car"
/usr/libexec/PlistBuddy -c "Merge $ACTOOL_OUT/partial.plist" "$APP/Contents/Info.plist" 2>/dev/null || true

echo "==> Stripping extended attributes…"
xattr -cr "$APP"

echo "==> Signing (Developer ID + hardened runtime + sandbox)…"
shopt -s nullglob
for bundle in "$APP/Contents/Resources/"*.bundle; do
    plist="$bundle/Contents/Info.plist"; [[ -f "$plist" ]] || plist="$bundle/Info.plist"
    /usr/libexec/PlistBuddy -c "Delete :CFBundleExecutable" "$plist" 2>/dev/null || true
    codesign --force --sign "$SIGN_APP" --timestamp --options runtime "$bundle"
done
shopt -u nullglob
codesign --force --sign "$SIGN_APP" --entitlements "$ENTITLEMENTS" \
    --options runtime --timestamp "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> Notarizing the app (this can take a few minutes)…"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP"
rm -f "$ZIP"

echo "==> Building drag-to-install .dmg…"
STAGE="$(mktemp -d)/ReKey"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "ReKey" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null

echo "==> Signing + notarizing the .dmg…"
codesign --force --sign "$SIGN_APP" --timestamp "$DMG"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG"

echo ""
echo "Built + notarized: $DMG"
echo "Verify:  spctl -a -t open --context context:primary-signature -v \"$DMG\""
echo "Then attach $DMG to a GitHub Release."
