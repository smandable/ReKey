#!/bin/bash
#
# Build a Mac App Store submission package: a universal, pure-auditor (MAS_BUILD)
# ReKey.app signed with your Apple Distribution identity and an embedded App Store
# provisioning profile, wrapped in an installer .pkg signed with your Mac
# Installer identity — ready to upload via Transporter.
#
# This is the production counterpart to build_app.sh (which ad-hoc signs for local
# dev). The deletion / Terminal workflow is compiled OUT here via -DMAS_BUILD.
#
# REQUIRED environment variables (see Scripts/README or the submission checklist):
#   TEAM_ID            Your 10-char Apple Developer Team ID (e.g. ABCDE12345)
#   PROVISION_PROFILE  Path to the downloaded Mac App Store provisioning profile
#                      (.provisionprofile) for com.seanmandable.rekey
#   SIGN_APP           App-signing identity, e.g.
#                      "Apple Distribution: Your Name (ABCDE12345)"
#                      (older accounts: "3rd Party Mac Developer Application: …")
#   SIGN_INSTALLER     Installer-signing identity, e.g.
#                      "3rd Party Mac Developer Installer: Your Name (ABCDE12345)"
#                      (newer accounts: "Mac Installer Distribution: …")
#
# Find your identities with:
#   security find-identity -p codesigning -v     # app-signing certs
#   security find-identity -p basic -v           # installer certs
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${TEAM_ID:?Set TEAM_ID to your Apple Developer Team ID}"
: "${PROVISION_PROFILE:?Set PROVISION_PROFILE to your .provisionprofile path}"
: "${SIGN_APP:?Set SIGN_APP to your Apple Distribution identity}"
: "${SIGN_INSTALLER:?Set SIGN_INSTALLER to your Mac Installer identity}"
[[ -f "$PROVISION_PROFILE" ]] || { echo "Provisioning profile not found: $PROVISION_PROFILE" >&2; exit 1; }

BUNDLE_ID="com.seanmandable.rekey"
APP="$ROOT/build/ReKey.app"
PKG="$ROOT/build/ReKey-MAS.pkg"
BASE_ENT="$ROOT/App/ReKey.entitlements"
MAS_ENT="$ROOT/build/ReKey.mas.entitlements"
INFO_PLIST="$ROOT/App/Info.plist"

echo "==> Building universal pure-auditor binary (MAS_BUILD, arm64 + x86_64)…"
swift build -c release --arch arm64 --arch x86_64 -Xswiftc -DMAS_BUILD --product ReKey
BIN_PATH="$(swift build -c release --arch arm64 --arch x86_64 --product ReKey --show-bin-path)"

echo "==> Assembling $APP …"
rm -rf "$APP" "$PKG" "$MAS_ENT"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_PATH/ReKey" "$APP/Contents/MacOS/ReKey"
cp "$INFO_PLIST" "$APP/Contents/Info.plist"

# Auto-stamp a unique, strictly-increasing build number — App Store Connect rejects
# a re-used CFBundleVersion, and you should never have to hand-bump it. Date-based so
# it's monotonic and self-documenting (when the build was made). Override with
# BUILD_NUMBER=… for an explicit value. The marketing version
# (CFBundleShortVersionString) is untouched — bump that by hand for a new release.
BUILD_NUMBER="${BUILD_NUMBER:-$(date +%Y%m%d.%H%M%S)}"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP/Contents/Info.plist"
echo "==> Build number (CFBundleVersion): $BUILD_NUMBER"

shopt -s nullglob
for bundle in "$BIN_PATH"/*.bundle; do cp -R "$bundle" "$APP/Contents/Resources/"; done
shopt -u nullglob
cp "$ROOT/App/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/App/PrivacyInfo.xcprivacy" "$APP/Contents/Resources/PrivacyInfo.xcprivacy"
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> Compiling asset catalog (App Store requires a compiled icon catalog)…"
ACTOOL_OUT="$(mktemp -d)"
xcrun actool "$ROOT/App/Assets.xcassets" \
    --compile "$ACTOOL_OUT" \
    --platform macosx \
    --minimum-deployment-target 15.0 \
    --app-icon AppIcon \
    --output-partial-info-plist "$ACTOOL_OUT/partial.plist" \
    --errors --warnings >/dev/null
cp "$ACTOOL_OUT/Assets.car" "$APP/Contents/Resources/Assets.car"
[[ -f "$ACTOOL_OUT/AppIcon.icns" ]] && cp "$ACTOOL_OUT/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
# Merge actool's icon keys (CFBundleIconName etc.) into the app Info.plist.
/usr/libexec/PlistBuddy -c "Merge $ACTOOL_OUT/partial.plist" "$APP/Contents/Info.plist" 2>/dev/null || true

echo "==> Embedding provisioning profile…"
cp "$PROVISION_PROFILE" "$APP/Contents/embedded.provisionprofile"

echo "==> Composing MAS entitlements (sandbox + app/team identifiers)…"
cp "$BASE_ENT" "$MAS_ENT"
/usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string ${TEAM_ID}.${BUNDLE_ID}" "$MAS_ENT"
/usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string ${TEAM_ID}" "$MAS_ENT"

# Strip extended attributes (e.g. com.apple.quarantine on the downloaded
# provisioning profile) — App Store validation rejects any xattrs in the bundle.
echo "==> Stripping extended attributes…"
xattr -cr "$APP"

echo "==> Signing nested resource bundles…"
shopt -s nullglob
for bundle in "$APP/Contents/Resources/"*.bundle; do
    # SwiftPM stamps these resource-only bundles with a CFBundleExecutable key, but
    # they contain no binary — App Store validation rejects that (409 "Bad
    # CFBundleExecutable"). Strip the key before signing so codesign re-seals the
    # corrected Info.plist. (Resource loading doesn't use CFBundleExecutable.)
    plist="$bundle/Contents/Info.plist"
    [[ -f "$plist" ]] || plist="$bundle/Info.plist"
    /usr/libexec/PlistBuddy -c "Delete :CFBundleExecutable" "$plist" 2>/dev/null || true
    codesign --force --sign "$SIGN_APP" --timestamp --options runtime "$bundle"
done
shopt -u nullglob

echo "==> Signing the app (hardened runtime + MAS entitlements)…"
codesign --force --sign "$SIGN_APP" --entitlements "$MAS_ENT" \
    --timestamp --options runtime "$APP"

echo "==> Verifying signature + entitlements…"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign --display --entitlements - --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null || true

echo "==> Building signed installer package…"
productbuild --component "$APP" /Applications --sign "$SIGN_INSTALLER" "$PKG"

echo ""
echo "Built: $PKG"
echo "Next: upload it to App Store Connect with the Transporter app (drag the .pkg in),"
echo "      or:  xcrun altool --upload-app -t macos -f \"$PKG\" \\"
echo "             --apiKey <KEY_ID> --apiIssuer <ISSUER_ID>"
