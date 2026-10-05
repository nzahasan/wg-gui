#!/bin/bash
# Builds dist/wg-gui.app and dist/wg-gui-<version>.zip, signed and (with
# credentials) notarized, ready for the Homebrew cask.
#
# Environment:
#   SIGN_IDENTITY   "Developer ID Application: Name (TEAMID)"; default "-"
#                   (ad-hoc: for checking the bundle locally, not for release)
#   WG_TEAM_ID      Apple team id, compiled into wg-helper so it only serves
#                   our signed app. Required with a real SIGN_IDENTITY.
#   TARGETS         Rust targets to merge into a universal binary; default
#                   "aarch64-apple-darwin x86_64-apple-darwin". "native"
#                   builds for this Mac only (e.g. Homebrew's rust, no rustup).
#   NOTARY_PROFILE  notarytool keychain profile (xcrun notarytool
#                   store-credentials), or else APPLE_ID, APPLE_TEAM_ID and
#                   APPLE_APP_PASSWORD. Without either, notarizing is skipped.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$PWD
PACKAGING=$ROOT/packaging/macos
DIST=$ROOT/dist
APP=$DIST/wg-gui.app
BINS=(wg-gui wg-helper wg-cli)

VERSION=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
SIGN_IDENTITY=${SIGN_IDENTITY:--}
TARGETS=${TARGETS:-aarch64-apple-darwin x86_64-apple-darwin}
export MACOSX_DEPLOYMENT_TARGET=13.0

if [[ $SIGN_IDENTITY != "-" && -z ${WG_TEAM_ID:-} ]]; then
    echo "WG_TEAM_ID must be set when signing for release" >&2
    exit 1
fi
export WG_TEAM_ID=${WG_TEAM_ID:-}

echo "==> building wg-gui $VERSION for: $TARGETS"
build() { # build [--target T]
    cargo build --release "$@" --bin wg-cli --bin wg-helper
    cargo build --release "$@" --bin wg-gui --features gui
}
rm -rf "$DIST"
mkdir -p "$DIST/bin"
if [[ $TARGETS == native ]]; then
    build
    for bin in "${BINS[@]}"; do cp "target/release/$bin" "$DIST/bin/$bin"; done
else
    for target in $TARGETS; do build --target "$target"; done
    for bin in "${BINS[@]}"; do
        inputs=()
        for target in $TARGETS; do inputs+=("target/$target/release/$bin"); done
        lipo -create -output "$DIST/bin/$bin" "${inputs[@]}"
    done
fi

echo "==> assembling $APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchDaemons"
sed "s/__VERSION__/$VERSION/g" "$PACKAGING/Info.plist" > "$APP/Contents/Info.plist"
cp "$PACKAGING/com.nzahasan.wg-gui.helper.plist" "$APP/Contents/Library/LaunchDaemons/"
cp "$ROOT/assets/icons/1-AppIcon-macOS/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
for bin in "${BINS[@]}"; do cp "$DIST/bin/$bin" "$APP/Contents/MacOS/$bin"; done
plutil -lint "$APP/Contents/Info.plist" "$APP/Contents/Library/LaunchDaemons/"*.plist

echo "==> signing with: $SIGN_IDENTITY"
# Inside out: nested executables first, the bundle last. Each executable
# gets its own identifier; the helper checks the app's.
sign() { codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$@"; }
if [[ $SIGN_IDENTITY == "-" ]]; then
    sign() { codesign --force --options runtime --sign - "$@"; }
fi
sign --identifier com.nzahasan.wg-gui.helper "$APP/Contents/MacOS/wg-helper"
sign --identifier com.nzahasan.wg-gui.cli "$APP/Contents/MacOS/wg-cli"
sign "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

ZIP=$DIST/wg-gui-$VERSION.zip
zip_app() { rm -f "$ZIP"; ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"; }
zip_app

notary_args=()
if [[ -n ${NOTARY_PROFILE:-} ]]; then
    notary_args=(--keychain-profile "$NOTARY_PROFILE")
elif [[ -n ${APPLE_ID:-} && -n ${APPLE_TEAM_ID:-} && -n ${APPLE_APP_PASSWORD:-} ]]; then
    notary_args=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD")
fi
if [[ $SIGN_IDENTITY != "-" && ${#notary_args[@]} -gt 0 ]]; then
    echo "==> notarizing"
    xcrun notarytool submit "$ZIP" "${notary_args[@]}" --wait
    xcrun stapler staple "$APP"
    xcrun stapler validate "$APP"
    zip_app # again, now with the ticket stapled
    spctl --assess --type execute --verbose=2 "$APP"
else
    echo "==> not notarizing (ad-hoc signature or no notary credentials)"
fi

rm -rf "$DIST/bin"
echo "==> $ZIP"
shasum -a 256 "$ZIP"
