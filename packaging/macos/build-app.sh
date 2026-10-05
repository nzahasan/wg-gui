#!/bin/bash
# Builds dist/wg-gui.app and dist/wg-gui-<version>.zip, the file the
# Homebrew cask downloads.
#
# Usage: packaging/macos/build-app.sh [--universal]
#   --universal  build for Apple Silicon and Intel (needs both rustup
#                targets); without it, only for this Mac
#
# Without these the app is ad-hoc signed: fine for testing on this Mac.
#   SIGN_IDENTITY       "Developer ID Application: Name (TEAMID)"
#   WG_TEAM_ID          your team id; wg-helper only serves apps signed by it
# Notarizing also needs:
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
APP=dist/wg-gui.app
ZIP=dist/wg-gui-$VERSION.zip
SIGN_IDENTITY=${SIGN_IDENTITY:--}
export WG_TEAM_ID=${WG_TEAM_ID:-}
export MACOSX_DEPLOYMENT_TARGET=13.0

if [[ ${1:-} == --universal ]]; then
    TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
else
    TARGETS=$(rustc -vV | sed -n 's/^host: //p')
fi

if [[ $SIGN_IDENTITY != - && -z $WG_TEAM_ID ]]; then
    echo "set WG_TEAM_ID too when signing with SIGN_IDENTITY" >&2
    exit 1
fi

echo "==> building wg-gui $VERSION for $TARGETS"
for target in $TARGETS; do
    cargo build --release --target "$target" --bin wg-cli --bin wg-helper
    cargo build --release --target "$target" --bin wg-gui --features gui
done

echo "==> assembling $APP"
rm -rf dist
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchDaemons"
sed "s/__VERSION__/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
cp packaging/macos/com.nzahasan.wg-gui.helper.plist "$APP/Contents/Library/LaunchDaemons/"
cp assets/icons/1-AppIcon-macOS/AppIcon.icns "$APP/Contents/Resources/"
for bin in wg-gui wg-helper wg-cli; do
    # One binary per target, merged into one file.
    builds=()
    for target in $TARGETS; do builds+=("target/$target/release/$bin"); done
    lipo -create -output "$APP/Contents/MacOS/$bin" "${builds[@]}"
done

echo "==> signing as $SIGN_IDENTITY"
if [[ $SIGN_IDENTITY == - ]]; then TIMESTAMP=--timestamp=none; else TIMESTAMP=--timestamp; fi
sign() { codesign --force --options runtime "$TIMESTAMP" --sign "$SIGN_IDENTITY" "$@"; }
# The binaries inside first, the app last. The helper checks the app's
# identifier, so each gets its own.
sign --identifier com.nzahasan.wg-gui.helper "$APP/Contents/MacOS/wg-helper"
sign --identifier com.nzahasan.wg-gui.cli "$APP/Contents/MacOS/wg-cli"
sign "$APP"
codesign --verify --deep --strict "$APP"

make_zip() { rm -f "$ZIP"; ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"; }
make_zip

if [[ $SIGN_IDENTITY != - && -n ${APPLE_ID:-} ]]; then
    echo "==> notarizing"
    xcrun notarytool submit "$ZIP" --wait \
        --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD"
    xcrun stapler staple "$APP"
    make_zip # again, now with the notarization ticket inside
    spctl --assess --type execute "$APP"
fi

echo "==> $ZIP"
shasum -a 256 "$ZIP"
