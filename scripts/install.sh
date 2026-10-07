#!/bin/bash
# Builds wg-gui from this source tree and installs it on this Mac: the app
# in /Applications, wg-cli on the PATH and wg-helper as a launchd daemon.
# Installs what the build needs first, if it is missing: the Xcode Command
# Line Tools, Homebrew and Rust (from Homebrew). Running it again upgrades
# the install.
#
# Usage: scripts/install.sh
#        scripts/install.sh --uninstall [--zap]
#   --uninstall  stop and remove everything this script installed
#   --zap        also delete your profiles (~/.config/wg-gui, with their keys)
#                and wg-gui's settings, as `brew uninstall --zap` does
#
# Unsigned (the default), the helper runs with --dev and accepts any local
# client, and the app finds it through WG_HELPER_SOCKET in its Info.plist.
# With SIGN_IDENTITY and WG_TEAM_ID set (see build-app.sh) it is a release
# build: the app registers the helper itself and you allow it once in
# System Settings → General → Login Items.
#
# Run it as yourself; it asks for your password.
set -euo pipefail
cd "$(dirname "$0")/.."

LABEL=com.nzahasan.wg-gui.helper
APP=/Applications/wg-gui.app
DAEMON=/Library/LaunchDaemons/$LABEL.plist
SOCKET=/var/run/$LABEL.sock
LOG=/var/log/wg-gui-helper.log
BUNDLE_ID=com.nzahasan.wg-gui
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
MIN_RUST=1.85 # edition 2024
# What the GUI creates in your home folder; the cask's `zap` list.
USER_DATA=(
    "$HOME/.config/wg-gui"
    "$HOME/.wg-gui"
    "$HOME/Library/Caches/$BUNDLE_ID"
    "$HOME/Library/HTTPStorages/$BUNDLE_ID"
    "$HOME/Library/Preferences/$BUNDLE_ID.plist"
    "$HOME/Library/Saved Application State/$BUNDLE_ID.savedState"
)

UNINSTALL=0 ZAP=0
for arg; do
    case $arg in
        --uninstall) UNINSTALL=1 ;;
        --zap) ZAP=1 ;;
        *) echo "unknown argument $arg; see the top of $0" >&2; exit 2 ;;
    esac
done
if ((ZAP && !UNINSTALL)); then echo "--zap goes with --uninstall" >&2; exit 2; fi
[[ $EUID -ne 0 ]] || { echo "run this as yourself, not root" >&2; exit 1; }

# Homebrew on the PATH, if it is installed but this shell does not have it.
find_brew() {
    command -v brew >/dev/null && return 0
    for brew in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [[ -x $brew ]]; then eval "$("$brew" shellenv)"; return 0; fi
    done
    return 1
}

daemon_loaded() { sudo launchctl print "system/$LABEL" >/dev/null 2>&1; }
app_running() { pgrep -f "^$APP/Contents/MacOS/" >/dev/null; }

# Quits the app and stops the helper; the helper restores DNS and routes
# on SIGTERM, which bootout sends.
stop_all() {
    pkill -INT -f "^$APP/Contents/MacOS/wg-gui" || true
    if daemon_loaded; then sudo launchctl bootout "system/$LABEL" || true; fi
    for _ in $(seq 50); do app_running || break; sleep 0.1; done
    sudo pkill -KILL -f "^$APP/Contents/MacOS/" || true
}

find_brew || true
# wg-cli on the PATH, where the cask's `binary` stanza puts it.
cli_link() { echo "$(brew --prefix 2>/dev/null || echo /opt/homebrew)/bin/wg-cli"; }
cli_linked() { [[ $(readlink "$(cli_link)" 2>/dev/null) == "$APP/"* ]]; }

if command -v brew >/dev/null && brew list --cask wg-gui >/dev/null 2>&1; then
    echo "wg-gui is installed with Homebrew; remove it first: brew uninstall --cask wg-gui" >&2
    exit 1
fi

if ((UNINSTALL)); then
    sudo -v
    echo "==> uninstalling wg-gui"
    trap '' INT TERM # don't stop half-way
    stop_all
    if cli_linked; then rm -f "$(cli_link)"; fi
    sudo rm -rf "$APP" "$DAEMON" "$SOCKET" "$LOG"
    if ((ZAP)); then
        echo "==> removing your profiles and settings"
        defaults delete "$BUNDLE_ID" 2>/dev/null || true # also clears cfprefsd's copy
        rm -rf "${USER_DATA[@]}"
    fi
    echo "==> done; Homebrew and Rust are still installed"
    exit 0
fi

macos=$(sw_vers -productVersion)
if ((${macos%%.*} < 13)); then echo "wg-gui needs macOS 13 or later; this is $macos" >&2; exit 1; fi

echo "==> checking build tools"
if ! xcode-select -p >/dev/null 2>&1; then
    echo "     installing the Xcode Command Line Tools; run this script again when that is done"
    xcode-select --install || true
    exit 1
fi

if ! find_brew; then
    echo "     installing Homebrew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    find_brew || { echo "Homebrew did not install" >&2; exit 1; }
fi

# A rustup install may not be on this shell's PATH yet.
[[ -d $HOME/.cargo/bin ]] && export PATH=$HOME/.cargo/bin:$PATH
if ! command -v cargo >/dev/null || ! command -v rustc >/dev/null; then
    echo "     installing Rust"
    brew install rust
fi
rust_version() { rustc -V | awk '{print $2}'; }
rust_too_old() {
    local have want
    IFS=. read -r -a have <<<"$(rust_version)"
    IFS=. read -r -a want <<<"$MIN_RUST"
    ((have[0] < want[0] || (have[0] == want[0] && have[1] < want[1])))
}
if rust_too_old; then
    echo "     Rust $(rust_version) is too old (needs $MIN_RUST); upgrading"
    if command -v rustup >/dev/null; then rustup update stable; else brew upgrade rust; fi
    if rust_too_old; then echo "Rust is still $(rust_version); needs $MIN_RUST" >&2; exit 1; fi
fi
echo "     $(rustc -V)"

echo "==> building"
packaging/macos/build-app.sh

sudo -v
if [[ -e $APP ]] || daemon_loaded; then
    echo "==> stopping the installed wg-gui"
    stop_all
    sudo rm -rf "$APP" "$DAEMON" "$SOCKET"
fi

echo "==> installing $APP"
sudo ditto -x -k dist/wg-gui-*.zip /Applications

if [[ -z ${WG_TEAM_ID:-} ]]; then
    echo "==> starting wg-helper with launchd ($LABEL)"
    # The bundled plist is for SMAppService; launchd needs the full path.
    plist=$(mktemp)
    cp "packaging/macos/$LABEL.plist" "$plist"
    /usr/libexec/PlistBuddy \
        -c "Delete :BundleProgram" \
        -c "Add :ProgramArguments array" \
        -c "Add :ProgramArguments:0 string $APP/Contents/MacOS/wg-helper" \
        -c "Add :ProgramArguments:1 string --dev" \
        "$plist"
    sudo install -m 644 -o root -g wheel "$plist" "$DAEMON"
    rm -f "$plist"
    sudo launchctl bootstrap system "$DAEMON"
    for _ in $(seq 100); do [[ -S $SOCKET ]] && break; sleep 0.1; done
    if [[ ! -S $SOCKET ]]; then
        echo "the helper did not start:" >&2
        sudo cat "$LOG" >&2
        exit 1
    fi

    # However the app is opened, it uses that helper instead of SMAppService.
    sudo /usr/libexec/PlistBuddy \
        -c "Add :LSEnvironment dict" \
        -c "Add :LSEnvironment:WG_HELPER_SOCKET string $SOCKET" \
        "$APP/Contents/Info.plist"
    sudo codesign --force --options runtime --timestamp=none --sign - "$APP"
    "$LSREGISTER" -f "$APP"
    echo "     unsigned build: the helper runs with --dev and accepts any local client"
else
    echo "==> the app registers its helper on first launch; allow it in"
    echo "     System Settings → General → Login Items & Extensions → Allow in the Background"
fi

CLI_LINK=$(cli_link)
if [[ -e $CLI_LINK || -L $CLI_LINK ]] && ! cli_linked; then
    echo "     $CLI_LINK exists already; not linking wg-cli"
else
    ln -sf "$APP/Contents/MacOS/wg-cli" "$CLI_LINK" && echo "     linked $CLI_LINK"
fi

rm -rf dist
echo "==> installed; open wg-gui from /Applications (uninstall with: $0 --uninstall)"
