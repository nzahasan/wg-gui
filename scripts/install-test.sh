#!/bin/bash
# Tests wg-gui the way users get it: builds the app with build-app.sh,
# installs it in /Applications, runs wg-helper as a launchd daemon and
# starts the GUI. When the GUI quits (or on Ctrl-C) it runs itself with
# --clean, which uninstalls everything and checks nothing is left behind.
#
# Usage: scripts/install-test.sh [--zap]
#        scripts/install-test.sh --clean [--zap]
#   --clean  only uninstall and check; also cleans up after a crashed run
#   --zap    also delete ~/.wg-gui (your profiles and their keys)
#
# Unsigned, the helper runs with --dev and accepts any local client. With
# SIGN_IDENTITY and WG_TEAM_ID set (see build-app.sh) it checks the GUI's
# signature, as in a release.
#
# Run it as yourself; it asks for your password.
set -uo pipefail
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
cd "$(dirname "$0")/.."

LABEL=com.nzahasan.wg-gui.helper
APP=/Applications/wg-gui.app
DAEMON=/Library/LaunchDaemons/$LABEL.plist
SOCKET=/var/run/$LABEL.sock
LOG=/var/log/wg-gui-helper.log
SAVED_LOG=/tmp/wg-gui-install-test-helper.log

CLEAN=0 ZAP=0
for arg; do
    case $arg in
        --clean) CLEAN=1 ;;
        --zap) ZAP=1 ;;
        *) echo "unknown argument $arg; see the top of $0" >&2; exit 2 ;;
    esac
done
[[ $EUID -ne 0 ]] || { echo "run this as yourself, not root" >&2; exit 1; }

FAILED=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; FAILED=1; }

dns_now() { scutil --dns | sed -n 's/.*nameserver\[[0-9]*\] : //p' | sort -u | tr '\n' ' '; }
route_lines() { netstat -rn | wc -l | tr -d ' '; }
daemon_loaded() { sudo launchctl print "system/$LABEL" >/dev/null 2>&1; }
app_running() { pgrep -f "^$APP/Contents/MacOS/" >/dev/null; }

uninstall() {
    trap '' INT TERM # don't stop half-way on a second Ctrl-C
    echo "==> uninstalling"
    # The GUI takes its tunnel down when it quits.
    pkill -INT -f "^$APP/Contents/MacOS/wg-gui"
    # bootout sends SIGTERM; the helper restores DNS and routes, then exits.
    if daemon_loaded; then sudo launchctl bootout "system/$LABEL"; fi
    for _ in $(seq 50); do app_running || break; sleep 0.1; done
    sudo pkill -KILL -f "^$APP/Contents/MacOS/" # anything still hanging on

    if sudo test -f "$LOG"; then sudo cat "$LOG" >"$SAVED_LOG"; fi
    sudo rm -rf "$APP" "$DAEMON" "$SOCKET" "$LOG" dist
    if ((ZAP)); then rm -rf ~/.wg-gui; fi
}

check_nothing_left() {
    echo "==> checking nothing is left"
    if daemon_loaded; then fail "launchd still has $LABEL"; else pass "no launchd job $LABEL"; fi
    if app_running; then fail "wg-gui is still running"; else pass "nothing from wg-gui.app running"; fi
    for path in "$APP" "$DAEMON" "$SOCKET" "$LOG"; do
        if sudo test -e "$path"; then fail "$path is still there"; else pass "$path removed"; fi
    done
    if sudo sfltool dumpbtm 2>/dev/null | grep -qi wg-gui; then
        fail "Login Items still lists wg-gui (sfltool dumpbtm)"
    else
        pass "not in Login Items"
    fi
    if ((ZAP)); then
        if [[ -e ~/.wg-gui ]]; then fail "~/.wg-gui is still there"; else pass "~/.wg-gui removed"; fi
    fi
    if [[ -n ${DNS_BEFORE:-} ]]; then
        if [[ $(dns_now) == "$DNS_BEFORE" ]]; then pass "DNS as before"; else fail "DNS is $(dns_now), was $DNS_BEFORE"; fi
        if [[ $(route_lines) == "$ROUTES_BEFORE" ]]; then pass "routing table as before"; else fail "routing table has $(route_lines) lines, had $ROUTES_BEFORE"; fi
    fi
}

finish() {
    uninstall
    check_nothing_left
    if [[ -s $SAVED_LOG ]]; then
        echo
        echo "helper log ($SAVED_LOG):"
        sed 's/^/       /' "$SAVED_LOG"
    fi
    echo
    if [[ $FAILED == 0 ]]; then echo "ALL CLEAN"; else echo "SOMETHING WAS LEFT BEHIND"; fi
    exit $FAILED
}

if command -v brew >/dev/null && brew list --cask wg-gui >/dev/null 2>&1; then
    echo "wg-gui is installed with Homebrew; remove it first: brew uninstall --cask wg-gui" >&2
    exit 1
fi

sudo -v || exit 1
if ((CLEAN)); then finish; fi

if [[ -e $APP ]] || daemon_loaded; then
    echo "an earlier install or run is still here; remove it with: $0 --clean" >&2
    exit 1
fi

# Whatever happens from here on, end with --clean. It compares DNS and
# routes with how they are now.
export DNS_BEFORE ROUTES_BEFORE
DNS_BEFORE=$(dns_now)
ROUTES_BEFORE=$(route_lines)
CLEAN_ARGS=(--clean)
if ((ZAP)); then CLEAN_ARGS+=(--zap); fi
trap '"$SELF" "${CLEAN_ARGS[@]}"; exit $?' EXIT
trap 'exit 130' INT TERM

echo "==> building"
packaging/macos/build-app.sh || exit 1

echo "==> installing $APP"
sudo ditto -x -k dist/wg-gui-*.zip /Applications || exit 1

echo "==> starting wg-helper with launchd ($LABEL)"
# The bundled plist is for SMAppService; launchd needs the full path.
plist=$(mktemp)
cp packaging/macos/$LABEL.plist "$plist"
/usr/libexec/PlistBuddy \
    -c "Delete :BundleProgram" \
    -c "Add :ProgramArguments array" \
    -c "Add :ProgramArguments:0 string $APP/Contents/MacOS/wg-helper" \
    "$plist"
if [[ -z ${WG_TEAM_ID:-} ]]; then
    echo "     unsigned build: the helper runs with --dev and accepts any local client"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string --dev" "$plist"
fi
sudo install -m 644 -o root -g wheel "$plist" "$DAEMON"
rm -f "$plist"
sudo launchctl bootstrap system "$DAEMON" || exit 1

for _ in $(seq 100); do [[ -S $SOCKET ]] && break; sleep 0.1; done
if [[ ! -S $SOCKET ]]; then
    echo "the helper did not start:" >&2
    sudo cat "$LOG" >&2
    exit 1
fi
pass "launchd started the helper"

echo "==> starting the GUI; quit it or press Ctrl-C to uninstall"
WG_HELPER_SOCKET=$SOCKET "$APP/Contents/MacOS/wg-gui"
