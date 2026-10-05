#!/bin/bash
# Runs wg-gui the way the installed app does, without building a bundle:
# wg-helper as root (--dev, on a private socket) and the GUI as you.
# Quitting the GUI (or Ctrl-C here) stops the helper again.
#
# Usage: scripts/dev-run.sh [--debug]
# Run it as yourself; it asks for your password once, for the helper.
# Under sudo it works too: the GUI is then started as $SUDO_USER.
set -euo pipefail

cd "$(dirname "$0")/.."
PROFILE=release
CARGO_FLAGS=(--release)
if [[ ${1:-} == --debug ]]; then
    PROFILE=debug
    CARGO_FLAGS=()
fi

SOCKET=/tmp/wg-gui-dev.sock
LOG=/tmp/wg-gui-dev-helper.log
HELPER=$PWD/target/$PROFILE/wg-helper
GUI=$PWD/target/$PROFILE/wg-gui

if [[ $EUID -eq 0 ]]; then
    USER_NAME=${SUDO_USER:?run this as yourself, or with sudo from your account}
    as_root() { "$@"; }
    as_user() { sudo -u "$USER_NAME" -H "$@"; }
else
    USER_NAME=$(id -un)
    as_root() { sudo "$@"; }
    as_user() { "$@"; }
fi

echo "==> building ($PROFILE)"
as_user cargo build "${CARGO_FLAGS[@]}" --bin wg-helper
as_user cargo build "${CARGO_FLAGS[@]}" --bin wg-gui --features gui

stop_helper() {
    if as_root pkill -TERM -f "^$HELPER --dev --socket $SOCKET" 2>/dev/null; then
        # It restores DNS and routes before exiting.
        for _ in $(seq 50); do
            as_root pgrep -f "^$HELPER --dev --socket $SOCKET" >/dev/null || break
            sleep 0.1
        done
        echo "==> helper stopped (log: $LOG)"
    fi
}

echo "==> starting wg-helper as root (log: $LOG)"
[[ $EUID -eq 0 ]] || sudo -v # ask for the password before going to the background
stop_helper # a leftover from an earlier run
as_root rm -f "$SOCKET"
as_root "$HELPER" --dev --socket "$SOCKET" >"$LOG" 2>&1 &
trap stop_helper EXIT
trap 'exit 130' INT TERM

for _ in $(seq 50); do
    [[ -S $SOCKET ]] && break
    sleep 0.1
done
if [[ ! -S $SOCKET ]]; then
    echo "helper did not start:" >&2
    cat "$LOG" >&2
    exit 1
fi

echo "==> starting wg-gui as $USER_NAME"
as_user env WG_HELPER_SOCKET="$SOCKET" "$GUI"
