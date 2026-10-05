#!/bin/bash
# Runs wg-gui from the source tree: wg-helper as root on a private socket
# and the GUI as you. Quitting the GUI (or Ctrl-C here) stops the helper.
#
# Usage: scripts/dev-run.sh [--debug]
set -euo pipefail

# Started with sudo: run as yourself again, and use sudo only for the helper.
if [[ $EUID -eq 0 ]]; then exec sudo -u "$SUDO_USER" -H "$0" "$@"; fi
cd "$(dirname "$0")/.."

PROFILE=release
FLAGS=--release
if [[ ${1:-} == --debug ]]; then PROFILE=debug FLAGS=; fi

HELPER=$PWD/target/$PROFILE/wg-helper
GUI=$PWD/target/$PROFILE/wg-gui
SOCKET=/tmp/wg-gui-dev.sock
LOG=/tmp/wg-gui-dev-helper.log

echo "==> building ($PROFILE)"
cargo build $FLAGS --bin wg-helper
cargo build $FLAGS --bin wg-gui --features gui

stop_helper() {
    # On SIGTERM the helper restores DNS and routes, then exits.
    sudo pkill -TERM -f "^$HELPER" || return 0
    while sudo pgrep -f "^$HELPER" >/dev/null; do sleep 0.1; done
    echo "==> helper stopped (log: $LOG)"
}

echo "==> starting wg-helper as root (log: $LOG)"
sudo -v
stop_helper # left over from an earlier run
sudo "$HELPER" --dev --socket "$SOCKET" >"$LOG" 2>&1 &
trap stop_helper EXIT
trap 'exit 130' INT TERM

for _ in $(seq 50); do [[ -S $SOCKET ]] && break; sleep 0.1; done
if [[ ! -S $SOCKET ]]; then
    echo "the helper did not start:" >&2
    cat "$LOG" >&2
    exit 1
fi

echo "==> starting wg-gui"
WG_HELPER_SOCKET=$SOCKET "$GUI"
