#!/bin/bash
# Runs wg-gui from the source tree, to check that it works: wg-helper as
# root on a private socket and the GUI as you. Nothing is installed.
# Quitting the GUI (or Ctrl-C here) stops the helper.
#
# Usage: scripts/dev-run.sh
set -euo pipefail

# Started with sudo: run as yourself again, and use sudo only for the helper.
if [[ $EUID -eq 0 ]]; then exec sudo -u "$SUDO_USER" -H "$0" "$@"; fi
cd "$(dirname "$0")/.."

HELPER=$PWD/target/release/wg-helper
GUI=$PWD/target/release/wg-gui
SOCKET=/tmp/wg-gui-dev.sock
LOG=/tmp/wg-gui-dev-helper.log

stop_helper() {
    # On SIGTERM the helper restores DNS and routes, then exits.
    sudo pkill -TERM -f "^$HELPER" || return 0
    while sudo pgrep -f "^$HELPER" >/dev/null; do sleep 0.1; done
    echo "==> helper stopped (log: $LOG)"
}

echo "==> building"
cargo build --release --bin wg-helper
cargo build --release --bin wg-gui --features gui

echo "==> starting wg-helper as root (log: $LOG)"
sudo -v
stop_helper # left over from an earlier run
sudo rm -f "$SOCKET" "$LOG" # may be root's, from a run started with sudo
sudo "$HELPER" --dev --socket "$SOCKET" >"$LOG" 2>&1 &
trap stop_helper EXIT
trap 'exit 130' INT TERM

for _ in $(seq 50); do [[ -S $SOCKET ]] && break; sleep 0.1; done
if [[ ! -S $SOCKET ]]; then
    echo "the helper did not start:" >&2
    cat "$LOG" >&2
    exit 1
fi

echo "==> starting wg-gui; quit it or press Ctrl-C to stop"
WG_HELPER_SOCKET=$SOCKET "$GUI"
