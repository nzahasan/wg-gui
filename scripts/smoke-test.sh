#!/bin/bash
# End-to-end check of wg-helper with a real tunnel, no GUI needed:
# starts the helper as root, drives it like the GUI does and checks that
# the tunnel comes up, handshakes, and that routes and DNS are restored
# when it goes down, including when the client just disappears.
#
# Usage: scripts/smoke-test.sh [profile.conf]   (default: Jobaer.conf)
# Run it as yourself; it asks for your password once.
set -uo pipefail

cd "$(dirname "$0")/.."
CONF=${1:-Jobaer.conf}
SOCKET=/tmp/wg-gui-smoke.sock
LOG=/tmp/wg-gui-smoke-helper.log
HELPER=$PWD/target/release/wg-helper
CLIENT=(python3 "$PWD/scripts/helper-client.py" "$SOCKET")
FAILED=0

pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; FAILED=1; }
field() { sed -n "s/^$1=//p" <<<"$2" | head -1; }
dns_now() { scutil --dns | sed -n 's/.*nameserver\[[0-9]*\] : //p' | sort -u | tr '\n' ' '; }
tun_exists() { ifconfig "$1" >/dev/null 2>&1; }
tun_routes() { netstat -rn | awk -v t="$1" '$NF == t' | wc -l | tr -d ' '; }

[[ -f $CONF ]] || { echo "no such profile: $CONF" >&2; exit 1; }
[[ $EUID -ne 0 ]] || { echo "run this as yourself, not root" >&2; exit 1; }

echo "==> building"
cargo build --release --bin wg-helper || exit 1

echo "==> starting wg-helper as root (log: $LOG)"
sudo -v || exit 1
sudo pkill -TERM -f "^$HELPER --dev --socket $SOCKET" 2>/dev/null
sudo rm -f "$SOCKET"
sudo "$HELPER" --dev --socket "$SOCKET" >"$LOG" 2>&1 &
stop_helper() { sudo pkill -TERM -f "^$HELPER --dev --socket $SOCKET" 2>/dev/null; }
trap stop_helper EXIT
for _ in $(seq 50); do [[ -S $SOCKET ]] && break; sleep 0.1; done
[[ -S $SOCKET ]] || { echo "helper did not start:"; cat "$LOG"; exit 1; }

DNS_BEFORE=$(dns_now)
ROUTES_BEFORE=$(netstat -rn | wc -l | tr -d ' ')

echo "==> 1. connect, handshake, disconnect"
out=$("${CLIENT[@]}" up-down "$CONF" 2>&1)
echo "$out" | sed 's/^/       /'
tun=$(field TUN "$out")
[[ -n $tun ]] && pass "tunnel came up as $tun" || fail "no tunnel"
[[ $(field HANDSHAKE "$out") == yes ]] && pass "handshake with the peer" || fail "no handshake (is the server reachable?)"
[[ $(field DOWN "$out") == ok ]] && pass "DOWN acknowledged" || fail "DOWN failed"
if [[ -n $tun ]]; then
    sleep 1
    tun_exists "$tun" && fail "$tun still exists" || pass "$tun removed"
fi
[[ $(dns_now) == "$DNS_BEFORE" ]] && pass "DNS restored ($DNS_BEFORE)" || fail "DNS is $(dns_now), was $DNS_BEFORE"

echo "==> 2. the client vanishes without DOWN (a crashed GUI)"
out=$("${CLIENT[@]}" up-and-vanish "$CONF" 2>&1)
tun=$(field TUN "$out")
[[ -n $tun ]] && pass "tunnel came up as $tun" || fail "no tunnel: $out"
if [[ -n $tun ]]; then
    for _ in $(seq 50); do tun_exists "$tun" || break; sleep 0.2; done
    tun_exists "$tun" && fail "$tun left behind" || pass "helper took $tun down by itself"
    [[ $(tun_routes "$tun") == 0 ]] && pass "no routes left on $tun" || fail "routes left on $tun"
fi
[[ $(dns_now) == "$DNS_BEFORE" ]] && pass "DNS restored" || fail "DNS is $(dns_now), was $DNS_BEFORE"

echo "==> 3. a second client cannot take over a running tunnel"
"${CLIENT[@]}" hold "$CONF" 6 >/dev/null 2>&1 &
holder=$!
sleep 3
out=$("${CLIENT[@]}" up-expect-error "$CONF" 2>&1)
[[ $(field REFUSED "$out") == yes* ]] && pass "refused: $(field REFUSED "$out" | cut -c6-)" || fail "second client: $out"
wait $holder

echo "==> 4. network change: the endpoint route disappears (as when its interface goes away)"
"${CLIENT[@]}" hold "$CONF" 14 >/tmp/wg-gui-smoke-hold.log 2>&1 &
holder=$!
sleep 4
endpoint=$(sed -n 's/^ENDPOINT=//p' /tmp/wg-gui-smoke-hold.log | sed 's/:[0-9]*$//; s/^\[//; s/\]$//')
if [[ -z $endpoint ]]; then
    fail "tunnel did not come up: $(cat /tmp/wg-gui-smoke-hold.log)"
elif ! netstat -rn | awk '{print $1}' | grep -qx "$endpoint"; then
    echo "  skip no endpoint route to remove (split tunnel for $endpoint's address family)"
else
    sudo route -q -n delete "$endpoint" >/dev/null
    sleep 5 # the watcher waits 1 s for things to settle, then re-pins and handshakes
    netstat -rn | awk '{print $1}' | grep -qx "$endpoint" && pass "endpoint route restored" || fail "endpoint route not restored"
    grep -q "network changed" "$LOG" && pass "helper noticed the change" || fail "no 'network changed' in the helper log"
fi
wait $holder

echo "==> 5. stopping the helper"
stop_helper
for _ in $(seq 50); do [[ -S $SOCKET ]] || break; sleep 0.1; done
[[ -S $SOCKET ]] && fail "socket left behind" || pass "helper exited and removed its socket"
trap - EXIT

ROUTES_AFTER=$(netstat -rn | wc -l | tr -d ' ')
[[ $ROUTES_AFTER == "$ROUTES_BEFORE" ]] && pass "routing table back to $ROUTES_BEFORE lines" \
    || fail "routing table has $ROUTES_AFTER lines, had $ROUTES_BEFORE"

echo
echo "helper log ($LOG):"
sed 's/^/       /' "$LOG"
echo
if [[ $FAILED == 0 ]]; then echo "ALL PASSED"; else echo "SOME CHECKS FAILED"; fi
exit $FAILED
