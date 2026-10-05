# WireGuard protocol — knowledge base for this client

This is a condensed reference of the WireGuard rules that matter to a
single-peer **initiator** (client), collected from the official sources
below. Each rule names the place in this repository that implements it.

Sources:

- WireGuard protocol page — https://www.wireguard.com/protocol/
- WireGuard whitepaper — https://www.wireguard.com/papers/wireguard.pdf
- Linux kernel implementation, `drivers/net/wireguard/`:
  `timers.c`, `send.c`, `receive.c`, `cookie.c`, `noise.c`, `messages.h`
  (https://github.com/torvalds/linux/tree/master/drivers/net/wireguard)
- `wg-quick` for macOS and FreeBSD (`set_mtu`) —
  https://github.com/WireGuard/wireguard-tools/tree/master/src/wg-quick

---

## 1. Messages

All integers are little-endian. The first 4 bytes are the type followed
by three zero bytes.

| Type | Name | Size | Layout |
|---|---|---|---|
| 1 | Handshake initiation | 148 | type(4) · sender_index(4) · ephemeral(32) · encrypted_static(32+16) · encrypted_timestamp(12+16) · mac1(16) · mac2(16) |
| 2 | Handshake response | 92 | type(4) · sender_index(4) · receiver_index(4) · ephemeral(32) · encrypted_nothing(0+16) · mac1(16) · mac2(16) |
| 3 | Cookie reply | 64 | type(4) · receiver_index(4) · nonce(24) · encrypted_cookie(16+16) |
| 4 | Transport data | ≥ 32 | type(4) · receiver_index(4) · counter(8) · encrypted_packet(n+16) |

Implemented in `src/common/noise.rs` (types 1–3) and `src/common/session.rs` (type 4).

## 2. Handshake (Noise_IKpsk2)

- Construction `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, identifier
  `WireGuard v1 zx2c4 Jason@zx2c4.com`.
- HASH = BLAKE2s-256, HMAC = HMAC-BLAKE2s, MAC = keyed BLAKE2s with 16-byte output,
  AEAD = ChaCha20-Poly1305 with nonce `0⁴ ‖ counter_le⁸`.
- The initiator sends with T1 and receives with T2 = KDF2(C, ε).
- Every initiation (including retries) uses a fresh ephemeral key, a fresh
  timestamp and a fresh random sender index.

**TAI64N timestamp**: 8 bytes big-endian `2^62 + 10 + unix_seconds`, then
4 bytes big-endian nanoseconds. The kernel **rounds the nanoseconds down** to
a power of two near `1e9 / INITIATIONS_PER_SECOND` (2^24 ns ≈ 16.7 ms), so
the timestamp does not leak a precise clock. The responder rejects any
timestamp that is not larger than the last one it saw from us.
→ `noise::tai64n`.

## 3. mac1, mac2 and cookies (DoS protection)

- `mac1 = MAC(HASH("mac1----" ‖ receiver_static_public), msg[..mac1])`.
  Always present. We verify mac1 on responses using our own public key.
- `mac2 = MAC(cookie, msg[..mac2])` if we hold a cookie younger than
  `COOKIE_SECRET_MAX_AGE − COOKIE_SECRET_LATENCY` (120 − 5 = 115 s);
  otherwise 16 zero bytes.
- A server under load answers an initiation with a **cookie reply** instead
  of a response. The client decrypts it with
  `XChaCha20-Poly1305(key = HASH("cookie--" ‖ server_static_public), nonce = msg.nonce, aad = mac1 of the initiation we sent last)`.
  Each sent mac1 can be used for only one cookie. The client does **not** resend
  immediately; the next retransmission carries mac2.

→ `noise::consume_cookie_reply`, `noise::build_initiation(.., cookie)`,
`State::cookie` / `State::last_mac1` in `src/common/tunnel.rs`.

## 4. Transport data

- Plaintext is zero-padded to a multiple of 16 bytes. An empty plaintext is a
  **keepalive**.
- The send counter starts at 0 and never goes backwards.
- On receive: authenticate **first**, then check the counter against a sliding
  replay window. The kernel and wireguard-go use RFC 6479 with 8192 bits of
  storage (window ≈ 8128 counters).
- After decrypting, trim the padding using the IP header's own length. Drop the packet if
  it is not IPv4/IPv6 or its length field lies.
- **Cryptokey routing**: an incoming packet whose *source* address is not
  inside the peer's AllowedIPs is dropped.

→ `session.rs` (`ReplayWindow`), `ip.rs`, `tunnel::handle_transport`.

## 5. Constants (`messages.h`)

| Name | Value |
|---|---|
| `REKEY_AFTER_MESSAGES` | 2^60 |
| `REJECT_AFTER_MESSAGES` | 2^64 − 1 − 8128 − 1 |
| `REKEY_AFTER_TIME` | 120 s |
| `REJECT_AFTER_TIME` | 180 s |
| `REKEY_ATTEMPT_TIME` | 90 s (`MAX_TIMER_HANDSHAKES = 90 / REKEY_TIMEOUT = 18`) |
| `REKEY_TIMEOUT` | 5 s, plus jitter of 0–333 ms |
| `KEEPALIVE_TIMEOUT` | 10 s |
| `COOKIE_SECRET_MAX_AGE` / `_LATENCY` | 120 s / 5 s |
| `MAX_STAGED_PACKETS` | 128 |

→ `src/common/session.rs`, `src/common/timers.rs`.

## 6. Timers (kernel `timers.c`): the exact rules

The kernel keeps five per-peer timers. Each is armed or cancelled by a few
events. `src/common/timers.rs` mirrors them one-to-one as optional deadlines.

| Timer | Armed by | Cancelled by | When it fires |
|---|---|---|---|
| **retransmit_handshake** | initiation sent → `REKEY_TIMEOUT + jitter` | handshake complete | if attempts > 18: give up (cancel send_keepalive, drop staged packets); otherwise attempts += 1 and resend the initiation |
| **send_keepalive** | *data* received, if not already armed → `KEEPALIVE_TIMEOUT`. If already armed, set `need_another_keepalive` | any authenticated packet **sent** | send a keepalive; if `need_another_keepalive`, clear it and re-arm for `KEEPALIVE_TIMEOUT` |
| **new_handshake** | *data* (not keepalive) sent, if not already armed → `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter` | any authenticated packet **received** (incl. keepalive) | start a new handshake |
| **zero_key_material** | session derived → `REJECT_AFTER_TIME × 3` | — | erase all keys and the pending handshake |
| **persistent_keepalive** | any authenticated packet sent **or** received (incl. handshake) → `interval` | — | send a keepalive |

Event hooks:

- **any authenticated packet sent** (data, keepalive, handshake): cancel send_keepalive.
- **any authenticated packet received** (data, keepalive, handshake): cancel new_handshake.
- **any traversal** (both directions): re-arm persistent_keepalive.
- **data sent**: keepalives do **not** count.
- **data received**: keepalives do **not** count.

## 7. When handshakes start

- **Rate limit**: never more than one initiation per `REKEY_TIMEOUT`.
- **Not a retry** (any trigger except the retransmit timer): resets the attempt counter.
- **Sending with no usable session**: the packet is *staged* (queue of up to 128).
  A session is unusable if there is none, it is older than `REJECT_AFTER_TIME`, or its counter
  would reach `REJECT_AFTER_MESSAGES`. Start a handshake.
- **After sending**: if counter > `REKEY_AFTER_MESSAGES`, or we are the initiator and the
  session is older than `REKEY_AFTER_TIME`, start a handshake.
- **After receiving**: if we are the initiator and the session is older than
  `REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT` (165 s), start a handshake,
  only once per session (`sent_lastminute_handshake`).
- **new_handshake timer**: data sent but nothing heard for 15 s.
- **Handshake response accepted**: install the session as current. The previous current
  session becomes "previous" and stays valid for receiving late packets.
  Then **send the staged packets, or a keepalive if there are none**. The responder cannot use the
  new session until it receives a packet from us (key confirmation).

An idle tunnel without PersistentKeepalive therefore does **no** handshakes;
keys simply age out. A keepalive is sent through the normal send path, so
it can trigger a handshake itself when there is no session.

## 8. MTU

WireGuard overhead is at most 80 bytes:
IPv6 header 40 + UDP 8 + WireGuard header 16 + Poly1305 tag 16.
(IPv4 needs only 60.) When `MTU` is not set, `wg-quick` takes the MTU of the
interface used to reach the endpoint (falling back to the default-route interface,
then to 1500) and **subtracts 80**. Ethernet and Wi-Fi give 1500 − 80 = **1420**.
→ `netconfig::auto_mtu`.

## 9. Not implemented here (client-irrelevant or optional)

- Responder role (receiving initiations) and endpoint roaming: a client
  only talks to its configured endpoint.
- DSCP marking of handshake packets (0x88). This is a QoS nicety.
- Multiple peers.
