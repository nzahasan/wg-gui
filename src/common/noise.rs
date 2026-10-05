//! The WireGuard handshake (Noise_IKpsk2), initiator side only.
//!
//! Message 1 (initiation, 148 bytes) is built by `build_initiation`, sent to
//! the peer, and the peer's message 2 (response, 92 bytes) is consumed by
//! `consume_response`, which yields the transport keys for a `Session`.
//! A busy peer may answer with a cookie reply (64 bytes) instead; its
//! cookie is read by `consume_cookie_reply` and goes into the next
//! initiation's mac2.
//!
//! Each step follows section 5.4 of the WireGuard whitepaper; comments quote
//! the whitepaper's variable names (C = chaining key, H = hash, k = key).

use blake2::digest::consts::U16;
use blake2::digest::Mac;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, XChaCha20Poly1305, XNonce};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::session::Session;

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
pub const MESSAGE_INITIATION: u8 = 1;
pub const MESSAGE_RESPONSE: u8 = 2;
pub const MESSAGE_COOKIE_REPLY: u8 = 3;

/// Where mac1 sits inside an initiation.
const INITIATION_MAC1: std::ops::Range<usize> = 116..132;

/// A cookie from a cookie reply; it keys mac2 of later initiations.
pub type Cookie = [u8; 16];

/// Kernel INITIATIONS_PER_SECOND; used to round the timestamp.
const INITIATIONS_PER_SECOND: u32 = 50;

/// Everything the initiator has to remember between sending message 1 and
/// receiving message 2.
pub struct HandshakeState {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    ephemeral_secret: StaticSecret,
    static_secret: StaticSecret,
    preshared_key: [u8; 32],
    pub local_index: u32,
}

// ---------------------------------------------------------------------------
// Primitives from the whitepaper: HASH, HMAC, KDF, MAC, AEAD, TAI64N
// ---------------------------------------------------------------------------

/// HASH(a || b) with BLAKE2s-256.
fn hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// HMAC-BLAKE2s as in RFC 2104 (block size 64 bytes).
fn hmac(key: &[u8], data: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut padded_key = [0u8; 64];
    padded_key[..key.len()].copy_from_slice(key);

    let inner_pad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x36).collect();
    let outer_pad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = Blake2s256::new();
    inner.update(&inner_pad);
    inner.update(data);
    inner.update(data2);
    let inner_hash: [u8; 32] = inner.finalize().into();

    hash(&outer_pad, &inner_hash)
}

/// KDF1: one derived key.
fn kdf1(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let t0 = hmac(key, input, &[]);
    hmac(&t0, &[1], &[])
}

/// KDF2: two derived keys.
fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac(key, input, &[]);
    let t1 = hmac(&t0, &[1], &[]);
    let t2 = hmac(&t0, &t1, &[2]);
    (t1, t2)
}

/// KDF3: three derived keys.
fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = hmac(key, input, &[]);
    let t1 = hmac(&t0, &[1], &[]);
    let t2 = hmac(&t0, &t1, &[2]);
    let t3 = hmac(&t0, &t2, &[3]);
    (t1, t2, t3)
}

/// MAC(key, input): keyed BLAKE2s with a 16-byte output.
fn mac(key: &[u8], input: &[u8]) -> [u8; 16] {
    let mut m = Blake2sMac::<U16>::new_from_slice(key).expect("32 byte key");
    m.update(input);
    m.finalize().into_bytes().into()
}

/// The mac1 key for messages sent *to* the holder of `public_key`.
fn mac1_key(public_key: &[u8; 32]) -> [u8; 32] {
    hash(LABEL_MAC1, public_key)
}

fn aead_nonce(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce)
}

/// AEAD(key, counter, plaintext, authtext) with ChaCha20-Poly1305.
fn aead_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32 byte key");
    cipher
        .encrypt(&aead_nonce(counter), Payload { msg: plaintext, aad })
        .expect("encryption cannot fail")
}

fn aead_decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32 byte key");
    cipher
        .decrypt(&aead_nonce(counter), Payload { msg: ciphertext, aad })
        .map_err(|_| "AEAD authentication failed".to_string())
}

/// TAI64N timestamp: 8-byte big-endian seconds (offset by 2^62 + 10 leap
/// seconds) followed by 4-byte big-endian nanoseconds.
///
/// Like the kernel, the nanoseconds are rounded down to a power of two
/// (2^24 ns, about 17 ms) so the timestamp does not reveal a precise clock.
fn tai64n() -> [u8; 12] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = (1u64 << 62) + 10 + now.as_secs();
    let step = 1u32 << (1_000_000_000 / INITIATIONS_PER_SECOND).ilog2();
    let nanos = now.subsec_nanos() / step * step;
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

/// 32 cryptographically random bytes from the kernel.
pub fn random_bytes() -> [u8; 32] {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    let mut urandom = std::fs::File::open("/dev/urandom").expect("/dev/urandom is readable");
    urandom.read_exact(&mut bytes).expect("/dev/urandom never runs dry");
    bytes
}

#[cfg(test)]
fn public_key_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Builds message 1. `local_index` is the sender index the peer will echo
/// back in its response and in transport packets. `cookie` is the latest
/// valid cookie from the peer, if any.
pub fn build_initiation(
    static_secret: [u8; 32],
    peer_public: [u8; 32],
    preshared_key: [u8; 32],
    local_index: u32,
    cookie: Option<&Cookie>,
) -> (Vec<u8>, HandshakeState) {
    let static_secret = StaticSecret::from(static_secret);
    let static_public = PublicKey::from(&static_secret).to_bytes();
    let ephemeral_secret = StaticSecret::from(random_bytes());
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let peer_public_key = PublicKey::from(peer_public);

    // Ci = HASH(CONSTRUCTION); Hi = HASH(Ci || IDENTIFIER); Hi = HASH(Hi || Sr_pub)
    let mut chaining_key = hash(CONSTRUCTION, &[]);
    let mut h = hash(&chaining_key, IDENTIFIER);
    h = hash(&h, &peer_public);

    let mut msg = Vec::with_capacity(INITIATION_LEN);
    msg.extend_from_slice(&[MESSAGE_INITIATION, 0, 0, 0]);
    msg.extend_from_slice(&local_index.to_le_bytes());

    // msg.ephemeral = Ei_pub; Ci = KDF1(Ci, Ei_pub); Hi = HASH(Hi || msg.ephemeral)
    msg.extend_from_slice(&ephemeral_public);
    chaining_key = kdf1(&chaining_key, &ephemeral_public);
    h = hash(&h, &ephemeral_public);

    // (Ci, k) = KDF2(Ci, DH(Ei_priv, Sr_pub)); msg.static = AEAD(k, 0, Si_pub, Hi)
    let dh = ephemeral_secret.diffie_hellman(&peer_public_key);
    let (ck, k) = kdf2(&chaining_key, dh.as_bytes());
    chaining_key = ck;
    let encrypted_static = aead_encrypt(&k, 0, &static_public, &h);
    msg.extend_from_slice(&encrypted_static);
    h = hash(&h, &encrypted_static);

    // (Ci, k) = KDF2(Ci, DH(Si_priv, Sr_pub)); msg.timestamp = AEAD(k, 0, TAI64N(), Hi)
    let dh = static_secret.diffie_hellman(&peer_public_key);
    let (ck, k) = kdf2(&chaining_key, dh.as_bytes());
    chaining_key = ck;
    let encrypted_timestamp = aead_encrypt(&k, 0, &tai64n(), &h);
    msg.extend_from_slice(&encrypted_timestamp);
    h = hash(&h, &encrypted_timestamp);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || Sr_pub), msg so far)
    let mac1 = mac(&mac1_key(&peer_public), &msg);
    msg.extend_from_slice(&mac1);

    // msg.mac2 = MAC(cookie, msg so far), or zeros without a cookie
    let mac2 = match cookie {
        Some(cookie) => mac(cookie, &msg),
        None => [0u8; 16],
    };
    msg.extend_from_slice(&mac2);
    debug_assert_eq!(msg.len(), INITIATION_LEN);

    let state = HandshakeState {
        chaining_key,
        hash: h,
        ephemeral_secret,
        static_secret,
        preshared_key,
        local_index,
    };
    (msg, state)
}

/// Consumes message 2 and returns the ready-to-use transport session.
pub fn consume_response(state: &HandshakeState, msg: &[u8]) -> Result<Session, String> {
    if msg.len() != RESPONSE_LEN || msg[0] != MESSAGE_RESPONSE {
        return Err("not a handshake response".to_string());
    }
    let remote_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    let receiver_index = u32::from_le_bytes(msg[8..12].try_into().unwrap());
    let peer_ephemeral: [u8; 32] = msg[12..44].try_into().unwrap();
    let encrypted_empty = &msg[44..60];
    let mac1 = &msg[60..76];

    if receiver_index != state.local_index {
        return Err("response is for a different handshake".to_string());
    }

    // The peer computed mac1 with our static public key.
    let our_public = PublicKey::from(&state.static_secret).to_bytes();
    if mac(&mac1_key(&our_public), &msg[..60]) != mac1 {
        return Err("bad mac1 on handshake response".to_string());
    }

    let mut chaining_key = state.chaining_key;
    let mut h = state.hash;
    let peer_ephemeral_key = PublicKey::from(peer_ephemeral);

    // Hr = HASH(Hi || Er_pub); Cr = KDF1(Ci, Er_pub)
    h = hash(&h, &peer_ephemeral);
    chaining_key = kdf1(&chaining_key, &peer_ephemeral);

    // Cr = KDF1(Cr, DH(Ei_priv, Er_pub)); Cr = KDF1(Cr, DH(Si_priv, Er_pub))
    let dh = state.ephemeral_secret.diffie_hellman(&peer_ephemeral_key);
    chaining_key = kdf1(&chaining_key, dh.as_bytes());
    let dh = state.static_secret.diffie_hellman(&peer_ephemeral_key);
    chaining_key = kdf1(&chaining_key, dh.as_bytes());

    // (Cr, tau, k) = KDF3(Cr, Q); Hr = HASH(Hr || tau)
    let (ck, tau, k) = kdf3(&chaining_key, &state.preshared_key);
    chaining_key = ck;
    h = hash(&h, &tau);

    // msg.empty = AEAD(k, 0, "", Hr) -- decrypting proves the peer knows everything.
    aead_decrypt(&k, 0, encrypted_empty, &h)?;

    // Transport keys: initiator sends with T1 and receives with T2.
    let (send_key, recv_key) = kdf2(&chaining_key, &[]);
    Ok(Session::new(send_key, recv_key, state.local_index, remote_index))
}

/// The mac1 of an initiation we built; a cookie reply must be bound to it.
pub fn initiation_mac1(initiation: &[u8]) -> [u8; 16] {
    initiation[INITIATION_MAC1].try_into().unwrap()
}

/// Decrypts a cookie reply. `last_mac1` is the mac1 of the initiation it
/// answers, which the peer used as associated data.
pub fn consume_cookie_reply(
    peer_public: &[u8; 32],
    last_mac1: &[u8; 16],
    msg: &[u8],
) -> Result<Cookie, String> {
    if msg.len() != COOKIE_REPLY_LEN || msg[0] != MESSAGE_COOKIE_REPLY {
        return Err("not a cookie reply".to_string());
    }
    let nonce = XNonce::try_from(&msg[8..32]).unwrap();
    let encrypted_cookie = &msg[32..64];

    // key = HASH(LABEL_COOKIE || Sr_pub); cookie = XAEAD-decrypt(key, nonce, ..., last mac1)
    let key = hash(LABEL_COOKIE, peer_public);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32 byte key");
    let cookie = cipher
        .decrypt(&nonce, Payload { msg: encrypted_cookie, aad: last_mac1 })
        .map_err(|_| "cookie reply authentication failed".to_string())?;
    Ok(cookie.try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Tests: a minimal responder lets us run the full handshake locally.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The responder half of the handshake, written straight from the
    /// whitepaper. Returns message 2 and the responder's (send, recv) keys.
    fn respond(
        responder_secret: [u8; 32],
        preshared_key: [u8; 32],
        initiation: &[u8],
        responder_index: u32,
    ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let responder_secret = StaticSecret::from(responder_secret);
        let responder_public = PublicKey::from(&responder_secret).to_bytes();

        let sender_index = u32::from_le_bytes(initiation[4..8].try_into().unwrap());
        let ephemeral: [u8; 32] = initiation[8..40].try_into().unwrap();
        let encrypted_static = &initiation[40..88];
        let encrypted_timestamp = &initiation[88..116];
        assert_eq!(mac(&mac1_key(&responder_public), &initiation[..116]), initiation[116..132]);

        let mut c = hash(CONSTRUCTION, &[]);
        let mut h = hash(&c, IDENTIFIER);
        h = hash(&h, &responder_public);

        c = kdf1(&c, &ephemeral);
        h = hash(&h, &ephemeral);

        let dh = responder_secret.diffie_hellman(&PublicKey::from(ephemeral));
        let (ck, k) = kdf2(&c, dh.as_bytes());
        c = ck;
        let initiator_public: [u8; 32] =
            aead_decrypt(&k, 0, encrypted_static, &h).unwrap().try_into().unwrap();
        h = hash(&h, encrypted_static);

        let dh = responder_secret.diffie_hellman(&PublicKey::from(initiator_public));
        let (ck, k) = kdf2(&c, dh.as_bytes());
        c = ck;
        aead_decrypt(&k, 0, encrypted_timestamp, &h).unwrap();
        h = hash(&h, encrypted_timestamp);

        // Message 2.
        let ephemeral_secret = StaticSecret::from(random_bytes());
        let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();

        let mut msg = vec![MESSAGE_RESPONSE, 0, 0, 0];
        msg.extend_from_slice(&responder_index.to_le_bytes());
        msg.extend_from_slice(&sender_index.to_le_bytes());
        msg.extend_from_slice(&ephemeral_public);

        c = kdf1(&c, &ephemeral_public);
        h = hash(&h, &ephemeral_public);
        let dh = ephemeral_secret.diffie_hellman(&PublicKey::from(ephemeral));
        c = kdf1(&c, dh.as_bytes());
        let dh = ephemeral_secret.diffie_hellman(&PublicKey::from(initiator_public));
        c = kdf1(&c, dh.as_bytes());
        let (ck, tau, k) = kdf3(&c, &preshared_key);
        c = ck;
        h = hash(&h, &tau);
        let empty = aead_encrypt(&k, 0, &[], &h);
        msg.extend_from_slice(&empty);

        let mac1 = mac(&mac1_key(&initiator_public), &msg);
        msg.extend_from_slice(&mac1);
        msg.extend_from_slice(&[0u8; 16]);

        let (initiator_sends, responder_sends) = kdf2(&c, &[]);
        (msg, responder_sends, initiator_sends)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hmac_and_mac_match_python_reference() {
        // hmac.new(b"key", msg, hashlib.blake2s).hexdigest()
        let out = hmac(b"key", b"The quick brown fox jumps over the lazy dog", &[]);
        assert_eq!(hex(&out), "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0");

        // hashlib.blake2s(b"abc", digest_size=16, key=b"k"*32).hexdigest()
        let out = mac(&[b'k'; 32], b"abc");
        assert_eq!(hex(&out), "da5b50d8f2073c6d2bc49dc3f556bde3");
    }

    #[test]
    fn full_handshake_agrees_on_keys() {
        let initiator_secret = random_bytes();
        let responder_secret = random_bytes();
        let psk = random_bytes();
        let responder_public = public_key_of(&responder_secret);

        let (msg1, state) = build_initiation(initiator_secret, responder_public, psk, 7, None);
        assert_eq!(msg1.len(), INITIATION_LEN);

        let (msg2, responder_send, responder_recv) = respond(responder_secret, psk, &msg1, 9);
        assert_eq!(msg2.len(), RESPONSE_LEN);

        let session = consume_response(&state, &msg2).unwrap();
        assert_eq!(session.remote_index, 9);
        assert_eq!(session.local_index, 7);

        // What the initiator encrypts, the responder must decrypt, and vice versa.
        let mut responder = Session::new(responder_send, responder_recv, 9, 7);
        let packet = b"hello over the tunnel".to_vec();
        let mut session = session;
        let wire = session.encrypt(&packet);
        let plain = responder.decrypt(&wire).unwrap();
        assert_eq!(&plain[..packet.len()], &packet[..]);

        let wire = responder.encrypt(&packet);
        let plain = session.decrypt(&wire).unwrap();
        assert_eq!(&plain[..packet.len()], &packet[..]);
    }

    #[test]
    fn rejects_tampered_response() {
        let initiator_secret = random_bytes();
        let responder_secret = random_bytes();
        let psk = [0u8; 32];
        let (msg1, state) = build_initiation(initiator_secret, public_key_of(&responder_secret), psk, 1, None);
        let (mut msg2, _, _) = respond(responder_secret, psk, &msg1, 2);
        msg2[20] ^= 1; // flip a bit in the ephemeral key
        assert!(consume_response(&state, &msg2).is_err());
    }

    #[test]
    fn cookie_reply_round_trip_and_mac2() {
        let responder_secret = random_bytes();
        let responder_public = public_key_of(&responder_secret);
        let (msg1, _) = build_initiation(random_bytes(), responder_public, [0u8; 32], 1, None);
        assert_eq!(&msg1[132..], &[0u8; 16]); // no cookie yet: mac2 is zeros
        let mac1 = initiation_mac1(&msg1);

        // What a busy responder sends back.
        let cookie: Cookie = [7u8; 16];
        let nonce = [9u8; 24];
        let key = hash(LABEL_COOKIE, &responder_public);
        let encrypted = XChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(&XNonce::from(nonce), Payload { msg: &cookie, aad: &mac1 })
            .unwrap();
        let mut reply = vec![MESSAGE_COOKIE_REPLY, 0, 0, 0, 1, 0, 0, 0];
        reply.extend_from_slice(&nonce);
        reply.extend_from_slice(&encrypted);

        assert_eq!(consume_cookie_reply(&responder_public, &mac1, &reply).unwrap(), cookie);
        assert!(consume_cookie_reply(&responder_public, &[0u8; 16], &reply).is_err());

        // The next initiation carries mac2 = MAC(cookie, msg[..132]).
        let (msg1, _) = build_initiation(random_bytes(), responder_public, [0u8; 32], 2, Some(&cookie));
        assert_eq!(&msg1[132..], &mac(&cookie, &msg1[..132]));
    }

    #[test]
    fn timestamp_is_rounded_and_increasing() {
        let t = tai64n();
        let nanos = u32::from_be_bytes(t[8..].try_into().unwrap());
        assert_eq!(nanos % (1 << 24), 0);
        assert!(u64::from_be_bytes(t[..8].try_into().unwrap()) > 1 << 62);
    }
}
