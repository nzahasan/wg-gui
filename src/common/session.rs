//! Transport data phase: encrypting and decrypting IP packets once the
//! handshake has produced a pair of keys (whitepaper section 5.4.6).

// ring runs BoringSSL's assembly: on Apple Silicon one NEON pass does
// both ChaCha20 and Poly1305 (RustCrypto's Poly1305 has no ARM SIMD).
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::time::{Duration, Instant};

pub const MESSAGE_TRANSPORT: u8 = 4;
const HEADER_LEN: usize = 16; // type(4) + receiver index(4) + counter(8)
const TAG_LEN: usize = 16;

// Timers and limits from whitepaper section 6.1 / kernel messages.h.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - WINDOW_SIZE - 1;
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Session {
    send_cipher: LessSafeKey,
    recv_cipher: LessSafeKey,
    pub local_index: u32,
    pub remote_index: u32,
    pub send_counter: u64,
    replay: ReplayWindow,
    pub created: Instant,
    /// We already started the "about to expire" handshake for this session.
    pub sent_lastminute_handshake: bool,
}

impl Session {
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32], local_index: u32, remote_index: u32) -> Session {
        Session {
            send_cipher: cipher(&send_key),
            recv_cipher: cipher(&recv_key),
            local_index,
            remote_index,
            send_counter: 0,
            replay: ReplayWindow::new(),
            created: Instant::now(),
            sent_lastminute_handshake: false,
        }
    }

    fn age(&self) -> Duration {
        self.created.elapsed()
    }

    /// True while this session may still encrypt one more packet.
    pub fn can_send(&self) -> bool {
        self.age() < REJECT_AFTER_TIME && self.send_counter < REJECT_AFTER_MESSAGES
    }

    /// Checked after sending: time for fresh keys? (We are always the
    /// initiator, so the time rule applies to us.)
    pub fn wants_rekey_after_send(&self) -> bool {
        self.send_counter > REKEY_AFTER_MESSAGES || self.age() >= REKEY_AFTER_TIME
    }

    /// Checked after receiving: the session is about to expire and the
    /// peer, as responder, will not rekey it for us.
    pub fn wants_rekey_after_receive(&self) -> bool {
        self.age() >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
    }

    /// Wraps an IP packet (or an empty keepalive) into a transport message.
    /// Callers must check `can_send` first.
    pub fn encrypt(&mut self, packet: &[u8]) -> Vec<u8> {
        assert!(self.send_counter < REJECT_AFTER_MESSAGES, "session exhausted");
        let counter = self.send_counter;
        self.send_counter += 1;

        // Plaintext is zero-padded to a multiple of 16 bytes to hide its size.
        let padded_len = packet.len().div_ceil(16) * 16;

        // Built in one buffer and encrypted in place after the header.
        let mut msg = Vec::with_capacity(HEADER_LEN + padded_len + TAG_LEN);
        msg.extend_from_slice(&[MESSAGE_TRANSPORT, 0, 0, 0]);
        msg.extend_from_slice(&self.remote_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(packet);
        msg.resize(HEADER_LEN + padded_len, 0);

        let tag = self
            .send_cipher
            .seal_in_place_separate_tag(nonce_for(counter), Aad::empty(), &mut msg[HEADER_LEN..])
            .expect("encryption cannot fail");
        msg.extend_from_slice(tag.as_ref());
        msg
    }

    /// Unwraps a transport message addressed to this session. The returned
    /// packet may carry trailing zero padding; the IP header knows its own
    /// length so the network stack ignores it. An empty result is a keepalive.
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, String> {
        if msg.len() < HEADER_LEN + TAG_LEN || msg[0] != MESSAGE_TRANSPORT {
            return Err("not a transport message".to_string());
        }
        let receiver_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(msg[8..16].try_into().unwrap());
        if receiver_index != self.local_index {
            return Err("transport message for another session".to_string());
        }
        if counter >= REJECT_AFTER_MESSAGES {
            return Err("counter too large".to_string());
        }
        if self.age() >= REJECT_AFTER_TIME {
            return Err("session expired".to_string());
        }

        let mut plaintext = msg[HEADER_LEN..].to_vec();
        let len = self
            .recv_cipher
            .open_in_place(nonce_for(counter), Aad::empty(), &mut plaintext)
            .map_err(|_| "transport authentication failed".to_string())?
            .len();
        plaintext.truncate(len); // drops the tag

        // Only mark the counter as seen after authentication succeeded, so a
        // forged packet cannot make us drop a genuine one.
        if !self.replay.accept(counter) {
            return Err("replayed packet".to_string());
        }
        Ok(plaintext)
    }
}

/// The receiver index of a transport message, which tells us which session
/// it belongs to. None if the message is too short to be one.
pub fn receiver_index(msg: &[u8]) -> Option<u32> {
    if msg.len() < HEADER_LEN + TAG_LEN {
        return None;
    }
    Some(u32::from_le_bytes(msg[4..8].try_into().unwrap()))
}

fn cipher(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32 byte key"))
}

/// Nonce is 4 zero bytes followed by the little-endian counter. Sending
/// never reuses one: the send counter only grows. (Decrypting a replayed
/// packet reuses its nonce, which is harmless; the replay window then
/// rejects it.)
fn nonce_for(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce)
}

/// Bits in the replay bitmap (kernel: COUNTER_BITS_TOTAL).
const WINDOW_BITS: u64 = 8192;
/// Bits per block of the bitmap.
const BLOCK_BITS: u64 = 64;
const BLOCKS: usize = (WINDOW_BITS / BLOCK_BITS) as usize;
/// How far behind the highest counter a packet may arrive (one block of
/// the ring is always being recycled, so it does not count).
const WINDOW_SIZE: u64 = WINDOW_BITS - BLOCK_BITS;

/// Sliding replay window from RFC 6479, as used by the kernel and
/// wireguard-go: packets may arrive out of order by up to `WINDOW_SIZE`
/// counters, but never twice.
///
/// The bitmap is a ring of 64-bit blocks; counter `c` lives in block
/// `(c / 64) % BLOCKS`, bit `c % 64`. Moving forward clears the blocks
/// that are being reused.
struct ReplayWindow {
    highest: u64,
    blocks: [u64; BLOCKS],
}

impl ReplayWindow {
    fn new() -> ReplayWindow {
        ReplayWindow { highest: 0, blocks: [0; BLOCKS] }
    }

    /// Returns true if `counter` is new, and records it.
    fn accept(&mut self, counter: u64) -> bool {
        let block = counter / BLOCK_BITS;
        if counter > self.highest {
            // Clear every block between the old highest and the new one.
            let current = self.highest / BLOCK_BITS;
            let to_clear = (block - current).min(BLOCKS as u64);
            for i in 1..=to_clear {
                self.blocks[((current + i) % BLOCKS as u64) as usize] = 0;
            }
            self.highest = counter;
        } else if self.highest - counter > WINDOW_SIZE {
            return false; // Too old to track.
        }

        let slot = &mut self.blocks[(block % BLOCKS as u64) as usize];
        let bit = 1u64 << (counter % BLOCK_BITS);
        if *slot & bit != 0 {
            return false; // Already seen.
        }
        *slot |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_new_and_rejects_old() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(3)); // out of order but within window
        assert!(!w.accept(3));
        assert!(w.accept(100));
        assert!(w.accept(30)); // well within the window
        assert!(!w.accept(30));
        assert!(w.accept(20_000));
        assert!(!w.accept(100)); // fell out of the window
        assert!(w.accept(20_000 - WINDOW_SIZE));
        assert!(!w.accept(20_000 - WINDOW_SIZE - 1));
        assert!(w.accept(19_999));
        assert!(!w.accept(19_999));
    }

    #[test]
    fn replay_window_survives_large_jumps() {
        let mut w = ReplayWindow::new();
        for c in 0..10_000 {
            assert!(w.accept(c));
        }
        assert!(w.accept(1_000_000));
        // Old blocks were cleared, so nearby fresh counters are accepted.
        assert!(w.accept(1_000_000 - 1));
        assert!(w.accept(1_000_000 - 5000));
        assert!(!w.accept(9_999));
    }

    #[test]
    fn encrypt_decrypt_round_trip_and_replay() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let mut alice = Session::new(key_a, key_b, 10, 20);
        let mut bob = Session::new(key_b, key_a, 20, 10);

        let wire = alice.encrypt(b"ping");
        assert_eq!(wire[0], MESSAGE_TRANSPORT);
        assert_eq!(&wire[4..8], &20u32.to_le_bytes());

        let plain = bob.decrypt(&wire).unwrap();
        assert_eq!(&plain[..4], b"ping");
        assert_eq!(plain.len(), 16); // padded

        assert!(bob.decrypt(&wire).is_err()); // replay
        assert!(alice.decrypt(&wire).is_err()); // wrong direction / index

        let keepalive = bob.encrypt(&[]);
        assert_eq!(alice.decrypt(&keepalive).unwrap().len(), 0);
    }

    #[test]
    fn receiver_index_reads_header() {
        let mut alice = Session::new([1u8; 32], [2u8; 32], 10, 20);
        assert_eq!(receiver_index(&alice.encrypt(&[])), Some(20));
        assert_eq!(receiver_index(&[MESSAGE_TRANSPORT; 8]), None);
    }

    /// RustCrypto, the implementation used before ring, as an independent
    /// reference: the bytes on the wire must not change.
    fn reference(key: [u8; 32]) -> chacha20poly1305::ChaCha20Poly1305 {
        use chacha20poly1305::KeyInit;
        chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap()
    }

    fn reference_nonce(counter: u64) -> chacha20poly1305::Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        chacha20poly1305::Nonce::from(nonce)
    }

    #[test]
    fn wire_format_matches_rustcrypto() {
        use chacha20poly1305::aead::Aead;
        let (key_a, key_b) = ([3u8; 32], [4u8; 32]);
        for size in [0usize, 1, 15, 16, 17, 1280, 1420, 65_000] {
            let packet: Vec<u8> = (0..size).map(|i| (i * 7 + 1) as u8).collect();
            let mut padded = packet.clone();
            padded.resize(size.div_ceil(16) * 16, 0);

            // ring encrypts, RustCrypto decrypts.
            let mut alice = Session::new(key_a, key_b, 10, 20);
            alice.send_counter = 41;
            let wire = alice.encrypt(&packet);
            assert_eq!(&wire[8..16], &41u64.to_le_bytes());
            let plain = reference(key_a).decrypt(&reference_nonce(41), &wire[HEADER_LEN..]).unwrap();
            assert_eq!(plain, padded, "size {size}");

            // RustCrypto encrypts, ring decrypts.
            let mut wire = vec![MESSAGE_TRANSPORT, 0, 0, 0];
            wire.extend_from_slice(&20u32.to_le_bytes());
            wire.extend_from_slice(&7u64.to_le_bytes());
            wire.extend(reference(key_a).encrypt(&reference_nonce(7), &padded[..]).unwrap());
            let mut bob = Session::new(key_b, key_a, 20, 10);
            assert_eq!(bob.decrypt(&wire).unwrap(), padded, "size {size}");
        }
    }

    #[test]
    fn tampering_is_rejected_without_burning_the_counter() {
        let mut alice = Session::new([5u8; 32], [6u8; 32], 10, 20);
        let mut bob = Session::new([6u8; 32], [5u8; 32], 20, 10);
        let wire = alice.encrypt(b"hello");
        for flip in [HEADER_LEN, wire.len() - 1] {
            // A bit in the ciphertext, then in the tag.
            let mut forged = wire.clone();
            forged[flip] ^= 1;
            assert_eq!(bob.decrypt(&forged), Err("transport authentication failed".to_string()));
        }
        assert_eq!(&bob.decrypt(&wire).unwrap()[..5], b"hello");
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: String = text.chars().filter(char::is_ascii_hexdigit).collect();
        (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap()).collect()
    }

    /// The AEAD test vector of RFC 8439 section 2.8.2, through ring's
    /// ChaCha20-Poly1305 as used here: anchors it to the standard, not
    /// only to RustCrypto.
    #[test]
    fn rfc8439_aead_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
        let key: [u8; 32] = (0x80..=0x9f).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = hex("07 00 00 00 40 41 42 43 44 45 46 47").try_into().unwrap();
        let ciphertext = hex(
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
             a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
             3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
             1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
             92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
             fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
             3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
             61 16",
        );
        let tag = hex("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91");

        let key = cipher(&key);
        let mut buf = plaintext.to_vec();
        let sealed = key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut buf)
            .unwrap();
        assert_eq!(buf, ciphertext);
        assert_eq!(sealed.as_ref(), &tag[..]);

        let mut wire = [ciphertext, tag].concat();
        let opened = key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut wire).unwrap();
        assert_eq!(opened, &plaintext[..]);
    }

    /// Throughput of transport encryption and decryption on full-size
    /// packets. Run with:
    /// cargo test --release --lib session::tests::bench_transport -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_transport() {
        const PACKETS: usize = 200_000;
        let packet = vec![0x5a_u8; 1420];
        let mut alice = Session::new([1u8; 32], [2u8; 32], 10, 20);
        let mut bob = Session::new([2u8; 32], [1u8; 32], 20, 10);

        let start = Instant::now();
        let wires: Vec<Vec<u8>> = (0..PACKETS).map(|_| alice.encrypt(&packet)).collect();
        let encrypt = start.elapsed();
        let start = Instant::now();
        for wire in &wires {
            bob.decrypt(wire).unwrap();
        }
        let decrypt = start.elapsed();

        // The raw AEADs side by side on identical buffers, alternating, so
        // order and CPU temperature do not favour either.
        use chacha20poly1305::AeadInOut;
        let (rust_crypto, ring_key) = (reference([1u8; 32]), cipher(&[1u8; 32]));
        let (mut rust_crypto_time, mut ring_time) = (Duration::ZERO, Duration::ZERO);
        let mut buf = packet.clone();
        for round in 0..10 {
            for backend in [round % 2, 1 - round % 2] {
                let start = Instant::now();
                for counter in 0..PACKETS as u64 / 10 {
                    if backend == 0 {
                        let tag = rust_crypto.encrypt_inout_detached(&reference_nonce(counter), &[], buf.as_mut_slice().into()).unwrap();
                        std::hint::black_box(&tag);
                    } else {
                        let tag = ring_key.seal_in_place_separate_tag(nonce_for(counter), Aad::empty(), &mut buf).unwrap();
                        std::hint::black_box(&tag);
                    }
                }
                *[&mut rust_crypto_time, &mut ring_time][backend] += start.elapsed();
            }
        }

        let mb = (PACKETS * packet.len()) as f64 / 1e6;
        for (what, took) in [("RustCrypto seal", rust_crypto_time), ("ring seal", ring_time)] {
            println!("{what}: {:.0} MB/s", mb / took.as_secs_f64());
        }
        for (what, took) in [("encrypt", encrypt), ("decrypt", decrypt)] {
            println!(
                "{what}: {:.0} MB/s, {:.0} ns/packet",
                mb / took.as_secs_f64(),
                took.as_nanos() as f64 / PACKETS as f64
            );
        }
    }
}
