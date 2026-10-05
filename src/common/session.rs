//! Transport data phase: encrypting and decrypting IP packets once the
//! handshake has produced a pair of keys (whitepaper section 5.4.6).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
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
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
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
            send_cipher: ChaCha20Poly1305::new_from_slice(&send_key).expect("32 byte key"),
            recv_cipher: ChaCha20Poly1305::new_from_slice(&recv_key).expect("32 byte key"),
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
        let mut plaintext = packet.to_vec();
        plaintext.resize(padded_len, 0);

        let mut msg = Vec::with_capacity(HEADER_LEN + padded_len + TAG_LEN);
        msg.extend_from_slice(&[MESSAGE_TRANSPORT, 0, 0, 0]);
        msg.extend_from_slice(&self.remote_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());

        let ciphertext = self
            .send_cipher
            .encrypt(&nonce_for(counter), Payload { msg: &plaintext, aad: &[] })
            .expect("encryption cannot fail");
        msg.extend_from_slice(&ciphertext);
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

        let plaintext = self
            .recv_cipher
            .decrypt(&nonce_for(counter), Payload { msg: &msg[HEADER_LEN..], aad: &[] })
            .map_err(|_| "transport authentication failed".to_string())?;

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

/// Nonce is 4 zero bytes followed by the little-endian counter.
fn nonce_for(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce)
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
}
