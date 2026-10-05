//! The five per-peer timers of the WireGuard kernel module (`timers.c`),
//! written as optional deadlines. See PROTOCOL.md section 6.
//!
//! The event methods (`data_sent`, `any_packet_received`, ...) arm and
//! cancel deadlines exactly like the kernel's `wg_timers_*` hooks. The
//! tunnel's ticker calls `expired` to find out which ones fired and then
//! carries out the action.

use std::time::{Duration, Instant};

use crate::session::{KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT};

/// After this many retransmissions (90 s of trying) we give up.
pub const MAX_TIMER_HANDSHAKES: u32 = (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as u32;

/// Random extra delay added to handshake timers, at most 333 ms.
fn jitter() -> Duration {
    let random = u32::from_le_bytes(crate::noise::random_bytes()[..4].try_into().unwrap());
    Duration::from_millis(u64::from(random % 334))
}

#[derive(Default)]
pub struct Timers {
    pub persistent_keepalive_interval: Option<Duration>,
    pub handshake_attempts: u32,

    retransmit_handshake: Option<Instant>,
    send_keepalive: Option<Instant>,
    need_another_keepalive: bool,
    new_handshake: Option<Instant>,
    zero_key_material: Option<Instant>,
    persistent_keepalive: Option<Instant>,
}

/// A timer that ran out; the tunnel decides what to do for each.
#[derive(Debug, PartialEq)]
pub enum Expired {
    RetransmitHandshake,
    SendKeepalive,
    NewHandshake,
    ZeroKeyMaterial,
    PersistentKeepalive,
}

impl Timers {
    pub fn new(persistent_keepalive_interval: Option<Duration>) -> Timers {
        Timers { persistent_keepalive_interval, ..Timers::default() }
    }

    // -- events (kernel: wg_timers_*) -------------------------------------

    /// A data packet (not a keepalive) was sent.
    pub fn data_sent(&mut self, now: Instant) {
        if self.new_handshake.is_none() {
            self.new_handshake = Some(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter());
        }
    }

    /// A data packet (not a keepalive) was received.
    pub fn data_received(&mut self, now: Instant) {
        if self.send_keepalive.is_none() {
            self.send_keepalive = Some(now + KEEPALIVE_TIMEOUT);
        } else {
            self.need_another_keepalive = true;
        }
    }

    /// Any authenticated packet was sent: data, keepalive or handshake.
    pub fn any_packet_sent(&mut self) {
        self.send_keepalive = None;
    }

    /// Any authenticated packet was received: data, keepalive or handshake.
    pub fn any_packet_received(&mut self) {
        self.new_handshake = None;
    }

    /// Any authenticated packet went either way.
    pub fn any_packet_traversal(&mut self, now: Instant) {
        if let Some(interval) = self.persistent_keepalive_interval {
            self.persistent_keepalive = Some(now + interval);
        }
    }

    /// A handshake initiation was sent.
    pub fn handshake_initiated(&mut self, now: Instant) {
        self.retransmit_handshake = Some(now + REKEY_TIMEOUT + jitter());
    }

    /// A handshake response was accepted.
    pub fn handshake_complete(&mut self) {
        self.retransmit_handshake = None;
        self.handshake_attempts = 0;
    }

    /// New session keys were derived.
    pub fn session_derived(&mut self, now: Instant) {
        self.zero_key_material = Some(now + REJECT_AFTER_TIME * 3);
    }

    /// Call after sending the keepalive for `Expired::SendKeepalive`. If
    /// more data arrived while we were waiting, reply once more later.
    /// (Must come after the send, which cancels the timer.)
    pub fn keepalive_timer_handled(&mut self, now: Instant) {
        if self.need_another_keepalive {
            self.need_another_keepalive = false;
            self.send_keepalive = Some(now + KEEPALIVE_TIMEOUT);
        }
    }

    /// We stopped retrying the handshake.
    pub fn gave_up(&mut self, now: Instant) {
        self.send_keepalive = None;
        if self.zero_key_material.is_none() {
            self.zero_key_material = Some(now + REJECT_AFTER_TIME * 3);
        }
    }

    // -- expiry ------------------------------------------------------------

    /// Removes and returns every timer whose deadline has passed.
    pub fn expired(&mut self, now: Instant) -> Vec<Expired> {
        let mut fired = Vec::new();
        if take_if_due(&mut self.retransmit_handshake, now) {
            fired.push(Expired::RetransmitHandshake);
        }
        if take_if_due(&mut self.send_keepalive, now) {
            fired.push(Expired::SendKeepalive);
        }
        if take_if_due(&mut self.new_handshake, now) {
            fired.push(Expired::NewHandshake);
        }
        if take_if_due(&mut self.zero_key_material, now) {
            fired.push(Expired::ZeroKeyMaterial);
        }
        if take_if_due(&mut self.persistent_keepalive, now) {
            fired.push(Expired::PersistentKeepalive);
        }
        fired
    }
}

/// Clears `deadline` and returns true if it has passed.
fn take_if_due(deadline: &mut Option<Instant>, now: Instant) -> bool {
    if deadline.is_some_and(|d| now >= d) {
        *deadline = None;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn keepalives_do_not_start_the_dead_peer_timer() {
        let start = Instant::now();
        let mut t = Timers::new(Some(25 * SECOND));

        // Sending a keepalive is "any packet sent" + traversal, never data_sent.
        t.any_packet_sent();
        t.any_packet_traversal(start);
        assert_eq!(t.expired(start + 60 * SECOND), vec![Expired::PersistentKeepalive]);
    }

    #[test]
    fn unanswered_data_starts_a_new_handshake() {
        let start = Instant::now();
        let mut t = Timers::new(None);
        t.data_sent(start);
        t.data_sent(start + 10 * SECOND); // does not push the deadline back
        assert!(t.expired(start + 14 * SECOND).is_empty());
        assert_eq!(t.expired(start + 16 * SECOND), vec![Expired::NewHandshake]);

        // Any reply, even a keepalive, cancels it.
        t.data_sent(start);
        t.any_packet_received();
        assert!(t.expired(start + 60 * SECOND).is_empty());
    }

    #[test]
    fn received_data_gets_a_keepalive_reply_unless_we_send() {
        let start = Instant::now();
        let mut t = Timers::new(None);
        t.data_received(start);
        assert!(t.expired(start + 9 * SECOND).is_empty());
        assert_eq!(t.expired(start + 10 * SECOND), vec![Expired::SendKeepalive]);

        t.data_received(start);
        t.any_packet_sent(); // we replied with real traffic
        assert!(t.expired(start + 60 * SECOND).is_empty());
    }

    #[test]
    fn more_data_while_waiting_schedules_another_keepalive() {
        let start = Instant::now();
        let mut t = Timers::new(None);
        t.data_received(start);
        t.data_received(start + 5 * SECOND);

        // What the tunnel does: send the keepalive, then ask for a re-arm.
        let fire = |t: &mut Timers, at: Instant| {
            let fired = t.expired(at);
            t.any_packet_sent();
            t.keepalive_timer_handled(at);
            fired
        };
        assert_eq!(fire(&mut t, start + 10 * SECOND), vec![Expired::SendKeepalive]);
        assert_eq!(fire(&mut t, start + 20 * SECOND), vec![Expired::SendKeepalive]);
        assert!(fire(&mut t, start + 60 * SECOND).is_empty());
    }

    #[test]
    fn persistent_keepalive_is_pushed_back_by_any_traffic() {
        let start = Instant::now();
        let mut t = Timers::new(Some(25 * SECOND));
        t.any_packet_traversal(start);
        t.any_packet_traversal(start + 20 * SECOND); // e.g. a packet received
        assert!(t.expired(start + 30 * SECOND).is_empty());
        assert_eq!(t.expired(start + 45 * SECOND), vec![Expired::PersistentKeepalive]);
    }

    #[test]
    fn handshake_retransmits_until_complete() {
        let start = Instant::now();
        let mut t = Timers::new(None);
        t.handshake_initiated(start);
        assert!(t.expired(start + 4 * SECOND).is_empty());
        assert_eq!(t.expired(start + 6 * SECOND), vec![Expired::RetransmitHandshake]);

        t.handshake_initiated(start);
        t.handshake_complete();
        assert!(t.expired(start + 60 * SECOND).is_empty());
    }
}
