//! The running tunnel: moves packets between the utun device and the UDP
//! socket, and keeps the session fresh with handshakes and keepalives.
//!
//! Three threads share one `State` behind a mutex:
//!   * tun -> udp : stage outgoing IP packets and send them encrypted
//!   * udp -> tun : decrypt incoming packets, finish handshakes, take cookies
//!   * timer      : every 100 ms, act on the timers that expired
//!
//! The rules follow the Linux kernel implementation; PROTOCOL.md lists
//! them with sources.
//!
//! `run` hands back a `TunnelHandle`; stopping it sets a flag the threads
//! check at least every `POLL_TIMEOUT`, joins them and closes the utun.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::{Cidr, Config};
use crate::ip;
use crate::noise::{self, Cookie, HandshakeState, MESSAGE_COOKIE_REPLY, MESSAGE_RESPONSE};
use crate::session::{receiver_index, Session, MESSAGE_TRANSPORT, REJECT_AFTER_TIME, REKEY_TIMEOUT};
use crate::timers::{Expired, Timers, MAX_TIMER_HANDSHAKES};
use crate::tun::Tun;

/// How often the timer thread checks for expired timers.
const TICK: Duration = Duration::from_millis(100);
/// Packets kept while waiting for a session; the oldest are dropped first.
const MAX_STAGED_PACKETS: usize = 128;
/// A cookie is used for mac2 for this long (COOKIE_SECRET_MAX_AGE -
/// COOKIE_SECRET_LATENCY in the kernel).
const COOKIE_LIFETIME: Duration = Duration::from_secs(120 - 5);
/// Pause after a failed read so a persistent error cannot spin the CPU.
const ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// Longest a blocking read waits before the thread re-checks the stop flag.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

struct State {
    session: Option<Session>,
    /// The session before the last rekey, kept only to decrypt packets
    /// that were already in flight.
    previous_session: Option<Session>,
    pending: Option<HandshakeState>,
    /// For the one-initiation-per-REKEY_TIMEOUT rate limit.
    last_handshake_sent: Option<Instant>,
    /// Outgoing packets waiting for a usable session.
    staged: VecDeque<Vec<u8>>,
    /// mac1 of our last initiation; a cookie reply must be bound to it.
    /// Taken once a cookie is accepted, so each mac1 yields one cookie.
    last_mac1: Option<[u8; 16]>,
    /// Latest cookie from a busy peer and when we got it.
    cookie: Option<(Cookie, Instant)>,
    /// When the most recent handshake completed.
    last_handshake: Option<Instant>,
    timers: Timers,
}

impl State {
    /// The session a transport message with this receiver index belongs to.
    fn session_for(&mut self, index: u32) -> Option<&mut Session> {
        if self.session.as_ref().is_some_and(|s| s.local_index == index) {
            return self.session.as_mut();
        }
        if self.previous_session.as_ref().is_some_and(|s| s.local_index == index) {
            return self.previous_session.as_mut();
        }
        None
    }
}

/// Transport-message totals, counted in bytes on the wire like `wg show`.
#[derive(Default)]
struct Counters {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
}

/// A snapshot of the tunnel's traffic and handshake state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// None until the first handshake completes.
    pub last_handshake: Option<Instant>,
}

struct Tunnel {
    tun: Tun,
    socket: UdpSocket,
    endpoint: SocketAddr,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: [u8; 32],
    allowed_ips: Vec<Cidr>,
    state: Mutex<State>,
    counters: Counters,
    stop: AtomicBool,
}

/// A running tunnel. Dropping it without `stop` leaves the threads running
/// until the process exits, which is what a CLI killed by a signal gets.
pub struct TunnelHandle {
    tunnel: Arc<Tunnel>,
    threads: Vec<JoinHandle<()>>,
}

impl TunnelHandle {
    /// Stops the threads and closes the utun device; the interface and
    /// every route through it disappear.
    pub fn stop(self) {
        self.tunnel.stop.store(true, Ordering::SeqCst);
        for thread in self.threads {
            let _ = thread.join();
        }
        // The last reference to the Tunnel goes here, closing the utun.
    }

    pub fn stats(&self) -> Stats {
        let c = &self.tunnel.counters;
        Stats {
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            rx_packets: c.rx_packets.load(Ordering::Relaxed),
            tx_packets: c.tx_packets.load(Ordering::Relaxed),
            last_handshake: self.tunnel.state.lock().unwrap().last_handshake,
        }
    }
}

/// Starts the tunnel threads and returns a handle to stop them.
pub fn run(tun: Tun, config: &Config) -> Result<TunnelHandle, String> {
    let bind_addr = if config.peer.endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_addr).map_err(|e| format!("cannot bind UDP socket: {e}"))?;
    socket
        .connect(config.peer.endpoint)
        .map_err(|e| format!("cannot connect UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(POLL_TIMEOUT))
        .map_err(|e| format!("cannot set UDP read timeout: {e}"))?;
    tun.set_read_timeout(POLL_TIMEOUT)
        .map_err(|e| format!("cannot set {} read timeout: {e}", tun.name))?;

    let keepalive_interval = config.peer.keepalive_seconds.map(|s| Duration::from_secs(s.into()));
    let tunnel = Arc::new(Tunnel {
        tun,
        socket,
        endpoint: config.peer.endpoint,
        private_key: config.private_key,
        peer_public_key: config.peer.public_key,
        preshared_key: config.peer.preshared_key,
        allowed_ips: config.peer.allowed_ips.clone(),
        state: Mutex::new(State {
            session: None,
            previous_session: None,
            pending: None,
            last_handshake_sent: None,
            staged: VecDeque::new(),
            last_mac1: None,
            cookie: None,
            last_handshake: None,
            timers: Timers::new(keepalive_interval),
        }),
        counters: Counters::default(),
        stop: AtomicBool::new(false),
    });

    // Connect right away so problems show up at startup, not on first use.
    tunnel.send_handshake(&mut tunnel.state.lock().unwrap(), false);

    let t = Arc::clone(&tunnel);
    let tun_to_udp = thread::spawn(move || t.tun_to_udp_loop());
    let t = Arc::clone(&tunnel);
    let udp_to_tun = thread::spawn(move || t.udp_to_tun_loop());
    let t = Arc::clone(&tunnel);
    let timer = thread::spawn(move || t.timer_loop());
    Ok(TunnelHandle { tunnel, threads: vec![tun_to_udp, udp_to_tun, timer] })
}

impl Tunnel {
    // -- handshake ---------------------------------------------------------

    /// Sends a handshake initiation, at most once per REKEY_TIMEOUT.
    /// `is_retry` is true only for the retransmit timer; any other reason
    /// starts a fresh round of attempts.
    fn send_handshake(&self, state: &mut State, is_retry: bool) {
        if !is_retry {
            state.timers.handshake_attempts = 0;
        }
        let now = Instant::now();
        if state.last_handshake_sent.is_some_and(|t| now.duration_since(t) < REKEY_TIMEOUT) {
            return;
        }

        let cookie = state
            .cookie
            .as_ref()
            .filter(|(_, received)| now.duration_since(*received) < COOKIE_LIFETIME)
            .map(|(cookie, _)| cookie);
        let local_index = u32::from_le_bytes(noise::random_bytes()[..4].try_into().unwrap());
        let (msg, handshake) = noise::build_initiation(
            self.private_key,
            self.peer_public_key,
            self.preshared_key,
            local_index,
            cookie,
        );

        state.pending = Some(handshake);
        state.last_mac1 = Some(noise::initiation_mac1(&msg));
        state.last_handshake_sent = Some(now);
        state.timers.any_packet_traversal(now);
        state.timers.any_packet_sent();
        state.timers.handshake_initiated(now);

        println!("sending handshake initiation to {}", self.endpoint);
        if let Err(e) = self.socket.send(&msg) {
            eprintln!("error: cannot send handshake: {e}");
        }
    }

    fn handle_response(&self, msg: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let Some(handshake) = &state.pending else {
            return; // Not expecting a response; ignore.
        };
        // A bad response leaves the pending handshake in place, so a
        // stale or forged packet cannot cancel it.
        let session = match noise::consume_response(handshake, msg) {
            Ok(session) => session,
            Err(e) => {
                eprintln!("error: handshake response rejected: {e}");
                return;
            }
        };
        println!("handshake complete, session index {}", session.local_index);
        let now = Instant::now();
        state.pending = None;
        state.previous_session = state.session.replace(session);
        state.last_handshake = Some(now);
        state.timers.any_packet_received();
        state.timers.any_packet_traversal(now);
        state.timers.session_derived(now);
        state.timers.handshake_complete();

        // The peer may use the new session only after it hears from us on
        // it (key confirmation): send what was waiting, or a keepalive.
        self.send_keepalive(&mut state);
    }

    /// A busy peer answered our initiation with a cookie instead of a
    /// response. Keep it; the next retransmission will carry mac2.
    fn handle_cookie_reply(&self, msg: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let (Some(pending), Some(last_mac1)) = (&state.pending, state.last_mac1) else {
            return; // Not expecting one.
        };
        if msg.get(4..8) != Some(&pending.local_index.to_le_bytes()[..]) {
            return; // Not for our current handshake.
        }
        match noise::consume_cookie_reply(&self.peer_public_key, &last_mac1, msg) {
            Ok(cookie) => {
                println!("peer is under load; got a cookie for the next attempt");
                state.cookie = Some((cookie, Instant::now()));
                state.last_mac1 = None;
            }
            Err(e) => eprintln!("error: cookie reply rejected: {e}"),
        }
    }

    // -- sending -----------------------------------------------------------

    /// Queues an outgoing IP packet and sends everything queued.
    fn send_data(&self, state: &mut State, packet: Vec<u8>) {
        if state.staged.len() == MAX_STAGED_PACKETS {
            state.staged.pop_front();
        }
        state.staged.push_back(packet);
        self.send_staged(state);
    }

    /// Sends a keepalive. Waiting packets prove we are alive just as well,
    /// so the empty packet is only added when nothing else is queued.
    fn send_keepalive(&self, state: &mut State) {
        if state.staged.is_empty() {
            state.staged.push_back(Vec::new());
        }
        self.send_staged(state);
    }

    /// Encrypts and sends the queued packets. Without a usable session
    /// they stay queued and a handshake is started.
    fn send_staged(&self, state: &mut State) {
        let now = Instant::now();
        let mut sent_any = false;
        let mut sent_data = false;

        while let Some(packet) = state.staged.pop_front() {
            let Some(session) = state.session.as_mut().filter(|s| s.can_send()) else {
                state.staged.push_front(packet);
                break;
            };
            let msg = session.encrypt(&packet);
            match self.socket.send(&msg) {
                Ok(_) => {
                    self.counters.tx_bytes.fetch_add(msg.len() as u64, Ordering::Relaxed);
                    self.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                    sent_any = true;
                    sent_data |= !packet.is_empty();
                }
                Err(e) => eprintln!("error: cannot send packet: {e}"),
            }
        }

        if sent_any {
            state.timers.any_packet_traversal(now);
            state.timers.any_packet_sent();
        }
        if sent_data {
            state.timers.data_sent(now);
        }

        // Handshake if packets are stuck, or if the keys are getting old.
        let stuck = !state.staged.is_empty();
        let wants_rekey = state.session.as_ref().is_some_and(|s| s.wants_rekey_after_send());
        if stuck || wants_rekey {
            self.send_handshake(state, false);
        }
    }

    // -- receiving ---------------------------------------------------------

    fn handle_transport(&self, msg: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let Some(index) = receiver_index(msg) else {
            return;
        };
        let Some(session) = state.session_for(index) else {
            return; // Unknown or erased session.
        };
        let packet = match session.decrypt(msg) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("error: dropping packet: {e}");
                return;
            }
        };
        self.counters.rx_bytes.fetch_add(msg.len() as u64, Ordering::Relaxed);
        self.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();

        // The peer never rekeys for us (it is the responder), so renew a
        // session that is about to expire, once.
        if let Some(current) = state.session.as_mut()
            && current.wants_rekey_after_receive()
            && !current.sent_lastminute_handshake
        {
            current.sent_lastminute_handshake = true;
            self.send_handshake(&mut state, false);
        }

        state.timers.any_packet_received();
        state.timers.any_packet_traversal(now);
        if packet.is_empty() {
            return; // Keepalive.
        }
        state.timers.data_received(now);
        drop(state);

        let Some((packet, source)) = ip::parse(&packet) else {
            eprintln!("error: dropping packet that is not valid IPv4/IPv6");
            return;
        };
        // Cryptokey routing: the peer may only send from its AllowedIPs.
        if !self.allowed_ips.iter().any(|net| net.contains(source)) {
            eprintln!("error: dropping packet from {source}, which is outside AllowedIPs");
            return;
        }
        if let Err(e) = self.tun.write_packet(packet) {
            eprintln!("error: cannot write to {}: {e}", self.tun.name);
        }
    }

    // -- threads -----------------------------------------------------------

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn tun_to_udp_loop(&self) {
        while !self.stopping() {
            let packet = match self.tun.read_packet() {
                Ok(packet) => packet,
                Err(e) if is_timeout(&e) => continue,
                Err(e) => {
                    eprintln!("error: cannot read from {}: {e}", self.tun.name);
                    thread::sleep(ERROR_BACKOFF);
                    continue;
                }
            };
            let mut state = self.state.lock().unwrap();
            self.send_data(&mut state, packet);
        }
    }

    fn udp_to_tun_loop(&self) {
        let mut buf = vec![0u8; 65536];
        while !self.stopping() {
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if is_timeout(&e) => continue,
                Err(e) => {
                    eprintln!("error: cannot receive: {e}");
                    thread::sleep(ERROR_BACKOFF);
                    continue;
                }
            };
            let msg = &buf[..n];
            match msg.first() {
                Some(&MESSAGE_RESPONSE) => self.handle_response(msg),
                Some(&MESSAGE_COOKIE_REPLY) => self.handle_cookie_reply(msg),
                Some(&MESSAGE_TRANSPORT) => self.handle_transport(msg),
                _ => {} // A client never answers initiations.
            }
        }
    }

    fn timer_loop(&self) {
        while !self.stopping() {
            thread::sleep(TICK);
            self.tick();
        }
    }

    /// Carries out whatever the expired timers ask for (PROTOCOL.md §6).
    fn tick(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();

        for expired in state.timers.expired(now) {
            match expired {
                Expired::RetransmitHandshake => {
                    if state.timers.handshake_attempts > MAX_TIMER_HANDSHAKES {
                        println!(
                            "handshake did not complete after {} attempts, giving up until there is traffic",
                            MAX_TIMER_HANDSHAKES + 2
                        );
                        state.staged.clear();
                        state.timers.gave_up(now);
                    } else {
                        state.timers.handshake_attempts += 1;
                        println!(
                            "no handshake response after {} s, retrying (try {})",
                            REKEY_TIMEOUT.as_secs(),
                            state.timers.handshake_attempts + 1
                        );
                        self.send_handshake(&mut state, true);
                    }
                }
                Expired::SendKeepalive => {
                    self.send_keepalive(&mut state);
                    state.timers.keepalive_timer_handled(now);
                }
                Expired::PersistentKeepalive => self.send_keepalive(&mut state),
                Expired::NewHandshake => {
                    println!("sent data but heard nothing back, starting a new handshake");
                    self.send_handshake(&mut state, false);
                }
                Expired::ZeroKeyMaterial => {
                    println!("no new keys for {} s, erasing all keys", (REJECT_AFTER_TIME * 3).as_secs());
                    state.session = None;
                    state.previous_session = None;
                    state.pending = None;
                    state.last_mac1 = None;
                }
            }
        }

        // The old session only serves late packets; drop it once expired.
        if state.previous_session.as_ref().is_some_and(|s| s.created.elapsed() >= REJECT_AFTER_TIME) {
            state.previous_session = None;
        }
    }
}

/// A read that gave up after POLL_TIMEOUT; not an error.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}
