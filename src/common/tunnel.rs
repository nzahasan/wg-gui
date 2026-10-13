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
//! Its `TunnelControl` replaces the UDP socket when the network changes.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::{Cidr, Config};
use crate::ip;
use crate::noise::{self, Cookie, HandshakeState, MESSAGE_COOKIE_REPLY, MESSAGE_RESPONSE};
use crate::session::{receiver_index, Session, KEEPALIVE_TIMEOUT, MESSAGE_TRANSPORT, REJECT_AFTER_TIME, REKEY_TIMEOUT};
use crate::timers::{Expired, Timers, MAX_TIMER_HANDSHAKES};
use crate::tun::{Tun, MAX_PACKET};

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
/// Sends must keep failing this long before the link counts as offline,
/// so one stray error does not flip the status.
const SEND_FAILURE_GRACE: Duration = Duration::from_secs(1);
/// Data sent with nothing back for this long means the peer is not
/// hearing us (the kernel's new-handshake timeout: it would have sent a
/// keepalive within KEEPALIVE_TIMEOUT).
const STALE_AFTER: Duration = Duration::from_secs(KEEPALIVE_TIMEOUT.as_secs() + REKEY_TIMEOUT.as_secs());
/// The machine slept at least this long between two timer ticks.
const WAKE_THRESHOLD: Duration = Duration::from_secs(2);
/// UDP socket buffer size, as wireguard-go uses; absorbs bursts.
const SOCKET_BUFFER: i32 = 7 << 20;

const ENOBUFS: i32 = 55;
const SOL_SOCKET: i32 = 0xffff;
const SO_SNDBUF: i32 = 0x1001;
const SO_RCVBUF: i32 = 0x1002;
/// Counts time asleep; CLOCK_UPTIME_RAW (what Instant uses) does not.
const CLOCK_MONOTONIC: u32 = 6;
const CLOCK_UPTIME_RAW: u32 = 8;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn clock_gettime(clock: u32, ts: *mut Timespec) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const std::ffi::c_void, len: u32) -> i32;
}

/// Total time the machine has spent asleep since boot.
fn time_asleep() -> Duration {
    let read = |clock| {
        let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { clock_gettime(clock, &mut ts) };
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    };
    read(CLOCK_MONOTONIC).saturating_sub(read(CLOCK_UPTIME_RAW))
}

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
    /// When the first initiation that is still unanswered went out.
    unanswered_since: Option<Instant>,
    /// When the first data packet that got nothing back went out.
    unreplied_since: Option<Instant>,
    /// When an authenticated packet last arrived.
    heard_at: Option<Instant>,
    /// When sends started failing (no route, no address).
    send_failing_since: Option<Instant>,
    /// The network watcher found no network.
    offline: bool,
    timers: Timers,
}

impl State {
    /// Records a send's outcome. Returns true if the error is worth
    /// logging: only the first of a run of failures is.
    fn sent(&mut self, result: &std::io::Result<usize>, now: Instant) -> bool {
        match result {
            Ok(_) => self.send_failing_since = None,
            // The interface queue is full: a dropped packet, not a dead link.
            Err(e) if e.raw_os_error() == Some(ENOBUFS) => {}
            Err(_) => return self.send_failing_since.replace(self.send_failing_since.unwrap_or(now)).is_none(),
        }
        false
    }

    /// An authenticated packet arrived: the peer hears us and we hear it.
    fn heard_from_peer(&mut self) {
        self.heard_at = Some(Instant::now());
        self.unreplied_since = None;
        self.offline = false;
    }

    fn link_state(&self) -> LinkState {
        let now = Instant::now();
        let over = |since: Option<Instant>, limit: Duration| since.is_some_and(|t| now.duration_since(t) >= limit);
        if self.offline || over(self.send_failing_since, SEND_FAILURE_GRACE) {
            LinkState::Offline
        } else if over(self.unanswered_since, REKEY_TIMEOUT) || over(self.unreplied_since, STALE_AFTER) {
            LinkState::Stale
        } else {
            LinkState::Up
        }
    }
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
    pub link: LinkState,
}

/// Whether the peer can be reached right now. A quiet tunnel is `Up`:
/// WireGuard sends nothing when there is nothing to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkState {
    #[default]
    Up,
    /// The peer stopped answering: a handshake unanswered for 5 s, or
    /// data with no reply for 15 s. Handshakes keep being retried.
    Stale,
    /// No network: sends fail, or the network watcher found no route.
    Offline,
}

/// The UDP socket and the endpoint it is connected to; replaced together
/// when the network changes (`TunnelControl::rebind`).
struct Link {
    socket: UdpSocket,
    endpoint: SocketAddr,
}

impl Link {
    fn open(endpoint: SocketAddr) -> Result<Link, String> {
        let bind_addr = if endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind_addr).map_err(|e| format!("cannot bind UDP socket: {e}"))?;
        socket.connect(endpoint).map_err(|e| format!("cannot connect UDP socket: {e}"))?;
        socket
            .set_read_timeout(Some(POLL_TIMEOUT))
            .map_err(|e| format!("cannot set UDP read timeout: {e}"))?;
        // Best effort: the system may cap it lower.
        for option in [SO_SNDBUF, SO_RCVBUF] {
            let size: *const i32 = &SOCKET_BUFFER;
            unsafe { setsockopt(socket.as_raw_fd(), SOL_SOCKET, option, size.cast(), 4) };
        }
        Ok(Link { socket, endpoint })
    }
}

struct Tunnel {
    tun: Tun,
    /// Swapped whole, so a thread that took the current one keeps a
    /// working socket while it is replaced.
    link: Mutex<Arc<Link>>,
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
        let state = self.tunnel.state.lock().unwrap();
        Stats {
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            rx_packets: c.rx_packets.load(Ordering::Relaxed),
            tx_packets: c.tx_packets.load(Ordering::Relaxed),
            last_handshake: state.last_handshake,
            link: state.link_state(),
        }
    }

    pub fn control(&self) -> TunnelControl {
        TunnelControl(Arc::clone(&self.tunnel))
    }
}

/// Adjusts a running tunnel from another thread (the network watcher).
/// Holding one keeps the utun open, so drop it before `TunnelHandle::stop`
/// returns, or the device closes only when this does.
#[derive(Clone)]
pub struct TunnelControl(Arc<Tunnel>);

impl TunnelControl {
    /// The endpoint the tunnel is sending to.
    pub fn endpoint(&self) -> SocketAddr {
        self.0.link().endpoint
    }

    /// The network watcher found the network gone; `rebind` or any packet
    /// from the peer clears it.
    pub fn set_offline(&self) {
        self.0.state.lock().unwrap().offline = true;
    }

    /// Replaces the UDP socket with a new one connected to `endpoint`, so
    /// it picks up the current interface and source address, then tells
    /// the peer where we are now, like wireguard-go after a network
    /// change: a keepalive on the current session (the peer roams to the
    /// address it comes from) and a fresh handshake in case that session
    /// is no longer valid, e.g. after sleep.
    pub fn rebind(&self, endpoint: SocketAddr) -> Result<(), String> {
        self.0.rebind(endpoint)
    }
}

/// Starts the tunnel threads and returns a handle to stop them.
pub fn run(tun: Tun, config: &Config) -> Result<TunnelHandle, String> {
    let link = Link::open(config.peer.endpoint)?;
    tun.set_read_timeout(POLL_TIMEOUT)
        .map_err(|e| format!("cannot set {} read timeout: {e}", tun.name))?;

    let keepalive_interval = config.peer.keepalive_seconds.map(|s| Duration::from_secs(s.into()));
    let tunnel = Arc::new(Tunnel {
        tun,
        link: Mutex::new(Arc::new(link)),
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
            unanswered_since: None,
            unreplied_since: None,
            heard_at: None,
            send_failing_since: None,
            offline: false,
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
    fn link(&self) -> Arc<Link> {
        Arc::clone(&self.link.lock().unwrap())
    }

    /// See `TunnelControl::rebind`.
    fn rebind(&self, endpoint: SocketAddr) -> Result<(), String> {
        let link = Link::open(endpoint)?;
        *self.link.lock().unwrap() = Arc::new(link);
        let mut state = self.state.lock().unwrap();
        state.offline = false;
        state.send_failing_since = None;
        if state.session.as_ref().is_some_and(|s| s.can_send()) {
            self.send_keepalive(&mut state);
        }
        state.last_handshake_sent = None; // skip the rate limit this once
        self.send_handshake(&mut state, false);
        Ok(())
    }

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
        state.unanswered_since.get_or_insert(now);
        state.timers.any_packet_traversal(now);
        state.timers.any_packet_sent();
        state.timers.handshake_initiated(now);

        let link = self.link();
        println!("sending handshake initiation to {}", link.endpoint);
        let result = link.socket.send(&msg);
        if state.sent(&result, now)
            && let Err(e) = result
        {
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
        state.unanswered_since = None;
        state.heard_from_peer();
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
        let messages = self.encrypt_staged(state);
        let sent_at = Instant::now();
        let results = self.transmit(&messages);
        self.record_sent(state, &messages, results, sent_at);
    }

    /// Encrypts what is queued and can be sent now. Each message comes
    /// with whether it carries data (not a keepalive).
    fn encrypt_staged(&self, state: &mut State) -> Vec<(Vec<u8>, bool)> {
        let mut messages = Vec::new();
        while let Some(packet) = state.staged.pop_front() {
            let Some(session) = state.session.as_mut().filter(|s| s.can_send()) else {
                state.staged.push_front(packet);
                break;
            };
            messages.push((session.encrypt(&packet), !packet.is_empty()));
        }
        messages
    }

    /// Sends encrypted messages; needs no lock.
    fn transmit(&self, messages: &[(Vec<u8>, bool)]) -> Vec<std::io::Result<usize>> {
        let link = self.link();
        messages.iter().map(|(msg, _)| link.socket.send(msg)).collect()
    }

    /// Accounts for what `transmit` did, starting at `now`, and handshakes
    /// if packets are stuck or the keys are getting old.
    fn record_sent(&self, state: &mut State, messages: &[(Vec<u8>, bool)], results: Vec<std::io::Result<usize>>, now: Instant) {
        let mut sent_any = false;
        let mut sent_data = false;
        for ((msg, is_data), result) in messages.iter().zip(results) {
            let log = state.sent(&result, now);
            match result {
                Ok(_) => {
                    self.counters.tx_bytes.fetch_add(msg.len() as u64, Ordering::Relaxed);
                    self.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                    sent_any = true;
                    sent_data |= is_data;
                }
                Err(e) if log => eprintln!("error: cannot send packet: {e}"),
                Err(_) => {}
            }
        }

        if sent_any {
            state.timers.any_packet_traversal(now);
            state.timers.any_packet_sent();
        }
        // Unless the peer already answered while the lock was free (the
        // upload path records late): then nothing is unanswered.
        if sent_data && !state.heard_at.is_some_and(|t| t >= now) {
            state.timers.data_sent(now);
            state.unreplied_since.get_or_insert(now);
        }

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

        state.heard_from_peer();
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
        let mut buf = vec![0u8; MAX_PACKET];
        while !self.stopping() {
            let packet = match self.tun.read_packet(&mut buf) {
                Ok(packet) => packet,
                Err(e) if is_timeout(&e) => continue,
                Err(e) => {
                    eprintln!("error: cannot read from {}: {e}", self.tun.name);
                    thread::sleep(ERROR_BACKOFF);
                    continue;
                }
            };
            // The bulk upload path: the send syscalls happen outside the
            // lock, so receiving and timers are not held up by them.
            let mut state = self.state.lock().unwrap();
            if state.staged.len() == MAX_STAGED_PACKETS {
                state.staged.pop_front();
            }
            state.staged.push_back(packet.to_vec());
            let messages = self.encrypt_staged(&mut state);
            drop(state);
            let sent_at = Instant::now();
            let results = self.transmit(&messages);
            self.record_sent(&mut self.state.lock().unwrap(), &messages, results, sent_at);
        }
    }

    fn udp_to_tun_loop(&self) {
        let mut buf = vec![0u8; 65536];
        while !self.stopping() {
            let n = match self.link().socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if is_timeout(&e) => continue,
                // A stale ICMP port-unreachable reported on the connected
                // socket; the next packet may well get through.
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => continue,
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
        let mut asleep = time_asleep();
        while !self.stopping() {
            thread::sleep(TICK);
            // After sleep the peer has likely dropped our session, and
            // our timers (on Instant) did not see the time pass: get a
            // fresh socket and handshake now rather than ~15 s later.
            let now_asleep = time_asleep();
            if now_asleep.saturating_sub(asleep) >= WAKE_THRESHOLD {
                println!("woke from sleep, reconnecting");
                if let Err(e) = self.rebind(self.link().endpoint) {
                    eprintln!("warning: {e}");
                }
            }
            asleep = now_asleep;
            self.tick();
        }
    }

    /// Carries out whatever the expired timers ask for (PROTOCOL.md §6).
    fn tick(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let mut gave_up = false;

        for expired in state.timers.expired(now) {
            match expired {
                Expired::RetransmitHandshake => {
                    if state.timers.handshake_attempts > MAX_TIMER_HANDSHAKES {
                        gave_up = true;
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
                // A keepalive due in the same tick as a give-up would
                // restage a packet and restart the handshakes. (Persistent
                // keepalive is meant to keep retrying, so it still runs.)
                Expired::SendKeepalive if gave_up => {}
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

#[cfg(test)]
mod link_state_tests {
    use super::*;

    fn quiet() -> State {
        State {
            session: None,
            previous_session: None,
            pending: None,
            last_handshake_sent: None,
            staged: VecDeque::new(),
            last_mac1: None,
            cookie: None,
            last_handshake: None,
            unanswered_since: None,
            unreplied_since: None,
            heard_at: None,
            send_failing_since: None,
            offline: false,
            timers: Timers::new(None),
        }
    }

    fn ago(seconds: u64) -> Instant {
        Instant::now() - Duration::from_secs(seconds)
    }

    #[test]
    fn a_quiet_tunnel_is_up() {
        assert_eq!(quiet().link_state(), LinkState::Up);
    }

    #[test]
    fn wifi_off_is_offline() {
        // Sends fail at once with no route; a single error is tolerated.
        let mut state = quiet();
        let failed: std::io::Result<usize> = Err(std::io::Error::from(ErrorKind::NetworkUnreachable));
        state.sent(&failed, Instant::now());
        assert_eq!(state.link_state(), LinkState::Up);
        state.send_failing_since = Some(ago(2));
        assert_eq!(state.link_state(), LinkState::Offline);
        state.sent(&Ok(32), Instant::now());
        assert_eq!(state.link_state(), LinkState::Up);

        // The watcher's verdict holds until the peer is heard again.
        state.offline = true;
        assert_eq!(state.link_state(), LinkState::Offline);
        state.heard_from_peer();
        assert_eq!(state.link_state(), LinkState::Up);
    }

    #[test]
    fn silence_after_sending_is_stale() {
        let mut state = quiet();
        state.unreplied_since = Some(ago(5));
        assert_eq!(state.link_state(), LinkState::Up, "the peer has 15 s to answer");
        state.unreplied_since = Some(ago(16));
        assert_eq!(state.link_state(), LinkState::Stale);
        state.heard_from_peer();
        assert_eq!(state.link_state(), LinkState::Up);

        state.unanswered_since = Some(ago(6));
        assert_eq!(state.link_state(), LinkState::Stale);
        // No network outranks an unanswered peer.
        state.offline = true;
        assert_eq!(state.link_state(), LinkState::Offline);
    }

    #[test]
    fn full_send_queue_is_not_a_dead_link() {
        let mut state = quiet();
        let full: std::io::Result<usize> = Err(std::io::Error::from_raw_os_error(ENOBUFS));
        assert!(!state.sent(&full, ago(2)), "not logged");
        assert_eq!(state.send_failing_since, None);
    }

    #[test]
    fn only_the_first_send_failure_is_logged() {
        let mut state = quiet();
        let failed = || -> std::io::Result<usize> { Err(std::io::Error::from(ErrorKind::NetworkUnreachable)) };
        let first = ago(5);
        assert!(state.sent(&failed(), first));
        assert!(!state.sent(&failed(), Instant::now()));
        assert_eq!(state.send_failing_since, Some(first), "the run keeps its start");
        assert!(!state.sent(&Ok(32), Instant::now()));
        assert!(state.sent(&failed(), Instant::now()), "a new run is logged again");
    }

    #[test]
    fn uptime_clock_matches_instant_and_sleep_never_shrinks() {
        // Instant must be CLOCK_UPTIME_RAW, or time_asleep measures the
        // wrong thing.
        let uptime = || {
            let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
            assert_eq!(unsafe { clock_gettime(CLOCK_UPTIME_RAW, &mut ts) }, 0);
            Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
        };
        let (u0, i0, a0) = (uptime(), Instant::now(), time_asleep());
        thread::sleep(Duration::from_millis(200));
        let (u1, i1, a1) = (uptime(), Instant::now(), time_asleep());
        let drift = (u1 - u0).abs_diff(i1 - i0);
        assert!(drift < Duration::from_millis(5), "drift {drift:?}");
        // CLOCK_MONOTONIC has microsecond granularity, so the difference
        // jitters by tens of microseconds either way; far below the
        // threshold.
        assert!(a1 + Duration::from_millis(1) >= a0);
        assert!(a1.saturating_sub(a0) < WAKE_THRESHOLD, "no wake while awake");
    }

    #[test]
    fn link_gets_big_socket_buffers() {
        unsafe extern "C" {
            fn getsockopt(fd: i32, level: i32, name: i32, value: *mut u8, len: *mut u32) -> i32;
        }
        let link = Link::open("127.0.0.1:9".parse().unwrap()).unwrap();
        for option in [SO_SNDBUF, SO_RCVBUF] {
            let (mut size, mut len) = (0i32, 4u32);
            let rc = unsafe { getsockopt(link.socket.as_raw_fd(), SOL_SOCKET, option, (&mut size as *mut i32).cast(), &mut len) };
            assert_eq!(rc, 0);
            assert_eq!(size, SOCKET_BUFFER, "option {option:#x}");
        }
    }
}
