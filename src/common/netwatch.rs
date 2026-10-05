//! Notices network changes that can break the path to the endpoint:
//! moving from Wi-Fi to Ethernet, joining another network, a new DHCP
//! address, waking from sleep.
//!
//! macOS reports every routing-table and interface-address change on a
//! PF_ROUTE socket (what `route monitor` prints; wireguard-go and
//! Tailscale watch the same socket). Changes come in bursts, so the
//! callback runs once things have been quiet for `SETTLE`; it decides
//! for itself whether anything that matters changed.

use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long the routing table must stay quiet before the callback runs.
const SETTLE: Duration = Duration::from_secs(1);
/// Longest a read waits before the thread re-checks the stop flag.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

const PF_ROUTE: i32 = 17;
const SOCK_RAW: i32 = 3;
const SOL_SOCKET: i32 = 0xffff;
const SO_RCVTIMEO: i32 = 0x1006;

// <net/route.h> message types and flags.
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_CHANGE: u8 = 0x3;
const RTM_NEWADDR: u8 = 0xc;
const RTM_DELADDR: u8 = 0xd;
const RTM_IFINFO: u8 = 0xe;
/// Link-layer (ARP/NDP) entries and routes cloned from them come and go
/// all the time as hosts are contacted; they say nothing about the path.
const RTF_LLINFO: i32 = 0x400;
const RTF_WASCLONED: i32 = 0x20000;

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i32,
}

unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn setsockopt(socket: i32, level: i32, name: i32, value: *const std::ffi::c_void, len: u32) -> i32;
}

/// The watching thread; stop it with `stop`.
pub struct Watcher {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl Watcher {
    /// Starts watching; `on_change` runs on the watcher's thread after
    /// each settled burst of changes.
    pub fn start(mut on_change: impl FnMut() + Send + 'static) -> io::Result<Watcher> {
        let mut routes = open_route_socket()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut last_change: Option<Instant> = None;
            while !stopping.load(Ordering::SeqCst) {
                match routes.read(&mut buf) {
                    Ok(n) if is_relevant(&buf[..n]) => last_change = Some(Instant::now()),
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                    Err(e) => {
                        eprintln!("warning: network watcher stopped: {e}");
                        return;
                    }
                }
                if last_change.is_some_and(|t| t.elapsed() >= SETTLE) {
                    last_change = None;
                    on_change();
                }
            }
        });
        Ok(Watcher { stop, thread })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.thread.join();
    }
}

fn open_route_socket() -> io::Result<File> {
    let fd = unsafe { socket(PF_ROUTE, SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a new socket that nothing else owns.
    let file = unsafe { File::from_raw_fd(fd) };
    let timeout = Timeval { tv_sec: 0, tv_usec: POLL_TIMEOUT.as_micros() as i32 };
    let rc = unsafe {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (&raw const timeout).cast(), size_of::<Timeval>() as u32)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

/// Whether a routing message is about routes, addresses or interfaces.
/// The header starts with u16 length, u8 version, u8 type; route
/// messages have their i32 flags at offset 8.
fn is_relevant(msg: &[u8]) -> bool {
    let Some(&kind) = msg.get(3) else {
        return false;
    };
    match kind {
        RTM_ADD | RTM_DELETE | RTM_CHANGE => {
            let Some(flags) = msg.get(8..12) else {
                return false;
            };
            let flags = i32::from_ne_bytes(flags.try_into().unwrap());
            flags & (RTF_LLINFO | RTF_WASCLONED) == 0
        }
        RTM_NEWADDR | RTM_DELADDR | RTM_IFINFO => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u8, flags: i32) -> Vec<u8> {
        let mut msg = vec![0u8; 92];
        msg[0..2].copy_from_slice(&92u16.to_ne_bytes());
        msg[2] = 5;
        msg[3] = kind;
        msg[8..12].copy_from_slice(&flags.to_ne_bytes());
        msg
    }

    #[test]
    fn only_path_changes_count() {
        const RTF_UP: i32 = 0x1;
        const RTF_GATEWAY: i32 = 0x2;
        assert!(is_relevant(&message(RTM_ADD, RTF_UP | RTF_GATEWAY)));
        assert!(is_relevant(&message(RTM_DELETE, RTF_UP)));
        assert!(is_relevant(&message(RTM_NEWADDR, 0)));
        assert!(is_relevant(&message(RTM_IFINFO, 0)));
        // ARP entries and clones of them do not.
        assert!(!is_relevant(&message(RTM_ADD, RTF_UP | RTF_LLINFO)));
        assert!(!is_relevant(&message(RTM_DELETE, RTF_UP | RTF_WASCLONED)));
        // Nor do lookups and misses (RTM_GET, RTM_MISS) or short reads.
        assert!(!is_relevant(&message(0x4, 0)));
        assert!(!is_relevant(&message(0x7, 0)));
        assert!(!is_relevant(&[0, 0]));
    }

    #[test]
    fn route_socket_opens_without_root() {
        // Reading routing messages needs no privileges; a timeout is
        // the normal result on a quiet machine.
        let mut routes = open_route_socket().unwrap();
        let mut buf = [0u8; 2048];
        let started = Instant::now();
        match routes.read(&mut buf) {
            Ok(_) => {}
            Err(e) => assert!(matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut), "{e}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
