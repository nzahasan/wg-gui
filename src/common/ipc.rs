//! The link between the GUI, which runs as the user, and `wg-helper`, the
//! root daemon that owns the tunnel. They talk over a Unix socket in a
//! small line protocol:
//!
//! ```text
//! UP <len>\n<len bytes of config text>   -> STARTED <tun> <mtu> <dns 0|1> <endpoint> <n>\n
//!                                           ROUTE <destination> <gateway> <interface>\n  (n times)
//! STATS\n                                -> STATS <rx> <tx> <rx pkts> <tx pkts> <handshake age ms|-> <up|stale|offline>\n
//! DOWN\n                                 -> OK\n
//! any                                    -> ERR <message>\n
//! ```
//!
//! The GUI sends the config text rather than a path, so root never reads
//! files in the user's home. The tunnel belongs to the connection that
//! started it: when that connection closes, the helper takes it down.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::netconfig::Route;
use crate::tunnel::{LinkState, Stats};

/// Bundle identifier of the app; the helper only serves code signed with it.
pub const APP_ID: &str = "com.nzahasan.wg-gui";
/// launchd label of the helper, and the name of its plist in the bundle.
pub const HELPER_LABEL: &str = "com.nzahasan.wg-gui.helper";
pub const DEFAULT_SOCKET: &str = "/var/run/com.nzahasan.wg-gui.helper.sock";
/// Overrides the socket path, for running the helper by hand.
pub const SOCKET_ENV: &str = "WG_HELPER_SOCKET";

/// WireGuard configs are a few hundred bytes; anything this big is not one.
const MAX_CONFIG_LEN: usize = 64 * 1024;
const MAX_LINE_LEN: u64 = 4096;
const MAX_ROUTES: usize = 4096;

const START_TIMEOUT: Duration = Duration::from_secs(60);
const STATS_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// Bring a tunnel up from this config text.
    Up(String),
    Stats,
    Down,
}

/// What the helper reports once a tunnel is up.
#[derive(Debug, Clone, PartialEq)]
pub struct Started {
    pub tun_name: String,
    pub mtu: u16,
    pub dns_changed: bool,
    /// The endpoint the helper resolved and is sending to.
    pub endpoint: SocketAddr,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone)]
pub enum Response {
    Started(Started),
    Stats(Stats),
    Ok,
    Error(String),
}

pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV).filter(|p| !p.is_empty()).map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

// -- encoding ----------------------------------------------------------------

pub fn write_request(w: &mut impl Write, request: &Request) -> io::Result<()> {
    match request {
        Request::Up(text) => write!(w, "UP {}\n{text}", text.len())?,
        Request::Stats => w.write_all(b"STATS\n")?,
        Request::Down => w.write_all(b"DOWN\n")?,
    }
    w.flush()
}

/// The next request, or None once the other side has closed the socket.
pub fn read_request(r: &mut impl BufRead) -> io::Result<Option<Request>> {
    let Some(line) = read_line(r)? else {
        return Ok(None);
    };
    let request = match line.split_once(' ') {
        Some(("UP", len)) => {
            let len: usize = len.parse().map_err(|_| invalid("bad UP length"))?;
            if len > MAX_CONFIG_LEN {
                return Err(invalid("config too large"));
            }
            let mut text = vec![0; len];
            r.read_exact(&mut text)?;
            Request::Up(String::from_utf8(text).map_err(|_| invalid("config is not UTF-8"))?)
        }
        None if line == "STATS" => Request::Stats,
        None if line == "DOWN" => Request::Down,
        _ => return Err(invalid(&format!("unknown request: {line}"))),
    };
    Ok(Some(request))
}

pub fn write_response(w: &mut impl Write, response: &Response) -> io::Result<()> {
    match response {
        Response::Started(s) => {
            writeln!(
                w,
                "STARTED {} {} {} {} {}",
                s.tun_name,
                s.mtu,
                u8::from(s.dns_changed),
                s.endpoint,
                s.routes.len()
            )?;
            for route in &s.routes {
                writeln!(w, "ROUTE {} {} {}", route.destination, route.gateway, route.interface)?;
            }
        }
        Response::Stats(s) => {
            let age = s.last_handshake.map_or("-".to_string(), |t| t.elapsed().as_millis().to_string());
            writeln!(
                w,
                "STATS {} {} {} {} {age} {}",
                s.rx_bytes,
                s.tx_bytes,
                s.rx_packets,
                s.tx_packets,
                match s.link {
                    LinkState::Up => "up",
                    LinkState::Stale => "stale",
                    LinkState::Offline => "offline",
                }
            )?;
        }
        Response::Ok => w.write_all(b"OK\n")?,
        Response::Error(message) => writeln!(w, "ERR {}", message.replace(['\r', '\n'], " "))?,
    }
    w.flush()
}

pub fn read_response(r: &mut impl BufRead) -> io::Result<Response> {
    let line = read_line(r)?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the helper closed the connection"))?;
    let (kind, rest) = line.split_once(' ').unwrap_or((&line, ""));
    let fields: Vec<&str> = rest.split(' ').collect();
    let response = match (kind, fields.as_slice()) {
        ("OK", _) => Response::Ok,
        ("ERR", _) => Response::Error(rest.to_string()),
        ("STARTED", [tun, mtu, dns, endpoint, count]) => {
            let count: usize = number(count)?;
            if count > MAX_ROUTES {
                return Err(invalid("too many routes"));
            }
            let mut routes = Vec::with_capacity(count);
            for _ in 0..count {
                let line = read_line(r)?.ok_or_else(|| invalid("missing ROUTE line"))?;
                let mut parts = line.splitn(4, ' ');
                let (Some("ROUTE"), Some(destination), Some(gateway), Some(interface)) =
                    (parts.next(), parts.next(), parts.next(), parts.next())
                else {
                    return Err(invalid(&format!("bad ROUTE line: {line}")));
                };
                routes.push(Route {
                    destination: destination.to_string(),
                    gateway: gateway.to_string(),
                    interface: interface.to_string(),
                });
            }
            Response::Started(Started {
                tun_name: tun.to_string(),
                mtu: number(mtu)?,
                dns_changed: *dns == "1",
                endpoint: endpoint.parse().map_err(|_| invalid("bad endpoint"))?,
                routes,
            })
        }
        ("STATS", [rx, tx, rx_packets, tx_packets, age, link]) => Response::Stats(Stats {
            rx_bytes: number(rx)?,
            tx_bytes: number(tx)?,
            rx_packets: number(rx_packets)?,
            tx_packets: number(tx_packets)?,
            last_handshake: match *age {
                "-" => None,
                ms => Instant::now().checked_sub(Duration::from_millis(number(ms)?)),
            },
            link: match *link {
                "up" => LinkState::Up,
                "stale" => LinkState::Stale,
                "offline" => LinkState::Offline,
                other => return Err(invalid(&format!("bad link state: {other}"))),
            },
        }),
        _ => return Err(invalid(&format!("unexpected reply: {line}"))),
    };
    Ok(response)
}

/// One line without its newline; None at end of stream.
fn read_line(r: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut line = String::new();
    if r.take(MAX_LINE_LEN).read_line(&mut line)? == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        return Err(invalid("line too long or cut short"));
    }
    line.pop();
    Ok(Some(line))
}

fn number<T: std::str::FromStr>(text: &str) -> io::Result<T> {
    text.parse().map_err(|_| invalid(&format!("bad number: {text}")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

// -- client --------------------------------------------------------------------

/// The GUI's end of the socket. Keep it for as long as the tunnel should
/// stay up: dropping it closes the socket and the helper stops the tunnel.
pub struct HelperClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl HelperClient {
    pub fn connect() -> Result<HelperClient, String> {
        let path = socket_path();
        let stream = UnixStream::connect(&path)
            .map_err(|e| format!("cannot reach the wg-gui helper at {}: {e}", path.display()))?;
        let writer = stream.try_clone().map_err(|e| e.to_string())?;
        Ok(HelperClient { reader: BufReader::new(stream), writer })
    }

    pub fn start(&mut self, config_text: &str) -> Result<Started, String> {
        match self.call(&Request::Up(config_text.to_string()), START_TIMEOUT)? {
            Response::Started(started) => Ok(started),
            other => Err(unexpected(other)),
        }
    }

    pub fn stats(&mut self) -> Result<Stats, String> {
        match self.call(&Request::Stats, STATS_TIMEOUT)? {
            Response::Stats(stats) => Ok(stats),
            other => Err(unexpected(other)),
        }
    }

    pub fn stop(&mut self) -> Result<(), String> {
        match self.call(&Request::Down, STOP_TIMEOUT)? {
            Response::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn call(&mut self, request: &Request, timeout: Duration) -> Result<Response, String> {
        let helper_error = |e: io::Error| format!("helper: {e}");
        self.writer.set_read_timeout(Some(timeout)).map_err(helper_error)?;
        write_request(&mut self.writer, request).map_err(helper_error)?;
        read_response(&mut self.reader).map_err(helper_error)
    }
}

fn unexpected(response: Response) -> String {
    match response {
        Response::Error(message) => message,
        other => format!("unexpected reply from the helper: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(response: &Response) -> Response {
        let mut bytes = Vec::new();
        write_response(&mut bytes, response).unwrap();
        let mut reader = &bytes[..];
        let decoded = read_response(&mut reader).unwrap();
        assert!(reader.is_empty(), "left over: {:?}", String::from_utf8_lossy(reader));
        decoded
    }

    #[test]
    fn requests_round_trip() {
        let text = "[Interface]\nPrivateKey = abc=\n\n[Peer]\nEndpoint = vpn.example.org:51820\n";
        let mut bytes = Vec::new();
        for request in [Request::Up(text.to_string()), Request::Stats, Request::Down] {
            write_request(&mut bytes, &request).unwrap();
        }
        let mut reader = &bytes[..];
        assert_eq!(read_request(&mut reader).unwrap(), Some(Request::Up(text.to_string())));
        assert_eq!(read_request(&mut reader).unwrap(), Some(Request::Stats));
        assert_eq!(read_request(&mut reader).unwrap(), Some(Request::Down));
        assert_eq!(read_request(&mut reader).unwrap(), None);
    }

    #[test]
    fn bad_requests_are_refused() {
        assert!(read_request(&mut &b"UP 99999999\n"[..]).is_err());
        assert!(read_request(&mut &b"REBOOT\n"[..]).is_err());
        assert!(read_request(&mut &b"UP 10\nshort"[..]).is_err());
        assert!(read_request(&mut &[b'x'; 5000][..]).is_err());
    }

    #[test]
    fn started_round_trips() {
        let started = Started {
            tun_name: "utun7".to_string(),
            mtu: 1420,
            dns_changed: true,
            endpoint: "[2001:db8::1]:51820".parse().unwrap(),
            routes: vec![
                Route { destination: "0.0.0.0/1".to_string(), gateway: "on-link".to_string(), interface: "utun7".to_string() },
                Route { destination: "203.0.113.10".to_string(), gateway: "192.168.1.1".to_string(), interface: "en0".to_string() },
            ],
        };
        match round_trip(&Response::Started(started.clone())) {
            Response::Started(decoded) => assert_eq!(decoded, started),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stats_and_errors_round_trip() {
        let stats = Stats {
            rx_bytes: 1 << 40,
            tx_bytes: 7,
            rx_packets: 3,
            tx_packets: 4,
            last_handshake: Some(Instant::now() - Duration::from_secs(5)),
            link: LinkState::Stale,
        };
        match round_trip(&Response::Stats(stats)) {
            Response::Stats(s) => {
                assert_eq!((s.rx_bytes, s.tx_bytes, s.rx_packets, s.tx_packets), (1 << 40, 7, 3, 4));
                assert_eq!(s.link, LinkState::Stale);
                let age = s.last_handshake.unwrap().elapsed().as_secs();
                assert!((4..=6).contains(&age), "age {age}");
            }
            other => panic!("{other:?}"),
        }
        match round_trip(&Response::Stats(Stats::default())) {
            Response::Stats(s) => assert!(s.last_handshake.is_none() && s.link == LinkState::Up),
            other => panic!("{other:?}"),
        }
        match round_trip(&Response::Error("no\nluck".to_string())) {
            Response::Error(message) => assert_eq!(message, "no luck"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(round_trip(&Response::Ok), Response::Ok));
    }
}
