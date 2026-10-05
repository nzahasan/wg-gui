//! The privileged half of wg-gui: a root daemon, started by launchd,
//! that owns the tunnel while the GUI runs as the user. The two talk over
//! a Unix socket (see `wg_common::ipc`).
//!
//! Usage: wg-helper [--socket <path>] [--dev]
//!
//! Inside wg-gui.app, launchd runs it with no arguments. For development,
//! run `sudo wg-helper --dev --socket /tmp/wg.sock` and start the GUI with
//! WG_HELPER_SOCKET=/tmp/wg.sock. `--dev` skips the client signature
//! check, so only use it on your own machine.
//!
//! A tunnel belongs to the connection that started it and goes down when
//! that connection closes, so a crashed GUI cannot leave DNS and routes
//! changed. SIGTERM (launchctl bootout, uninstall) takes it down as well.

mod codesign;

use std::ffi::{CString, c_int};
use std::fs;
use std::io::{BufReader, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use wg_common::config;
use wg_common::connection::Connection;
use wg_common::ipc::{self, Request, Response, Started};

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;
const POLL_INTERVAL: Duration = Duration::from_millis(200);

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);

/// The running tunnel and the client that owns it.
static TUNNEL: Mutex<Option<(u64, Connection)>> = Mutex::new(None);

unsafe extern "C" {
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
    fn geteuid() -> u32;
    fn chmod(path: *const std::ffi::c_char, mode: u16) -> c_int;
}

extern "C" fn on_signal(_signum: c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("wg-helper: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut socket = ipc::socket_path();
    let mut dev = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket = PathBuf::from(args.next().ok_or("--socket needs a path")?),
            "--dev" => dev = true,
            _ => return Err(format!("unknown argument {arg}\nusage: wg-helper [--socket <path>] [--dev]")),
        }
    }
    if unsafe { geteuid() } != 0 {
        return Err("must run as root".to_string());
    }

    let requirement = if dev {
        eprintln!("wg-helper: --dev: accepting any local client");
        None
    } else {
        match codesign::requirement() {
            Some(requirement) => Some(requirement),
            None => return Err("built without WG_TEAM_ID, so clients cannot be verified; use --dev for development".to_string()),
        }
    };

    unsafe {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
    }

    let listener = listen(&socket)?;
    eprintln!("wg-helper: listening on {}", socket.display());

    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let requirement = requirement.clone();
                thread::spawn(move || serve(stream, requirement.as_deref()));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(POLL_INTERVAL),
            Err(e) => eprintln!("wg-helper: accept: {e}"),
        }
    }

    eprintln!("wg-helper: shutting down");
    if let Some((_, connection)) = TUNNEL.lock().unwrap().take() {
        connection.stop();
    }
    let _ = fs::remove_file(&socket);
    Ok(())
}

/// Binds the socket, replacing a stale one, and lets every user connect;
/// access is decided per connection by the signature check.
fn listen(path: &Path) -> Result<UnixListener, String> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot remove old {}: {e}", path.display())),
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "bad socket path".to_string())?;
    if unsafe { chmod(c_path.as_ptr(), 0o666) } != 0 {
        return Err(format!("cannot chmod {}: {}", path.display(), std::io::Error::last_os_error()));
    }
    // Non-blocking, so the accept loop notices SIGTERM.
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(listener)
}

fn serve(stream: UnixStream, requirement: Option<&str>) {
    let id = NEXT_CLIENT.fetch_add(1, Ordering::Relaxed);
    if let Err(e) = stream.set_nonblocking(false) {
        eprintln!("wg-helper: client {id}: {e}");
        return;
    }
    if let Some(requirement) = requirement
        && let Err(e) = codesign::check_peer(&stream, requirement)
    {
        eprintln!("wg-helper: client {id} refused: {e}");
        let mut writer = &stream;
        let _ = ipc::write_response(&mut writer, &Response::Error("not authorised".to_string()));
        return;
    }

    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    loop {
        let request = match ipc::read_request(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(e) => {
                eprintln!("wg-helper: client {id}: {e}");
                let _ = ipc::write_response(&mut writer, &Response::Error(e.to_string()));
                break;
            }
        };
        let response = handle(id, request);
        if let Err(e) = ipc::write_response(&mut writer, &response) {
            eprintln!("wg-helper: client {id}: {e}");
            break;
        }
    }

    // The client is gone: its tunnel goes with it.
    let mut tunnel = TUNNEL.lock().unwrap();
    if tunnel.as_ref().is_some_and(|(owner, _)| *owner == id) {
        let (_, connection) = tunnel.take().unwrap();
        eprintln!("wg-helper: client {id} left, stopping {}", connection.tun_name);
        connection.stop();
    }
}

fn handle(id: u64, request: Request) -> Response {
    let mut tunnel = TUNNEL.lock().unwrap();
    match request {
        Request::Up(text) => {
            match tunnel.take() {
                Some((owner, connection)) if owner == id => connection.stop(),
                Some(other) => {
                    *tunnel = Some(other);
                    return Response::Error("another wg-gui session has a tunnel up".to_string());
                }
                None => {}
            }
            let result = config::parse(&text).and_then(Connection::start);
            match result {
                Ok(connection) => {
                    let started = Started {
                        tun_name: connection.tun_name.clone(),
                        mtu: connection.mtu(),
                        dns_changed: connection.dns_changed(),
                        endpoint: connection.endpoint(),
                        routes: connection.routes(),
                    };
                    eprintln!("wg-helper: client {id} brought up {}", started.tun_name);
                    *tunnel = Some((id, connection));
                    Response::Started(started)
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::Stats => match tunnel.as_ref() {
            Some((owner, connection)) if *owner == id => Response::Stats(connection.stats()),
            _ => Response::Error("no tunnel".to_string()),
        },
        Request::Down => {
            if tunnel.as_ref().is_some_and(|(owner, _)| *owner == id) {
                let (_, connection) = tunnel.take().unwrap();
                eprintln!("wg-helper: client {id} took down {}", connection.tun_name);
                connection.stop();
            }
            Response::Ok
        }
    }
}
