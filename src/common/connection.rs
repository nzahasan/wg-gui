//! One tunnel from start to finish: create the utun device, configure the
//! system around it, run the protocol threads, follow network changes,
//! and undo it all on stop. Both front-ends drive the tunnel through this
//! type.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::config::{self, Config};
use crate::netconfig::{self, Route, Undo};
use crate::netwatch::Watcher;
use crate::tun::Tun;
use crate::tunnel::{self, Stats, TunnelControl, TunnelHandle};

pub struct Connection {
    pub tun_name: String,
    pub config: Config,
    pub started: Instant,
    /// What was configured; shared with the network watcher, which moves
    /// the endpoint route when the network changes.
    undo: Arc<Mutex<Undo>>,
    handle: TunnelHandle,
    watcher: Option<Watcher>,
}

impl Connection {
    /// Brings the tunnel up. Needs root. On error nothing is left behind:
    /// netconfig rolls back its own changes and the utun closes on drop.
    pub fn start(config: Config) -> Result<Connection, String> {
        let tun = Tun::open().map_err(|e| format!("cannot create utun device (are you root?): {e}"))?;
        println!("created {}", tun.name);
        let tun_name = tun.name.clone();

        let undo = netconfig::configure(&tun_name, &config)?;
        let handle = match tunnel::run(tun, &config) {
            Ok(handle) => handle,
            Err(e) => {
                netconfig::cleanup(&undo);
                return Err(e);
            }
        };
        let undo = Arc::new(Mutex::new(undo));
        let follow = follow_network(handle.control(), Arc::clone(&undo), config.peer.endpoint_text.clone());
        let watcher = Watcher::start(follow)
            .inspect_err(|e| eprintln!("warning: cannot watch for network changes: {e}"))
            .ok();
        Ok(Connection { tun_name, config, started: Instant::now(), undo, handle, watcher })
    }

    pub fn stats(&self) -> Stats {
        self.handle.stats()
    }

    /// The endpoint the tunnel is sending to; it can change if the
    /// endpoint's host name resolves differently after a network change.
    pub fn endpoint(&self) -> SocketAddr {
        self.handle.control().endpoint()
    }

    /// The MTU given to the tunnel interface.
    pub fn mtu(&self) -> u16 {
        self.undo.lock().unwrap().mtu
    }

    /// True if the system DNS servers were replaced by the config's.
    pub fn dns_changed(&self) -> bool {
        self.undo.lock().unwrap().dns_changed()
    }

    /// Every route added, as it is now.
    pub fn routes(&self) -> Vec<Route> {
        self.undo.lock().unwrap().routes.clone()
    }

    /// Takes the tunnel down: the watcher and threads stop, the utun
    /// closes (taking its routes with it), then DNS and the endpoint
    /// route are restored.
    pub fn stop(self) {
        // First, so it holds no reference to the tunnel and cannot touch
        // routes while they are being removed.
        if let Some(watcher) = self.watcher {
            watcher.stop();
        }
        self.handle.stop();
        netconfig::cleanup(&self.undo.lock().unwrap());
    }
}

/// What the way to the endpoint looks like. When it changes, the socket
/// may be sending from an address that no longer exists and, for a full
/// tunnel, the endpoint route may point at a gateway that is gone.
#[derive(Debug, PartialEq)]
struct Path {
    /// None while there is no network.
    gateway: Option<String>,
    /// The local address packets to the endpoint would leave from.
    source: Option<IpAddr>,
}

impl Path {
    fn current(endpoint: SocketAddr) -> Path {
        Path { gateway: netconfig::default_gateway(endpoint.is_ipv4()).ok(), source: source_address(endpoint) }
    }
}

/// The local address the system picks to reach `endpoint`. Connecting a
/// UDP socket only consults the routing table; nothing is sent.
fn source_address(endpoint: SocketAddr) -> Option<IpAddr> {
    let probe = UdpSocket::bind(if endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    probe.connect(endpoint).ok()?;
    Some(probe.local_addr().ok()?.ip())
}

/// The network watcher's callback: when the path to the endpoint changed,
/// re-pin the endpoint route, rebind the socket and handshake at once,
/// instead of waiting for the timers to notice the tunnel is dead.
fn follow_network(control: TunnelControl, undo: Arc<Mutex<Undo>>, endpoint_text: String) -> impl FnMut() + Send {
    let mut last = Path::current(control.endpoint());
    move || {
        let path = Path::current(control.endpoint());
        if path == last {
            return;
        }
        if path.gateway.is_none() {
            println!("network is gone, waiting for it to come back");
            control.set_offline();
            last = path;
            return;
        }
        println!(
            "network changed (gateway {}, source {}), reconnecting",
            path.gateway.as_deref().unwrap_or("-"),
            path.source.map_or("-".to_string(), |ip| ip.to_string())
        );
        reconnect(&control, &undo, control.endpoint());

        // The endpoint's name may resolve differently on the new network.
        // Looked up only now that the tunnel works again, since its DNS
        // may go through the tunnel.
        match config::resolve_endpoint(&endpoint_text) {
            Ok(endpoint) if endpoint != control.endpoint() => {
                println!("endpoint {endpoint_text} is now {endpoint}");
                reconnect(&control, &undo, endpoint);
            }
            Ok(_) => {}
            Err(e) => eprintln!("warning: {e}; keeping {}", control.endpoint()),
        }
        last = Path::current(control.endpoint());
    }
}

fn reconnect(control: &TunnelControl, undo: &Mutex<Undo>, endpoint: SocketAddr) {
    if let Err(e) = netconfig::repin_endpoint(&mut undo.lock().unwrap(), endpoint.ip()) {
        eprintln!("warning: cannot move the endpoint route: {e}");
    }
    if let Err(e) = control.rebind(endpoint) {
        eprintln!("warning: {e}");
    }
}
