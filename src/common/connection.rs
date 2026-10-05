//! One tunnel from start to finish: create the utun device, configure the
//! system around it, run the protocol threads, and undo it all on stop.
//! Both front-ends drive the tunnel through this type.

use std::time::Instant;

use crate::config::Config;
use crate::netconfig::{self, Undo};
use crate::tun::Tun;
use crate::tunnel::{self, Stats, TunnelHandle};

pub struct Connection {
    pub tun_name: String,
    pub config: Config,
    /// What was configured; also lists the routes and the MTU.
    pub undo: Undo,
    pub started: Instant,
    handle: TunnelHandle,
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
        Ok(Connection { tun_name, config, undo, started: Instant::now(), handle })
    }

    pub fn stats(&self) -> Stats {
        self.handle.stats()
    }

    /// Takes the tunnel down: the threads stop, the utun closes (taking its
    /// routes with it), then DNS and the endpoint route are restored.
    pub fn stop(self) {
        self.handle.stop();
        netconfig::cleanup(&self.undo);
    }
}
