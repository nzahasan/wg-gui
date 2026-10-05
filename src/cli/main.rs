//! A small userspace WireGuard client for macOS.
//!
//! Usage: sudo wg-cli <config.conf>
//!
//! The tunnel stays up while the program runs; Ctrl-C tears it down.

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use wg_common::config;
use wg_common::connection::Connection;

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
}

extern "C" fn on_signal(_signum: c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: sudo wg-cli <config.conf>");
        std::process::exit(1);
    };

    if let Err(e) = run(&path) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(path: &str) -> Result<(), String> {
    let config = config::load(path)?;

    unsafe {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
    }

    let connection = Connection::start(config)?;
    println!("tunnel is up, press Ctrl-C to stop");

    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }

    println!("\nshutting down");
    connection.stop();
    Ok(())
}
