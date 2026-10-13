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

const SIGHUP: c_int = 1;
const SIGINT: c_int = 2;
const SIGQUIT: c_int = 3;
const SIGTERM: c_int = 15;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

const O_WRONLY: c_int = 1;

unsafe extern "C" {
    fn open(path: *const std::ffi::c_char, flags: c_int, ...) -> c_int;
    fn dup2(from: c_int, to: c_int) -> c_int;
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
}

extern "C" fn on_signal(signum: c_int) {
    if signum == SIGHUP {
        // The terminal is gone: printing to it would fail, and Rust's
        // print macros panic on that, skipping the cleanup. open and dup2
        // are safe in a signal handler.
        unsafe {
            let null = open(c"/dev/null".as_ptr(), O_WRONLY);
            if null >= 0 {
                dup2(null, 1);
                dup2(null, 2);
            }
        }
    }
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

    // Closing the terminal (SIGHUP) must clean up like Ctrl-C does.
    unsafe {
        for signum in [SIGHUP, SIGINT, SIGQUIT, SIGTERM] {
            signal(signum, on_signal);
        }
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
