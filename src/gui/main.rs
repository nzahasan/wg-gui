//! WireGuard desktop client built on the shared core in `src/common`.
//!
//! Runs as the user; tunnels are brought up by `wg-helper`, the root
//! daemon bundled with the app (see `helper.rs`).
//!
//! Profiles live in ~/.config/wg-gui, listed in wg-profiles.conf.
//! Closing the window (or Ctrl-C in the terminal) takes the tunnel down
//! and restores DNS and routes first.

mod app;
mod format;
mod graph;
mod helper;
mod icons;
mod screens;
mod storage;
mod theme;
mod tray;

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

use iced::{Size, window};

use app::App;

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;
const HSIZE: f32 = 400.0;
const VSIZE: f32 = 620.0;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
}

extern "C" fn on_signal(_signum: c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// True once SIGINT or SIGTERM arrived; the app then shuts down cleanly.
pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

fn main() -> iced::Result {
    unsafe {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
    }

    iced::application(App::new, App::update, App::view)
        .title("wg-gui")
        .subscription(App::subscription)
        .window(window::Settings {
            size: Size::new(HSIZE, VSIZE),
            resizable: false,
            exit_on_close_request: false,
            ..window::Settings::default()
        })
        .font(theme::SANS_REGULAR_TTF)
        .font(theme::SANS_MEDIUM_TTF)
        .font(theme::SANS_SEMIBOLD_TTF)
        .font(theme::SANS_BOLD_TTF)
        .font(theme::MONO_REGULAR_TTF)
        .font(theme::MONO_MEDIUM_TTF)
        .default_font(theme::SANS)
        // No theme of our own: iced then follows the system appearance and
        // reports changes (`Message::ThemeChanged`); our styles take their
        // colours from `theme::palette()`.
        .antialiasing(true)
        .run()
}
