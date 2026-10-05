//! The WireGuard client core shared by the command-line and GUI front-ends.
//!
//! `connection` is the entry point: it brings a tunnel up from a parsed
//! `config` and tears it down again. Everything below it implements the
//! protocol (PROTOCOL.md) and the macOS plumbing.

pub mod base64;
pub mod config;
pub mod connection;
pub mod ip;
pub mod netconfig;
pub mod noise;
pub mod session;
pub mod timers;
pub mod tun;
pub mod tunnel;
