//! Configures the operating system around the tunnel: interface address,
//! MTU, routes for AllowedIPs, and DNS. Everything here shells out to the
//! standard macOS tools (`ifconfig`, `route`, `networksetup`) exactly the
//! way `wg-quick` does.

use std::net::IpAddr;
use std::process::Command;

use crate::config::{Cidr, Config};

/// Worst-case bytes WireGuard adds to each packet: IPv6 header (40) +
/// UDP (8) + WireGuard data header (16) + Poly1305 tag (16).
const WIREGUARD_OVERHEAD: u16 = 80;
/// Assumed link MTU when the real one cannot be found (Ethernet, Wi-Fi).
const FALLBACK_LINK_MTU: u16 = 1500;

/// What has to be undone when the tunnel goes down, plus a record of what
/// was set up so a front-end can show it.
#[derive(Debug, Default)]
pub struct Undo {
    endpoint_route: Option<IpAddr>,
    /// (network service name, DNS servers it had before we changed them).
    dns_backup: Vec<(String, Vec<String>)>,
    /// The MTU given to the tunnel interface.
    pub mtu: u16,
    /// Every route added, in order.
    pub routes: Vec<Route>,
}

impl Undo {
    /// True if the system DNS servers were replaced by the config's.
    pub fn dns_changed(&self) -> bool {
        !self.dns_backup.is_empty()
    }
}

/// One route added for the tunnel.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub destination: String,
    /// "on-link" for routes straight onto the tunnel interface.
    pub gateway: String,
    pub interface: String,
}

/// Configures the system for the tunnel. On failure, whatever was already
/// changed is undone before the error is returned.
pub fn configure(tun_name: &str, config: &Config) -> Result<Undo, String> {
    let mut undo = Undo::default();
    match apply(tun_name, config, &mut undo) {
        Ok(()) => Ok(undo),
        Err(e) => {
            cleanup(&undo);
            Err(e)
        }
    }
}

fn apply(tun_name: &str, config: &Config, undo: &mut Undo) -> Result<(), String> {
    for address in &config.addresses {
        add_address(tun_name, address)?;
    }
    // Must run before our routes exist, so the endpoint lookup still
    // sees the physical interface.
    let endpoint_ip = config.peer.endpoint.ip();
    let physical = outgoing_interface(endpoint_ip);
    undo.mtu = match config.mtu {
        Some(mtu) => mtu,
        None => auto_mtu(physical.as_deref()),
    };
    run(&["ifconfig", tun_name, "mtu", &undo.mtu.to_string(), "up"])?;

    for allowed in &config.peer.allowed_ips {
        if allowed.prefix == 0 {
            // Full tunnel. Two half-width routes beat the existing default
            // route without replacing it, and the endpoint itself must keep
            // going out the real gateway or encrypted packets would loop.
            for half in add_default_routes(tun_name, allowed.ip.is_ipv4())? {
                undo.routes.push(Route { destination: half.to_string(), gateway: "on-link".to_string(), interface: tun_name.to_string() });
            }
            if endpoint_ip.is_ipv4() == allowed.ip.is_ipv4() {
                let gateway = add_endpoint_route(endpoint_ip)?;
                undo.endpoint_route = Some(endpoint_ip);
                let host_prefix = if endpoint_ip.is_ipv4() { 32 } else { 128 };
                undo.routes.push(Route {
                    destination: format!("{endpoint_ip}/{host_prefix}"),
                    gateway,
                    interface: physical.clone().unwrap_or_else(|| "?".to_string()),
                });
            }
        } else {
            add_route(tun_name, allowed)?;
            undo.routes.push(Route {
                destination: format!("{}/{}", allowed.ip, allowed.prefix),
                gateway: "on-link".to_string(),
                interface: tun_name.to_string(),
            });
        }
    }

    if !config.dns.is_empty() {
        set_dns(&config.dns, &mut undo.dns_backup)?;
    }
    Ok(())
}

/// After a network change: points the endpoint's host route at the
/// current default gateway, moving it to `endpoint` if the endpoint's
/// address changed, and updates `undo` to match. A split tunnel pins no
/// route, so there is nothing to do.
pub fn repin_endpoint(undo: &mut Undo, endpoint: IpAddr) -> Result<(), String> {
    let Some(old) = undo.endpoint_route else {
        return Ok(());
    };
    let gateway = default_gateway(endpoint.is_ipv4())?;
    // The old route may already be gone, along with its interface.
    let _ = capture(&["route", "-q", "-n", "delete", family_flag(old), &old.to_string()]);
    run(&["route", "-q", "-n", "add", family_flag(endpoint), &endpoint.to_string(), "-gateway", &gateway])?;
    undo.endpoint_route = Some(endpoint);

    let interface = outgoing_interface(endpoint).unwrap_or_else(|| "?".to_string());
    let host_prefix = if endpoint.is_ipv4() { 32 } else { 128 };
    let old_destination = format!("{old}/{}", if old.is_ipv4() { 32 } else { 128 });
    if let Some(route) = undo.routes.iter_mut().find(|r| r.destination == old_destination) {
        *route = Route { destination: format!("{endpoint}/{host_prefix}"), gateway, interface };
    }
    Ok(())
}

pub fn cleanup(undo: &Undo) {
    // Errors here are only reported; there is nothing more we can do.
    for (service, servers) in &undo.dns_backup {
        if let Err(e) = restore_dns(service, servers) {
            eprintln!("warning: {e}");
        }
    }
    if let Some(ip) = undo.endpoint_route {
        let family = family_flag(ip);
        if let Err(e) = run(&["route", "-q", "-n", "delete", family, &ip.to_string()]) {
            eprintln!("warning: {e}");
        }
    }
    // The utun interface and every route through it vanish when the
    // device is closed (TunnelHandle::stop, or process exit).
}

fn add_address(tun_name: &str, address: &Cidr) -> Result<(), String> {
    let cidr = format!("{}/{}", address.ip, address.prefix);
    if address.ip.is_ipv4() {
        // A point-to-point interface: the destination is the address itself.
        let ip = address.ip.to_string();
        run(&["ifconfig", tun_name, "inet", &cidr, &ip, "alias"])
    } else {
        run(&["ifconfig", tun_name, "inet6", &cidr, "alias"])
    }
}

fn add_route(tun_name: &str, cidr: &Cidr) -> Result<(), String> {
    let family = family_flag(cidr.ip);
    let target = format!("{}/{}", cidr.ip, cidr.prefix);
    run(&["route", "-q", "-n", "add", family, &target, "-interface", tun_name])
}

/// Adds the two half-width routes and returns them.
fn add_default_routes(tun_name: &str, ipv4: bool) -> Result<[&'static str; 2], String> {
    let halves: [&str; 2] = if ipv4 { ["0.0.0.0/1", "128.0.0.0/1"] } else { ["::/1", "8000::/1"] };
    let family = if ipv4 { "-inet" } else { "-inet6" };
    for half in halves {
        run(&["route", "-q", "-n", "add", family, half, "-interface", tun_name])?;
    }
    Ok(halves)
}

/// Pins the endpoint to the current default gateway, which is returned.
fn add_endpoint_route(endpoint_ip: IpAddr) -> Result<String, String> {
    let gateway = default_gateway(endpoint_ip.is_ipv4())?;
    let family = family_flag(endpoint_ip);
    run(&["route", "-q", "-n", "add", family, &endpoint_ip.to_string(), "-gateway", &gateway])?;
    Ok(gateway)
}

/// Reads the current default gateway from `route -n get default`. Our
/// half-width routes do not hide it: "default" asks for the 0/0 entry.
pub fn default_gateway(ipv4: bool) -> Result<String, String> {
    let family = if ipv4 { "-inet" } else { "-inet6" };
    let output = capture(&["route", "-n", "get", family, "default"])?;
    for line in output.lines() {
        if let Some(gateway) = line.trim().strip_prefix("gateway:") {
            return Ok(gateway.trim().to_string());
        }
    }
    Err("could not determine the default gateway".to_string())
}

/// The rule `wg-quick` uses when the config has no MTU: the MTU of the
/// interface that reaches the endpoint, minus WireGuard's overhead, so an
/// encrypted packet still fits in one datagram on the real link.
fn auto_mtu(link: Option<&str>) -> u16 {
    let link_mtu = link.and_then(interface_mtu).unwrap_or(FALLBACK_LINK_MTU);
    let mtu = link_mtu - WIREGUARD_OVERHEAD;
    println!(
        "MTU not set; using {mtu} ({} MTU {link_mtu} - {WIREGUARD_OVERHEAD})",
        link.unwrap_or("assumed link")
    );
    mtu
}

/// The interface the kernel would use to reach `destination`, from
/// `route -n get`.
fn outgoing_interface(destination: IpAddr) -> Option<String> {
    let output =
        capture(&["route", "-n", "get", family_flag(destination), &destination.to_string()]).ok()?;
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(|name| name.trim().to_string())
}

/// Reads "mtu N" from `ifconfig <name>`.
fn interface_mtu(name: &str) -> Option<u16> {
    let output = capture(&["ifconfig", name]).ok()?;
    let mut words = output.split_whitespace();
    words.find(|&word| word == "mtu")?;
    words.next()?.parse().ok().filter(|&mtu| mtu > WIREGUARD_OVERHEAD)
}

fn family_flag(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "-inet" } else { "-inet6" }
}

// ---------------------------------------------------------------------------
// DNS via networksetup
// ---------------------------------------------------------------------------

/// Points every network service at `servers`, recording each service's
/// previous servers in `backup` as soon as it is changed.
fn set_dns(servers: &[IpAddr], backup: &mut Vec<(String, Vec<String>)>) -> Result<(), String> {
    let server_strings: Vec<String> = servers.iter().map(|ip| ip.to_string()).collect();

    for service in network_services()? {
        let previous = current_dns(&service)?;
        let mut args = vec!["networksetup", "-setdnsservers", service.as_str()];
        args.extend(server_strings.iter().map(String::as_str));
        run(&args)?;
        backup.push((service, previous));
    }
    Ok(())
}

fn restore_dns(service: &str, servers: &[String]) -> Result<(), String> {
    let mut args = vec!["networksetup", "-setdnsservers", service];
    if servers.is_empty() {
        args.push("empty"); // networksetup's word for "no manual servers"
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    run(&args)
}

/// Enabled network services (Wi-Fi, Ethernet, ...). Disabled ones are
/// listed with a leading `*`, and the first line is an explanatory header.
fn network_services() -> Result<Vec<String>, String> {
    let output = capture(&["networksetup", "-listallnetworkservices"])?;
    Ok(output
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(|line| line.to_string())
        .collect())
}

fn current_dns(service: &str) -> Result<Vec<String>, String> {
    let output = capture(&["networksetup", "-getdnsservers", service])?;
    // When nothing is set the tool prints a sentence instead of addresses.
    Ok(output
        .lines()
        .filter(|line| line.parse::<IpAddr>().is_ok())
        .map(|line| line.to_string())
        .collect())
}

// ---------------------------------------------------------------------------
// Running commands
// ---------------------------------------------------------------------------

/// Runs a command, echoing it like `wg-quick` does, and fails on non-zero exit.
fn run(args: &[&str]) -> Result<(), String> {
    println!("[#] {}", args.join(" "));
    capture(args).map(|_| ())
}

fn capture(args: &[&str]) -> Result<String, String> {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", args[0]))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("'{}' failed: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
