//! Configures the operating system around the tunnel: interface address,
//! MTU, routes for AllowedIPs, and DNS. Everything here shells out to the
//! standard macOS tools (`ifconfig`, `route`, `networksetup`) exactly the
//! way `wg-quick` does.

use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use crate::config::{Cidr, Config};

/// Worst-case bytes WireGuard adds to each packet: IPv6 header (40) +
/// UDP (8) + WireGuard data header (16) + Poly1305 tag (16).
const WIREGUARD_OVERHEAD: u16 = 80;
/// Assumed link MTU when the real one cannot be found (Ethernet, Wi-Fi).
const FALLBACK_LINK_MTU: u16 = 1500;
/// What `cleanup` would undo, kept on disk while a tunnel is up so a
/// crashed or killed process can be cleaned up after (`recover`).
/// DNS set with networksetup and the endpoint route outlive the process.
const STATE_FILE: &str = "/var/db/wg-gui/state";

/// What has to be undone when the tunnel goes down, plus a record of what
/// was set up so a front-end can show it.
#[derive(Debug, Default)]
pub struct Undo {
    /// The utun the routes go to; to tell whether the endpoint is caught.
    tun_name: String,
    endpoint_route: Option<IpAddr>,
    /// IPv6 reject routes; unlike routes on the utun they outlive it.
    rejects: Vec<String>,
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
    recover();
    let mut undo = Undo { tun_name: tun_name.to_string(), ..Undo::default() };
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

    // How the endpoint is reached without the tunnel, looked up before
    // our routes exist.
    let path_before = route_to(endpoint_ip);

    for allowed in &config.peer.allowed_ips {
        if allowed.prefix == 0 {
            // Full tunnel. Two half-width routes beat the existing default
            // route without replacing it.
            for half in add_default_routes(tun_name, allowed.ip.is_ipv4())? {
                undo.routes.push(Route { destination: half.to_string(), gateway: "on-link".to_string(), interface: tun_name.to_string() });
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

    // A full IPv4 tunnel with no IPv6 in it would let IPv6 traffic go
    // out the physical interface unencrypted. Reject it instead: unlike a
    // blackhole, apps get an immediate error and fall back to IPv4.
    let full_ipv4 = config.peer.allowed_ips.iter().any(|a| a.prefix == 0 && a.ip.is_ipv4());
    let any_ipv6 = config.peer.allowed_ips.iter().any(|a| a.ip.is_ipv6());
    if full_ipv4 && !any_ipv6 {
        for half in ["::/1", "8000::/1"] {
            // A route left by a tunnel that crashed would make the add fail.
            let _ = capture(&["route", "-q", "-n", "delete", "-inet6", half]);
            run(&["route", "-q", "-n", "add", "-inet6", half, "::1", "-reject"])?;
            undo.rejects.push(half.to_string());
            undo.routes.push(Route { destination: half.to_string(), gateway: "reject".to_string(), interface: "lo0".to_string() });
        }
    }

    // If our routes now catch the endpoint, encrypted packets would loop
    // into the tunnel (or be rejected): keep them on the path they had.
    // Nothing is sent before the tunnel threads start, after this.
    if is_caught(endpoint_ip, tun_name) {
        let path = path_before.ok_or_else(|| format!("no route to the endpoint {endpoint_ip}"))?;
        pin_endpoint(undo, endpoint_ip, &path)?;
    }

    // On disk before DNS changes; set_dns adds each service as it goes.
    save_state(undo);
    if !config.dns.is_empty() {
        set_dns(&config.dns, undo)?;
    }
    Ok(())
}

/// After a network change: moves the endpoint's host route to the
/// current default gateway (and to `endpoint`, if its address changed),
/// or drops it if the tunnel no longer catches the endpoint, and updates
/// `undo` to match.
pub fn repin_endpoint(undo: &mut Undo, endpoint: IpAddr) -> Result<(), String> {
    if let Some(old) = undo.endpoint_route.take() {
        // The old route may already be gone, along with its interface.
        let _ = capture(&["route", "-q", "-n", "delete", family_flag(old), &old.to_string()]);
        let old_destination = host_route(old);
        undo.routes.retain(|r| r.destination != old_destination);
    }
    if is_caught(endpoint, &undo.tun_name) {
        let gateway = default_gateway(endpoint.is_ipv4())?;
        pin_endpoint(undo, endpoint, &RouteTo { gateway: Some(gateway), interface: None })?;
    }
    save_state(undo);
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
    for half in &undo.rejects {
        if let Err(e) = run(&["route", "-q", "-n", "delete", "-inet6", half]) {
            eprintln!("warning: {e}");
        }
    }
    // The utun interface and every route through it vanish when the
    // device is closed (TunnelHandle::stop, or process exit).
    let _ = fs::remove_file(STATE_FILE);
}

/// Undoes what a tunnel that did not shut down cleanly (crash, SIGKILL,
/// power loss) left behind: DNS servers and routes that outlive it. Call
/// before bringing a tunnel up; does nothing if the last one stopped
/// cleanly.
pub fn recover() {
    let Ok(text) = fs::read_to_string(STATE_FILE) else {
        return;
    };
    if owner(&text).is_some_and(|pid| pid != std::process::id() && process_alive(pid)) && same_boot(&text) {
        return; // Another process's tunnel is up; those settings are live.
    }
    println!("restoring network settings left by a tunnel that did not stop cleanly");
    cleanup(&parse_state(&text));
}

/// Records what `cleanup` would undo. Best effort: a failure only costs
/// crash recovery.
fn save_state(undo: &Undo) {
    let path = Path::new(STATE_FILE);
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Err(e) = fs::write(path, format_state(undo)) {
        eprintln!("warning: cannot write {STATE_FILE}: {e}");
    }
}

/// One line per item, tab-separated (service names may contain spaces).
fn format_state(undo: &Undo) -> String {
    let mut text = format!("pid\t{}\nboot\t{}\n", std::process::id(), boot_time().unwrap_or(0));
    for (service, servers) in &undo.dns_backup {
        text += &format!("dns\t{service}\t{}\n", servers.join(" "));
    }
    if let Some(ip) = undo.endpoint_route {
        text += &format!("route\t{ip}\n");
    }
    for half in &undo.rejects {
        text += &format!("reject\t{half}\n");
    }
    text
}

fn parse_state(text: &str) -> Undo {
    let mut undo = Undo::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields[..] {
            ["dns", service, servers] => {
                undo.dns_backup.push((service.to_string(), servers.split_whitespace().map(String::from).collect()));
            }
            ["route", ip] => undo.endpoint_route = ip.parse().ok(),
            ["reject", half] => undo.rejects.push(half.to_string()),
            ["pid" | "boot", _] => {}
            _ => eprintln!("warning: ignoring '{line}' in {STATE_FILE}"),
        }
    }
    undo
}

/// The process that wrote the state file.
fn owner(text: &str) -> Option<u32> {
    text.lines().find_map(|line| line.strip_prefix("pid\t")?.parse().ok())
}

/// True if the state file was written since the last boot. Its process
/// id means nothing after a reboot: another process may have it now.
fn same_boot(text: &str) -> bool {
    let written = text.lines().find_map(|line| line.strip_prefix("boot\t")?.parse::<i64>().ok());
    written.is_some() && written == boot_time()
}

/// When the system booted, in seconds since the epoch (kern.boottime).
fn boot_time() -> Option<i64> {
    let mut timeval = [0i64; 2]; // struct timeval: tv_sec, tv_usec + padding
    let mut len = std::mem::size_of_val(&timeval);
    let rc = unsafe {
        sysctlbyname(c"kern.boottime".as_ptr(), timeval.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0)
    };
    (rc == 0).then_some(timeval[0])
}

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn sysctlbyname(
        name: *const std::ffi::c_char,
        old: *mut std::ffi::c_void,
        old_len: *mut usize,
        new: *mut std::ffi::c_void,
        new_len: usize,
    ) -> i32;
}

/// Signal 0 checks for existence; EPERM still means the process exists.
fn process_alive(pid: u32) -> bool {
    let rc = unsafe { kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(1)
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

/// Where `route -n get` says packets to an address go.
#[derive(Debug)]
struct RouteTo {
    /// None for an on-link destination.
    gateway: Option<String>,
    interface: Option<String>,
}

fn route_to(destination: IpAddr) -> Option<RouteTo> {
    let output = capture(&["route", "-n", "get", family_flag(destination), &destination.to_string()]).ok()?;
    let field = |name: &str| {
        output.lines().find_map(|line| Some(line.trim().strip_prefix(name)?.trim().to_string()))
    };
    // Directly connected networks show their link as the "gateway".
    let gateway = field("gateway:").filter(|g| !g.starts_with("link#"));
    Some(RouteTo { gateway, interface: field("interface:") })
}

/// True if packets to `ip` would go into the tunnel or be rejected.
fn is_caught(ip: IpAddr, tun_name: &str) -> bool {
    let Ok(output) = capture(&["route", "-n", "get", family_flag(ip), &ip.to_string()]) else {
        return false; // No route at all; nothing to protect.
    };
    output.lines().any(|line| {
        let line = line.trim();
        line.strip_prefix("interface:").is_some_and(|name| name.trim() == tun_name)
            || (line.starts_with("flags:") && line.contains("REJECT"))
    })
}

/// Adds a host route sending the endpoint along `path`, and records it.
fn pin_endpoint(undo: &mut Undo, endpoint: IpAddr, path: &RouteTo) -> Result<(), String> {
    let family = family_flag(endpoint);
    let target = endpoint.to_string();
    // A route left by a tunnel that crashed would make the add fail.
    let _ = capture(&["route", "-q", "-n", "delete", family, &target]);
    match (&path.gateway, &path.interface) {
        (Some(gateway), _) => run(&["route", "-q", "-n", "add", family, &target, "-gateway", gateway])?,
        (None, Some(interface)) => run(&["route", "-q", "-n", "add", family, &target, "-interface", interface])?,
        (None, None) => return Err(format!("no route to the endpoint {endpoint}")),
    }
    undo.endpoint_route = Some(endpoint);
    undo.routes.push(Route {
        destination: host_route(endpoint),
        gateway: path.gateway.clone().unwrap_or_else(|| "on-link".to_string()),
        interface: path.interface.clone().or_else(|| outgoing_interface(endpoint)).unwrap_or_else(|| "?".to_string()),
    });
    Ok(())
}

fn host_route(ip: IpAddr) -> String {
    format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
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

/// Points every network service at `servers`. Each service's previous
/// servers are recorded, on disk too, before it is changed, so a crash
/// part-way can still put them back.
fn set_dns(servers: &[IpAddr], undo: &mut Undo) -> Result<(), String> {
    let server_strings: Vec<String> = servers.iter().map(|ip| ip.to_string()).collect();

    for service in network_services()? {
        let previous = current_dns(&service)?;
        undo.dns_backup.push((service.clone(), previous));
        save_state(undo);
        let mut args = vec!["networksetup", "-setdnsservers", service.as_str()];
        args.extend(server_strings.iter().map(String::as_str));
        run(&args)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips() {
        let undo = Undo {
            endpoint_route: Some("203.0.113.7".parse().unwrap()),
            rejects: vec!["::/1".to_string(), "8000::/1".to_string()],
            dns_backup: vec![
                ("Wi-Fi".to_string(), vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()]),
                ("USB 10/100 LAN".to_string(), vec![]),
            ],
            ..Undo::default()
        };
        let text = format_state(&undo);
        assert_eq!(owner(&text), Some(std::process::id()));
        assert!(same_boot(&text));
        assert!(!same_boot(&text.replace(&format!("boot\t{}", boot_time().unwrap()), "boot\t12345")));
        let back = parse_state(&text);
        assert_eq!(back.endpoint_route, undo.endpoint_route);
        assert_eq!(back.rejects, undo.rejects);
        assert_eq!(back.dns_backup, undo.dns_backup);
    }

    #[test]
    fn reads_the_real_routing_table() {
        // Needs a network, but not root.
        let Some(path) = route_to("1.1.1.1".parse().unwrap()) else {
            return; // Offline.
        };
        assert!(path.interface.is_some(), "{path:?}");
        assert!(!path.gateway.as_deref().is_some_and(|g| g.starts_with("link#")));
        assert!(!is_caught("1.1.1.1".parse().unwrap(), "utun999"));
    }

    #[test]
    fn boot_time_is_plausible() {
        let boot = boot_time().unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(boot > 1_600_000_000 && boot < now, "{boot}");
    }

    #[test]
    fn this_process_is_alive() {
        assert!(process_alive(std::process::id()));
    }
}
