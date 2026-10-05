//! Parser for wg-quick style configuration files:
//!
//! ```text
//! [Interface]
//! PrivateKey = ...
//! Address = 10.0.0.2/32
//! DNS = 1.1.1.1
//!
//! [Peer]
//! PublicKey = ...
//! Endpoint = vpn.example.com:51820
//! AllowedIPs = 0.0.0.0/0
//! ```

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::base64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// True if `ip` lies inside this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_matches(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_matches(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Compares the first `prefix` bits of two addresses.
fn prefix_matches(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full_bytes = usize::from(prefix / 8);
    let extra_bits = prefix % 8;
    if a[..full_bytes] != b[..full_bytes] {
        return false;
    }
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - extra_bits);
    a[full_bytes] & mask == b[full_bytes] & mask
}

#[derive(Debug)]
pub struct Peer {
    pub public_key: [u8; 32],
    /// All zeros when the config has no PresharedKey.
    pub preshared_key: [u8; 32],
    pub endpoint: SocketAddr,
    /// The Endpoint exactly as written, e.g. "vpn.example.com:51820".
    pub endpoint_text: String,
    pub allowed_ips: Vec<Cidr>,
    pub keepalive_seconds: Option<u16>,
}

#[derive(Debug)]
pub struct Config {
    pub private_key: [u8; 32],
    pub addresses: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    /// None means "work it out from the outgoing interface", like wg-quick.
    pub mtu: Option<u16>,
    pub peer: Peer,
}

pub fn load(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    parse(&text)
}

/// Everything a config says, checked, without resolving the endpoint
/// (which needs the network). Used to list and import profiles.
#[derive(Debug, Clone)]
pub struct Summary {
    /// "host:port" as written.
    pub endpoint: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub allowed_ips: Vec<Cidr>,
    pub keepalive_seconds: Option<u16>,
    pub has_preshared_key: bool,
}

/// Parses and checks a config, resolving its endpoint.
pub fn parse(text: &str) -> Result<Config, String> {
    let (mut config, endpoint_text) = parse_unresolved(text)?;
    config.peer.endpoint = resolve_endpoint(&endpoint_text)?;
    config.peer.endpoint_text = endpoint_text;
    Ok(config)
}

/// Parses and checks a config without touching the network.
pub fn summary(text: &str) -> Result<Summary, String> {
    let (config, endpoint) = parse_unresolved(text)?;
    let (host, port) = split_endpoint(&endpoint)?;
    Ok(Summary {
        host,
        port,
        endpoint,
        addresses: config.addresses,
        dns: config.dns,
        mtu: config.mtu,
        allowed_ips: config.peer.allowed_ips,
        keepalive_seconds: config.peer.keepalive_seconds,
        has_preshared_key: config.peer.preshared_key != [0u8; 32],
    })
}

/// The config with a placeholder endpoint, and the Endpoint text.
fn parse_unresolved(text: &str) -> Result<(Config, String), String> {
    // Raw values collected while reading the file; validated at the end.
    let mut private_key = None;
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut mtu = None;

    let mut public_key = None;
    let mut preshared_key = [0u8; 32];
    let mut endpoint = None;
    let mut allowed_ips = Vec::new();
    let mut keepalive_seconds = None;

    let mut section = String::new();
    let mut peer_count = 0;

    for (line_number, raw_line) in text.lines().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let where_ = || format!("line {}", line_number + 1);

        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_lowercase();
            if section == "peer" {
                peer_count += 1;
                if peer_count > 1 {
                    return Err("only one [Peer] section is supported".to_string());
                }
            }
            continue;
        }

        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim()),
            None => return Err(format!("{}: expected 'Key = Value'", where_())),
        };

        match (section.as_str(), key.as_str()) {
            ("interface", "privatekey") => private_key = Some(base64::decode_key(value)?),
            ("interface", "address") => addresses.extend(parse_list(value, parse_cidr)?),
            ("interface", "dns") => dns.extend(parse_list(value, parse_dns)?),
            ("interface", "mtu") => mtu = Some(value.parse().map_err(|_| format!("{}: bad MTU", where_()))?),
            ("interface", "listenport") => {}
            ("peer", "publickey") => public_key = Some(base64::decode_key(value)?),
            ("peer", "presharedkey") => preshared_key = base64::decode_key(value)?,
            ("peer", "endpoint") => {
                split_endpoint(value)?;
                endpoint = Some(value.to_string());
            }
            ("peer", "allowedips") => allowed_ips.extend(parse_list(value, parse_cidr)?),
            ("peer", "persistentkeepalive") => {
                keepalive_seconds = Some(value.parse().map_err(|_| format!("{}: bad keepalive", where_()))?)
            }
            _ => eprintln!("warning: {}: ignoring '{}' in [{}]", where_(), key, section),
        }
    }

    let endpoint = endpoint.ok_or("missing Endpoint in [Peer]")?;
    let peer = Peer {
        public_key: public_key.ok_or("missing PublicKey in [Peer]")?,
        preshared_key,
        endpoint: SocketAddr::from(([0, 0, 0, 0], 0)),
        endpoint_text: String::new(),
        allowed_ips,
        keepalive_seconds,
    };
    let config = Config {
        private_key: private_key.ok_or("missing PrivateKey in [Interface]")?,
        addresses,
        dns,
        mtu,
        peer,
    };
    Ok((config, endpoint))
}

/// Splits "host:port" or "[v6]:port" without resolving the host.
fn split_endpoint(text: &str) -> Result<(String, u16), String> {
    let bad = || format!("bad Endpoint '{text}', expected host:port");
    let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() {
        return Err(bad());
    }
    let port = port.parse().map_err(|_| bad())?;
    Ok((host.to_string(), port))
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn parse_list<T>(value: &str, parse_one: fn(&str) -> Result<T, String>) -> Result<Vec<T>, String> {
    value.split(',').map(|item| parse_one(item.trim())).collect()
}

fn parse_cidr(text: &str) -> Result<Cidr, String> {
    let (ip_text, prefix_text) = match text.split_once('/') {
        Some(parts) => parts,
        None => (text, ""),
    };
    let ip: IpAddr = ip_text.parse().map_err(|_| format!("bad IP address '{text}'"))?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = if prefix_text.is_empty() {
        max_prefix
    } else {
        prefix_text.parse().map_err(|_| format!("bad prefix in '{text}'"))?
    };
    if prefix > max_prefix {
        return Err(format!("prefix too large in '{text}'"));
    }
    Ok(Cidr { ip, prefix })
}

fn parse_dns(text: &str) -> Result<IpAddr, String> {
    text.parse().map_err(|_| format!("bad DNS server '{text}'"))
}

fn resolve_endpoint(text: &str) -> Result<SocketAddr, String> {
    let mut addrs = text
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve endpoint '{text}': {e}"))?;
    addrs.next().ok_or(format!("endpoint '{text}' resolved to nothing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "
# a comment
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1400

[Peer]
PublicKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
";

    #[test]
    fn parses_sample() {
        let cfg = parse(SAMPLE).unwrap();
        assert_eq!(cfg.mtu, Some(1400));
        assert_eq!(cfg.addresses.len(), 2);
        assert_eq!(cfg.addresses[0].prefix, 32);
        assert_eq!(cfg.dns, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(cfg.peer.endpoint, "127.0.0.1:51820".parse().unwrap());
        assert_eq!(cfg.peer.endpoint_text, "127.0.0.1:51820");
        assert_eq!(cfg.peer.allowed_ips[0].prefix, 0);
        assert_eq!(cfg.peer.keepalive_seconds, Some(25));
        assert_eq!(cfg.peer.preshared_key, [0u8; 32]);
    }

    #[test]
    fn rejects_missing_keys_and_extra_peers() {
        assert!(parse(&SAMPLE.replace("PrivateKey", "X")).is_err());
        assert!(parse(&SAMPLE.replace("Endpoint", "X")).is_err());
        assert!(parse(&format!("{SAMPLE}\n[Peer]\n")).is_err());
    }

    #[test]
    fn summary_does_not_resolve() {
        let text = SAMPLE.replace("127.0.0.1:51820", "vpn.invalid:51820");
        let summary = summary(&text).unwrap();
        assert_eq!(summary.host, "vpn.invalid");
        assert_eq!(summary.port, 51820);
        assert!(!summary.has_preshared_key);
        let v6 = summary_of_endpoint("[fd00::1]:443");
        assert_eq!((v6.host.as_str(), v6.port), ("fd00::1", 443));
        assert!(super::summary(&SAMPLE.replace("127.0.0.1:51820", "nohost")).is_err());
    }

    fn summary_of_endpoint(endpoint: &str) -> Summary {
        summary(&SAMPLE.replace("127.0.0.1:51820", endpoint)).unwrap()
    }

    #[test]
    fn mtu_is_optional() {
        assert_eq!(parse(&SAMPLE.replace("MTU = 1400", "")).unwrap().mtu, None);
    }

    #[test]
    fn cidr_contains() {
        let net = parse_cidr("10.1.0.0/16").unwrap();
        assert!(net.contains("10.1.200.3".parse().unwrap()));
        assert!(!net.contains("10.2.0.1".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));
        assert!(parse_cidr("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        let odd = parse_cidr("192.168.4.0/22").unwrap();
        assert!(odd.contains("192.168.7.255".parse().unwrap()));
        assert!(!odd.contains("192.168.8.0".parse().unwrap()));
        let v6 = parse_cidr("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
    }
}
