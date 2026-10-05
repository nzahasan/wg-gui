//! Just enough IP header parsing to handle a decrypted packet: its real
//! length (to strip WireGuard's zero padding) and its source address (to
//! enforce AllowedIPs).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

/// Returns the packet trimmed to the length its header claims, and its
/// source address. None if it is not a well-formed IPv4/IPv6 packet.
pub fn parse(packet: &[u8]) -> Option<(&[u8], IpAddr)> {
    let version = packet.first()? >> 4;
    let (len, source) = match version {
        4 if packet.len() >= IPV4_HEADER_LEN => {
            let len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let source: [u8; 4] = packet[12..16].try_into().unwrap();
            (len, IpAddr::V4(Ipv4Addr::from(source)))
        }
        6 if packet.len() >= IPV6_HEADER_LEN => {
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let source: [u8; 16] = packet[8..24].try_into().unwrap();
            (IPV6_HEADER_LEN + payload_len, IpAddr::V6(Ipv6Addr::from(source)))
        }
        _ => return None,
    };
    if len > packet.len() || (version == 4 && len < IPV4_HEADER_LEN) {
        return None; // The header lies about the size.
    }
    Some((&packet[..len], source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_padding_and_reads_source() {
        let mut v4 = vec![0u8; 32]; // 28-byte packet + 4 bytes padding
        v4[0] = 0x45;
        v4[3] = 28;
        v4[12..16].copy_from_slice(&[10, 0, 0, 1]);
        let (packet, source) = parse(&v4).unwrap();
        assert_eq!(packet.len(), 28);
        assert_eq!(source, "10.0.0.1".parse::<IpAddr>().unwrap());

        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        v6[5] = 8;
        v6[23] = 1;
        let (packet, source) = parse(&v6).unwrap();
        assert_eq!(packet.len(), 48);
        assert_eq!(source, "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45; 10]).is_none()); // too short
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[3] = 200; // claims more than we have
        assert!(parse(&v4).is_none());
        assert!(parse(&[0x00; 40]).is_none()); // not IP
    }
}
