use tracing::debug;

/// UoT（UDP over TCP）数据包编码。`max_payload` 为单包载荷上限，
/// 由调用方按隧道帧容量传入，本层不感知会话实现。
pub fn encode_udp_packet(
    data: &[u8],
    addr: &std::net::SocketAddr,
    max_payload: usize,
) -> Result<Vec<u8>, anyhow::Error> {
    let encoded_addr = match addr {
        std::net::SocketAddr::V4(a) => {
            let mut buf = vec![0x01u8];
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf
        }
        std::net::SocketAddr::V6(a) => {
            let mut buf = vec![0x04u8];
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf
        }
    };

    let max_data_len = max_payload.saturating_sub(encoded_addr.len() + 2);
    if data.len() > max_data_len {
        anyhow::bail!("udp packet too large: {} > {}", data.len(), max_data_len);
    }

    let mut packet = Vec::with_capacity(encoded_addr.len() + 2 + data.len());
    packet.extend_from_slice(&encoded_addr);
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.extend_from_slice(data);
    Ok(packet)
}

pub fn encode_socks5_udp(data: &[u8], addr: &std::net::SocketAddr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + 18 + data.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    match addr {
        std::net::SocketAddr::V4(a) => {
            packet.push(0x01);
            packet.extend_from_slice(&a.ip().octets());
            packet.extend_from_slice(&a.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(a) => {
            packet.push(0x04);
            packet.extend_from_slice(&a.ip().octets());
            packet.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(data);
    packet
}

pub fn decode_socks5_udp(data: &[u8]) -> Option<(std::net::SocketAddr, Vec<u8>)> {
    if data.len() < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
        return None;
    }

    let atyp = data[3];
    match atyp {
        0x01 => {
            if data.len() < 10 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            if port == 0 {
                return None;
            }
            let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
            Some((addr, data[10..].to_vec()))
        }
        0x04 => {
            if data.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            if port == 0 {
                return None;
            }
            let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0));
            Some((addr, data[22..].to_vec()))
        }
        0x03 => {
            debug!("socks5 udp domain ATYP is unsupported by current UoT address model");
            None
        }
        atyp => {
            debug!("invalid socks5 udp atyp: {}", atyp);
            None
        }
    }
}

pub fn decode_udp_packet(data: &[u8]) -> Option<(std::net::SocketAddr, Vec<u8>)> {
    if data.is_empty() {
        return None;
    }

    let atyp = data[0];
    let (addr, offset) = match atyp {
        0x01 => {
            if data.len() < 8 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            if port == 0 {
                return None;
            }
            (
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)),
                7,
            )
        }
        0x04 => {
            if data.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            if port == 0 {
                return None;
            }
            (
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)),
                19,
            )
        }
        _ => return None,
    };

    if data.len() < offset + 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    if data.len() < offset + 2 + len {
        return None;
    }

    let payload = data[offset + 2..offset + 2 + len].to_vec();
    Some((addr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::is_blocked_destination;

    #[test]
    fn socks5_udp_round_trip_ipv4() {
        let addr = "8.8.8.8:53".parse::<std::net::SocketAddr>().unwrap();
        let packet = encode_socks5_udp(b"abc", &addr);
        let (decoded_addr, payload) = decode_socks5_udp(&packet).unwrap();
        assert_eq!(decoded_addr, addr);
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn uot_rejects_oversized_payload() {
        let addr = "8.8.8.8:53".parse::<std::net::SocketAddr>().unwrap();
        assert!(encode_udp_packet(&vec![0u8; 65529], &addr, 65535).is_err());
    }

    #[test]
    fn uot_rejects_zero_port() {
        assert!(decode_udp_packet(&[0x01, 8, 8, 8, 8, 0, 0, 0, 0]).is_none());
        assert!(decode_socks5_udp(&[0, 0, 0, 0x01, 8, 8, 8, 8, 0, 0]).is_none());
    }

    #[test]
    fn private_address_filter_blocks_local_ranges() {
        for raw in [
            "127.0.0.1:53",
            "10.0.0.1:53",
            "100.64.0.1:53",
            "255.255.255.255:53",
            "240.0.0.1:53",
            "0.0.0.0:53",
            "[::1]:53",
            "[fc00::1]:53",
            "[::ffff:127.0.0.1]:53",
            "[::ffff:10.0.0.1]:53",
        ] {
            let addr = raw.parse::<std::net::SocketAddr>().unwrap();
            assert!(is_blocked_destination(&addr));
        }
    }
}
