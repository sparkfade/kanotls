use kanotls_session::frame::MAX_PAYLOAD_LEN;
use kanotls_session::Stream;
use kanotls_session::RELAY_CHUNK_SIZE;
use tokio::net::UdpSocket;
use tracing::debug;

const UDP_CHANNEL_CAPACITY: usize = 128;
const UDP_RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub async fn relay_udp_client_mode(
    mut stream: Stream,
    local: UdpSocket,
    client_ip: std::net::IpAddr,
    mut control_reader: impl tokio::io::AsyncReadExt + Unpin,
) -> Result<(), anyhow::Error> {
    let local_addr = local.local_addr()?;
    debug!("udp client bound to {}", local_addr);

    let local = std::sync::Arc::new(local);
    let local_recv = local.clone();
    let peer = std::sync::Arc::new(tokio::sync::Mutex::new(None::<std::net::SocketAddr>));
    let peer_recv = peer.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel(UDP_CHANNEL_CAPACITY);

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        while let Ok((n, addr)) = local_recv.recv_from(&mut buf).await {
            // RFC 1928 section 7: only the client holding the TCP control
            // connection may use this UDP association. Lock onto the source
            // address of its first valid datagram and reject everything else.
            let locked = *peer_recv.lock().await;
            match locked {
                Some(expected) if expected != addr => continue,
                None if addr.ip() != client_ip => continue,
                _ => {}
            }
            if let Some((target, payload)) = decode_socks5_udp(&buf[..n]) {
                if locked.is_none() {
                    *peer_recv.lock().await = Some(addr);
                }
                match encode_udp_packet(&payload, &target) {
                    Ok(packet) => {
                        if tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => debug!("udp encode error: {}", e),
                }
            }
        }
    });

    let mut ctrl_buf = [0u8; 1];
    // idle 定时器循环外创建：任一方向有流量才重置，持续空闲
    // UDP_RELAY_IDLE_TIMEOUT 后终止本次 UDP 关联。
    let idle = tokio::time::sleep(UDP_RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            data = stream.read() => {
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                match data {
                    Some(d) => {
                        if let Some((addr, payload)) = decode_udp_packet(&d) {
                            if let Some(peer_addr) = *peer.lock().await {
                                let packet = encode_socks5_udp(&payload, &addr);
                                let _ = local.send_to(&packet, peer_addr).await;
                            }
                        }
                    }
                    None => break,
                }
            }
            Some(packet) = rx.recv() => {
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                if let Err(e) = stream.write(&packet).await {
                    debug!("udp write error: {}", e);
                    break;
                }
            }
            // RFC 1928: the UDP association ends when the TCP control
            // connection closes.
            result = control_reader.read(&mut ctrl_buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("udp control connection closed");
                        break;
                    }
                    Ok(_) => {}
                }
            }
            _ = &mut idle => {
                debug!("udp client relay idle timeout");
                break;
            }
        }
    }

    recv_task.abort();
    Ok(())
}

pub fn encode_udp_packet(
    data: &[u8],
    addr: &std::net::SocketAddr,
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

    let max_data_len = MAX_PAYLOAD_LEN.saturating_sub(encoded_addr.len() + 2);
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
        assert!(encode_udp_packet(&vec![0u8; MAX_PAYLOAD_LEN - 6], &addr).is_err());
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
