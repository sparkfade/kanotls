//! 数据管线闭环：本地连接 ↔ 隧道流的双向中继（TCP 与 UoT）。

use kanotls_proto::outbound::UdpRelay;
use kanotls_proto::target::is_blocked_destination;
use kanotls_proto::uot::{decode_udp_packet, encode_udp_packet};
use kanotls_session::frame::MAX_PAYLOAD_LEN;
use kanotls_session::server::ServerStream;
use kanotls_session::{Stream, RELAY_CHUNK_SIZE};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;
use tracing::debug;

const UDP_CHANNEL_CAPACITY: usize = 128;
const UDP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// 客户端 TCP 中继：本地连接 ↔ 隧道流，返回 (tx, rx) 字节数。
pub async fn relay_tcp_client(
    mut local_reader: impl AsyncReadExt + Unpin,
    mut local_writer: impl AsyncWriteExt + Unpin,
    mut remote: Stream,
) -> Result<(u64, u64), anyhow::Error> {
    let mut tx_total: u64 = 0;
    let mut rx_total: u64 = 0;
    let mut read_buf = vec![0u8; RELAY_CHUNK_SIZE];
    let mut local_eof = false;
    let mut remote_eof = false;

    while !local_eof || !remote_eof {
        tokio::select! {
            result = local_reader.read(&mut read_buf), if !local_eof => {
                match result {
                    Ok(0) => {
                        let _ = remote.close_write().await;
                        local_eof = true;
                    }
                    Ok(n) => {
                        remote.write(&read_buf[..n]).await?;
                        tx_total += n as u64;
                    }
                    Err(_) => {
                        let _ = remote.close_write().await;
                        local_eof = true;
                    }
                }
            }
            data = remote.read(), if !remote_eof => {
                match data {
                    Some(d) => {
                        local_writer.write_all(&d).await?;
                        rx_total += d.len() as u64;
                        // 字节已交付本地应用：回补对端窗口（H2 流控语义）。
                        remote.note_consumed(d.len());
                    }
                    None => {
                        local_writer.shutdown().await?;
                        remote_eof = true;
                    }
                }
            }
        }
    }

    let _ = remote.close().await;
    Ok((tx_total, rx_total))
}

/// 服务端 TCP 中继：隧道流 ↔ 远端连接。
pub async fn relay_tcp_server(
    stream: &mut ServerStream,
    remote: &mut TcpStream,
) -> Result<(), anyhow::Error> {
    let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
    let mut stream_eof = false;
    let mut remote_eof = false;
    while !stream_eof || !remote_eof {
        tokio::select! {
            data = stream.read(), if !stream_eof => {
                match data {
                    Some(d) => {
                        remote.write_all(&d).await?;
                        // 字节已交付远端：回补对端窗口（H2 流控语义）。
                        stream.note_consumed(d.len());
                    }
                    None => {
                        let _ = remote.shutdown().await;
                        stream_eof = true;
                    }
                }
            }
            result = remote.read(&mut buf), if !remote_eof => {
                match result {
                    Ok(0) => {
                        let _ = stream.close_write().await;
                        remote_eof = true;
                    }
                    Ok(n) => {
                        stream.write(&buf[..n]).await?;
                    }
                    Err(e) => {
                        debug!("remote read error: {}", e);
                        let _ = stream.close_write().await;
                        remote_eof = true;
                    }
                }
            }
        }
    }
    let _ = stream.close().await;
    Ok(())
}

/// 服务端 UoT 中继：隧道流 ↔ 出站 UDP 通道（直连或 socks5 中继，
/// 封装差异由 [`UdpRelay`] 内部消化）。
pub async fn relay_udp_server(
    stream: &mut ServerStream,
    relay: UdpRelay,
) -> Result<(), anyhow::Error> {
    let relay = Arc::new(relay);
    let relay_recv = relay.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(UDP_CHANNEL_CAPACITY);

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        while let Some((addr, payload)) = relay_recv.recv(&mut buf).await {
            match encode_udp_packet(&payload, &addr, MAX_PAYLOAD_LEN) {
                Ok(packet) => {
                    if tx.send(packet).await.is_err() {
                        break;
                    }
                }
                Err(e) => debug!("udp encode error: {}", e),
            }
        }
    });

    // idle 定时器循环外创建：任一方向有流量才重置，持续空闲
    // UDP_RELAY_IDLE_TIMEOUT 后结束中继。
    let idle = tokio::time::sleep(UDP_RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            data = stream.read() => {
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                match data {
                    Some(d) => {
                        if let Some((addr, payload)) = decode_udp_packet(&d) {
                            if is_blocked_destination(&addr) {
                                debug!("udp blocked: private addr {}", addr);
                                continue;
                            }
                            let _ = relay.send_to(&payload, &addr).await;
                            stream.note_consumed(payload.len());
                        }
                    }
                    None => break,
                }
            }
            Some(packet) = rx.recv() => {
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                if let Err(e) = stream.write(&packet).await {
                    debug!("udp write error: {}", e);
                    break;
                }
            }
            _ = &mut idle => {
                debug!("udp relay idle timeout");
                break;
            }
            // RFC 1928: UDP 关联随 TCP 控制连接关闭而终止（直连无控制面，
            // is_control_alive 恒 true，该分支永不触发）。
            _ = tokio::time::sleep(Duration::from_millis(500)), if !relay.is_control_alive() => {
                recv_task.abort();
                anyhow::bail!("SOCKS5 UDP control channel closed");
            }
        }
    }

    recv_task.abort();
    Ok(())
}

/// 客户端 UoT 中继：隧道流 ↔ 本地 UDP socket（socks5 UDP 关联的本地端）。
pub async fn relay_udp_client_mode(
    mut stream: Stream,
    local: UdpSocket,
    client_ip: std::net::IpAddr,
    mut control_reader: impl AsyncReadExt + Unpin,
) -> Result<(), anyhow::Error> {
    let local_addr = local.local_addr()?;
    debug!("udp client bound to {}", local_addr);

    let local = Arc::new(local);
    let local_recv = local.clone();
    let peer = Arc::new(tokio::sync::Mutex::new(None::<std::net::SocketAddr>));
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
            if let Some((target, payload)) = kanotls_proto::uot::decode_socks5_udp(&buf[..n]) {
                if locked.is_none() {
                    *peer_recv.lock().await = Some(addr);
                }
                match encode_udp_packet(&payload, &target, MAX_PAYLOAD_LEN) {
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
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                match data {
                    Some(d) => {
                        if let Some((addr, payload)) = decode_udp_packet(&d) {
                            if let Some(peer_addr) = *peer.lock().await {
                                let packet = kanotls_proto::uot::encode_socks5_udp(&payload, &addr);
                                let _ = local.send_to(&packet, peer_addr).await;
                                stream.note_consumed(payload.len());
                            }
                        }
                    }
                    None => break,
                }
            }
            Some(packet) = rx.recv() => {
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
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
