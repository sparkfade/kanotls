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
///
/// 上行与下行跑在两个独立任务里（流经 `into_split` 拆半）：写方向在流控门
/// （等 WINDOW_UPDATE）挂起时，读方向的交付与回补照常进行。拆分前的单任务
/// `select!` 里 `write().await` 一旦挂起会连带冻住 `read()`——读方向停摆、
/// 反向回补中断，双向饱和时两端互等形成无定时器的死锁环。
pub async fn relay_tcp_client(
    mut local_reader: impl AsyncReadExt + Unpin + Send + 'static,
    mut local_writer: impl AsyncWriteExt + Unpin,
    remote: Stream,
) -> Result<(u64, u64), anyhow::Error> {
    let (mut remote_read, mut remote_write) = remote.into_split();

    let up = tokio::spawn(async move {
        let mut tx_total = 0u64;
        let mut read_buf = vec![0u8; RELAY_CHUNK_SIZE];
        // 开流宽限期（服务端先说话的协议，见 stream.rs 的
        // DEFERRED_OPEN_GRACE）：本地一直不写也要把 SYN+目标冲刷出去。
        // 一次性计时器；若首写已先行把开流发出，触发时是空操作。
        let grace_deadline = remote_write.open_grace_deadline();
        let grace = tokio::time::sleep_until(
            grace_deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600)),
        );
        tokio::pin!(grace);
        let mut grace_armed = grace_deadline.is_some();
        loop {
            tokio::select! {
                result = local_reader.read(&mut read_buf) => {
                    match result {
                        Ok(0) => {
                            remote_write.close_write().await?;
                            break;
                        }
                        Ok(n) => {
                            remote_write.write(&read_buf[..n]).await?;
                            tx_total += n as u64;
                        }
                        Err(_) => {
                            remote_write.close_write().await?;
                            break;
                        }
                    }
                }
                _ = &mut grace, if grace_armed => {
                    grace_armed = false;
                    remote_write.flush_unsent_open_if_pending().await?;
                }
            }
        }
        Ok::<u64, anyhow::Error>(tx_total)
    });

    let mut rx_total = 0u64;
    let down_result: Result<(), anyhow::Error> = async {
        while let Some(d) = remote_read.read().await {
            local_writer.write_all(&d).await?;
            rx_total += d.len() as u64;
            // 字节已交付本地应用：回补对端每流窗口（H2 流控语义）。
            remote_read.note_consumed(d.len());
        }
        local_writer.shutdown().await?;
        Ok(())
    }
    .await;

    // 两个方向都终结后汇总。任一出错时两半句柄随任务/作用域先后
    // drop，拆除协调器（StreamTeardown）保证整流清理恰好执行一次。
    let tx_total = up.await??;
    down_result?;
    Ok((tx_total, rx_total))
}

/// 服务端 TCP 中继：隧道流 ↔ 远端连接。
///
/// 上行（源站 → 隧道）经 `write_handle` 独立成任务，与客户端拆半同一
/// 目的：写方向在流控门挂起时读方向不被冻结。
pub async fn relay_tcp_server(
    stream: &mut ServerStream,
    remote: TcpStream,
) -> Result<(), anyhow::Error> {
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let stream_write = stream.write_handle();

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        loop {
            match remote_reader.read(&mut buf).await {
                Ok(0) => {
                    stream_write.close_write().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                Ok(n) => {
                    stream_write.write(&buf[..n]).await?;
                }
                Err(e) => {
                    debug!("remote read error: {}", e);
                    stream_write.close_write().await?;
                    return Ok::<(), anyhow::Error>(());
                }
            }
        }
    });

    let down_result: Result<(), anyhow::Error> = async {
        while let Some(d) = stream.read().await {
            remote_writer.write_all(&d).await?;
            // 字节已交付远端：回补对端每流窗口（H2 流控语义）。
            stream.note_consumed(d.len());
        }
        remote_writer.shutdown().await?;
        Ok(())
    }
    .await;

    up.await??;
    down_result
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
                            // 回补口径必须与发送方扣费一致：对端按编码后整包
                            // （d）扣信贷，故按 d.len() 回补，而不是剥掉 UoT
                            // 头后的 payload——每个包漏 9/21 字节会在长 QUIC
                            // 流上把窗口慢慢漏干。被拦截的包同样已占过窗口，
                            // 一样要补。
                            if is_blocked_destination(&addr) {
                                debug!("udp blocked: private addr {}", addr);
                                stream.note_consumed(d.len());
                                continue;
                            }
                            let _ = relay.send_to(&payload, &addr).await;
                            stream.note_consumed(d.len());
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
                                // 与服务端同口径：按编码后整包回补（对端按
                                // 整包扣信贷），避免每包 9/21 字节的慢性泄漏。
                                stream.note_consumed(d.len());
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
