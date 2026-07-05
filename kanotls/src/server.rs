use anyhow::Context;
use kanotls_config::server::load_server_config;
use kanotls_config::{find_routing_rule, ServerConfig};
use kanotls_proto::socks5::{
    socks5_handshake, socks5_send_connect, socks5_send_udp_associate, Socks5Target,
};
use kanotls_proto::target::{is_blocked_destination, parse_authority_target};
use kanotls_proto::uot::{
    decode_server_udp, decode_socks5_udp, encode_server_udp, encode_socks5_udp,
};
use kanotls_session::{
    server::{ServerSessionHandler, ServerStream},
    SessionConfig, RELAY_CHUNK_SIZE,
};
use kanotls_tunnel::{init_entropy_pool, server_accept, validate_camouflage_endpoint};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

const MAX_CONCURRENT_SERVER_CONNECTIONS: usize = 4096;

#[derive(Clone)]
enum ServerOutbound {
    Direct,
    Socks5 {
        address: String,
        username: Option<String>,
        password: Option<String>,
    },
}

pub async fn run_server(config_path: &str) -> anyhow::Result<()> {
    let config = load_server_config(config_path)?;
    info!("loaded server config, {} inbounds", config.inbounds.len());

    if config.inbounds.is_empty() {
        anyhow::bail!("no inbounds configured");
    }

    validate_server_routing_runtime(&config)?;

    let inbound = &config.inbounds[0];
    let selected_outbound = resolve_server_outbound(&config, inbound.tag.as_deref())?;
    info!("server outbound: {}", selected_outbound);
    let camouflage_host = &inbound.settings.camouflage.host;
    let camouflage_port = inbound.settings.camouflage.port;

    validate_camouflage_endpoint(camouflage_host, camouflage_port).await?;
    info!(
        "validated camouflage endpoint {}:{}",
        camouflage_host, camouflage_port
    );

    init_entropy_pool();

    let listen_addr = format!("{}:{}", inbound.listen, inbound.port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("server listening on {}", listen_addr);

    let password = inbound.settings.password.clone();
    let camouflage_host = camouflage_host.to_string();
    let max_streams_per_session = inbound
        .settings
        .session
        .as_ref()
        .map(|s| s.max_streams_per_session)
        .unwrap_or(256);
    let idle_timeout_secs = inbound
        .settings
        .session
        .as_ref()
        .map(|s| s.idle_timeout_secs)
        .unwrap_or(45);
    let traffic_script = inbound
        .settings
        .session
        .as_ref()
        .and_then(|s| s.traffic_script.clone());
    let session_config =
        SessionConfig::with_script(false, max_streams_per_session, idle_timeout_secs, traffic_script);

    let shutdown = tokio::sync::watch::channel(false);
    let mut shutdown_rx = shutdown.1.clone();
    let shutdown_tx = shutdown.0;
    let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_SERVER_CONNECTIONS));
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        info!("shutting down...");
        let _ = shutdown_tx.send(true);
    });

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((tcp, addr)) => {
                        if let Err(e) = tcp.set_nodelay(true) {
                            debug!("failed to enable TCP_NODELAY for {}: {}", addr, e);
                        }
                        let permit = match connection_limiter.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!("connection {} rejected: server connection limit reached", addr);
                                continue;
                            }
                        };
                        let psk = password.clone();
                        let host = camouflage_host.clone();
                        let port = camouflage_port;
                        let sess_cfg = session_config.clone();
                        let outbound = selected_outbound.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_server_conn(
                                tcp,
                                addr,
                                &psk,
                                &host,
                                port,
                                sess_cfg,
                                outbound,
                            ).await {
                                let msg = e.to_string();
                                if msg.contains("session shutting down")
                                    || msg.contains("session closed")
                                    || msg.contains("session read loop ended")
                                {
                                    info!("connection {} closed: {}", addr, msg);
                                } else {
                                    error!("connection {} error: {}", addr, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("server stopped");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_server_conn(
    tcp: TcpStream,
    addr: SocketAddr,
    psk: &str,
    camouflage_host: &str,
    camouflage_port: u16,
    session_config: SessionConfig,
    outbound: ServerOutbound,
) -> anyhow::Result<()> {
    let tunnel = server_accept(tcp, psk.as_bytes(), camouflage_host, camouflage_port).await?;
    info!("client {} connected", addr);

    let first_data_timeout = session_config.idle_timeout_secs.clamp(1, 30);
    let handler = ServerSessionHandler::new(tunnel, session_config);

    let session = handler.get_session();
    let _read_handle = tokio::spawn(async move {
        let _ = session.run_read_loop().await;
        info!("read loop ended for {}", addr);
    });

    loop {
        let (sid, stream) = handler.accept_stream().await?;

        let ob = outbound.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_server_stream(sid, stream, first_data_timeout, ob).await {
                warn!("stream {} error: {}", sid, e);
            }
        });
    }
}

fn validate_server_routing_runtime(config: &ServerConfig) -> anyhow::Result<()> {
    let outbound_tags: std::collections::HashSet<_> = config
        .outbounds
        .iter()
        .filter_map(|ob| ob.tag.as_deref())
        .collect();

    for rule in config
        .routing
        .as_ref()
        .into_iter()
        .flat_map(|routing| routing.rules.iter())
    {
        if !outbound_tags.contains(rule.outbound_tag.as_str()) {
            anyhow::bail!(
                "routing rule outbound_tag '{}' not found in configured outbounds",
                rule.outbound_tag
            );
        }
    }

    Ok(())
}

fn resolve_server_outbound(
    config: &ServerConfig,
    inbound_tag: Option<&str>,
) -> anyhow::Result<ServerOutbound> {
    let tag = find_routing_rule(config.routing.as_ref(), inbound_tag)
        .map(|rule| rule.outbound_tag.as_str());

    let tag = match tag {
        Some(tag) => tag,
        None if config.outbounds.is_empty() => {
            anyhow::bail!("no outbounds configured and no routing rule matched");
        }
        None => {
            let fallback_tag = config.outbounds[0].tag.as_deref().unwrap_or("<unnamed>");
            debug!(
                "no routing rule matched inbound {:?}, falling back to outbound '{}'",
                inbound_tag, fallback_tag
            );
            fallback_tag
        }
    };

    let outbound = config
        .outbounds
        .iter()
        .find(|ob| ob.tag.as_deref() == Some(tag))
        .ok_or_else(|| {
            anyhow::anyhow!("outbound tag '{}' not found in configured outbounds", tag)
        })?;

    match outbound.protocol.as_str() {
        "direct" => Ok(ServerOutbound::Direct),
        "socks5" => {
            let s = outbound
                .settings
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("socks5 outbound requires settings"))?;
            let host = s
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("socks5 outbound requires settings.address"))?;
            let port = s
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("socks5 outbound requires settings.port"))?;
            let address = format!("{}:{}", host, port);
            let username = s
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            let password = s
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            Ok(ServerOutbound::Socks5 {
                address,
                username,
                password,
            })
        }
        other => anyhow::bail!("unsupported outbound protocol: {}", other),
    }
}

impl std::fmt::Display for ServerOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerOutbound::Direct => write!(f, "direct"),
            ServerOutbound::Socks5 {
                address, username, ..
            } => {
                if let Some(user) = username {
                    write!(f, "socks5://{}@{}", user, address)
                } else {
                    write!(f, "socks5://{}", address)
                }
            }
        }
    }
}

async fn handle_server_stream(
    sid: u32,
    mut stream: ServerStream,
    first_data_timeout_secs: u64,
    outbound: ServerOutbound,
) -> anyhow::Result<()> {
    let result =
        handle_server_stream_inner(sid, &mut stream, first_data_timeout_secs, &outbound).await;
    let _ = stream.close().await;
    result
}

async fn handle_server_stream_inner(
    sid: u32,
    stream: &mut ServerStream,
    first_data_timeout_secs: u64,
    outbound: &ServerOutbound,
) -> anyhow::Result<()> {
    let first_data = match tokio::time::timeout(
        std::time::Duration::from_secs(first_data_timeout_secs),
        stream.read(),
    )
    .await
    {
        Ok(Some(data)) => data,
        Ok(None) => anyhow::bail!("stream closed before first data"),
        Err(_) => anyhow::bail!("stream first data timeout"),
    };

    let target = String::from_utf8_lossy(&first_data).to_string();
    info!("stream {} connect to {}", sid, target);

    if target.starts_with("udp:") {
        stream.send_synack().await?;
        match outbound {
            ServerOutbound::Socks5 {
                address,
                username,
                password,
            } => {
                let auth = username.as_deref().zip(password.as_deref());
                relay_udp_via_socks5(stream, address, auth).await?;
            }
            ServerOutbound::Direct => {
                let local_udp = UdpSocket::bind("0.0.0.0:0").await?;
                debug!(
                    "stream {} udp-over-tcp via {}",
                    sid,
                    local_udp.local_addr()?
                );
                relay_udp_server(stream, local_udp).await?;
            }
        }
    } else {
        match outbound {
            ServerOutbound::Socks5 {
                address,
                username,
                password,
            } => {
                const SOCKS5_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
                const SOCKS5_COMMAND_TIMEOUT_SECS: u64 = 10;

                let (host, port) = parse_authority_target(&target)?;
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    let sock_addr = SocketAddr::new(ip, port);
                    if is_blocked_destination(&sock_addr) {
                        anyhow::bail!("blocked destination: {}", sock_addr);
                    }
                }

                let socks_target = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => Socks5Target::Ip(SocketAddr::new(ip, port)),
                    Err(_) => Socks5Target::Domain(host.clone(), port),
                };

                let auth = username.as_deref().zip(password.as_deref());

                let mut remote = tokio::time::timeout(
                    Duration::from_secs(SOCKS5_HANDSHAKE_TIMEOUT_SECS),
                    socks5_handshake(address, auth),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "socks5 handshake to {} timed out after {}s",
                        address,
                        SOCKS5_HANDSHAKE_TIMEOUT_SECS
                    )
                })?
                .with_context(|| format!("socks5 handshake to {} failed", address))?;

                tokio::time::timeout(
                    Duration::from_secs(SOCKS5_COMMAND_TIMEOUT_SECS),
                    socks5_send_connect(&mut remote, socks_target),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!("socks5 CONNECT to {} via {} timed out", target, address)
                })?
                .with_context(|| format!("socks5 CONNECT to {} via {} failed", target, address))?;
                remote.set_nodelay(true)?;
                stream.send_synack().await?;
                relay_tcp_server(stream, &mut remote).await?;
            }
            ServerOutbound::Direct => {
                const DIRECT_CONNECT_TIMEOUT_SECS: u64 = 10;
                let remote_addr = validate_remote_target(&target).await?;
                let mut remote = tokio::time::timeout(
                    Duration::from_secs(DIRECT_CONNECT_TIMEOUT_SECS),
                    TcpStream::connect(remote_addr),
                )
                .await
                .map_err(|_| anyhow::anyhow!("direct connect to {} timed out", remote_addr))??;
                remote.set_nodelay(true)?;
                stream.send_synack().await?;
                relay_tcp_server(stream, &mut remote).await?;
            }
        }
    }

    Ok(())
}

async fn validate_remote_target(target: &str) -> anyhow::Result<std::net::SocketAddr> {
    let (host, port) = parse_authority_target(target)?;
    let resolved = tokio::net::lookup_host((host.as_str(), port)).await?;
    let mut first_allowed = None;
    for addr in resolved {
        if is_blocked_destination(&addr) {
            debug!("skipping blocked destination address: {}", addr);
            continue;
        }
        first_allowed.get_or_insert(addr);
    }
    first_allowed.ok_or_else(|| anyhow::anyhow!("unable to resolve target host"))
}

async fn relay_tcp_server(
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

const UDP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

async fn relay_udp_server(
    stream: &mut ServerStream,
    local: UdpSocket,
) -> Result<(), anyhow::Error> {
    let local = Arc::new(local);
    let local_recv = local.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        while let Ok((n, addr)) = local_recv.recv_from(&mut buf).await {
            match encode_server_udp(&buf[..n], &addr) {
                Ok(packet) => {
                    if tx.send(packet).await.is_err() {
                        break;
                    }
                }
                Err(e) => debug!("udp encode error: {}", e),
            }
        }
    });

    loop {
        let idle = tokio::time::sleep(UDP_RELAY_IDLE_TIMEOUT);
        tokio::pin!(idle);

        tokio::select! {
            data = stream.read() => {
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                match data {
                    Some(d) => {
                        if let Some((addr, payload)) = decode_server_udp(&d) {
                            if is_blocked_destination(&addr) {
                                debug!("udp blocked: private addr {}", addr);
                                continue;
                            }
                            let _ = local.send_to(&payload, addr).await;
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
                return Ok(());
            }
        }
    }

    recv_task.abort();
    Ok(())
}

async fn relay_udp_via_socks5(
    stream: &mut ServerStream,
    socks5_addr: &str,
    auth: Option<(&str, &str)>,
) -> Result<(), anyhow::Error> {
    // 1. establish TCP control channel and get UDP relay address
    const SOCKS5_UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    let mut tcp_control = tokio::time::timeout(
        SOCKS5_UDP_HANDSHAKE_TIMEOUT,
        socks5_handshake(socks5_addr, auth),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "socks5 UDP handshake to {} timed out after {}s",
            socks5_addr,
            SOCKS5_UDP_HANDSHAKE_TIMEOUT.as_secs()
        )
    })??;
    let relay_addr = tokio::time::timeout(
        SOCKS5_UDP_HANDSHAKE_TIMEOUT,
        socks5_send_udp_associate(&mut tcp_control),
    )
    .await
    .map_err(|_| anyhow::anyhow!("socks5 UDP ASSOCIATE to {} timed out", socks5_addr))??;
    debug!(
        "udp via socks5: relay address {} (control {})",
        relay_addr, socks5_addr
    );

    // 2. bind local UDP socket for data channel
    let local_udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // 3. TCP control channel liveness monitor
    let control_alive = Arc::new(AtomicBool::new(true));
    let alive_flag = control_alive.clone();
    let _control_guard = AbortOnDrop(tokio::spawn(async move {
        let mut ctrl = tcp_control;
        let mut buf = [0u8; 1];
        if ctrl.read(&mut buf).await.is_err() || buf.is_empty() {
            alive_flag.store(false, Ordering::SeqCst);
        }
    }));

    // 4. UDP recv task: SOCKS5 relay -> UoT -> kanotls stream
    let local_recv = local_udp.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
    let recv_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        while let Ok((n, src)) = local_recv.recv_from(&mut buf).await {
            if src != relay_addr {
                continue;
            }
            if let Some((src_addr, payload)) = decode_socks5_udp(&buf[..n]) {
                match encode_server_udp(&payload, &src_addr) {
                    Ok(packet) => {
                        if tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => debug!("udp via socks5 encode error: {}", e),
                }
            }
        }
    });

    // 5. main relay loop
    loop {
        let idle = tokio::time::sleep(UDP_RELAY_IDLE_TIMEOUT);
        tokio::pin!(idle);

        tokio::select! {
            data = stream.read() => {
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                match data {
                    Some(d) => {
                        if let Some((target, payload)) = decode_server_udp(&d) {
                            if is_blocked_destination(&target) {
                                debug!("udp via socks5 blocked: private addr {}", target);
                                continue;
                            }
                            let packet = encode_socks5_udp(&payload, &target);
                            let _ = local_udp.send_to(&packet, relay_addr).await;
                        }
                    }
                    None => break,
                }
            }
            Some(packet) = rx.recv() => {
                idle.as_mut().reset(Instant::now() + UDP_RELAY_IDLE_TIMEOUT);
                if let Err(e) = stream.write(&packet).await {
                    debug!("udp via socks5 stream write error: {}", e);
                    break;
                }
            }
            _ = &mut idle => {
                debug!("udp via socks5 relay idle timeout");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(500)), if !control_alive.load(Ordering::SeqCst) => {
                anyhow::bail!("SOCKS5 UDP control channel closed");
            }
        }
    }

    recv_handle.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_supports_ipv4_domain_and_ipv6() {
        assert_eq!(
            parse_authority_target("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority_target("1.2.3.4:80").unwrap(),
            ("1.2.3.4".to_string(), 80)
        );
        assert_eq!(
            parse_authority_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn blocks_private_and_loopback_addresses() {
        for raw in [
            "127.0.0.1:80",
            "10.0.0.1:80",
            "192.168.1.1:80",
            "0.0.0.0:80",
            "224.0.0.1:80",
            "100.64.0.1:80",
            "100.127.255.255:80",
            "255.255.255.255:80",
            "240.0.0.1:80",
            "[::1]:80",
            "[fc00::1]:80",
            "[::]:80",
            "[::ffff:127.0.0.1]:80",
            "[::ffff:10.0.0.1]:80",
            "[::ffff:100.64.0.1]:80",
        ] {
            let addr = raw.parse::<std::net::SocketAddr>().unwrap();
            assert!(is_blocked_destination(&addr), "{} should be blocked", raw);
        }
    }

    #[test]
    fn split_host_port_rejects_missing_or_zero_port() {
        assert!(parse_authority_target("example.com").is_err());
        assert!(parse_authority_target("example.com:0").is_err());
        assert!(parse_authority_target("[2001:db8::1]:0").is_err());
    }
}
