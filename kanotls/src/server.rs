use crate::relay;
use kanotls_config::server::load_server_config;
use kanotls_config::{find_routing_rule, ServerConfig};
use kanotls_proto::outbound::Outbound;
use kanotls_proto::target::{Network, Target};
use kanotls_session::{
    server::{ServerSessionHandler, ServerStream},
    SessionConfig,
};
use kanotls_tunnel::{init_entropy_pool, server_accept, validate_camouflage_endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

const MAX_CONCURRENT_SERVER_CONNECTIONS: usize = 4096;

pub async fn run_server(config_path: &str) -> anyhow::Result<()> {
    let config = load_server_config(config_path)?;
    info!("loaded server config, {} inbounds", config.inbounds.len());

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
    let post_script_off = inbound
        .settings
        .session
        .as_ref()
        .is_some_and(|s| s.post_script_shaping.as_deref() == Some("off"));
    let session_config = SessionConfig::with_script(
        false,
        max_streams_per_session,
        idle_timeout_secs,
        traffic_script,
        post_script_off,
    );

    let shutdown = tokio::sync::watch::channel(false);
    let mut shutdown_rx = shutdown.1.clone();
    let shutdown_tx = shutdown.0;
    let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_SERVER_CONNECTIONS));
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        info!("shutting down...");
        let _ = shutdown_tx.send(true);
    });

    let mut accept_error_delay = Duration::from_millis(10);
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((tcp, addr)) => {
                        accept_error_delay = Duration::from_millis(10);
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
                        tokio::time::sleep(accept_error_delay).await;
                        accept_error_delay = (accept_error_delay * 2).min(Duration::from_secs(1));
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
    tcp: tokio::net::TcpStream,
    addr: SocketAddr,
    psk: &str,
    camouflage_host: &str,
    camouflage_port: u16,
    session_config: SessionConfig,
    outbound: Outbound,
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

fn resolve_server_outbound(
    config: &ServerConfig,
    inbound_tag: Option<&str>,
) -> anyhow::Result<Outbound> {
    let outbound = match find_routing_rule(config.routing.as_ref(), inbound_tag) {
        Some(rule) => {
            let tag = rule.outbound_tag.as_str();
            config
                .outbounds
                .iter()
                .find(|ob| ob.tag.as_deref() == Some(tag))
                .ok_or_else(|| {
                    anyhow::anyhow!("outbound tag '{}' not found in configured outbounds", tag)
                })?
        }
        None if config.outbounds.is_empty() => {
            anyhow::bail!("no outbounds configured and no routing rule matched");
        }
        None => {
            debug!(
                "no routing rule matched inbound {:?}, falling back to outbound '{}'",
                inbound_tag,
                config.outbounds[0].tag.as_deref().unwrap_or("<unnamed>")
            );
            &config.outbounds[0]
        }
    };

    match outbound.protocol.as_str() {
        "direct" => Ok(Outbound::direct()),
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
            Ok(Outbound::socks5(address, username, password))
        }
        other => anyhow::bail!("unsupported outbound protocol: {}", other),
    }
}

async fn handle_server_stream(
    sid: u32,
    mut stream: ServerStream,
    first_data_timeout_secs: u64,
    outbound: Outbound,
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
    outbound: &Outbound,
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

    let target = Target::decode_wire(&first_data)?;
    info!("stream {} connect to {}", sid, target);

    match target.network {
        Network::Udp => {
            stream.send_synack().await?;
            let relay = outbound.udp_associate().await?;
            debug!("stream {} udp-over-tcp via {}", sid, relay.local_addr()?);
            relay::relay_udp_server(stream, relay).await?;
        }
        Network::Tcp => {
            let mut remote = outbound.connect(&target).await?;
            stream.send_synack().await?;
            relay::relay_tcp_server(stream, &mut remote).await?;
        }
    }

    Ok(())
}
