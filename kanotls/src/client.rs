use kanotls_config::client::load_client_config;
use kanotls_config::{find_routing_rule, ClientConfig, ClientOutbound};
use kanotls_proto::http::{parse_http_inbound, relay_http_connect, write_http_connect_success};
use kanotls_proto::socks5::{
    parse_socks5_inbound, relay_socks5_connect, write_socks5_connect_success,
    write_socks5_udp_success, Socks5Request,
};
use kanotls_session::{
    ClientPool, ClientPoolConnectOptions, PoolBehaviorConfig, SessionConfig, Stream,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

const MAX_CONCURRENT_CLIENT_CONNECTIONS: usize = 4096;
const MIN_CLIENT_IDLE_TIMEOUT_SECS: u64 = 5;
const MAX_CLIENT_IDLE_TIMEOUT_SECS: u64 = 3600;

pub async fn run_client(config_path: &str) -> anyhow::Result<()> {
    let config = load_client_config(config_path)?;
    info!(
        "loaded client config, {} inbounds, {} outbounds",
        config.inbounds.len(),
        config.outbounds.len()
    );

    if config.outbounds.is_empty() {
        anyhow::bail!("no outbounds configured");
    }

    validate_client_routing_runtime(&config)?;

    // Eagerly materialize the shared high-entropy noise pool so the first
    // shaped record does not pay the 8 MiB CSPRNG fill on the hot path.
    kanotls_tunnel::init_entropy_pool();

    let outbound = &config.outbounds[0];
    let server_addr = format!("{}:{}", outbound.settings.server, outbound.settings.port);
    let sni = outbound.settings.tls.sni.clone();
    let password = outbound.settings.password.clone();
    let insecure = outbound.settings.tls.insecure;
    let fingerprint = outbound
        .settings
        .tls
        .fingerprint
        .clone()
        .or_else(|| Some("firefox".to_string()));
    let tpl_path = outbound.settings.tls.template_path.as_ref();

    const TEMPLATE_RELOAD_INTERVAL_SECS: u64 = 30;

    let custom_template_bytes = Arc::new(RwLock::new(match tpl_path {
        Some(path) => Some(kanotls_tunnel::templates::load_and_validate_custom_template(path)?),
        None => None,
    }));

    if let Some(path_str) = tpl_path.cloned() {
        let watcher_bytes = custom_template_bytes.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(TEMPLATE_RELOAD_INTERVAL_SECS));
            ticker.tick().await;
            let mut last_mtime = std::time::SystemTime::UNIX_EPOCH;
            loop {
                ticker.tick().await;
                match tokio::fs::metadata(&path_str).await {
                    Ok(meta) => match meta.modified() {
                        Ok(mtime) if mtime > last_mtime => {
                            last_mtime = mtime;
                            match kanotls_tunnel::templates::load_and_validate_custom_template(
                                &path_str,
                            ) {
                                Ok(bytes) => {
                                    *watcher_bytes.write().await = Some(bytes);
                                    kanotls_tunnel::invalidate_client_hello_template_cache();
                                    info!("hot-reloaded ClientHello template from {}", path_str);
                                }
                                Err(e) => {
                                    warn!("hot-reload: failed to parse template {}: {} (keeping previous)", path_str, e);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => warn!("hot-reload: failed to read mtime of {}: {}", path_str, e),
                    },
                    Err(e) => warn!("hot-reload: failed to stat {}: {}", path_str, e),
                }
            }
        });
    }

    let max_streams_per_session = outbound
        .settings
        .session
        .as_ref()
        .map(|s| s.max_streams_per_session)
        .unwrap_or(256);
    let idle_timeout_secs = outbound
        .settings
        .session
        .as_ref()
        .map(|s| s.idle_timeout_secs)
        .unwrap_or(45)
        .clamp(MIN_CLIENT_IDLE_TIMEOUT_SECS, MAX_CLIENT_IDLE_TIMEOUT_SECS);
    let install_salt: [u8; 16] = rand::random();
    let traffic_script = outbound
        .settings
        .session
        .as_ref()
        .and_then(|s| s.traffic_script.clone());
    let pool = Arc::new(ClientPool::new(
        SessionConfig::with_script(true, max_streams_per_session, idle_timeout_secs, traffic_script),
        ClientPoolConnectOptions {
            server_addr: server_addr.clone(),
            sni: sni.clone(),
            psk: password.as_bytes().to_vec(),
            insecure,
            fingerprint: fingerprint.clone(),
            custom_template_bytes: custom_template_bytes.clone(),
        },
        PoolBehaviorConfig::from_psk(password.as_bytes(), &install_salt),
    ));

    let mut handles = vec![];
    let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENT_CONNECTIONS));
    for inbound in &config.inbounds {
        let listen_addr = format!("{}:{}", inbound.listen, inbound.port);
        let protocol = inbound.protocol.clone();
        let inbound_tag = inbound.tag.clone();
        let selected_outbound_tag = select_client_outbound_tag(&config, inbound_tag.as_deref())?;
        let pool_clone = pool.clone();
        let inbound_connection_limiter = connection_limiter.clone();

        let handle = tokio::spawn(async move {
            let listener = match TcpListener::bind(&listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("cannot bind {}: {}", listen_addr, e);
                    return;
                }
            };
            info!(
                "{} proxy listening on {} via outbound {}",
                protocol, listen_addr, selected_outbound_tag
            );

            loop {
                match listener.accept().await {
                    Ok((local, addr)) => {
                        if let Err(e) = local.set_nodelay(true) {
                            debug!("failed to enable TCP_NODELAY for {}: {}", addr, e);
                        }
                        let permit = match inbound_connection_limiter.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!(
                                    "connection {} rejected: client connection limit reached",
                                    addr
                                );
                                continue;
                            }
                        };
                        let p = protocol.clone();
                        let pool = pool_clone.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            let result = match p.as_str() {
                                "socks5" | "socks" => handle_socks5_connection(local, &pool).await,
                                "http" => handle_http_connection(local, &pool).await,
                                _ => {
                                    error!("unsupported protocol: {}", p);
                                    return;
                                }
                            };

                            if let Err(e) = result {
                                debug!("proxy error for {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("accept error on {}: {}", listen_addr, e);
                    }
                }
            }
        });

        handles.push(handle);
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("client shutting down...");
        }
        _ = async {
            for handle in handles {
                let _ = handle.await;
            }
        } => {}
    }

    info!("client stopped");
    Ok(())
}

fn validate_client_routing_runtime(config: &ClientConfig) -> anyhow::Result<()> {
    if config.outbounds.is_empty() {
        return Ok(());
    }

    let first_tag = config.outbounds[0].tag.as_deref();

    for rule in config
        .routing
        .as_ref()
        .into_iter()
        .flat_map(|routing| routing.rules.iter())
    {
        if Some(rule.outbound_tag.as_str()) != first_tag {
            anyhow::bail!(
                "routing rule outbound_tag '{}' is configured, but the current client runtime only supports the first outbound{}",
                rule.outbound_tag,
                first_tag
                    .map(|tag| format!(" ('{}')", tag))
                    .unwrap_or_default()
            );
        }
    }

    Ok(())
}

fn select_client_outbound_tag(
    config: &ClientConfig,
    inbound_tag: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(rule) = find_routing_rule(config.routing.as_ref(), inbound_tag) {
        return Ok(rule.outbound_tag.clone());
    }

    Ok(first_outbound_tag(&config.outbounds))
}

fn first_outbound_tag(outbounds: &[ClientOutbound]) -> String {
    outbounds
        .first()
        .and_then(|outbound| outbound.tag.clone())
        .unwrap_or_else(|| "<unnamed>".to_string())
}

async fn handle_socks5_connection(
    local: tokio::net::TcpStream,
    pool: &Arc<ClientPool>,
) -> anyhow::Result<()> {
    match parse_socks5_inbound(local).await? {
        Socks5Request::Connect {
            local_reader,
            mut local_writer,
            target,
        } => {
            let mut stream = create_or_reuse_stream(pool).await?;
            stream.defer_target(target.as_bytes());
            write_socks5_connect_success(&mut local_writer).await?;
            let (tx, rx) = relay_socks5_connect(local_reader, local_writer, stream).await?;
            debug!("socks5 relay done: tx={} rx={}", tx, rx);
        }
        Socks5Request::UdpAssociate {
            local_reader,
            mut local_writer,
            udp,
            target,
        } => {
            let udp_addr = udp.local_addr()?;
            let mut stream = create_or_reuse_stream(pool).await?;
            stream.write_early(target.as_bytes()).await?;
            stream.wait_open().await?;
            write_socks5_udp_success(&mut local_writer, udp_addr).await?;
            let control = (local_reader, local_writer);
            let result = kanotls_proto::uot::relay_udp_client_mode(stream, udp).await;
            drop(control);
            result?;
        }
    }
    Ok(())
}

async fn handle_http_connection(
    local: tokio::net::TcpStream,
    pool: &Arc<ClientPool>,
) -> anyhow::Result<()> {
    let req = parse_http_inbound(local).await?;
    let mut stream = create_or_reuse_stream(pool).await?;
    stream.defer_target(req.target.as_bytes());
    let mut local_writer = req.local_writer;
    write_http_connect_success(&mut local_writer).await?;
    let (tx, rx) = relay_http_connect(req.local_reader, local_writer, stream).await?;
    debug!("http relay done: tx={} rx={}", tx, rx);
    Ok(())
}

async fn create_or_reuse_stream(pool: &Arc<ClientPool>) -> anyhow::Result<Stream> {
    pool.open_stream().await
}
