use crate::connector::{KanotlsConnector, TunnelConnectOptions};
use crate::{relay, template_watch};
use kanotls_config::client::load_client_config;
use kanotls_config::{find_routing_rule, ClientConfig, ClientOutbound};
use kanotls_pool::{ClientPool, PoolBehaviorConfig, PoolBehaviorContext};
use kanotls_proto::inbound::{InboundKind, InboundRequest};
use kanotls_session::SessionConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info};

const MAX_CONCURRENT_CLIENT_CONNECTIONS: usize = 4096;
const MIN_CLIENT_IDLE_TIMEOUT_SECS: u64 = 5;
const MAX_CLIENT_IDLE_TIMEOUT_SECS: u64 = 3600;

type TunnelPool = ClientPool<KanotlsConnector>;

pub async fn run_client(config_path: &str) -> anyhow::Result<()> {
    let config = load_client_config(config_path)?;
    info!(
        "loaded client config, {} inbounds, {} outbounds",
        config.inbounds.len(),
        config.outbounds.len()
    );

    validate_client_routing_runtime(&config)?;

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

    let custom_template_bytes = Arc::new(RwLock::new(match tpl_path {
        Some(path) => Some(kanotls_tunnel::templates::load_and_validate_custom_template(path)?),
        None => None,
    }));

    if let Some(path_str) = tpl_path.cloned() {
        template_watch::spawn_template_watcher(path_str, custom_template_bytes.clone());
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
        .unwrap_or(75)
        .clamp(MIN_CLIENT_IDLE_TIMEOUT_SECS, MAX_CLIENT_IDLE_TIMEOUT_SECS);
    let install_salt: [u8; 16] = rand::random();
    let traffic_script = outbound
        .settings
        .session
        .as_ref()
        .and_then(|s| s.traffic_script.clone());
    let post_script_off = outbound
        .settings
        .session
        .as_ref()
        .is_some_and(|s| s.post_script_shaping.as_deref() == Some("off"));
    let session_config = SessionConfig::with_script(
        true,
        max_streams_per_session,
        idle_timeout_secs,
        traffic_script,
        post_script_off,
    );
    let fingerprint_family = kanotls_config::normalize_tls_fingerprint(
        fingerprint.as_deref().unwrap_or("firefox"),
    )
    .unwrap_or("firefox");
    let pool = Arc::new(TunnelPool::new(
        session_config.clone(),
        PoolBehaviorConfig::from_psk(password.as_bytes(), &install_salt),
        PoolBehaviorContext::new(fingerprint_family, &sni),
        Arc::new(KanotlsConnector::new(
            session_config,
            TunnelConnectOptions {
                server_addr: server_addr.clone(),
                sni: sni.clone(),
                psk: password.as_bytes().to_vec(),
                insecure,
                fingerprint: fingerprint.clone(),
                custom_template_bytes: custom_template_bytes.clone(),
            },
        )),
    ));

    // 此前这里会在启动时后台建立一条一次性「预检」隧道，握手成功后立刻
    // shutdown。它在线上的形态是：ClientHello → 服务端 flight → 客户端
    // flight → 24 字节 close_notify → FIN，零条数据记录，且恒定是进程的
    // 第一条连接。「完成 TLS 握手、不发任何应用数据、约 1 个 RTT 内主动
    // 关闭」是 TLS 扫描器与健康检查的形态——浏览器的投机预连接会空闲留存
    // 一段时间，绝不会在 Finished 之后立刻发 close_notify。叠加它在进程
    // 生命周期中的固定位置，构成一条稳定的启动签名。
    //
    // 预检唯一不可替代的价值是错误分类（区分「服务端拒绝认证后走了
    // fallback 透明中继」与普通网络不可达），该分类已移入
    // `KanotlsConnector::connect()` 的失败路径：池的第一条真实连接会自然
    // 触发同样的诊断，于是既消除了这条异常连接，又省掉一次多余握手。
    let mut handles = vec![];
    let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENT_CONNECTIONS));
    for inbound in &config.inbounds {
        let listen_addr = format!("{}:{}", inbound.listen, inbound.port);
        let Some(kind) = InboundKind::from_protocol(&inbound.protocol) else {
            error!("unsupported protocol: {}", inbound.protocol);
            continue;
        };
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
                kind.as_str(),
                listen_addr,
                selected_outbound_tag
            );

            let mut accept_error_delay = Duration::from_millis(10);
            loop {
                match listener.accept().await {
                    Ok((local, addr)) => {
                        accept_error_delay = Duration::from_millis(10);
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
                        let pool = pool_clone.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_inbound_connection(local, kind, &pool).await {
                                debug!("proxy error for {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("accept error on {}: {}", listen_addr, e);
                        tokio::time::sleep(accept_error_delay).await;
                        accept_error_delay = (accept_error_delay * 2).min(Duration::from_secs(1));
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

fn validate_client_routing_runtime(config: &ClientConfig) -> anyhow::Result<()> {    // 配置校验已保证 outbounds 非空。
    let first_tag = config.outbounds[0].tag.as_deref();

    for rule in config
        .routing
        .as_ref()
        .into_iter()
        .flat_map(|routing| routing.rules.iter())
    {
        if Some(rule.outbound.as_str()) != first_tag {
            anyhow::bail!(
                "routing rule outbound '{}' is configured, but the current client runtime only supports the first outbound{}",
                rule.outbound,
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
    if let Some(rule) = find_routing_rule(config.routing.as_ref(), inbound_tag, None) {
        return Ok(rule.outbound.clone());
    }

    Ok(first_outbound_tag(&config.outbounds))
}

fn first_outbound_tag(outbounds: &[ClientOutbound]) -> String {
    outbounds
        .first()
        .and_then(|outbound| outbound.tag.clone())
        .unwrap_or_else(|| "<unnamed>".to_string())
}

async fn handle_inbound_connection(
    local: tokio::net::TcpStream,
    kind: InboundKind,
    pool: &Arc<TunnelPool>,
) -> anyhow::Result<()> {
    let client_ip = local.peer_addr()?.ip();
    match kind.handshake(local).await? {
        InboundRequest::Connect(mut handshake) => {
            let mut stream = pool.open_stream().await?;
            stream.defer_target(&handshake.target.encode_wire());
            handshake.reply_success().await?;
            let (tx, rx) =
                relay::relay_tcp_client(handshake.reader, handshake.writer, stream).await?;
            debug!("{} relay done: tx={} rx={}", kind.as_str(), tx, rx);
        }
        InboundRequest::UdpAssociate(mut handshake) => {
            let mut stream = pool.open_stream().await?;
            stream.write_early(&handshake.target.encode_wire()).await?;
            stream.wait_open().await?;
            handshake.reply_success().await?;
            let result =
                relay::relay_udp_client_mode(stream, handshake.udp, client_ip, handshake.reader)
                    .await;
            drop(handshake.writer);
            result?;
        }
    }
    Ok(())
}
