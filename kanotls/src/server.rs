use crate::relay;
use kanotls_config::server::load_server_config;
use kanotls_config::{find_routing_rule, ServerConfig};
use kanotls_proto::outbound::Outbound;
use kanotls_proto::target::{Network, Target};
use kanotls_session::{
    server::{ServerSessionHandler, ServerStream},
    SessionConfig,
};
use kanotls_tunnel::{server_accept, validate_camouflage_endpoint, ServerAcceptError};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

const MAX_CONCURRENT_SERVER_CONNECTIONS: usize = 4096;

#[derive(Clone)]
struct ServerConnContext {
    user_names: Arc<Vec<String>>,
    user_psks: Arc<Vec<[u8; kanotls_tunnel::PSK_LEN]>>,
    camouflage_host: Arc<str>,
    camouflage_port: u16,
    session_config: SessionConfig,
    config: Arc<ServerConfig>,
    inbound_tag: Option<String>,
}

pub async fn run_server(config_path: &str) -> anyhow::Result<()> {
    let config = Arc::new(load_server_config(config_path)?);
    info!("loaded server config, {} inbounds", config.inbounds.len());

    let inbound = &config.inbounds[0];
    let inbound_tag = inbound.tag.clone();
    let camouflage_host = &inbound.settings.camouflage.host;
    let camouflage_port = inbound.settings.camouflage.port;

    validate_camouflage_endpoint(camouflage_host, camouflage_port).await?;
    info!(
        "validated camouflage endpoint {}:{}",
        camouflage_host, camouflage_port
    );

    let listen_addr = format!("{}:{}", inbound.listen, inbound.port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("server listening on {}", listen_addr);

    let user_names: Vec<String> = inbound
        .settings
        .users
        .iter()
        .map(|user| user.name.clone())
        .collect();
    let user_psks: Vec<[u8; kanotls_tunnel::PSK_LEN]> = inbound
        .settings
        .users
        .iter()
        .map(|user| kanotls_tunnel::derive_psk(user.password.as_bytes()))
        .collect();
    info!("server inbound has {} users", user_names.len());
    let camouflage_host: Arc<str> = Arc::from(camouflage_host.as_str());
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
        .unwrap_or(75);
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

    let conn_ctx = ServerConnContext {
        user_names: Arc::new(user_names),
        user_psks: Arc::new(user_psks),
        camouflage_host,
        camouflage_port,
        session_config,
        config,
        inbound_tag,
    };

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
                                // 此前是 error!：连接数上限由对端的连接速率决定，
                                // 一次泛洪即可让服务端按行写下等量 error 日志，
                                // 每行还带攻击者可控的源 IP。
                                debug!("connection {} rejected: server connection limit reached", addr);
                                continue;
                            }
                        };
                        let ctx = conn_ctx.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            match handle_server_conn(tcp, addr, &ctx).await {
                                Ok(()) => {}
                                Err(ConnectionEnd::Expected(e)) => {
                                    debug!("connection {} closed: {}", addr, e)
                                }
                                Err(ConnectionEnd::Fault(e)) => {
                                    error!("connection {} error: {}", addr, e)
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

/// 一条连接如何结束，以及该记哪个日志级别。
///
/// # 为什么这个分流必须存在
///
/// 对任何暴露在公网 443 的端口，pre-auth 失败（端口扫描、主动探测、误连、
/// 走错 SNI 的真实浏览器）都是**常态**而非故障。若它们走 `error!`，扫描者
/// 每建一条 TCP 就能让服务端写下一行含其可控源 IP 的日志——日志放大 / 磁盘
/// 填满，而且日志写入在 tokio worker 上同步发生。它同时也让「谁在探测我」
/// 变成必须落盘的记录。
///
/// # 为什么它此前是按错误字符串做的，以及为什么不能再那样
///
/// 此前是一张 needle 列表配 `Error::to_string().contains()`。这种做法已经
/// **静默失效过一次**：needle `"session closed"` 与任何实际文案都不匹配
/// （真实文案是 `"session is closed"`），把一类预期结束长期误判成 `error!`
/// 而无人察觉——它不会编译失败、不会有测试变红，只会安静地多写日志。
/// 现在 `server_accept` 返回 [`ServerAcceptError`]，分类由类型给出：新增
/// 失败路径必须显式选一个变体，改文案不再有任何影响。
enum ConnectionEnd {
    /// 预期结果：pre-auth 拒绝，或 session 正常拆除。`debug!`
    Expected(anyhow::Error),
    /// 真正的故障：配置错误、伪装端点不可用、认证后的协议校验失败。`error!`
    Fault(anyhow::Error),
}

async fn handle_server_conn(
    tcp: tokio::net::TcpStream,
    addr: SocketAddr,
    ctx: &ServerConnContext,
) -> Result<(), ConnectionEnd> {
    let (tunnel, user_index) = server_accept(
        tcp,
        &ctx.user_psks,
        &ctx.camouflage_host,
        ctx.camouflage_port,
    )
    .await
    .map_err(|e| match e {
        ServerAcceptError::PreAuth(err) => ConnectionEnd::Expected(err),
        ServerAcceptError::Internal(err) => ConnectionEnd::Fault(err),
    })?;
    let user_name = ctx.user_names[user_index].as_str();
    let outbound =
        resolve_server_outbound(&ctx.config, ctx.inbound_tag.as_deref(), Some(user_name))
            .map_err(ConnectionEnd::Fault)?;
    // 此前是 info!（默认级别），于是服务端在默认配置下就把「客户端 IP ↔
    // 用户名」的配对逐连接落盘：服务器一旦被查封，日志本身就是「谁在什么
    // 时间用这个代理」的名单。仅去掉 IP 也不够——保留在 info! 的逐连接行
    // 依然给出每个用户的接入时刻与频次，对翻墙工具而言这已足够定位到人。
    // 整行降到 debug!；「服务是否活着」由启动期的 info! 行承载。
    debug!("client {} connected as user '{}'", addr, user_name);

    let session_config = ctx.session_config.clone();
    let first_data_timeout = session_config.idle_timeout_secs.clamp(1, 30);
    let handler = ServerSessionHandler::new(tunnel, session_config);

    let session = handler.get_session();
    let _read_handle = tokio::spawn(async move {
        let _ = session.run_read_loop().await;
        debug!("read loop ended for {}", addr);
    });

    loop {
        // `accept_stream` 只在 session 结束时返回 Err，因此**每一条正常连接**
        // 都以它收尾（"session shutting down" / "session is closed" /
        // "session read loop ended"，以及对端直接断线）。连接拆除对一个代理
        // 而言不是故障，而且它由对端随时可触发——记 error! 同样是日志放大面。
        let (sid, stream) = handler
            .accept_stream()
            .await
            .map_err(ConnectionEnd::Expected)?;

        let ob = outbound.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_server_stream(sid, stream, first_data_timeout, ob).await {
                // 此前是 warn!（默认级别同样可见），而出站失败的错误文案本身
                // 就带目的地：`direct connect to {addr} failed`、
                // `blocked destination: {addr}`、`socks5 connect ... to {addr}`。
                // 于是即便把下面那条「connect to」降级，「连不上的目的地」
                // 仍会从这里漏进默认日志。
                debug!("stream {} error: {}", sid, e);
            }
        });
    }
}

fn resolve_server_outbound(
    config: &ServerConfig,
    inbound_tag: Option<&str>,
    auth_user: Option<&str>,
) -> anyhow::Result<Outbound> {
    let outbound = match find_routing_rule(config.routing.as_ref(), inbound_tag, auth_user) {
        Some(rule) => {
            let tag = rule.outbound.as_str();
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
                "no routing rule matched inbound {:?} user {:?}, falling back to outbound '{}'",
                inbound_tag,
                auth_user,
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
    // 此前是 info!，而默认 log.level 就是 info：服务端在默认配置下逐流
    // 记下每个被代理的目的地 host:port，等价于为每个用户留存一份完整的
    // 浏览历史。对一台随时可能被查封的翻墙服务器，这份记录的危害远大于
    // 它的运维价值——目的地只在排查具体故障时才需要，属于 debug 语义。
    debug!("stream {} connect to {}", sid, target);

    match target.network {
        Network::Udp => {
            stream.send_synack().await?;
            let relay = outbound.udp_associate().await?;
            debug!("stream {} udp-over-tcp via {}", sid, relay.local_addr()?);
            relay::relay_udp_server(stream, relay).await?;
        }
        Network::Tcp => {
            let remote = outbound.connect(&target).await?;
            stream.send_synack().await?;
            relay::relay_tcp_server(stream, remote).await?;
        }
    }

    Ok(())
}
