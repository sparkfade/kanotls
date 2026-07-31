use futures::future::BoxFuture;
use futures::FutureExt;
use kanotls_pool::{PoolSession, TunnelConnector};
use kanotls_session::{Session, SessionConfig, Stream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::error;

/// 认证误配诊断的「只提示一次」守卫：池会持续重试建连，同一条误配
/// 结论若每次失败都打印就会刷屏，而它对运维只需要说一次。
static AUTH_MISCONFIG_REPORTED: AtomicBool = AtomicBool::new(false);

/// 隧道连接参数：由客户端配置装配，注入连接池的连接工厂。
#[derive(Clone)]
pub struct TunnelConnectOptions {
    pub server_addr: String,
    pub sni: String,
    pub psk: Vec<u8>,
    pub insecure: bool,
    pub fingerprint: Option<String>,
    pub custom_template_bytes: Arc<RwLock<Option<Vec<u8>>>>,
}

/// 装配层连接工厂：封装一次 kanotls-tunnel 握手 + 会话创建 + 读循环启动，
/// 作为闭包注入上移后的 client_pool，切断会话层对隧道实例化的认知。
pub struct KanotlsConnector {
    session_config: SessionConfig,
    options: TunnelConnectOptions,
}

impl KanotlsConnector {
    pub fn new(session_config: SessionConfig, options: TunnelConnectOptions) -> Self {
        Self {
            session_config,
            options,
        }
    }
}

impl TunnelConnector for KanotlsConnector {
    type Session = LiveSession;

    fn connect(&self) -> BoxFuture<'_, Result<Arc<LiveSession>, anyhow::Error>> {
        let session_config = self.session_config.clone();
        let options = self.options.clone();
        async move {
            // 模板在握手前克隆出来即释放读锁：此前读锁被跨整段握手 await
            // 持有，而 tokio RwLock 对写者公平——`template_watch` 的热重载
            // 写锁一旦排队，就会连带阻塞后续所有新建连接读锁，直到那条
            // 在飞的握手结束。克隆一份 ~2 KiB 模板的代价可以忽略。
            let template_bytes = options.custom_template_bytes.read().await.clone();
            let tunnel = match kanotls_tunnel::client::client_tunnel(
                &options.server_addr,
                &options.sni,
                &options.psk,
                options.insecure,
                options.fingerprint.as_deref(),
                template_bytes.as_deref(),
            )
            .await
            {
                Ok(tunnel) => tunnel,
                Err(err) => {
                    report_auth_misconfiguration(&err, &options.sni);
                    return Err(err.into());
                }
            };

            let session = Arc::new(Session::new(tunnel, session_config, None));
            let read_loop = session.clone();
            tokio::spawn(async move {
                let _ = read_loop.run_read_loop().await;
            });

            Ok(Arc::new(LiveSession { session }))
        }
        .boxed()
    }
}

/// 按失败形态分类建连错误，替代此前那条一次性的启动预检连接。
///
/// [`TunnelConnectError::AuthRejected`] 说明服务端拒绝认证后把这条连接交给了
/// fallback 透明中继——只可能是 PSK 不匹配，或 `tls.sni` 与服务端
/// `camouflage.host` 不一致（两者在客户端侧不可区分，一并提示）。其余错误
/// （连接被拒、超时、DNS 失败）由池自己的 `pooled tunnel connection failed`
/// 告警承载，不在此重复。
fn report_auth_misconfiguration(err: &kanotls_tunnel::client::TunnelConnectError, sni: &str) {
    if !matches!(err, kanotls_tunnel::client::TunnelConnectError::AuthRejected(_)) {
        return;
    }
    if AUTH_MISCONFIG_REPORTED.swap(true, Ordering::Relaxed) {
        return;
    }
    error!(
        "tunnel authentication rejected: the server fell back to its camouflage relay — verify the client password matches the server PSK, and that tls.sni ('{}') exactly matches the server camouflage.host",
        sni
    );
}

/// 池化会话：包装多路复用会话句柄，供连接池调度。
pub struct LiveSession {
    session: Arc<Session>,
}

impl PoolSession for LiveSession {
    fn open_stream(&self) -> BoxFuture<'_, Result<Stream, anyhow::Error>> {
        async move { self.session.open_stream().await }.boxed()
    }

    fn active_streams(&self) -> usize {
        self.session.active_stream_count()
    }

    fn buffered_stream_bytes(&self) -> usize {
        self.session.buffered_stream_bytes()
    }

    fn is_alive(&self) -> bool {
        self.session.is_alive()
    }

    fn is_closing(&self) -> bool {
        self.session.is_closing()
    }

    fn force_close(&self) {
        self.session.force_close();
    }
}
