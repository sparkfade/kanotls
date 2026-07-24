use futures::future::BoxFuture;
use futures::FutureExt;
use kanotls_pool::{PoolSession, TunnelConnector};
use kanotls_session::{Session, SessionConfig, Stream};
use std::sync::Arc;
use tokio::sync::RwLock;

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
            let template_bytes = options.custom_template_bytes.read().await;
            let tunnel = kanotls_tunnel::client::client_tunnel(
                &options.server_addr,
                &options.sni,
                &options.psk,
                options.insecure,
                options.fingerprint.as_deref(),
                template_bytes.as_deref(),
            )
            .await?;
            drop(template_bytes);

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
