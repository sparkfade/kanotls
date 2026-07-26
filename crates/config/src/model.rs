use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub log: Option<LogConfig>,
    pub inbounds: Vec<ServerInbound>,
    pub outbounds: Vec<Outbound>,
    pub routing: Option<Routing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub log: Option<LogConfig>,
    pub inbounds: Vec<ClientInbound>,
    pub outbounds: Vec<ClientOutbound>,
    pub routing: Option<Routing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routing {
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub inbound: Vec<String>,
    #[serde(default)]
    pub auth_user: Option<Vec<String>>,
    pub outbound: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInbound {
    pub tag: Option<String>,
    pub listen: String,
    pub port: u16,
    pub protocol: String,
    pub settings: KanotlsServerSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KanotlsServerSettings {
    pub users: Vec<User>,
    #[serde(alias = "reference")]
    pub camouflage: CamouflageConfig,
    pub session: Option<SessionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CamouflageConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInbound {
    pub tag: Option<String>,
    pub listen: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOutbound {
    pub tag: Option<String>,
    pub protocol: String,
    pub settings: KanotlsClientSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KanotlsClientSettings {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsConfig,
    pub session: Option<SessionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub template_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_max_streams_per_session")]
    pub max_streams_per_session: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub traffic_script: Option<Vec<String>>,
    #[serde(default)]
    pub post_script_shaping: Option<String>,
}

fn default_max_streams_per_session() -> usize {
    256
}

/// 服务端 session 空闲拆除的默认秒数：nginx `keepalive_timeout` 的默认值。
///
/// 此前取 45 秒——不对应任何真实服务器的默认值，于是「空闲连接在 45 秒整被
/// 服务端关掉」本身就是一条跨部署恒定、可指认的拆除时序（原则 2 的第二种
/// 违反形式：取值虽是常量，但常量对不上任何真实来源，见 MECHANISM §9.11）。
///
/// **为什么是 `keepalive_timeout`(75s) 而不是 `http2_idle_timeout`(3min)**：
/// nginx **1.19.7**（2021-02）把 HTTP/2 的连接处理改为与 HTTP/1.x 一致，
/// **删除**了 `http2_recv_timeout` / `http2_idle_timeout` / `http2_max_requests`
/// 三个指令，并要求改用 `keepalive_timeout` / `keepalive_requests`。也就是说
/// 「H2 连接的空闲超时 = 3 分钟」只存在于 2021 年之前的 nginx；今天任何一台
/// 可供审查者对照的 nginx，其 H2 空闲连接都走 `keepalive_timeout` 的 75 秒。
/// KanoTLS 的连接虽是 H2 形态的多路复用连接，对应的也正是这条 75 秒。
///
/// 这个取值还维持了一条既有的行为不变量：客户端连接池的空闲回收是 115 秒
/// （Firefox `network.http.keep-alive.timeout`），75 < 115 ⇒ **先关闭的一方仍是
/// 服务端**，与真实的 Firefox ↔ nginx 配对一致（Firefox 的 115 秒本就选在常见
/// 服务端 keepalive 之上）。若改取 3 分钟，先关的会变成客户端，那是真实浏览器
/// 与真实服务器之间不会出现的顺序。
///
/// 附带收益：空闲窗口从 45 秒拉到 75 秒 ⇒ 同等使用强度下重连次数下降 ⇒
/// `P(被检出) = 1 − (1−TPR)^N` 里的 N 更小（§9.1）。
fn default_idle_timeout() -> u64 {
    75
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_streams_per_session: default_max_streams_per_session(),
            idle_timeout_secs: default_idle_timeout(),
            traffic_script: None,
            post_script_shaping: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    pub tag: Option<String>,
    pub protocol: String,
    pub settings: Option<serde_json::Value>,
}
