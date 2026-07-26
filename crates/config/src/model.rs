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

fn default_idle_timeout() -> u64 {
    45
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
