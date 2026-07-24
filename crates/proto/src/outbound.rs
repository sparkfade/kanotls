use crate::socks5::{socks5_handshake, socks5_send_connect, socks5_send_udp_associate, Socks5Target};
use crate::target::{is_blocked_destination, Host, Target};
use crate::uot::{decode_socks5_udp, encode_socks5_udp};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 直连出站：解析并校验目标后直接建立 TCP，或绑定本地 UDP。
#[derive(Clone, Debug)]
pub struct DirectOutbound {
    pub connect_timeout: Duration,
}

impl DirectOutbound {
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
        }
    }

    async fn connect(&self, target: &Target) -> Result<TcpStream, anyhow::Error> {
        let remote_addr = resolve_remote_target(target).await?;
        let remote = tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect(remote_addr),
        )
        .await
        .map_err(|_| anyhow::anyhow!("direct connect to {} timed out", remote_addr))??;
        remote.set_nodelay(true)?;
        Ok(remote)
    }

    async fn udp_associate(&self) -> Result<UdpRelay, anyhow::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(UdpRelay::Direct {
            socket: Arc::new(socket),
        })
    }
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new()
    }
}

/// SOCKS5 上级代理出站。
#[derive(Clone, Debug)]
pub struct Socks5Outbound {
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub handshake_timeout: Duration,
    pub command_timeout: Duration,
}

impl Socks5Outbound {
    pub fn new(address: String, username: Option<String>, password: Option<String>) -> Self {
        Self {
            address,
            username,
            password,
            handshake_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            command_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
        }
    }

    fn auth(&self) -> Option<(&str, &str)> {
        self.username.as_deref().zip(self.password.as_deref())
    }

    async fn connect(&self, target: &Target) -> Result<TcpStream, anyhow::Error> {
        let socks_target = match &target.host {
            Host::Ipv4(ip) => Socks5Target::Ip(SocketAddr::new((*ip).into(), target.port)),
            Host::Ipv6(ip) => Socks5Target::Ip(SocketAddr::new((*ip).into(), target.port)),
            Host::Domain(domain) => Socks5Target::Domain(domain.clone(), target.port),
        };
        if let Socks5Target::Ip(addr) = &socks_target {
            if is_blocked_destination(addr) {
                anyhow::bail!("blocked destination: {}", addr);
            }
        }

        let mut remote = tokio::time::timeout(
            self.handshake_timeout,
            socks5_handshake(&self.address, self.auth()),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "socks5 handshake to {} timed out after {}s",
                self.address,
                self.handshake_timeout.as_secs()
            )
        })?
        .map_err(|e| anyhow::anyhow!("socks5 handshake to {} failed: {}", self.address, e))?;

        tokio::time::timeout(
            self.command_timeout,
            socks5_send_connect(&mut remote, socks_target),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "socks5 CONNECT to {} via {} timed out",
                target.authority(),
                self.address
            )
        })?
        .map_err(|e| {
            anyhow::anyhow!(
                "socks5 CONNECT to {} via {} failed: {}",
                target.authority(),
                self.address,
                e
            )
        })?;
        remote.set_nodelay(true)?;
        Ok(remote)
    }

    async fn udp_associate(&self) -> Result<UdpRelay, anyhow::Error> {
        let mut control = tokio::time::timeout(
            self.handshake_timeout,
            socks5_handshake(&self.address, self.auth()),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "socks5 UDP handshake to {} timed out after {}s",
                self.address,
                self.handshake_timeout.as_secs()
            )
        })??;
        let relay_addr = tokio::time::timeout(
            self.command_timeout,
            socks5_send_udp_associate(&mut control),
        )
        .await
        .map_err(|_| anyhow::anyhow!("socks5 UDP ASSOCIATE to {} timed out", self.address))??;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let control_alive = Arc::new(AtomicBool::new(true));
        let alive_flag = control_alive.clone();
        let control_guard = AbortOnDrop(tokio::spawn(async move {
            let mut control = control;
            let mut buf = [0u8; 1];
            match control.read(&mut buf).await {
                Ok(0) | Err(_) => alive_flag.store(false, Ordering::SeqCst),
                Ok(_) => {}
            }
        }));

        Ok(UdpRelay::Socks5(Socks5UdpRelay {
            socket: Arc::new(socket),
            relay_addr,
            control_alive,
            _control_guard: control_guard,
        }))
    }
}

/// 统一出站接口（枚举静态分发）。
#[derive(Clone, Debug)]
pub enum Outbound {
    Direct(DirectOutbound),
    Socks5(Socks5Outbound),
}

impl Outbound {
    pub fn direct() -> Self {
        Self::Direct(DirectOutbound::new())
    }

    pub fn socks5(address: String, username: Option<String>, password: Option<String>) -> Self {
        Self::Socks5(Socks5Outbound::new(address, username, password))
    }

    /// 建立到 target 的 TCP 连接（含目的地阻断与超时）。
    pub async fn connect(&self, target: &Target) -> Result<TcpStream, anyhow::Error> {
        match self {
            Self::Direct(outbound) => outbound.connect(target).await,
            Self::Socks5(outbound) => outbound.connect(target).await,
        }
    }

    /// 建立 UDP 中继通道。
    pub async fn udp_associate(&self) -> Result<UdpRelay, anyhow::Error> {
        match self {
            Self::Direct(outbound) => outbound.udp_associate().await,
            Self::Socks5(outbound) => outbound.udp_associate().await,
        }
    }
}

impl std::fmt::Display for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outbound::Direct(_) => write!(f, "direct"),
            Outbound::Socks5(outbound) => {
                if let Some(user) = &outbound.username {
                    write!(f, "socks5://{}@{}", user, outbound.address)
                } else {
                    write!(f, "socks5://{}", outbound.address)
                }
            }
        }
    }
}

/// 出站 UDP 中继通道：直连为本地 UDP socket；
/// socks5 为本地 UDP socket + 远端 relay 地址 + TCP 控制面存活监控。
pub enum UdpRelay {
    Direct { socket: Arc<UdpSocket> },
    Socks5(Socks5UdpRelay),
}

pub struct Socks5UdpRelay {
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    control_alive: Arc<AtomicBool>,
    _control_guard: AbortOnDrop,
}

impl UdpRelay {
    pub fn local_addr(&self) -> Result<SocketAddr, anyhow::Error> {
        Ok(self.socket().local_addr()?)
    }

    fn socket(&self) -> &Arc<UdpSocket> {
        match self {
            Self::Direct { socket } => socket,
            Self::Socks5(relay) => &relay.socket,
        }
    }

    /// 控制面是否存活（直连无控制面，恒为 true）。
    pub fn is_control_alive(&self) -> bool {
        match self {
            Self::Direct { .. } => true,
            Self::Socks5(relay) => relay.control_alive.load(Ordering::SeqCst),
        }
    }

    /// 向目标发送载荷（socks5 中继自动封装 UDP 头）。
    pub async fn send_to(&self, payload: &[u8], target: &SocketAddr) -> Result<(), anyhow::Error> {
        match self {
            Self::Direct { socket } => {
                socket.send_to(payload, target).await?;
            }
            Self::Socks5(relay) => {
                let packet = encode_socks5_udp(payload, target);
                relay.socket.send_to(&packet, relay.relay_addr).await?;
            }
        }
        Ok(())
    }

    /// 接收下一个载荷，返回（原始来源地址, 载荷）。
    /// socks5 中继自动过滤非 relay 来源并解封装。
    pub async fn recv(&self, buf: &mut [u8]) -> Option<(SocketAddr, Vec<u8>)> {
        match self {
            Self::Direct { socket } => {
                let (n, src) = socket.recv_from(buf).await.ok()?;
                Some((src, buf[..n].to_vec()))
            }
            Self::Socks5(relay) => loop {
                let (n, src) = relay.socket.recv_from(buf).await.ok()?;
                if src != relay.relay_addr {
                    continue;
                }
                if let Some(decoded) = decode_socks5_udp(&buf[..n]) {
                    return Some(decoded);
                }
            },
        }
    }
}

async fn resolve_remote_target(target: &Target) -> Result<SocketAddr, anyhow::Error> {
    let check = |addr: SocketAddr| -> Result<SocketAddr, anyhow::Error> {
        if is_blocked_destination(&addr) {
            anyhow::bail!("blocked destination: {}", addr);
        }
        Ok(addr)
    };
    match &target.host {
        Host::Ipv4(ip) => check(SocketAddr::new((*ip).into(), target.port)),
        Host::Ipv6(ip) => check(SocketAddr::new((*ip).into(), target.port)),
        Host::Domain(domain) => {
            let resolved = tokio::net::lookup_host((domain.as_str(), target.port)).await?;
            let mut first_allowed = None;
            for addr in resolved {
                if is_blocked_destination(&addr) {
                    continue;
                }
                first_allowed.get_or_insert(addr);
            }
            first_allowed.ok_or_else(|| anyhow::anyhow!("unable to resolve target host"))
        }
    }
}
