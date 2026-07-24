use crate::target::Target;
use crate::{http, socks5};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};

/// 标准化入站接口：消费一条本地 TCP 连接，产出统一握手结构。
/// 实现均为零尺寸类型，调用方通过泛型单态化静态分发，兼容 LTO。
pub trait Inbound: Send + Sync {
    fn handshake(
        &self,
        conn: TcpStream,
    ) -> impl std::future::Future<Output = Result<InboundRequest, anyhow::Error>> + Send;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Socks5Inbound;

#[derive(Clone, Copy, Debug, Default)]
pub struct HttpInbound;

impl Inbound for Socks5Inbound {
    fn handshake(
        &self,
        conn: TcpStream,
    ) -> impl std::future::Future<Output = Result<InboundRequest, anyhow::Error>> + Send {
        socks5::handshake(conn)
    }
}

impl Inbound for HttpInbound {
    fn handshake(
        &self,
        conn: TcpStream,
    ) -> impl std::future::Future<Output = Result<InboundRequest, anyhow::Error>> + Send {
        http::handshake(conn)
    }
}

/// 配置协议字符串到入站实现的静态映射。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundKind {
    Socks5,
    Http,
}

impl InboundKind {
    pub fn from_protocol(protocol: &str) -> Option<Self> {
        match protocol {
            "socks5" | "socks" => Some(Self::Socks5),
            "http" => Some(Self::Http),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }

    /// 枚举静态分发：等价于 `Socks5Inbound`/`HttpInbound` 的 trait 调用。
    pub async fn handshake(&self, conn: TcpStream) -> Result<InboundRequest, anyhow::Error> {
        match self {
            Self::Socks5 => Socks5Inbound.handshake(conn).await,
            Self::Http => HttpInbound.handshake(conn).await,
        }
    }
}

/// TCP CONNECT 统一握手返回结构。
pub struct ConnectHandshake {
    pub reader: OwnedReadHalf,
    pub writer: OwnedWriteHalf,
    pub target: Target,
    kind: InboundKind,
}

impl ConnectHandshake {
    fn socks5(reader: OwnedReadHalf, writer: OwnedWriteHalf, target: Target) -> Self {
        Self {
            reader,
            writer,
            target,
            kind: InboundKind::Socks5,
        }
    }

    fn http(reader: OwnedReadHalf, writer: OwnedWriteHalf, target: Target) -> Self {
        Self {
            reader,
            writer,
            target,
            kind: InboundKind::Http,
        }
    }

    /// 按来源协议发出 CONNECT 成功应答。
    pub async fn reply_success(&mut self) -> Result<(), anyhow::Error> {
        match self.kind {
            InboundKind::Socks5 => {
                let reply = socks5::connect_success_reply();
                self.writer.write_all(&reply).await?;
            }
            InboundKind::Http => {
                self.writer
                    .write_all(http::connect_success_reply())
                    .await?;
            }
        }
        Ok(())
    }
}

/// UDP ASSOCIATE 统一握手返回结构（仅 socks5 入站产生）。
pub struct UdpHandshake {
    pub reader: OwnedReadHalf,
    pub writer: OwnedWriteHalf,
    pub udp: UdpSocket,
    pub target: Target,
    kind: InboundKind,
}

impl UdpHandshake {
    pub(crate) fn socks5(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        udp: UdpSocket,
        target: Target,
    ) -> Self {
        Self {
            reader,
            writer,
            udp,
            target,
            kind: InboundKind::Socks5,
        }
    }

    /// 按来源协议发出 UDP ASSOCIATE 成功应答。
    pub async fn reply_success(&mut self) -> Result<(), anyhow::Error> {
        match self.kind {
            InboundKind::Socks5 => {
                let reply = socks5::udp_success_reply(self.udp.local_addr()?)?;
                self.writer.write_all(&reply).await?;
            }
            InboundKind::Http => {
                anyhow::bail!("http inbound does not support UDP ASSOCIATE");
            }
        }
        Ok(())
    }
}

/// 统一入站握手返回：CONNECT 或 UDP ASSOCIATE。
pub enum InboundRequest {
    Connect(ConnectHandshake),
    UdpAssociate(UdpHandshake),
}

impl InboundRequest {
    pub(crate) fn connect_socks5(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        target: Target,
    ) -> Self {
        Self::Connect(ConnectHandshake::socks5(reader, writer, target))
    }

    pub(crate) fn connect_http(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        target: Target,
    ) -> Self {
        Self::Connect(ConnectHandshake::http(reader, writer, target))
    }

    pub fn target(&self) -> &Target {
        match self {
            Self::Connect(handshake) => &handshake.target,
            Self::UdpAssociate(handshake) => &handshake.target,
        }
    }

    /// 统一成功应答：按来源协议发出对应的成功报文。
    pub async fn reply_success(&mut self) -> Result<(), anyhow::Error> {
        match self {
            Self::Connect(handshake) => handshake.reply_success().await,
            Self::UdpAssociate(handshake) => handshake.reply_success().await,
        }
    }
}
