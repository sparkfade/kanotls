use kanotls_session::Stream;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::debug;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const REP_SUCCEEDED: u8 = 0x00;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const LOCAL_PROTOCOL_TIMEOUT_SECS: u64 = 10;

pub enum Socks5Request {
    Connect {
        local_reader: tokio::net::tcp::OwnedReadHalf,
        local_writer: tokio::net::tcp::OwnedWriteHalf,
        target: String,
    },
    UdpAssociate {
        local_reader: tokio::net::tcp::OwnedReadHalf,
        local_writer: tokio::net::tcp::OwnedWriteHalf,
        udp: UdpSocket,
        target: String,
    },
}

pub async fn parse_socks5_inbound(
    local: tokio::net::TcpStream,
) -> Result<Socks5Request, anyhow::Error> {
    tokio::time::timeout(
        std::time::Duration::from_secs(LOCAL_PROTOCOL_TIMEOUT_SECS),
        parse_socks5_inbound_inner(local),
    )
    .await
    .map_err(|_| anyhow::anyhow!("socks5 request timeout"))?
}

async fn parse_socks5_inbound_inner(
    local: tokio::net::TcpStream,
) -> Result<Socks5Request, anyhow::Error> {
    let (mut reader, mut writer) = local.into_split();
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        anyhow::bail!("unsupported socks version: {}", head[0]);
    }

    let nmethods = head[1] as usize;
    if nmethods == 0 || nmethods > 16 {
        anyhow::bail!("invalid socks5 method count: {}", nmethods);
    }
    let mut methods = vec![0u8; nmethods];
    reader.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        writer
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        anyhow::bail!("socks5 client did not offer no-auth method");
    }
    writer.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;

    let mut req = [0u8; 4];
    reader.read_exact(&mut req).await?;
    if req[0] != SOCKS_VERSION || req[2] != 0x00 {
        anyhow::bail!("invalid socks5 request header");
    }

    let cmd = req[1];
    let atyp = req[3];

    let addr = read_address(atyp, &mut reader).await?;
    debug!("socks5: cmd={} addr={}:{}", cmd, addr.0, addr.1);

    match cmd {
        CMD_CONNECT => {
            let target = format!("{}:{}", addr.0, addr.1);
            Ok(Socks5Request::Connect {
                local_reader: reader,
                local_writer: writer,
                target,
            })
        }
        CMD_UDP_ASSOCIATE => {
            let target = format!("udp:{}:{}", addr.0, addr.1);
            let udp = UdpSocket::bind("127.0.0.1:0").await?;
            Ok(Socks5Request::UdpAssociate {
                local_reader: reader,
                local_writer: writer,
                udp,
                target,
            })
        }
        _ => {
            writer
                .write_all(&socks_reply(REP_COMMAND_NOT_SUPPORTED))
                .await?;
            anyhow::bail!("unsupported socks5 cmd: {}", cmd);
        }
    }
}

pub async fn write_socks5_connect_success(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<(), anyhow::Error> {
    writer.write_all(&socks_reply(REP_SUCCEEDED)).await?;
    Ok(())
}

pub async fn write_socks5_udp_success(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    udp_addr: std::net::SocketAddr,
) -> Result<(), anyhow::Error> {
    writer.write_all(&socks_udp_reply(udp_addr)?).await?;
    Ok(())
}

pub async fn relay_socks5_connect(
    local_reader: impl AsyncReadExt + Unpin,
    local_writer: impl AsyncWriteExt + Unpin,
    remote: Stream,
) -> Result<(u64, u64), anyhow::Error> {
    crate::relay_bidirectional(local_reader, local_writer, remote).await
}

const METHOD_USER_PASS: u8 = 0x02;

pub enum Socks5Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

pub async fn socks5_handshake(
    proxy_addr: &str,
    auth: Option<(&str, &str)>,
) -> Result<tokio::net::TcpStream, anyhow::Error> {
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;

    match auth {
        None => {
            stream
                .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
                .await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != SOCKS_VERSION || resp[1] != METHOD_NO_AUTH {
                anyhow::bail!(
                    "socks5 proxy rejected no-auth method: {:02x} {:02x}",
                    resp[0],
                    resp[1]
                );
            }
        }
        Some((username, password)) => {
            stream
                .write_all(&[SOCKS_VERSION, 1, METHOD_USER_PASS])
                .await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != SOCKS_VERSION || resp[1] != METHOD_USER_PASS {
                anyhow::bail!(
                    "socks5 proxy does not support user/pass auth: {:02x} {:02x}",
                    resp[0],
                    resp[1]
                );
            }

            if username.len() > 255 {
                anyhow::bail!("socks5 username exceeds 255 bytes");
            }
            if password.len() > 255 {
                anyhow::bail!("socks5 password exceeds 255 bytes");
            }
            let ulen = username.len() as u8;
            let plen = password.len() as u8;
            let mut auth_req = Vec::with_capacity(3 + ulen as usize + plen as usize);
            auth_req.push(0x01);
            auth_req.push(ulen);
            auth_req.extend_from_slice(&username.as_bytes()[..ulen as usize]);
            auth_req.push(plen);
            auth_req.extend_from_slice(&password.as_bytes()[..plen as usize]);
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                anyhow::bail!("socks5 user/pass authentication failed");
            }
        }
    }

    Ok(stream)
}

enum Socks5ReplyAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

async fn read_socks5_reply_addr(
    stream: &mut tokio::net::TcpStream,
) -> Result<Socks5ReplyAddr, anyhow::Error> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    if head[0] != SOCKS_VERSION {
        anyhow::bail!("invalid socks5 reply version: {}", head[0]);
    }

    let rep = head[1];
    if rep != REP_SUCCEEDED {
        anyhow::bail!("socks5 request failed with reply code 0x{:02x}", rep);
    }

    if head[2] != 0x00 {
        anyhow::bail!("invalid socks5 reply reserved byte: {}", head[2]);
    }

    match head[3] {
        0x01 => {
            let mut bind = [0u8; 6];
            stream.read_exact(&mut bind).await?;
            let ip = std::net::Ipv4Addr::new(bind[0], bind[1], bind[2], bind[3]);
            let port = u16::from_be_bytes([bind[4], bind[5]]);
            Ok(Socks5ReplyAddr::Ip(SocketAddr::V4(
                std::net::SocketAddrV4::new(ip, port),
            )))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let len = len[0] as usize;
            if len == 0 {
                anyhow::bail!("invalid socks5 reply domain length: 0");
            }
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let name = String::from_utf8(name)?;
            Ok(Socks5ReplyAddr::Domain(name, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut bind = [0u8; 18];
            stream.read_exact(&mut bind).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bind[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([bind[16], bind[17]]);
            Ok(Socks5ReplyAddr::Ip(SocketAddr::V6(
                std::net::SocketAddrV6::new(ip, port, 0, 0),
            )))
        }
        atyp => anyhow::bail!("unexpected socks5 reply atyp: {}", atyp),
    }
}

pub async fn socks5_send_connect(
    stream: &mut tokio::net::TcpStream,
    target: Socks5Target,
) -> Result<(), anyhow::Error> {
    let mut connect_req = Vec::with_capacity(22);
    connect_req.push(SOCKS_VERSION);
    connect_req.push(CMD_CONNECT);
    connect_req.push(0x00);

    match &target {
        Socks5Target::Ip(addr) => match addr {
            SocketAddr::V4(v4) => {
                connect_req.push(0x01);
                connect_req.extend_from_slice(&v4.ip().octets());
                connect_req.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                connect_req.push(0x04);
                connect_req.extend_from_slice(&v6.ip().octets());
                connect_req.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        Socks5Target::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                anyhow::bail!("target hostname too long: {} bytes", host_bytes.len());
            }
            connect_req.push(0x03);
            connect_req.push(host_bytes.len() as u8);
            connect_req.extend_from_slice(host_bytes);
            connect_req.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&connect_req).await?;

    let _ = read_socks5_reply_addr(stream).await?;
    Ok(())
}

pub async fn socks5_send_udp_associate(
    stream: &mut tokio::net::TcpStream,
) -> Result<SocketAddr, anyhow::Error> {
    let assoc_req: [u8; 10] = [
        SOCKS_VERSION,
        CMD_UDP_ASSOCIATE,
        0x00,
        0x01,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    stream.write_all(&assoc_req).await?;

    let relay_addr = match read_socks5_reply_addr(stream).await? {
        Socks5ReplyAddr::Ip(addr) => addr,
        Socks5ReplyAddr::Domain(host, port) => {
            let mut resolved = tokio::net::lookup_host((host.as_str(), port)).await?;
            resolved
                .next()
                .ok_or_else(|| anyhow::anyhow!("unable to resolve socks5 UDP relay host"))?
        }
    };

    let relay_addr = resolve_zero_bind(stream, relay_addr)?;
    if relay_addr.port() == 0 {
        anyhow::bail!("socks5 UDP relay returned port 0");
    }
    Ok(relay_addr)
}

fn resolve_zero_bind(
    stream: &tokio::net::TcpStream,
    addr: SocketAddr,
) -> Result<SocketAddr, anyhow::Error> {
    let ip_is_unspecified = match &addr {
        SocketAddr::V4(v4) => v4.ip().is_unspecified(),
        SocketAddr::V6(v6) => v6.ip().is_unspecified(),
    };
    if !ip_is_unspecified {
        return Ok(addr);
    }
    let peer_addr = stream.peer_addr()?;
    Ok(SocketAddr::new(peer_addr.ip(), addr.port()))
}

async fn read_address(
    atyp: u8,
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<(String, u16), anyhow::Error> {
    match atyp {
        0x01 => {
            let mut data = [0u8; 6];
            reader.read_exact(&mut data).await?;
            let ip = format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]);
            let port = u16::from_be_bytes([data[4], data[5]]);
            Ok((ip, port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let domain_len = len[0] as usize;
            if domain_len == 0 || domain_len > 253 {
                anyhow::bail!("invalid domain length: {}", domain_len);
            }
            let mut domain = vec![0u8; domain_len];
            reader.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf).await?;
            let domain = String::from_utf8(domain)?;
            let port = u16::from_be_bytes(port_buf);
            Ok((domain, port))
        }
        0x04 => {
            let mut data = [0u8; 18];
            reader.read_exact(&mut data).await?;
            let segments: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", data[i * 2], data[i * 2 + 1]))
                .collect();
            let ip = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7]
            );
            let port = u16::from_be_bytes([data[16], data[17]]);
            Ok((format!("[{}]", ip), port))
        }
        _ => anyhow::bail!("unknown socks5 atyp: {}", atyp),
    }
}

fn socks_reply(code: u8) -> [u8; 10] {
    [SOCKS_VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

fn socks_udp_reply(addr: std::net::SocketAddr) -> Result<Vec<u8>, anyhow::Error> {
    let mut reply = Vec::with_capacity(22);
    reply.push(SOCKS_VERSION);
    reply.push(REP_SUCCEEDED);
    reply.push(0x00);
    match addr {
        std::net::SocketAddr::V4(v4) => {
            reply.push(0x01);
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(v6) => {
            reply.push(0x04);
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    Ok(reply)
}
