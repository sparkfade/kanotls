use std::net::{Ipv4Addr, Ipv6Addr};

/// 目标主机元数据：域名或 IP 字面量。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl Host {
    /// authority 形式的主机表示（IPv6 加方括号）。
    pub fn authority(&self) -> String {
        match self {
            Host::Domain(domain) => domain.clone(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => format!("[{}]", ip),
        }
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Domain(domain) => write!(f, "{}", domain),
            Host::Ipv4(ip) => write!(f, "{}", ip),
            Host::Ipv6(ip) => write!(f, "{}", ip),
        }
    }
}

impl From<&str> for Host {
    fn from(value: &str) -> Self {
        match value.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => Host::Ipv4(ip),
            Ok(std::net::IpAddr::V6(ip)) => Host::Ipv6(ip),
            Err(_) => Host::Domain(value.to_string()),
        }
    }
}

impl From<String> for Host {
    fn from(value: String) -> Self {
        Host::from(value.as_str())
    }
}

/// 传输层网络协议。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

/// 统一的目标元数据抽象：主机 + 端口 + 网络协议。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
    pub network: Network,
}

impl Target {
    pub fn new(host: Host, port: u16, network: Network) -> Self {
        Self {
            host,
            port,
            network,
        }
    }

    pub fn tcp(host: Host, port: u16) -> Self {
        Self::new(host, port, Network::Tcp)
    }

    pub fn udp(host: Host, port: u16) -> Self {
        Self::new(host, port, Network::Udp)
    }

    /// authority 形式 "host:port"（IPv6 主机加方括号）。
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host.authority(), self.port)
    }

    /// 隧道首帧线格式编码：TCP 为 "host:port"，UDP 为 "udp:host:port"。
    pub fn encode_wire(&self) -> Vec<u8> {
        match self.network {
            Network::Tcp => self.authority().into_bytes(),
            Network::Udp => format!("udp:{}", self.authority()).into_bytes(),
        }
    }

    /// 线格式解码（server 端首帧解析）。UDP 首帧目标是占位信息
    /// （真实目的地址在 UoT 包内），端口允许为 0；TCP 严格校验。
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let text = std::str::from_utf8(bytes)?;
        let (network, authority) = match text.strip_prefix("udp:") {
            Some(rest) => (Network::Udp, rest),
            None => (Network::Tcp, text),
        };
        let allow_zero_port = matches!(network, Network::Udp);
        let (host, port) = parse_authority(authority, allow_zero_port)?;
        Ok(Self::new(Host::from(host), port, network))
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.network {
            Network::Tcp => write!(f, "{}", self.authority()),
            Network::Udp => write!(f, "udp:{}", self.authority()),
        }
    }
}

pub fn parse_authority_target(target: &str) -> Result<(String, u16), anyhow::Error> {
    parse_authority(target, false)
}

fn parse_authority(target: &str, allow_zero_port: bool) -> Result<(String, u16), anyhow::Error> {
    if let Some(rest) = target.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed IPv6 target"))?;
        let host = &rest[..end];
        let port_part = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("missing port in target"))?;
        let port = port_part.parse::<u16>()?;
        if port == 0 && !allow_zero_port {
            anyhow::bail!("invalid target port 0");
        }
        return Ok((host.to_string(), port));
    }

    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("missing port in target"))?;
    if host.is_empty() {
        anyhow::bail!("empty target host");
    }
    let port = port.parse::<u16>()?;
    if port == 0 && !allow_zero_port {
        anyhow::bail!("invalid target port 0");
    }
    Ok((host.to_string(), port))
}

pub fn is_blocked_destination(addr: &std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000)
                || ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.octets()[0] >= 240
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_blocked_destination(&std::net::SocketAddr::new(
                    std::net::IpAddr::V4(v4),
                    addr.port(),
                ));
            }
            ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authority_target_supports_ipv4_domain_and_ipv6() {
        assert_eq!(
            parse_authority_target("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority_target("1.2.3.4:80").unwrap(),
            ("1.2.3.4".to_string(), 80)
        );
        assert_eq!(
            parse_authority_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn parse_authority_target_rejects_missing_or_zero_port() {
        assert!(parse_authority_target("example.com").is_err());
        assert!(parse_authority_target("example.com:0").is_err());
        assert!(parse_authority_target("[2001:db8::1]:0").is_err());
    }

    #[test]
    fn blocked_destination_rejects_private_loopback_and_cgnat() {
        for raw in [
            "127.0.0.1:80",
            "10.0.0.1:80",
            "192.168.1.1:80",
            "0.0.0.0:80",
            "224.0.0.1:80",
            "100.64.0.1:80",
            "100.127.255.255:80",
            "255.255.255.255:80",
            "240.0.0.1:80",
            "[::1]:80",
            "[fc00::1]:80",
            "[::]:80",
            "[::ffff:127.0.0.1]:80",
            "[::ffff:10.0.0.1]:80",
            "[::ffff:100.64.0.1]:80",
        ] {
            let addr = raw.parse::<std::net::SocketAddr>().unwrap();
            assert!(is_blocked_destination(&addr), "{} should be blocked", raw);
        }
    }

    #[test]
    fn target_wire_encoding_is_protocol_compatible() {
        // 线格式兼容性固定向量：不得漂移。
        let tcp_domain = Target::tcp(Host::Domain("example.com".to_string()), 443);
        assert_eq!(tcp_domain.encode_wire(), b"example.com:443");

        let tcp_v4 = Target::tcp(Host::Ipv4("1.2.3.4".parse().unwrap()), 80);
        assert_eq!(tcp_v4.encode_wire(), b"1.2.3.4:80");

        let tcp_v6 = Target::tcp(Host::Ipv6("2001:db8::1".parse().unwrap()), 443);
        assert_eq!(tcp_v6.encode_wire(), b"[2001:db8::1]:443");

        let udp_domain = Target::udp(Host::Domain("example.com".to_string()), 53);
        assert_eq!(udp_domain.encode_wire(), b"udp:example.com:53");

        let udp_v4 = Target::udp(Host::Ipv4("8.8.8.8".parse().unwrap()), 53);
        assert_eq!(udp_v4.encode_wire(), b"udp:8.8.8.8:53");
    }

    #[test]
    fn target_wire_decode_round_trips() {
        for target in [
            Target::tcp(Host::Domain("example.com".to_string()), 443),
            Target::tcp(Host::Ipv4("1.2.3.4".parse().unwrap()), 80),
            Target::tcp(Host::Ipv6("2001:db8::1".parse().unwrap()), 443),
            Target::udp(Host::Domain("example.com".to_string()), 53),
            Target::udp(Host::Ipv4("8.8.8.8".parse().unwrap()), 53),
            Target::udp(Host::Ipv6("2001:db8::1".parse().unwrap()), 53),
        ] {
            let decoded = Target::decode_wire(&target.encode_wire()).unwrap();
            assert_eq!(decoded, target);
        }
    }

    #[test]
    fn target_wire_decode_accepts_legacy_unbracketed_ipv6() {
        // 旧 client 的 HTTP CONNECT 路径可能产生不带方括号的 IPv6 线格式。
        let decoded = Target::decode_wire(b"2001:db8::1:443").unwrap();
        assert_eq!(
            decoded,
            Target::tcp(Host::Ipv6("2001:db8::1".parse().unwrap()), 443)
        );
    }

    #[test]
    fn target_wire_decode_rejects_garbage() {
        assert!(Target::decode_wire(b"example.com").is_err());
        assert!(Target::decode_wire(b"example.com:0").is_err());
        assert!(Target::decode_wire(b"udp:").is_err());
        assert!(Target::decode_wire(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn target_wire_decode_udp_tolerates_zero_port_placeholder() {
        // socks5 UDP ASSOCIATE 的首帧目标惯用 0.0.0.0:0 占位，
        // 服务端不解析其实际地址（真实目的地址在 UoT 包内）。
        let decoded = Target::decode_wire(b"udp:0.0.0.0:0").unwrap();
        assert_eq!(
            decoded,
            Target::udp(Host::Ipv4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        );
        assert_eq!(decoded.encode_wire(), b"udp:0.0.0.0:0");
    }

    #[test]
    fn host_display_and_authority() {
        assert_eq!(Host::Domain("a.b".to_string()).authority(), "a.b");
        assert_eq!(
            Host::Ipv6("::1".parse().unwrap()).authority(),
            "[::1]"
        );
        assert_eq!(Host::from("1.2.3.4"), Host::Ipv4("1.2.3.4".parse().unwrap()));
        assert_eq!(Host::from("example.com"), Host::Domain("example.com".to_string()));
    }
}
