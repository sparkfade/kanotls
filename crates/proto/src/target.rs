pub fn parse_authority_target(target: &str) -> Result<(String, u16), anyhow::Error> {
    if let Some(rest) = target.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed IPv6 target"))?;
        let host = &rest[..end];
        let port_part = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("missing port in target"))?;
        let port = port_part.parse::<u16>()?;
        if port == 0 {
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
    if port == 0 {
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
}
