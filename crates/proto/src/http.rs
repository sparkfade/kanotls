use crate::target::parse_authority_target;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

const MAX_REQUEST_LINE: usize = 8192;
const MAX_HEADER_BLOCK: usize = 32 * 1024;
const LOCAL_PROTOCOL_TIMEOUT_SECS: u64 = 10;

pub struct HttpConnectRequest {
    pub local_reader: tokio::net::tcp::OwnedReadHalf,
    pub local_writer: tokio::net::tcp::OwnedWriteHalf,
    pub target: String,
}

pub async fn parse_http_inbound(
    local: tokio::net::TcpStream,
) -> Result<HttpConnectRequest, anyhow::Error> {
    tokio::time::timeout(
        std::time::Duration::from_secs(LOCAL_PROTOCOL_TIMEOUT_SECS),
        parse_http_inbound_inner(local),
    )
    .await
    .map_err(|_| anyhow::anyhow!("http CONNECT request timeout"))?
}

async fn parse_http_inbound_inner(
    local: tokio::net::TcpStream,
) -> Result<HttpConnectRequest, anyhow::Error> {
    let (reader_init, mut writer) = local.into_split();
    let mut reader = BufReader::new(reader_init);

    let (method, target) = {
        let mut line = String::new();
        read_limited_line(&mut reader, &mut line, MAX_REQUEST_LINE).await?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            anyhow::bail!("invalid http request: {}", line);
        }
        let method = parts[0].to_string();
        let target = parts[1].to_string();

        // 只累计头部块字节数做上限检查，不保存内容。
        let mut header_block_len = line.len();
        loop {
            line = String::new();
            let n = read_limited_line(&mut reader, &mut line, MAX_REQUEST_LINE).await?;
            if n <= 2 {
                break;
            }
            header_block_len += line.len();
            if header_block_len > MAX_HEADER_BLOCK {
                anyhow::bail!("http header block too large");
            }
        }
        (method, target)
    };

    if method != "CONNECT" {
        writer
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await?;
        anyhow::bail!("only HTTP CONNECT is supported by this proxy");
    }

    let (host, port) = parse_connect_target(&target)?;
    debug!("http {} request to {}:{}", method, host, port);

    let local_reader = reader.into_inner();
    Ok(HttpConnectRequest {
        local_reader,
        local_writer: writer,
        target: format!("{}:{}", host, port),
    })
}

pub async fn write_http_connect_success(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<(), anyhow::Error> {
    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    Ok(())
}

async fn read_limited_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    line: &mut String,
    max_len: usize,
) -> Result<usize, anyhow::Error> {
    let mut total = 0usize;
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(total);
        }

        let take = match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => pos + 1,
            None => buf.len(),
        };
        if total.saturating_add(take) > max_len {
            anyhow::bail!("http request line too large");
        }
        line.push_str(std::str::from_utf8(&buf[..take])?);
        reader.consume(take);
        total += take;

        if line.ends_with('\n') {
            return Ok(total);
        }
    }
}

pub async fn relay_http_connect(
    local_reader: impl AsyncReadExt + Unpin,
    local_writer: impl AsyncWriteExt + Unpin,
    remote: kanotls_session::Stream,
) -> Result<(u64, u64), anyhow::Error> {
    crate::relay_bidirectional(local_reader, local_writer, remote).await
}

fn parse_connect_target(target: &str) -> Result<(String, u16), anyhow::Error> {
    if target.contains('/') || target.contains("://") {
        anyhow::bail!("CONNECT target must be authority-form host:port");
    }

    parse_authority_target(target).map_err(|e| match e.to_string().as_str() {
        "missing port in target" => anyhow::anyhow!("missing CONNECT port"),
        "empty target host" => anyhow::anyhow!("empty CONNECT host"),
        "invalid target port 0" => anyhow::anyhow!("invalid CONNECT port 0"),
        other => anyhow::anyhow!(other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_target_accepts_authority_form() {
        assert_eq!(
            parse_connect_target("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_connect_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn parse_connect_target_rejects_non_connect_forms() {
        assert!(parse_connect_target("http://example.com/").is_err());
        assert!(parse_connect_target("example.com").is_err());
        assert!(parse_connect_target("example.com:0").is_err());
    }
}
