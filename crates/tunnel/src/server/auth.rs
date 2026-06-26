use lazy_static::lazy_static;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::common::TLS_RECORD_HEADER_LEN;
use crate::utils::MAX_TLS_RECORD_PAYLOAD_LEN;

const MAX_HANDSHAKES: usize = 512;
const MAX_ACTIVE_SESSIONS: usize = 4096;
pub(super) const SERVER_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const MAX_SERVER_INITIAL_RECORD_BYTES: usize = MAX_TLS_RECORD_PAYLOAD_LEN + TLS_RECORD_HEADER_LEN;

lazy_static! {
    pub(super) static ref HANDSHAKE_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_HANDSHAKES));
    pub(super) static ref ACTIVE_SESSION_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_ACTIVE_SESSIONS));
}

pub(super) async fn read_initial_client_record(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> std::io::Result<(u8, usize)> {
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    read_exact_with_deadline(stream, &mut header, deadline).await?;
    buf.clear();
    buf.extend_from_slice(&header);

    let typ = header[0];
    if typ != 0x16 {
        return Ok((typ, 0));
    }

    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let record_len = TLS_RECORD_HEADER_LEN + len;
    if len > MAX_TLS_RECORD_PAYLOAD_LEN || record_len > MAX_SERVER_INITIAL_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record too large",
        ));
    }

    read_payload_with_deadline(stream, buf, len, deadline).await?;
    Ok((typ, len))
}

pub(super) fn is_oversized_initial_record_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidData
        && err.to_string().contains("TLS record too large")
}

async fn read_exact_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    tokio::time::timeout_at(deadline, stream.read_exact(buf))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS read deadline exceeded")
        })??;
    Ok(())
}

async fn read_payload_with_deadline(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    len: usize,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    let mut remaining = len;
    let mut chunk = [0u8; 2048];

    while remaining > 0 {
        let want = remaining.min(chunk.len());
        let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk[..want]))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS read deadline exceeded")
            })??;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected eof while reading TLS record",
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
        remaining -= read;
    }

    Ok(())
}
