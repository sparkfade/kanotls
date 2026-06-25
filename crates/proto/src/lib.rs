pub mod http;
pub mod socks5;
pub mod target;
pub mod uot;

use kanotls_session::{Stream, RELAY_CHUNK_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) async fn relay_bidirectional(
    mut local_reader: impl AsyncReadExt + Unpin,
    mut local_writer: impl AsyncWriteExt + Unpin,
    mut remote: Stream,
) -> Result<(u64, u64), anyhow::Error> {
    let mut tx_total: u64 = 0;
    let mut rx_total: u64 = 0;
    let mut read_buf = vec![0u8; RELAY_CHUNK_SIZE];
    let mut local_eof = false;
    let mut remote_eof = false;

    while !local_eof || !remote_eof {
        tokio::select! {
            result = local_reader.read(&mut read_buf), if !local_eof => {
                match result {
                    Ok(0) => {
                        let _ = remote.close_write().await;
                        local_eof = true;
                    }
                    Ok(n) => {
                        remote.write(&read_buf[..n]).await?;
                        tx_total += n as u64;
                    }
                    Err(_) => {
                        let _ = remote.close_write().await;
                        local_eof = true;
                    }
                }
            }
            data = remote.read(), if !remote_eof => {
                match data {
                    Some(d) => {
                        local_writer.write_all(&d).await?;
                        rx_total += d.len() as u64;
                    }
                    None => {
                        local_writer.shutdown().await?;
                        remote_eof = true;
                    }
                }
            }
        }
    }

    let _ = remote.close().await;
    Ok((tx_total, rx_total))
}
