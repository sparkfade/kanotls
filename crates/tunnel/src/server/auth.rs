use lazy_static::lazy_static;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::common::TLS_RECORD_HEADER_LEN;
use crate::utils::MAX_TLS_RECORD_PAYLOAD_LEN;

const MAX_HANDSHAKES: usize = 512;
const MAX_ACTIVE_SESSIONS: usize = 4096;
pub(super) const SERVER_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// 初始 record 读取的超时区间。固定 10s 会让「连上不发数据」的探测在
/// 恰好 T+10.000s 得到一个可测到毫秒的常量时刻；逐连接抖动消除该常量。
const INITIAL_RECORD_TIMEOUT_MIN_SECS: u64 = 8;
const INITIAL_RECORD_TIMEOUT_MAX_SECS: u64 = 15;

lazy_static! {
    pub(super) static ref HANDSHAKE_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_HANDSHAKES));
    pub(super) static ref ACTIVE_SESSION_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_ACTIVE_SESSIONS));
}

/// 本连接读取初始 record 的截止时刻（逐连接抖动，见上）。
pub(super) fn initial_record_deadline() -> tokio::time::Instant {
    let secs =
        rand::thread_rng().gen_range(INITIAL_RECORD_TIMEOUT_MIN_SECS..=INITIAL_RECORD_TIMEOUT_MAX_SECS);
    tokio::time::Instant::now() + Duration::from_secs(secs)
}

/// 读取客户端的第一条 TLS record 到 `buf`。
///
/// 不变量：**`buf` 只包含客户端真实发送过的字节**。任何失败路径下都不会
/// 出现填充或伪造的内容——因为失败时 `buf` 会被原样交给 pre-auth 回落
/// 转发给伪装端点，而向真实站点发送客户端从未发送过的字节，是直连所不
/// 可能出现的行为（此前的实现会先 `resize(len, 0)` 预填零，超时后把一个
/// 零填充的"完整" ClientHello 转发上游，站点随即回一个 decode_error 告警）。
pub(super) async fn read_initial_client_record(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> std::io::Result<(u8, usize)> {
    buf.clear();
    read_into_with_deadline(stream, buf, TLS_RECORD_HEADER_LEN, deadline).await?;

    let typ = buf[0];
    if typ != 0x16 {
        return Ok((typ, 0));
    }

    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len > MAX_TLS_RECORD_PAYLOAD_LEN {
        // 声明长度超限：不再 fail-closed。按非 0x16 记录同一口径返回，
        // 已收到的 5 字节头随回落转发给伪装端点、其余字节由转发的 copy
        // 循环流式泵送（本地不缓冲声明长度，无放大风险）。
        //
        // 此前这里返回 InvalidData 并被路由到静默关闭：探测者只需发
        // `16 03 03 41 01` 五个字节就能稳定拿到「瞬时关闭」，而真实站点
        // 要么继续读 body，要么回 record_overflow 告警，绝不会凭空消失。
        return Ok((typ, 0));
    }

    read_into_with_deadline(stream, buf, len, deadline).await?;
    Ok((typ, len))
}

/// 向 `buf` 追加读取 `len` 字节。全部到齐返回 Ok；超时 / EOF / IO 错误返回
/// Err，但 `buf` 始终恰好保留已经真实收到的字节数（不留零填充）。
async fn read_into_with_deadline(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    len: usize,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    let start = buf.len();
    let target = start + len;
    buf.resize(target, 0);

    let mut filled = start;
    while filled < target {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => {
                buf.truncate(filled);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof before initial TLS record completed",
                ));
            }
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => {
                buf.truncate(filled);
                return Err(e);
            }
            Err(_) => {
                buf.truncate(filled);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS read deadline exceeded",
                ));
            }
        }
    }
    Ok(())
}
