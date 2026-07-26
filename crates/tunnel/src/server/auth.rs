use lazy_static::lazy_static;
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

/// 尚未收到任何字节时的读截止时间。
///
/// 此前的实现有两处错误，方向相反但成因相同——都把「我们自己的超时」当成
/// 了需要被塑形的可观测量：
///
/// 1. **不按已收字节数分流。** 无论收到 0 字节还是半条 ClientHello，都用同
///    一个 8–15 s 的截止时间。而「连上不发数据」的路径是：读超时 →
///    `FailureClass::HandshakeTimeout` → `emit_pre_auth_failure` →
///    `try_pre_auth_fallback`（`initial_data` 为空）→ 连上游 → 上游按自己的
///    `client_header_timeout` 关闭。于是探测者观察到的总关闭时刻 =
///    **上游超时 + 我们的超时**，相对直连 nginx 的精确 60.000 s 是一个 8–15 s
///    量级的正偏移，一次连接即可测出。
/// 2. **用随机化去「消除常量」。** 真实 nginx 的 `client_header_timeout` 是一
///    个精确常量（默认 60 s）——真实服务器**没有**随机超时。给我们自己的超时
///    加抖动，等于在一个真实实现恒定的维度上引入随机性，那本身就是判别特征
///    （「全随机」和「有稳定常量」一样会被识别）。
///
/// 正确的目标不是让我们的超时看起来随机，而是**让它不可观测**：把我们贡献
/// 的那一项压到远小于上游超时，上游那个真实常量就会占绝对主导。因此这里取
/// 一个短的固定值，不做任何随机化。
///
/// 2 s 的取舍：合法客户端在 TCP 握手完成后的 0.5 RTT 内就发出 ClientHello，
/// 即使 1 s RTT 的极端链路也在 0.5 s 内到齐，2 s 留了 4× 余量；同时它相对
/// 上游数十秒的超时只贡献约 3% 的偏移。
const INITIAL_RECORD_ZERO_BYTE_TIMEOUT: Duration = Duration::from_secs(2);

/// 已收到 ≥1 字节后的读截止时间。
///
/// ClientHello 可能被 MSS 分片或被客户端分多次写出，所以这一档要宽于零字节
/// 档；但原来的 8–15 s 既无必要（剩余分片会在 1 个 RTT 内到齐）又把同样的
/// 偏移叠回总关闭时刻上。同样取固定值、不随机化。
const INITIAL_RECORD_PARTIAL_TIMEOUT: Duration = Duration::from_secs(5);

lazy_static! {
    pub(super) static ref HANDSHAKE_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_HANDSHAKES));
    pub(super) static ref ACTIVE_SESSION_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_ACTIVE_SESSIONS));
}

/// 本连接读取初始 record 的两个截止时刻（见上）。
///
/// 两者都以同一个 `now` 为原点，所以「ClientHello 被分片」这一路的总预算是
/// accept 起 5 s，而不是「零字节 2 s 之后再加 5 s」。
#[derive(Clone, Copy)]
pub(super) struct InitialRecordDeadlines {
    /// 一个字节都还没收到时的截止时刻。
    pub(super) zero_byte: tokio::time::Instant,
    /// 已收到 ≥1 字节后的截止时刻。
    pub(super) partial: tokio::time::Instant,
}

pub(super) fn initial_record_deadlines() -> InitialRecordDeadlines {
    let now = tokio::time::Instant::now();
    InitialRecordDeadlines {
        zero_byte: now + INITIAL_RECORD_ZERO_BYTE_TIMEOUT,
        partial: now + INITIAL_RECORD_PARTIAL_TIMEOUT,
    }
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
    deadlines: InitialRecordDeadlines,
) -> std::io::Result<(u8, usize)> {
    buf.clear();
    read_into_with_deadline(stream, buf, TLS_RECORD_HEADER_LEN, deadlines).await?;

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

    read_into_with_deadline(stream, buf, len, deadlines).await?;
    Ok((typ, len))
}

/// 向 `buf` 追加读取 `len` 字节。全部到齐返回 Ok；超时 / EOF / IO 错误返回
/// Err，但 `buf` 始终恰好保留已经真实收到的字节数（不留零填充）。
///
/// 每轮 `read` 前按「至今是否收到过字节」选择截止时刻：`filled` 从 `start`
/// 起算，因此 `filled == 0` 严格等价于「本连接一个字节都没收到过」（第二次
/// 调用读 record body 时 `start == 5`，恒走 `partial`）。收到第一个字节即自动
/// 延长到 `partial` 那一档，ClientHello 分片不会被误杀。
///
/// 注意 `buf` 只是**读缓冲**：`resize` 出来的零字节在任何失败路径上都会被
/// `truncate(filled)` 砍掉，交给 pre-auth 回落的永远只有客户端真实发送过的
/// 字节（§5.2 的关键性质）。分流不改变这一点。
async fn read_into_with_deadline(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    len: usize,
    deadlines: InitialRecordDeadlines,
) -> std::io::Result<()> {
    let start = buf.len();
    let target = start + len;
    buf.resize(target, 0);

    let mut filled = start;
    while filled < target {
        let deadline = if filled == 0 {
            deadlines.zero_byte
        } else {
            deadlines.partial
        };
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
