use lazy_static::lazy_static;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{resolve_allowed_camouflage, FailureClass};

/// 排空窗口。删掉此前那段 200–3000 ms 的随机关闭延迟之后，它就是这条路径上
/// **唯一**的自有时延，也因此直接等于对端观察到的关闭时刻。
///
/// 200 ms 的取舍：排空的目的是让「客户端已发出但尚在途中」的字节也落进接收
/// 队列并被读掉（未读数据会让 `close(2)` 补发 RST），因此它必须覆盖一个 RTT
/// 量级的窗口；另一方面它是我们叠在关闭时刻上的全部偏移，越短越好。
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(200);

/// 转发空闲上限：两个方向都在此时长内无字节流动才终止。取值远大于常见
/// 上游 keepalive_timeout（nginx 默认 75s），因此正常情况下总是上游先关闭、
/// 本超时不可观测；它只用来防止「双向永久静默」的连接把 per-IP 与全局
/// permit、fd 永久钉死——那会让限额被廉价耗尽，从而把服务器逼进
/// `emit_indistinguishable_close` 分支。
const PRE_AUTH_FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// 回落转发的限额。
///
/// **只剩并发限额，没有累计速率限额。** 此前还有一条「单 IP 3600 秒窗口内
/// 112 次回落 → 冷却 300 秒」的信誉规则，已删除，理由见 `try_pre_auth_fallback`
/// 上的说明：它是这套设计里唯一一处**探测者可以廉价、可复现地触发**的行为
/// 分叉。
pub(super) struct FallbackLimits {
    pub(super) max_pre_auth_fallbacks: usize,
    pub(super) max_pre_auth_fallbacks_per_ip: usize,
    pub(super) pre_auth_fallback_connect_timeout_secs: u64,
}

impl FallbackLimits {
    fn new() -> Self {
        Self {
            max_pre_auth_fallbacks: 512,
            max_pre_auth_fallbacks_per_ip: 16,
            pre_auth_fallback_connect_timeout_secs: 3,
        }
    }
}

pub(super) static FALLBACK_LIMITS: OnceLock<FallbackLimits> = OnceLock::new();

pub(super) fn fallback_limits() -> &'static FallbackLimits {
    FALLBACK_LIMITS.get_or_init(FallbackLimits::new)
}

lazy_static! {
    pub(super) static ref PRE_AUTH_FALLBACK_LIMITER: Arc<tokio::sync::Semaphore> = Arc::new(
        tokio::sync::Semaphore::new(fallback_limits().max_pre_auth_fallbacks)
    );
    pub(super) static ref PRE_AUTH_FALLBACK_PEER_COUNTS: std::sync::Mutex<HashMap<IpAddr, usize>> =
        std::sync::Mutex::new(HashMap::new());
}

pub(super) struct PreAuthFallbackPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    peer_ip: IpAddr,
}

impl Drop for PreAuthFallbackPermit {
    fn drop(&mut self) {
        let Ok(mut counts) = PRE_AUTH_FALLBACK_PEER_COUNTS.lock() else {
            warn!(peer_ip = %self.peer_ip, "pre-auth fallback peer-count mutex poisoned");
            return;
        };

        if let Some(count) = counts.get_mut(&self.peer_ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                counts.remove(&self.peer_ip);
            }
        }
    }
}

/// 无法回落时（限额耗尽 / 上游不可达）的统一关闭姿态：**有界排空，然后立刻
/// 关闭**。
///
/// # 必须保留的性质：先排空再关闭
///
/// socket 上留有未读数据时 `close(2)` 会在 FIN 之后再发一个 RST，于是「发过
/// ClientHello」与「什么都没发」得到不同的关闭序列——这个分裂本身就是一个
/// 免费的判别信号，一条连接即可据此分类服务器。排空后关闭类型恒为干净 FIN，
/// 与真实站点一致，且与客户端发过什么无关。
///
/// # 此前这里还有一段 200–3000 ms 的均匀随机延迟，现已删除
///
/// 它当初的理由是「把瞬时关闭（限额耗尽）与恒定时刻关闭（握手读超时）都抹成
/// 一个分布」。**但那个被抹的对象已经不存在了**：读超时（以及非 TLS 首记录、
/// 认证失败、超长 record 等全部输入驱动的失败）此后一律改走透明转发（§5.2），
/// 不再抵达本函数。于是这段延迟从「掩盖两个常量」退化成「凭空制造一个分布」。
///
/// 而**真实服务器不会在均匀随机延迟之后关闭**（原则 2：真实实现恒定的维度上
/// 随机化本身就是判别特征）。若这条分支被采样到，`U[0.2, 3.0] s` 的关闭时刻
/// 直方图是一眼可辨的合成形状——真实实现给出的要么是一个点质量，要么是由
/// RTT / 上游超时驱动的重尾分布，不会是一段干净的均匀分布。
///
/// 也不采用「对齐 `pre_auth_fallback_connect_timeout_secs`（3 秒）的
/// connect-timeout 形状」：
///   * 3 秒是**我们自己**的常量，不是任何 nginx 默认值（`proxy_connect_timeout`
///     默认 60 s）。对齐到一个观察者看不见的内部常量，等于换一个凭空的常量；
///   * 真正因「连不上上游」而到达这里的两条子路径（DNS 解析超时 / TCP connect
///     超时）**本来就已经花掉了那 3 秒**，再叠 3 秒只会得到 6 秒——那才是谁都
///     不像的形状；
///   * 其余子路径（握手并发限额、全局/单 IP 回落限额、活动会话限额）根本没有
///     尝试过上游，「上游超时」不是它们诚实的模型。
///
/// **诚实的模型是「服务端此刻没有容量」，而真实 nginx 在这个模型下给出的正是
/// accept 之后立即关闭**：`worker_connections` 耗尽时 nginx 会 accept 再
/// `ngx_close_accepted_connection()`，客户端观察到的就是一个几乎瞬时的干净 FIN。
/// 这是真实实现在**相同成因**下的真实行为，符合「对齐到真实来源」（§9.11）。
///
/// 附带的实质收益：删掉延迟之后，被拒连接不再在**服务端已经没有容量**的前提下
/// 额外占用 0.2–3 s 的 fd 与一个 `MAX_CONCURRENT_SERVER_CONNECTIONS` 名额。此前
/// 那是一个正反馈——越过载，每条被拒连接被扣留得越久，限额越容易被持续压满。
///
/// 关闭时刻因此收敛到「排空窗口」这一个短常量上，且与客户端发过什么无关
/// （无论收到多少字节，循环都跑满 `CLOSE_DRAIN_TIMEOUT`，除非对端先半关闭）。
pub(super) async fn emit_indistinguishable_close(mut client_stream: TcpStream) {
    let drain_deadline = Instant::now() + CLOSE_DRAIN_TIMEOUT;
    let mut scratch = [0u8; 4096];
    loop {
        let remaining = drain_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, client_stream.read(&mut scratch)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {}
        }
    }

    let _ = client_stream.shutdown().await;
}

pub(super) async fn emit_pre_auth_failure(
    mut client_stream: TcpStream,
    initial_data: Vec<u8>,
    host: &str,
    port: u16,
    class: FailureClass,
) {
    if matches!(class, FailureClass::CapacityLimited) {
        try_capacity_limited_fallback(client_stream, &initial_data, host, port).await;
        return;
    }

    match try_pre_auth_fallback(&mut client_stream, &initial_data, host, port).await {
        Ok(()) => return,
        Err(err) => debug!("pre-auth fallback unavailable: {}", err),
    }

    emit_indistinguishable_close(client_stream).await;
}

/// 把客户端已发送的字节透明转发到伪装端点，并双向中继到连接结束。
///
/// # 这里**没有**单 IP 累计速率限额（曾经有，已删除）
///
/// 此前存在一条 IP 信誉规则：单 IP 在 3600 秒窗口内回落 112 次即进入 300 秒
/// 冷却，冷却期内**停止转发**、一律走 `emit_indistinguishable_close`。它必须
/// 删掉，因为它恰好制造了这套设计声称不存在的东西：
///
/// 1. **它是可廉价、可复现触发的行为分叉。** §5.2 的核心主张是「探测者无法用
///    任何构造出的输入直接触发不转发的那条分支」。这条规则把该主张作废了——
///    不需要构造任何特殊输入，只需要**113 条普通 TCP 连接**。第 113 条起进入
///    冷却，此后 300 秒内该 IP 的每一条连接都落到那条分支上，探测者由此获得
///    一个免费、稳定、可反复取样的观测窗口。
/// 2. **暴露的差异是内容级的，不是时序级的。** 探测者第 1 条连接发
///    `GET / HTTP/1.1` 会拿到伪装站点真实的 HTTP 响应；第 114 条拿到的是静默
///    关闭。这是零误报的判别，**任何关闭姿态的整形都掩盖不了它**——差的不是
///    关闭时刻，是有没有内容。
/// 3. **阈值本身可被精确测出。** 耐心的探测者做二分即可得到 112 与 300 s 这两
///    个精确取值。真实 nginx 没有任何「同一 IP 连满 N 次就停止服务 300 秒」的
///    默认行为；即便显式配置了 `limit_req` / `limit_conn`，nginx 的应答也是一个
///    503 页面（可见内容），而不是静默关闭。
///
/// 删除它不损失实际的资源保护：真正约束 fd / 内存 / permit 的是**并发**限额
/// （全局 512、单 IP 16），它们仍在。放大比也没有变化——一条入站连接至多对应
/// 一条到伪装端点的出站连接，转发的字节就是探测者自己发的那些，探测者直连
/// 伪装站点能做的事情完全一样，经由我们并不更便宜。
pub(super) async fn try_pre_auth_fallback(
    client_stream: &mut TcpStream,
    initial_data: &[u8],
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let peer_ip = client_stream.peer_addr()?.ip();
    let _permit = try_acquire_pre_auth_fallback_permit(peer_ip)
        .ok_or_else(|| anyhow::anyhow!("pre-auth fallback limit reached"))?;

    let connect_timeout =
        Duration::from_secs(fallback_limits().pre_auth_fallback_connect_timeout_secs);
    let fallback_addr =
        tokio::time::timeout(connect_timeout, resolve_allowed_camouflage(host, port))
            .await
            .map_err(|_| anyhow::anyhow!("pre-auth fallback resolve timeout"))??;
    let mut fallback_stream =
        tokio::time::timeout(connect_timeout, TcpStream::connect(fallback_addr))
            .await
            .map_err(|_| anyhow::anyhow!("pre-auth fallback connect timeout"))??;
    fallback_stream.set_nodelay(true)?;

    if !initial_data.is_empty() {
        fallback_stream.write_all(initial_data).await?;
    }

    relay_pre_auth_fallback(client_stream, &mut fallback_stream).await?;
    Ok(())
}

pub(super) async fn relay_pre_auth_fallback(
    client_stream: &mut TcpStream,
    fallback_stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let (mut cr, mut cw) = tokio::io::split(client_stream);
    let (mut fr, mut fw) = tokio::io::split(&mut *fallback_stream);
    let activity = AtomicU64::new(0);

    let pump = async {
        tokio::join!(
            copy_and_propagate_eof(&mut cr, &mut fw, &activity),
            copy_and_propagate_eof(&mut fr, &mut cw, &activity),
        )
    };
    tokio::pin!(pump);

    loop {
        let seen = activity.load(Ordering::Relaxed);
        tokio::select! {
            (r1, r2) = &mut pump => {
                debug!(?r1, ?r2, "fallback relay ended");
                break;
            }
            _ = tokio::time::sleep(PRE_AUTH_FALLBACK_IDLE_TIMEOUT) => {
                if activity.load(Ordering::Relaxed) == seen {
                    debug!("fallback relay idle timeout");
                    break;
                }
            }
        }
    }
    Ok(())
}

/// 单向泵送，并在读到 EOF 后 **shutdown 对侧写端**。
///
/// `tokio::io::copy` 只在 EOF 时 flush、从不调 `poll_shutdown`，而原实现又
/// 把 `fallback_stream.shutdown()` 放在 `join!` 两向都结束之后。结果是客户端
/// 的 `shutdown(SHUT_WR)`（curl 等的标准收尾）不会传播到上游：nginx 看不到
/// EOF，连接一直挂到它自己的 keepalive_timeout，与直连行为可区分。
async fn copy_and_propagate_eof<R, W>(
    reader: &mut R,
    writer: &mut W,
    activity: &AtomicU64,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        activity.fetch_add(1, Ordering::Relaxed);
        total += n as u64;
    }
    let _ = writer.shutdown().await;
    Ok(total)
}

pub(super) async fn try_capacity_limited_fallback(
    mut client_stream: TcpStream,
    initial_data: &[u8],
    host: &str,
    port: u16,
) {
    match try_pre_auth_fallback(&mut client_stream, initial_data, host, port).await {
        Ok(()) => return,
        Err(e) => {
            debug!("capacity-limited fallback failed: {}", e);
        }
    }

    emit_indistinguishable_close(client_stream).await;
}

pub(super) fn try_acquire_pre_auth_fallback_permit(
    peer_ip: IpAddr,
) -> Option<PreAuthFallbackPermit> {
    let permit = PRE_AUTH_FALLBACK_LIMITER.clone().try_acquire_owned().ok()?;
    let Ok(mut counts) = PRE_AUTH_FALLBACK_PEER_COUNTS.lock() else {
        return None;
    };

    let count = counts.entry(peer_ip).or_insert(0);
    if *count >= fallback_limits().max_pre_auth_fallbacks_per_ip {
        return None;
    }
    *count += 1;

    Some(PreAuthFallbackPermit {
        _permit: permit,
        peer_ip,
    })
}
