use lazy_static::lazy_static;
use lru::LruCache;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{resolve_allowed_camouflage, FailureClass};

pub(super) const MAX_IP_REPUTATION_ENTRIES: usize = 65536;

/// `emit_indistinguishable_close` 关闭前的接收队列排空上限（见该函数注释）。
const CLOSE_DRAIN_MAX_BYTES: usize = 64 * 1024;
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(200);
/// 关闭延迟采样区间：宽到足以淹没常量特征，又不至于长期占用 fd。
const CLOSE_DELAY_MIN_MS: u64 = 200;
const CLOSE_DELAY_MAX_MS: u64 = 3000;

/// 转发空闲上限：两个方向都在此时长内无字节流动才终止。取值远大于常见
/// 上游 keepalive_timeout（nginx 默认 75s），因此正常情况下总是上游先关闭、
/// 本超时不可观测；它只用来防止「双向永久静默」的连接把 per-IP 与全局
/// permit、fd 永久钉死——那会让限额被廉价耗尽，从而把服务器逼进
/// `emit_indistinguishable_close` 分支。
const PRE_AUTH_FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub(super) struct FallbackLimits {
    pub(super) max_pre_auth_fallbacks: usize,
    pub(super) max_pre_auth_fallbacks_per_ip: usize,
    pub(super) pre_auth_fallback_connect_timeout_secs: u64,
    pub(super) ip_reputation_cooldown_secs: u64,
    pub(super) ip_reputation_reset_secs: u64,
    pub(super) ip_reputation_max_fallbacks_per_window: u64,
}

impl FallbackLimits {
    fn new() -> Self {
        Self {
            max_pre_auth_fallbacks: 512,
            max_pre_auth_fallbacks_per_ip: 16,
            pre_auth_fallback_connect_timeout_secs: 3,
            ip_reputation_cooldown_secs: 300,
            ip_reputation_reset_secs: 3600,
            ip_reputation_max_fallbacks_per_window: 112,
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
    pub(super) static ref IP_REPUTATIONS: std::sync::Mutex<LruCache<IpAddr, IpReputation>> =
        std::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_IP_REPUTATION_ENTRIES)
                .expect("non-zero IP reputation cache size")
        ));
}

pub(super) struct PreAuthFallbackPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    peer_ip: IpAddr,
}

#[derive(Clone, Debug)]
pub(super) struct IpReputation {
    fallback_count: u64,
    first_seen: Instant,
    last_seen: Instant,
    cooldown_until: Option<Instant>,
}

impl IpReputation {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            fallback_count: 0,
            first_seen: now,
            last_seen: now,
            cooldown_until: None,
        }
    }
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

/// 无法回落时（限额耗尽 / 冷却 / 上游不可达）的统一关闭姿态。
///
/// 两个要点，缺一不可：
///
/// 1. **先有界排空接收队列再关闭。** socket 上留有未读数据时 `close(2)` 会
///    发 RST 而非 FIN，于是「发过 ClientHello」与「什么都没发」得到不同的
///    关闭类型——这个分裂本身就是一个免费的判别信号。排空后关闭类型恒为
///    FIN，与真实站点一致。
/// 2. **关闭前插入随机延迟。** 瞬时关闭（限额耗尽）与恒定时刻关闭（握手
///    超时）都是可测到毫秒的常量。随机延迟把这两类失败塌缩成同一个无法
///    与彼此、也无法与网络抖动区分的分布。
///
/// 注意这条路径只在限额真正耗尽时才走得到——输入驱动的失败（非 TLS 首
/// 记录、认证失败、超长 record、读超时）一律走透明转发。
pub(super) async fn emit_indistinguishable_close(mut client_stream: TcpStream) {
    let drain_deadline = Instant::now() + CLOSE_DRAIN_TIMEOUT;
    let mut scratch = [0u8; 4096];
    let mut drained = 0usize;
    while drained < CLOSE_DRAIN_MAX_BYTES {
        let remaining = drain_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, client_stream.read(&mut scratch)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => drained += n,
        }
    }

    tokio::time::sleep(sample_close_delay()).await;
    let _ = client_stream.shutdown().await;
}

fn sample_close_delay() -> Duration {
    use rand::Rng;
    Duration::from_millis(
        rand::thread_rng().gen_range(CLOSE_DELAY_MIN_MS..=CLOSE_DELAY_MAX_MS),
    )
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

pub(super) fn check_ip_reputation(ip: IpAddr) -> bool {
    let Ok(mut reps) = IP_REPUTATIONS.lock() else {
        return false;
    };
    let now = Instant::now();

    let mut entry = match reps.get(&ip) {
        Some(reputation) => {
            if let Some(cooldown) = reputation.cooldown_until {
                if now < cooldown {
                    return false;
                }
            }
            reputation.clone()
        }
        None => IpReputation::new(),
    };
    entry.fallback_count += 1;
    entry.last_seen = now;

    let limits = fallback_limits();
    let age = now.duration_since(entry.first_seen);
    if entry.fallback_count > limits.ip_reputation_max_fallbacks_per_window
        && age < Duration::from_secs(limits.ip_reputation_reset_secs)
    {
        entry.cooldown_until = Some(now + Duration::from_secs(limits.ip_reputation_cooldown_secs));
        reps.put(ip, entry);
        warn!("IP {:?} placed in cooldown for excessive fallbacks", ip);
        return false;
    }

    if age > Duration::from_secs(limits.ip_reputation_reset_secs) {
        entry = IpReputation::new();
        entry.fallback_count = 1;
    }

    reps.put(ip, entry);
    true
}

pub(super) async fn try_pre_auth_fallback(
    client_stream: &mut TcpStream,
    initial_data: &[u8],
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let peer_ip = client_stream.peer_addr()?.ip();
    if !check_ip_reputation(peer_ip) {
        anyhow::bail!("IP in cooldown or rate-limited");
    }

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
