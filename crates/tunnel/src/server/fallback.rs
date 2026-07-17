use lazy_static::lazy_static;
use lru::LruCache;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{resolve_allowed_camouflage, FailureClass};

pub(super) const MAX_IP_REPUTATION_ENTRIES: usize = 65536;

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

pub(super) async fn emit_shaped_failure(mut client_stream: TcpStream) {
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

    emit_shaped_failure(client_stream).await;
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

    let c2f = tokio::io::copy(&mut cr, &mut fw);
    let f2c = tokio::io::copy(&mut fr, &mut cw);

    let (r1, r2) = tokio::join!(c2f, f2c);
    debug!(?r1, ?r2, "fallback relay ended");

    let _ = fallback_stream.shutdown().await;
    Ok(())
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

    emit_shaped_failure(client_stream).await;
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
