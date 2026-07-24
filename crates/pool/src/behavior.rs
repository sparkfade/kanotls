use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const MIN_INITIAL_CONNECTIONS: usize = 1;
pub(crate) const MAX_INITIAL_CONNECTIONS: usize = 3;
pub(crate) const IDLE_DRAIN_SECS: u64 = 30;
pub(crate) const DEFAULT_MONITOR_INTERVAL_MS: u64 = 500;
pub(crate) const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 15;
pub(crate) const TIME_OF_DAY_BUCKET_SECS: u64 = 4 * 60 * 60;

/// 连接池行为参数：由 PSK 与安装盐派生的基准范围，
/// 再叠加 [`PoolBehaviorContext`] 的种子解析出本次运行的具体值。
#[derive(Clone)]
pub struct PoolBehaviorConfig {
    pub(crate) min_target_pool_size: usize,
    pub(crate) max_target_pool_size: usize,
    pub(crate) min_initial_connections: usize,
    pub(crate) max_initial_connections: usize,
    pub(crate) min_startup_jitter_ms: u64,
    pub(crate) max_startup_jitter_ms: u64,
    pub(crate) soft_ttl_secs: u64,
    pub(crate) idle_drain_secs: u64,
    pub(crate) monitor_interval: Duration,
    pub(crate) acquire_timeout: Duration,
}

impl PoolBehaviorConfig {
    pub fn from_psk(psk: &[u8], install_salt: &[u8]) -> Self {
        let h = hash_bytes(0x1337_BEEF, psk);
        let h = hash_bytes(h, install_salt);
        let min_target = seeded_usize_inclusive(h, 4, 8);
        let max_target = seeded_usize_inclusive(h ^ 0x01, min_target + 2, 16);
        let min_jitter = seeded_u64_inclusive(h ^ 0x02, 50, 300);
        let max_jitter = seeded_u64_inclusive(h ^ 0x03, min_jitter + 300, 2500);
        let soft_ttl = seeded_u64_inclusive(h ^ 0x04, 120, 300);
        Self {
            min_target_pool_size: min_target,
            max_target_pool_size: max_target,
            min_initial_connections: MIN_INITIAL_CONNECTIONS,
            max_initial_connections: MAX_INITIAL_CONNECTIONS,
            min_startup_jitter_ms: min_jitter,
            max_startup_jitter_ms: max_jitter,
            soft_ttl_secs: soft_ttl,
            idle_drain_secs: IDLE_DRAIN_SECS,
            monitor_interval: Duration::from_millis(DEFAULT_MONITOR_INTERVAL_MS),
            acquire_timeout: Duration::from_secs(DEFAULT_ACQUIRE_TIMEOUT_SECS),
        }
    }

    pub(crate) fn resolve(&self, context: &PoolBehaviorContext) -> ResolvedPoolBehavior {
        let seed = context.seed();
        let target_pool_size = seeded_usize_inclusive(
            derive_seed(seed, 0x10),
            self.min_target_pool_size,
            self.max_target_pool_size,
        );
        let initial_connection_count = seeded_usize_inclusive(
            derive_seed(seed, 0x11),
            self.min_initial_connections.min(target_pool_size.max(1)),
            self.max_initial_connections.min(target_pool_size.max(1)),
        );

        ResolvedPoolBehavior {
            seed,
            target_pool_size,
            initial_connection_count,
            spawn_cluster_len: seeded_u64_inclusive(derive_seed(seed, 0x14), 2, 4),
        }
    }

    pub(crate) fn lifecycle(&self) -> PoolLifecycle {
        PoolLifecycle {
            soft_ttl: Duration::from_secs(self.soft_ttl_secs),
            idle_timeout: Duration::from_secs(self.idle_drain_secs),
        }
    }

    pub(crate) fn staggered_delays(
        &self,
        behavior: &ResolvedPoolBehavior,
        start_slot: u64,
        count: usize,
    ) -> Vec<Duration> {
        let mut delays = Vec::with_capacity(count);
        let mut total_ms = 0u64;
        let burst_gap_max = self
            .min_startup_jitter_ms
            .saturating_add(self.max_startup_jitter_ms)
            .saturating_div(2)
            .max(self.min_startup_jitter_ms);
        for idx in 0..count {
            let slot = start_slot + idx as u64;
            let gap_seed = derive_seed(behavior.seed ^ slot.rotate_left(11), 0x30);
            let gap_ms = if (slot + 1).is_multiple_of(behavior.spawn_cluster_len) {
                seeded_u64_inclusive(gap_seed, burst_gap_max, self.max_startup_jitter_ms)
            } else {
                seeded_u64_inclusive(gap_seed, self.min_startup_jitter_ms, burst_gap_max)
            };
            total_ms = total_ms.saturating_add(gap_ms);
            delays.push(Duration::from_millis(total_ms));
        }
        delays
    }
}

#[derive(Clone)]
pub(crate) struct PoolLifecycle {
    pub(crate) soft_ttl: Duration,
    pub(crate) idle_timeout: Duration,
}

#[derive(Clone)]
pub(crate) struct ResolvedPoolBehavior {
    pub(crate) seed: u64,
    pub(crate) target_pool_size: usize,
    pub(crate) initial_connection_count: usize,
    pub(crate) spawn_cluster_len: u64,
}

/// 行为种子上下文：由装配层以指纹族名与 SNI 构造，
/// 叠加启动时刻与随机 nonce 派生本次运行的池行为。
#[derive(Clone)]
pub struct PoolBehaviorContext {
    fingerprint_family: String,
    sni: String,
    startup_epoch_secs: u64,
    time_of_day_bucket: u64,
    random_nonce: u64,
}

impl PoolBehaviorContext {
    pub fn new(fingerprint_family: &str, sni: &str) -> Self {
        let startup_epoch_secs = current_unix_epoch_secs();
        Self {
            fingerprint_family: fingerprint_family.to_string(),
            sni: sni.trim().to_ascii_lowercase(),
            startup_epoch_secs,
            time_of_day_bucket: (startup_epoch_secs % 86_400) / TIME_OF_DAY_BUCKET_SECS,
            random_nonce: rand::random::<u64>(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            fingerprint_family: "firefox".to_string(),
            sni: "example.com".to_string(),
            startup_epoch_secs: 1_700_000_000,
            time_of_day_bucket: 3,
            random_nonce: 0xDEADBEEF,
        }
    }

    fn seed(&self) -> u64 {
        let mut seed = 0xcbf29ce484222325u64;
        seed = hash_bytes(seed, self.fingerprint_family.as_bytes());
        seed = hash_bytes(seed, self.sni.as_bytes());
        seed = hash_u64(seed, self.time_of_day_bucket);
        seed = hash_u64(seed, self.startup_epoch_secs);
        seed = hash_u64(seed, self.random_nonce);

        let temporal_salt = current_unix_epoch_secs() / 3600;
        seed ^= temporal_salt.wrapping_mul(0x9e3779b97f4a7c15);

        seed
    }
}

pub(crate) fn current_unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn hash_bytes(mut seed: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        seed ^= u64::from(*byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    seed
}

fn hash_u64(seed: u64, value: u64) -> u64 {
    hash_bytes(seed, &value.to_le_bytes())
}

pub(crate) fn derive_seed(seed: u64, salt: u64) -> u64 {
    splitmix64(seed ^ salt.wrapping_mul(0x9e3779b97f4a7c15))
}

pub(crate) fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

pub(crate) fn seeded_usize_inclusive(seed: u64, min: usize, max: usize) -> usize {
    if min >= max {
        min
    } else {
        min + (splitmix64(seed) as usize % (max - min + 1))
    }
}

pub(crate) fn seeded_u64_inclusive(seed: u64, min: u64, max: u64) -> u64 {
    if min >= max {
        min
    } else {
        min + (splitmix64(seed) % (max - min + 1))
    }
}
