use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const MIN_INITIAL_CONNECTIONS: usize = 1;
pub(crate) const MAX_INITIAL_CONNECTIONS: usize = 3;

/// 客户端空闲连接的拆除时限，取 Firefox 的
/// `network.http.keep-alive.timeout` 默认值（115 秒）。**不加抖动**：真实
/// 实现在这个维度上就是常量，在常量维度上随机化本身即判别特征。115 这个
/// 数字在 Firefox 里也不是随口取的——它刚好压在常见 NAT / 状态防火墙的
/// 2 分钟表项超时之下，所以它同时是「合理的实现者会选的值」。
///
/// 此前是 30 秒，于是客户端恒定早于服务端的空闲拆除（默认 75 秒）动手：
/// 观察者看到每条连接在静默后**恰好 30.0 秒**由客户端发出 close_notify +
/// FIN，且同一客户端所有连接都落在同一点上。改成 115 秒后先触发的那一侧
/// 变成服务端，与真实 H2 一致——现实中几乎总是服务端按自己的
/// `keepalive_timeout` 回收空闲连接，客户端的 keep-alive 上限反而很少被
/// 观测到。
pub(crate) const IDLE_DRAIN_SECS: u64 = 115;

/// 连接寿命的硬上限，取 nginx `keepalive_time` 的默认值（1 小时）——该
/// 指令的语义正是「一条 keep-alive 连接最长可被复用多久」，与本字段一致。
///
/// 此前是逐进程从 120–300 秒采样：真实浏览器**不会**每两三分钟主动回收一
/// 条健康的 H2 连接，它会一直用下去，直到空闲超时或服务端发 GOAWAY；而
/// 因为该值是进程常量，同一客户端的所有连接寿命还集中在同一点上。提到 1
/// 小时后，任何一次超过 115 秒的空闲（默认配置下超过服务端的 75 秒即可）
/// 都会先把连接收走，本上限在正常使用下不可观测——这是「让常量不可观测」
/// 而非「让常量变随机」的处理方式。
///
/// 它的角色因此从「行为伪装」退化为纯粹的**资源兜底**：防止一条持续繁忙
/// 的连接无限期存活、把 fd 与会话状态钉死。到期时连接先转入 Draining，
/// 等活跃流自然排空才关闭，因此不会打断在飞的传输。
pub(crate) const SOFT_TTL_SECS: u64 = 3600;

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
        Self {
            min_target_pool_size: min_target,
            max_target_pool_size: max_target,
            min_initial_connections: MIN_INITIAL_CONNECTIONS,
            max_initial_connections: MAX_INITIAL_CONNECTIONS,
            min_startup_jitter_ms: min_jitter,
            max_startup_jitter_ms: max_jitter,
            soft_ttl_secs: SOFT_TTL_SECS,
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

    /// 每条连接都拿到同一组时限，这是**有意为之**而非遗漏。
    ///
    /// 真实实现在这两个维度上都是常量：Firefox 的
    /// `network.http.keep-alive.timeout`、nginx 的 `keepalive_timeout` /
    /// `keepalive_time` 都是单一配置值，对所有连接一致。现实中连接寿命的
    /// 分布来自「哪一侧的常量先触发」叠加使用模式，不来自随机定时器——
    /// 若在这里逐连接采样，得到的寿命分布本身就是一条没有任何真实实现会
    /// 产生的特征。伪装靠的是让常量不可观测（见 [`SOFT_TTL_SECS`]），
    /// 不是让常量变随机。
    pub(crate) fn lifecycle(&self) -> PoolLifecycle {
        PoolLifecycle {
            soft_ttl: Duration::from_secs(self.soft_ttl_secs),
            idle_timeout: Duration::from_secs(self.idle_drain_secs),
        }
    }

    /// 扩容建连的错开延迟。**不是死代码**，但它的职责已经变窄，这里记下来
    /// 免得下一个人按旧意图去读它。
    ///
    /// 原意是模拟浏览器「一次开好几条连接」的建连节奏：`spawn_cluster_len`
    /// 把连续的 slot 切成 2–4 条一簇，簇内用小间隔、簇尾用大间隔。冷启动被
    /// 钳到 1 条之后（见 `desired_active_connection_count` 的
    /// `active_connections == 0` 分支），这个「一次开好几条」的形态本身已经
    /// 不该出现——真实 Firefox 对同一 origin 就只开一条 H2 连接。把单连接
    /// 并发目标提到会话上限后，`count >= 2` 更是要求需求瞬间跨过两个会话
    /// 上限（默认 512 条并发流）才可能发生。
    ///
    /// 于是常态是 `count == 1`：簇内/簇尾的**形状**语义退化，`spawn_cluster_len`
    /// 只剩「按全局 slot 计数在两个延迟区间之间切换」的作用。仍然保留，是因为
    /// 它现在承担的那件事恰恰还成立：溢流阀开出的第二条连接不能和第一条在
    /// 同一 IP:443 上零间隔地连续握手——微秒级相邻的两次握手是没有任何浏览器
    /// 对应物的机器特征，而删掉它得到的是恒定 0 间隔，比一个可变间隔更糟。
    /// 这里的随机化也不违反「恒定维度上不得随机」：真实建连间隔本就由页面
    /// 解析进度驱动，是天然可变量，与 keep-alive 超时那种单一配置值不同。
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
