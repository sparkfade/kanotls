use lazy_static::lazy_static;
use lru::LruCache;
use rand::{Rng, RngCore};
use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::resolve_allowed_camouflage;
use crate::common::{
    apply_tcp_keepalive, HANDSHAKE_CONTROL_LEN, HANDSHAKE_CONTROL_MAGIC,
    MIN_NOISE_RESPONSE_RECORD_LEN, NOISE_RESPONSE_OVERHEAD_LEN, TLS_RECORD_HEADER_LEN,
};
use crate::utils::{
    client_hello_random_and_session_id_ranges, derive_noise_e_mask, hex_encode_fingerprint,
    is_server_hello, read_tls_record_bounded, stable_client_hello_fingerprint, xor_in_place,
    TlsRecordReadLimits, TlsRecordReadState,
};

pub(super) const MAX_CAMOUFLAGE_PROFILES: usize = 1024;
pub(super) const MAX_CAMOUFLAGE_PROFILE_VARIANTS: usize = 4;
pub(super) const MAX_CAMOUFLAGE_REFRESH_FAILURES: usize = 1024;
pub(super) const STARTUP_CAMOUFLAGE_SAMPLE_COUNT: usize = 4;
pub(super) const CAMOUFLAGE_IO_TIMEOUT_SECS: u64 = 10;
pub(super) const CAMOUFLAGE_REFRESH_FAILURE_COOLDOWN_SECS: u64 = 30;
pub(super) const MAX_CAMOUFLAGE_SERVER_RECORD_BYTES: usize = 256 * 1024;
pub(super) const MAX_CAMOUFLAGE_TOTAL_RECORD_BYTES: usize = 512 * 1024;
pub(super) const MAX_CAMOUFLAGE_APP_DATA_RECORDS: usize = 256;
pub(super) const MAX_CAMOUFLAGE_TOTAL_RECORDS: usize = 512;
pub(super) const MAX_CAMOUFLAGE_PREFIX_APP_DATA_RECORDS: usize = 4;
pub(super) const CAMOUFLAGE_SAMPLE_IDLE_TIMEOUT_SECS: u64 = 5;
/// 合法 TLS 1.3 密文记录的最小长度：1 字节 inner content type + 16 字节
/// AEAD tag。此前取 23，会把端点真实发出的 17–22 字节记录静默丢弃，导致
/// 回放的记录条数与参考 flight 不一致。
pub(super) const MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN: usize = 17;

/// 回放时断开写批次的间隔阈值：低于此值的间隔并入同一次突发写
/// （见 establish_synthetic_camouflage_tunnel 中的说明）。
///
/// 量纲随 profile 一并从毫秒改为微秒（见 `CamouflageProfile` 上的说明），
/// 阈值本身仍是 5 ms。
pub(super) const SIGNIFICANT_REPLAY_GAP_US: u32 = 5_000;
pub(super) const MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN: usize = 16401;

pub(super) const CAMOUFLAGE_REFRESH_DAEMON_MIN_SECS: u64 = 300;
pub(super) const CAMOUFLAGE_REFRESH_DAEMON_MAX_SECS: u64 = 3000;

pub(super) const TLS12_DOWNGRADE_SENTINEL: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
pub(super) const TLS11_DOWNGRADE_SENTINEL: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// RFC 8446 §4.1.3：HelloRetryRequest 的 ServerHello.random 固定为
/// SHA-256("HelloRetryRequest")。
pub(super) const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// 判断一条 0x16 记录是否为 HelloRetryRequest（handshake type 0x02 且
/// random 等于 HRR magic）。record 偏移 11..43 = 5 字节 record 头 +
/// 4 字节 handshake 头 + 2 字节 version 之后。
pub(super) fn is_hello_retry_request(record: &[u8]) -> bool {
    if !is_server_hello(record) || record.len() < 43 {
        return false;
    }
    record[11..43] == HELLO_RETRY_REQUEST_RANDOM
}

lazy_static! {
    pub(super) static ref CAMOUFLAGE_PROFILES: tokio::sync::Mutex<LruCache<String, CamouflageProfilePool>> =
        tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_CAMOUFLAGE_PROFILES).expect("non-zero camouflage profile size")
        ));
    pub(super) static ref CAMOUFLAGE_REFRESH_FAILURES: tokio::sync::Mutex<LruCache<String, Instant>> =
        tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_CAMOUFLAGE_REFRESH_FAILURES)
                .expect("non-zero camouflage refresh failure size")
        ));
    pub(super) static ref CAMOUFLAGE_REFRESH_INFLIGHT: tokio::sync::Mutex<LruCache<String, Arc<CamouflageRefreshGate>>> =
        tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_CAMOUFLAGE_REFRESH_FAILURES)
                .expect("non-zero camouflage inflight size")
        ));
    pub(super) static ref CAMOUFLAGE_REFRESH_DAEMONS: std::sync::Mutex<HashSet<String>> =
        std::sync::Mutex::new(HashSet::new());
}

pub(super) struct CamouflageRefreshGate {
    notify: tokio::sync::Notify,
    completed: AtomicBool,
}

pub(super) struct CamouflageRefreshGateLease {
    pub(super) key: String,
    pub(super) gate: Arc<CamouflageRefreshGate>,
    pub(super) released: bool,
}

/// 参考端点可见 TLS 1.3 握手形态的采样结果。
///
/// **记录间隔以微秒存储。** 此前 `first_app_data_delay_ms: u16` /
/// `early_app_data_gap_ms: Vec<u16>` 是整毫秒，采样端 `as_millis()` 又是向下
/// 截断，于是：真实端点的帧内间隔多在 0–1 ms，全部被截断成 0；1.9 ms 记为
/// 1 ms（系统性低估最多 1 ms）；而所有活下来的间隔都落在整毫秒格点上，
/// `jitter_iat` 的 ±20% 只是围绕一个整毫秒中心散开——跨连接取均值，中心值
/// 收敛到精确整毫秒，这本身就是「回放自量化模板」的信号。改为 u32 微秒后
/// 存的是端点真实做过的事（u32 可覆盖 ~71 分钟，远超采样侧 10 s 的上限）。
#[derive(Clone, Debug)]
pub(super) struct CamouflageProfile {
    pub(super) server_records: Arc<[u8]>,
    pub(super) prefix_app_data_sizes: Vec<usize>,
    pub(super) app_data_sizes: Arc<[usize]>,
    pub(super) first_app_data_size: Option<usize>,
    pub(super) early_app_data_count: u8,
    pub(super) has_ccs: bool,
    pub(super) visible_server_record_count: u16,
    /// ServerHello 到达 → 首条 0x17 记录的间隔（微秒）。
    pub(super) first_app_data_delay_us: u32,
    /// 连续 0x17 记录之间的间隔（微秒）：`[i]` 是第 i 条与第 i+1 条之间。
    pub(super) early_app_data_gap_us: Vec<u32>,
}

#[derive(Clone, Debug)]
pub(super) struct PooledProfile {
    pub(super) profile: CamouflageProfile,
    pub(super) fetched_at: Instant,
}

#[derive(Clone, Debug)]
pub(super) struct CamouflageProfilePool {
    pub(super) profiles: VecDeque<PooledProfile>,
}

pub(super) fn make_control_payload(ghost_count: u16) -> [u8; HANDSHAKE_CONTROL_LEN] {
    let mut payload = [0u8; HANDSHAKE_CONTROL_LEN];
    payload[..4].copy_from_slice(HANDSHAKE_CONTROL_MAGIC);
    payload[4..6].copy_from_slice(&ghost_count.to_be_bytes());
    payload
}

/// 参考端点未提供任何可承载 Noise 响应的记录尺寸时的兜底长度。
///
/// 旧实现返回硬编码的 300 且完全不看参数，于是线上会出现一个真实端点从未
/// 产生过的固定尺寸（wire 305），一测长度即可命中。改为优先复用采样到的
/// 最大尺寸（那是端点真实发过的）；采样存在但都装不下 Noise 响应、或完全
/// 没有采样时，退回最小可用尺寸——一个固定点，而**绝不是**宽区间均匀抽样：
/// [54, 512] 的平直直方图不是任何真实 TLS 端点会产生的记录尺寸分布，观测者
/// 跨连接采样即可识别（真实端点的记录尺寸高度集中，且 54 是合法 TLS 1.3
/// 密文记录中几乎不会单独出现的尺寸，固定点至少不是一段不可能的形状）。
pub(super) fn fallback_noise_response_record_len(sampled_sizes: &[usize]) -> usize {
    if let Some(&largest) = sampled_sizes.iter().max() {
        if largest >= MIN_NOISE_RESPONSE_RECORD_LEN {
            return largest.min(MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN);
        }
    }
    MIN_NOISE_RESPONSE_RECORD_LEN
}

pub(super) fn sanitize_camouflage_profile(mut profile: CamouflageProfile) -> CamouflageProfile {
    profile.prefix_app_data_sizes = profile
        .prefix_app_data_sizes
        .into_iter()
        .filter(|&size| {
            (MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN..=MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN)
                .contains(&size)
        })
        .take(MAX_CAMOUFLAGE_PREFIX_APP_DATA_RECORDS)
        .collect();

    profile.app_data_sizes = Arc::from(
        profile
            .app_data_sizes
            .iter()
            .filter(|&&size| {
                (MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN..=MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN)
                    .contains(&size)
            })
            .take(MAX_CAMOUFLAGE_APP_DATA_RECORDS)
            .copied()
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );

    profile.first_app_data_size = profile.app_data_sizes.first().copied();
    profile.early_app_data_count = profile.app_data_sizes.len().min(u8::MAX as usize) as u8;
    profile
        .early_app_data_gap_us
        .truncate(profile.app_data_sizes.len().saturating_sub(1));

    profile
}

pub(super) fn merge_camouflage_profile(
    mut cached_profile: CamouflageProfile,
    sampled_profile: CamouflageProfile,
) -> CamouflageProfile {
    let sampled_profile = sanitize_camouflage_profile(sampled_profile);
    if !sampled_profile.server_records.is_empty() {
        cached_profile.server_records = sampled_profile.server_records;
        cached_profile.visible_server_record_count = sampled_profile.visible_server_record_count;
        cached_profile.has_ccs = sampled_profile.has_ccs;
    }
    if !sampled_profile.prefix_app_data_sizes.is_empty()
        || !sampled_profile.app_data_sizes.is_empty()
    {
        cached_profile.prefix_app_data_sizes = sampled_profile.prefix_app_data_sizes;
        if sampled_profile.app_data_sizes.len() <= 1 && cached_profile.app_data_sizes.len() > 1 {
            if let Some(first) = sampled_profile.app_data_sizes.first().copied() {
                let mut sizes: Vec<usize> = cached_profile.app_data_sizes.to_vec();
                sizes[0] = first;
                cached_profile.app_data_sizes = Arc::from(sizes.into_boxed_slice());
            }
        } else {
            cached_profile.app_data_sizes = sampled_profile.app_data_sizes;
            cached_profile.early_app_data_gap_us = sampled_profile.early_app_data_gap_us;
        }
        cached_profile.first_app_data_delay_us = sampled_profile.first_app_data_delay_us;
    }
    sanitize_camouflage_profile(cached_profile)
}

/// 防御性降级：单条 app-data 记录的 profile 是 fast 采样「首条匹配即停」的
/// 产物，不是一次完整的 flight——把它按 rank 3 入池，`sample_camouflage_profile`
/// 就会把它与完整 profile 等权均匀抽取，回放出一条 1-ghost-record 的退化
/// flight。任何未来路径都不允许把单条记录当作「完整」profile 提供。
pub(super) fn camouflage_profile_rank(profile: &CamouflageProfile) -> u8 {
    if profile.server_records.is_empty() {
        return if profile.app_data_sizes.is_empty() {
            0
        } else {
            1
        };
    }
    if profile.app_data_sizes.len() <= 1 {
        return 2;
    }
    3
}

pub(super) fn is_complete_camouflage_profile(profile: &CamouflageProfile) -> bool {
    camouflage_profile_rank(profile) == 3
}

pub(super) fn pick_best_camouflage_profile(
    candidates: impl IntoIterator<Item = CamouflageProfile>,
) -> Option<CamouflageProfile> {
    let mut best = None;
    let mut best_rank = 0;

    for candidate in candidates {
        let rank = camouflage_profile_rank(&candidate);
        if rank > best_rank {
            best_rank = rank;
            best = Some(candidate);
        }
    }

    best
}

pub(super) fn pick_refresh_base_profile(
    cached_specific_profile: Option<CamouflageProfile>,
    cached_family_profile: Option<CamouflageProfile>,
) -> Option<CamouflageProfile> {
    pick_best_camouflage_profile(
        [cached_specific_profile, cached_family_profile]
            .into_iter()
            .flatten(),
    )
}

/// 从池中按 rank 优先、同 rank 均匀随机地取一个变体。
///
/// **选取语义与此前逐字等价**（同一次 RNG 抽样下返回同一个变体），只是不再
/// 为了「排个序」而把整个池物化一遍：此前先 `sanitize + clone` **每一个**变体
/// 得到 `Vec<CamouflageProfile>`，再按 rank 过滤、再 `swap_remove` 取一个——
/// 最多 4 个变体，每个变体的 `prefix_app_data_sizes` / `early_app_data_gap_us`
/// / `app_data_sizes` 都是真实分配，于是「有没有 rank-3 条目」这个纯读问题要
/// 付十余次分配与数 KB memcpy，而其中至多 1 个结果会被用到。
///
/// 等价性依据：`camouflage_profile_rank` 只看 `server_records` 是否为空、
/// `app_data_sizes` 是否为空以及长度是否 > 1（单条记录视为 fast 采样提前
/// 停止的产物，按 rank 2 处理，见该函数注释）；`sanitize_camouflage_profile`
/// 从不改 `server_records`，且**入池的每个变体都已经过 sanitize**
/// （`push_profile_variant` 是唯一写入路径，它在存入前 sanitize），而 sanitize
/// 是幂等的 ⇒ 对池中变体 `rank(sanitize(p)) == rank(p)`，在引用上算 rank 与在
/// 克隆上算 rank 结果相同。
/// 这两条不变量由 `sanitize_camouflage_profile_is_idempotent` /
/// `pooled_profiles_are_stored_pre_sanitized` 锁定。
/// 迭代顺序、候选集合、`gen_range(0..len)` 的抽样域与 RNG 调用次数（恰好 1 次）
/// 全部不变。
pub(super) fn sample_camouflage_profile(pool: &CamouflageProfilePool) -> Option<CamouflageProfile> {
    let max_rank = pool
        .profiles
        .iter()
        .map(|entry| camouflage_profile_rank(&entry.profile))
        .max()?;
    if max_rank == 0 {
        return None;
    }
    let usable: Vec<&PooledProfile> = pool
        .profiles
        .iter()
        .filter(|entry| camouflage_profile_rank(&entry.profile) == max_rank)
        .collect();
    let idx = rand::thread_rng().gen_range(0..usable.len());
    Some(sanitize_camouflage_profile(usable[idx].profile.clone()))
}

pub(super) fn push_profile_variant(
    pool: Option<CamouflageProfilePool>,
    profile: CamouflageProfile,
) -> CamouflageProfilePool {
    let mut profiles = pool.map(|pool| pool.profiles).unwrap_or_default();
    let profile = sanitize_camouflage_profile(profile);

    if let Some(existing) = profiles.iter_mut().find(|existing| {
        existing.profile.server_records == profile.server_records
            && existing.profile.prefix_app_data_sizes == profile.prefix_app_data_sizes
            && existing.profile.app_data_sizes == profile.app_data_sizes
            && existing.profile.early_app_data_gap_us == profile.early_app_data_gap_us
            && existing.profile.first_app_data_delay_us == profile.first_app_data_delay_us
            && existing.profile.has_ccs == profile.has_ccs
    }) {
        existing.profile = profile;
        existing.fetched_at = Instant::now();
    } else {
        profiles.push_back(PooledProfile {
            profile,
            fetched_at: Instant::now(),
        });
        if profiles.len() > MAX_CAMOUFLAGE_PROFILE_VARIANTS {
            // Pool full: evict the stalest sample so refreshed fetches keep
            // the pool biased towards recently observed flights.
            if let Some(oldest_idx) = profiles
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.fetched_at)
                .map(|(idx, _)| idx)
            {
                profiles.remove(oldest_idx);
            }
        }
    }

    CamouflageProfilePool { profiles }
}

pub(super) fn sanitize_waste_record_sizes(sizes: &[usize]) -> Vec<usize> {
    sizes
        .iter()
        .copied()
        .filter(|&size| {
            (MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN..=MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN)
                .contains(&size)
        })
        .collect()
}

pub(super) fn extract_client_hello_session_id(client_hello: &[u8]) -> Option<&[u8]> {
    let (_, session_id_range) = client_hello_random_and_session_id_ranges(client_hello)?;
    Some(&client_hello[session_id_range])
}

pub(super) fn patch_server_hello_session_id_echo(
    server_records: &mut [u8],
    client_session_id: &[u8],
) -> bool {
    let mut offset = 0;
    while offset + 5 <= server_records.len() {
        let rec_type = server_records[offset];
        let rec_len =
            u16::from_be_bytes([server_records[offset + 3], server_records[offset + 4]]) as usize;
        let record_total = 5 + rec_len;
        if offset + record_total > server_records.len() {
            break;
        }
        if rec_type == 0x16 && rec_len > 0 && server_records[offset + 5] == 0x02 {
            let session_id_len_offset = offset + 43;
            if session_id_len_offset >= offset + record_total {
                return false;
            }
            let echo_len = server_records[session_id_len_offset] as usize;
            let echo_start = session_id_len_offset + 1;
            let echo_end = echo_start + echo_len;
            if echo_end > offset + record_total {
                return false;
            }
            if client_session_id.len() != echo_len {
                return false;
            }
            server_records[echo_start..echo_end].copy_from_slice(client_session_id);
            return true;
        }
        offset += record_total;
    }
    false
}

/// Regenerate the ServerHello `key_share` — the server's ephemeral ECDHE public
/// key — for this connection.
///
/// The cached camouflage profile replays the reference endpoint's ServerHello
/// byte for byte, so without this the server hands out the *same* ECDHE public
/// key on every connection (at most `MAX_CAMOUFLAGE_PROFILE_VARIANTS` distinct
/// values, rotating only on the 300–3000 s refresh cycle). A genuine TLS 1.3
/// server derives a fresh keypair per handshake; a repeated server share is
/// cryptographically impossible for a real endpoint, so an observer that stores
/// 32 bytes per flow identifies the server from two connections with no false
/// positives.
///
/// The replacement is written in place and is exactly the same length, so no
/// record / handshake / extension length field needs recomputing.
/// Returns false when the group is unknown or the encoding is malformed, so the
/// caller can fail closed rather than emit the fingerprint.
pub(super) fn patch_server_hello_key_share(server_records: &mut [u8]) -> bool {
    const X25519: u16 = 0x001D;
    const SECP256R1: u16 = 0x0017;
    const X25519MLKEM768: u16 = 0x11EC;
    /// ML-KEM-768 ciphertext length: c1 = 3·256 coefficients packed at 10 bits
    /// (960 B) plus c2 = 256 coefficients at 4 bits (128 B).
    const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

    let Some((group, range)) = crate::utils::server_hello_key_share_range(server_records) else {
        return false;
    };
    let key_exchange = &mut server_records[range];

    match group {
        X25519 if key_exchange.len() == 32 => crate::template::fill_x25519_public_key(key_exchange),
        SECP256R1 if key_exchange.len() == 65 => {
            // Must be a real curve point — random bytes fail point validation.
            crate::template::fill_p256_public_key(key_exchange)
        }
        X25519MLKEM768 if key_exchange.len() == MLKEM768_CIPHERTEXT_LEN + 32 => {
            // Layout: ML-KEM-768 ciphertext ‖ X25519 public key. The ciphertext
            // is densely packed (every 10-bit and 4-bit field value is a legal
            // compressed coefficient), so uniform random bytes are both valid
            // and correctly distributed. The X25519 half is not — see
            // fill_x25519_public_key.
            rand::thread_rng().fill_bytes(&mut key_exchange[..MLKEM768_CIPHERTEXT_LEN]);
            crate::template::fill_x25519_public_key(&mut key_exchange[MLKEM768_CIPHERTEXT_LEN..])
        }
        _ => false,
    }
}

pub(super) fn patch_server_hello_random(server_records: &mut [u8]) {
    let mut rng = rand::thread_rng();
    let mut fresh_random = [0u8; 32];
    let mut offset = 0;
    while offset + 5 <= server_records.len() {
        let rec_type = server_records[offset];
        let rec_len =
            u16::from_be_bytes([server_records[offset + 3], server_records[offset + 4]]) as usize;
        let record_total = 5 + rec_len;
        if offset + record_total > server_records.len() {
            break;
        }
        if rec_type == 0x16 && rec_len > 0 && server_records[offset + 5] == 0x02 {
            let random_start = offset + 11;
            if random_start + 32 > offset + record_total {
                break;
            }
            // 防御性跳过：HelloRetryRequest 的 random 是 RFC 8446 规定的
            // 固定 magic，重写它会破坏 HRR 的语义识别。
            if server_records[random_start..random_start + 32] == HELLO_RETRY_REQUEST_RANDOM {
                offset += record_total;
                continue;
            }
            use rand::RngCore;
            rng.fill_bytes(&mut fresh_random);
            let last8: &[u8] = &server_records[random_start + 24..random_start + 32];
            if last8 == TLS12_DOWNGRADE_SENTINEL || last8 == TLS11_DOWNGRADE_SENTINEL {
                server_records[random_start..random_start + 24]
                    .copy_from_slice(&fresh_random[..24]);
            } else {
                server_records[random_start..random_start + 32].copy_from_slice(&fresh_random);
            }
        }
        offset += record_total;
    }
}

pub async fn validate_camouflage_endpoint(host: &str, port: u16) -> anyhow::Result<()> {
    let _ = resolve_allowed_camouflage(host, port).await?;
    validate_camouflage_tls13_flight(host, port).await?;
    Ok(())
}

pub(super) async fn validate_camouflage_tls13_flight(host: &str, port: u16) -> anyhow::Result<()> {
    let client_hello = build_probe_client_hello(host)?;
    let fingerprint = stable_client_hello_fingerprint(&client_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to fingerprint probe ClientHello"))?;
    let mut sampled_profiles = Vec::new();
    for _ in 0..STARTUP_CAMOUFLAGE_SAMPLE_COUNT {
        let (_records, profile) =
            read_camouflage_server_records(host, port, &client_hello, false, None).await?;
        if profile.first_app_data_size.is_some() {
            sampled_profiles.push(profile);
        }
    }
    if sampled_profiles.is_empty() {
        anyhow::bail!("camouflage endpoint did not produce a TLS 1.3 application-data flight");
    }

    for profile in sampled_profiles {
        let mut hex_buf = [0u8; 64];
        store_camouflage_profile(
            camouflage_profile_key(
                host,
                port,
                hex_encode_fingerprint(&fingerprint, &mut hex_buf),
            ),
            profile.clone(),
        )
        .await;
        store_camouflage_profile(camouflage_baseline_key(host, port, "probe"), profile).await;
    }
    Ok(())
}

pub(super) fn build_probe_client_hello(host: &str) -> anyhow::Result<Vec<u8>> {
    // 探针与客户端复用同一 Firefox 模板：真实站点会按 ClientHello 特征
    // 选择 key_share / 证书链（如 ECDSA vs RSA），探针指纹若与客户端
    // 不一致，录制的 flight 便不是真实客户端应得的那份。归一化指纹
    // 一致还使启动采样直接落入客户端连接查询的 profile key。项目指纹
    // 即将收敛至 firefox 单一预设，探针不再硬编码 rustls 指纹。
    let template =
        crate::template::get_or_build_client_hello_template(host, Some("firefox"), None, true)?;
    // 注入材料仅充当随机字段填充：对真实伪装站点而言 random/session_id
    // 本就是不透明随机字节，探针无需携带有效 Noise 语义。
    let mut derived_psk = [0u8; 32];
    let mut psk_e = [0u8; 48];
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    rng.fill_bytes(&mut derived_psk);
    rng.fill_bytes(&mut psk_e);
    template.instantiate(&derived_psk, &psk_e, rng.gen())
}

pub(super) async fn fetch_camouflage_flight(
    host: &str,
    port: u16,
    client_hello: &[u8],
) -> anyhow::Result<(Arc<[u8]>, Arc<[usize]>, CamouflageProfile)> {
    // 指纹与全部 key 在这里算**一次**，随后所有查找都复用（见
    // `lookup_cached_camouflage_profile` 上关于双重指纹计算的说明）。
    let CamouflageCacheKeys {
        profile: profile_key,
        family_baseline: baseline_key,
        probe_baseline: probe_baseline_key,
        refresh_cooldown: refresh_cooldown_key,
        refresh_gate: refresh_gate_key,
    } = camouflage_cache_keys(host, port, client_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to fingerprint ClientHello"))?;
    let cached_profile = lookup_cached_camouflage_profile(
        Some(&profile_key),
        Some(&baseline_key),
        &probe_baseline_key,
    )
    .await;
    let cached_specific_profile = get_cached_camouflage_profile_entry(&profile_key).await;
    let cached_family_profile = get_cached_camouflage_profile_entry(&baseline_key).await;
    let cached_probe_profile = get_cached_camouflage_profile_entry(&probe_baseline_key).await;
    let refresh_base_profile = pick_refresh_base_profile(
        cached_specific_profile.clone(),
        cached_family_profile.clone(),
    );
    let cached_handshake_profile = cached_profile
        .clone()
        .filter(|profile| !profile.server_records.is_empty());
    if let Some(profile) = pick_best_camouflage_profile(
        [
            cached_specific_profile.clone(),
            cached_family_profile.clone(),
        ]
        .into_iter()
        .flatten()
        .filter(is_complete_camouflage_profile),
    ) {
        return Ok((
            profile.server_records.clone(),
            profile.app_data_sizes.clone(),
            profile,
        ));
    }
    if let Some(profile) = cached_probe_profile
        .clone()
        .filter(is_complete_camouflage_profile)
    {
        if cached_specific_profile.is_none() && cached_family_profile.is_none() {
            return Ok((
                profile.server_records.clone(),
                profile.app_data_sizes.clone(),
                profile,
            ));
        }
    }
    if camouflage_refresh_is_cooling_down(&refresh_cooldown_key).await {
        if let Some(profile) = cached_handshake_profile.clone() {
            debug!(
                host,
                port,
                baseline_key,
                "camouflage refresh cooldown active, using cached handshake profile"
            );
            return Ok((
                profile.server_records.clone(),
                profile.app_data_sizes.clone(),
                profile,
            ));
        }
        anyhow::bail!(
            "camouflage refresh cooldown active after recent failure for {}:{}",
            host,
            port
        );
    }
    let cached_sizes = refresh_base_profile
        .as_ref()
        .map(|profile| profile.app_data_sizes.clone());
    let expected_first = cached_sizes
        .as_ref()
        .and_then(|sizes| sizes.first().copied());
    let fast = expected_first.is_some();
    let (refresh_gate, is_refresh_leader) =
        acquire_camouflage_refresh_gate(&refresh_gate_key).await;
    let mut refresh_lease = is_refresh_leader.then(|| CamouflageRefreshGateLease {
        key: refresh_gate_key.clone(),
        gate: refresh_gate.clone(),
        released: false,
    });
    if !is_refresh_leader {
        wait_for_camouflage_refresh_gate(refresh_gate).await;
        let cached_after_wait = lookup_cached_camouflage_profile(
            Some(&profile_key),
            Some(&baseline_key),
            &probe_baseline_key,
        )
        .await;
        if let Some(profile) = cached_after_wait
            .clone()
            .filter(|profile| !profile.server_records.is_empty())
        {
            return Ok((
                profile.server_records.clone(),
                profile.app_data_sizes.clone(),
                profile,
            ));
        }
        if camouflage_refresh_is_cooling_down(&refresh_cooldown_key).await {
            anyhow::bail!(
                "camouflage refresh cooldown active after recent failure for {}:{}",
                host,
                port
            );
        }
    }
    let (server_records, sampled_profile) = match read_camouflage_server_records(
        host,
        port,
        client_hello,
        fast,
        expected_first,
    )
    .await
    {
        Ok(flight) => {
            clear_camouflage_refresh_failure(&refresh_cooldown_key).await;
            flight
        }
        Err(e) => {
            note_camouflage_refresh_failure(refresh_cooldown_key).await;
            if let Some(lease) = refresh_lease.as_mut() {
                lease.release_now();
            }
            if let Some(profile) = cached_handshake_profile {
                warn!(
                    "camouflage remote fetch failed, falling back to cached profile: {}",
                    e
                );
                let server_records = profile.server_records.clone();
                let app_data_sizes = profile.app_data_sizes.clone();
                return Ok((server_records, app_data_sizes, profile));
            }
            return Err(e);
        }
    };

    let (sizes, profile) = match cached_sizes {
        Some(_sizes) => {
            let cached_entry = get_cached_camouflage_profile_entry(&profile_key)
                .await
                .or(refresh_base_profile.clone())
                .or(cached_profile.clone())
                .unwrap_or_else(|| sanitize_camouflage_profile(sampled_profile.clone()));
            let merged_profile = merge_camouflage_profile(cached_entry, sampled_profile);
            store_camouflage_profile(profile_key.clone(), merged_profile.clone()).await;
            store_camouflage_profile(baseline_key.clone(), merged_profile.clone()).await;
            (
                Arc::from(
                    sanitize_waste_record_sizes(&merged_profile.app_data_sizes).into_boxed_slice(),
                ),
                merged_profile,
            )
        }
        None => {
            debug!(
                first_app_data_size = sampled_profile.first_app_data_size,
                early_app_data_count = sampled_profile.early_app_data_count,
                has_ccs = sampled_profile.has_ccs,
                visible_server_record_count = sampled_profile.visible_server_record_count,
                "caching extended camouflage profile"
            );
            let sampled_profile = sanitize_camouflage_profile(sampled_profile);
            store_camouflage_profile(profile_key, sampled_profile.clone()).await;
            store_camouflage_profile(baseline_key, sampled_profile.clone()).await;
            (sampled_profile.app_data_sizes.clone(), sampled_profile)
        }
    };

    if let Some(lease) = refresh_lease.as_mut() {
        lease.release_now();
    }

    Ok((server_records, sizes, profile))
}

pub(super) fn maybe_spawn_camouflage_refresh_daemon(
    host: String,
    port: u16,
    client_hello: Vec<u8>,
) {
    let daemon_key = format!("{}:{}", host, port);
    {
        let mut daemons = CAMOUFLAGE_REFRESH_DAEMONS.lock().unwrap();
        if daemons.contains(&daemon_key) {
            return;
        }
        daemons.insert(daemon_key);
    }
    tokio::spawn(async move {
        loop {
            let random_interval = rand::thread_rng()
                .gen_range(CAMOUFLAGE_REFRESH_DAEMON_MIN_SECS..=CAMOUFLAGE_REFRESH_DAEMON_MAX_SECS);
            tokio::time::sleep(Duration::from_secs(random_interval)).await;
            let Some(fingerprint) = stable_client_hello_fingerprint(&client_hello) else {
                continue;
            };
            let mut hex_buf = [0u8; 64];
            let fingerprint_hex = hex_encode_fingerprint(&fingerprint, &mut hex_buf);
            let key = camouflage_profile_key(&host, port, fingerprint_hex);
            // 与热路径同一契约：已有缓存 profile 时走快速采样，并按缓存的首条
            // app-data 尺寸对齐——首条命中即停，未命中则继续采全；随后把快速
            // 采样合并进缓存（只刷新首条尺寸），避免把 1 条记录的退化 flight
            // 存成 rank-3 的「完整」profile。无缓存时全量采样。
            let cached_profile = get_cached_camouflage_profile_entry(&key).await;
            let expected_first = cached_profile
                .as_ref()
                .and_then(|profile| profile.app_data_sizes.first().copied());
            match read_camouflage_server_records(
                &host,
                port,
                &client_hello,
                expected_first.is_some(),
                expected_first,
            )
            .await
            {
                Ok((_server_records, profile)) => {
                    let profile = match cached_profile {
                        Some(cached) => merge_camouflage_profile(cached, profile),
                        None => profile,
                    };
                    store_camouflage_profile(key, profile).await;
                }
                Err(e) => {
                    debug!(
                        "background camouflage refresh failed for {}:{}: {}",
                        host, port, e
                    );
                }
            }
        }
    });
}

pub(super) async fn establish_synthetic_camouflage_tunnel(
    tcp: &mut TcpStream,
    client_hello: &[u8],
    camouflage_host: &str,
    camouflage_port: u16,
    noise_state: &mut Option<snow::HandshakeState>,
    derived_psk: &[u8],
    client_noise_tag: &[u8; 16],
) -> anyhow::Result<crate::common::NoiseTransport> {
    let (camo_rx_buf_arc, camo_17_sizes_arc, camo_profile) =
        match fetch_camouflage_flight(camouflage_host, camouflage_port, client_hello).await {
            Ok(flight) => flight,
            Err(e) => anyhow::bail!("camouflage sampling failed: {}", e),
        };
    let sampled_17_sizes = sanitize_waste_record_sizes(&camo_17_sizes_arc);
    let mut remaining_17_sizes = sampled_17_sizes.clone();

    let too_small_count = remaining_17_sizes
        .iter()
        .take_while(|&&s| s < MIN_NOISE_RESPONSE_RECORD_LEN)
        .count();
    remaining_17_sizes.drain(..too_small_count);

    if remaining_17_sizes.is_empty() {
        let fallback = fallback_noise_response_record_len(&sampled_17_sizes);
        remaining_17_sizes.push(fallback);
    }

    let mut patched_server_records = camo_rx_buf_arc.to_vec();
    // RFC 8446 §4.1.3：ServerHello 必须回显客户端发来的 legacy_session_id。
    // 长度不匹配时缓存 profile 与本连接不自洽，若继续回放就会回显一个
    // 客户端从未发送过的 session_id——一次协议一致性检查即可命中。
    // 此前该返回值被丢弃，静默保留了采样端点的 echo。
    let client_session_id = extract_client_hello_session_id(client_hello)
        .ok_or_else(|| anyhow::anyhow!("ClientHello missing session_id for camouflage echo"))?;
    if !patch_server_hello_session_id_echo(&mut patched_server_records, client_session_id) {
        anyhow::bail!(
            "cached camouflage ServerHello could not echo the client session_id (length mismatch)"
        );
    }
    patch_server_hello_random(&mut patched_server_records);
    if !patch_server_hello_key_share(&mut patched_server_records) {
        anyhow::bail!(
            "cached camouflage ServerHello key_share could not be regenerated; \
             the endpoint negotiated an unsupported group — choose a different camouflage endpoint"
        );
    }

    let noise_records = build_noise_response_sequence(
        noise_state
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Noise handshake state already consumed"))?,
        derived_psk,
        client_noise_tag,
        &remaining_17_sizes,
    )?;

    // 统一的 app-data 记录序列：前置小记录（装不下 Noise 响应的那一段）在
    // 前，Noise 响应 + ghost 记录在后。它们本来就共享同一条时间轴，合并成
    // 一个序列后下标即 app-data 序号，`gap_base` 偏移随之消失。
    //
    // 每条前置记录仍在此逐连接新鲜 `fill_bytes`（与 ghost 记录同一口径：
    // ServerHello 之后写上线的明文字节在真实 TLS 1.3 里都是 AEAD 密文，
    // 绝不能复用任何缓冲）。
    let mut app_records: Vec<Vec<u8>> =
        Vec::with_capacity(camo_profile.prefix_app_data_sizes.len() + noise_records.len());
    for &size in &camo_profile.prefix_app_data_sizes {
        let mut record = vec![0u8; TLS_RECORD_HEADER_LEN + size];
        record[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
        record[3..5].copy_from_slice(&(size as u16).to_be_bytes());
        rand::thread_rng().fill_bytes(&mut record[TLS_RECORD_HEADER_LEN..]);
        app_records.push(record);
    }
    app_records.extend(noise_records);

    // 一次突发写：ServerHello 记录组 + 全部 app-data 记录喂进同一个缓冲，
    // 只在「显著」间隔处断开 write+flush 并 sleep。
    //
    // 此前只有 noise 记录循环享受这条规则，SH+CCS 与首条 app-data 的接缝、
    // 以及每两条前置记录之间都是独立的 write+flush。socket 开了 TCP_NODELAY，
    // 于是即便 `first_app_data_delay == 0`、`gap == 0`，这些位置也**恒定**落在
    // 不同的 TCP 分段里——真实 TLS 1.3 服务端把 SH|CCS|EE|CERT|CV|FIN 连续
    // 突发写出、由内核按 MSS 分段，分段边界与 TLS 记录边界并不对齐。一个
    // 「记录边界恒等于分段边界」的服务端只需被动看一条连接即可判别，而且
    // 每连接还白付 2–6 次 syscall。
    //
    // gap 下标由 `replay_gap_before_us` 统一给出（合并两段后下标轴只剩一条，
    // 原先的 `gap_base` 偏移随之消失）。最后一条记录之后的间隔不会被查询，
    // 与此前 `!is_last` 的语义一致。
    //
    // `first_app_data_delay_us` 若 >= 阈值仍会在 SH+CCS 之后断开并 sleep
    // （部分站点确实会隔一段时间才下发 NewSessionTicket）；低于阈值（含 0）
    // 则并入同一次突发——这正是本次修复的核心。
    let mut burst: Vec<u8> = Vec::with_capacity(
        patched_server_records.len() + app_records.iter().map(Vec::len).sum::<usize>(),
    );
    burst.extend_from_slice(&patched_server_records);

    for (idx, record) in app_records.iter().enumerate() {
        let gap_us = replay_gap_before_us(&camo_profile, idx);
        if gap_us >= SIGNIFICANT_REPLAY_GAP_US {
            if !burst.is_empty() {
                tcp.write_all(&burst).await?;
                tcp.flush().await?;
                burst.clear();
            }
            tokio::time::sleep(jitter_iat(gap_us)).await;
        }
        burst.extend_from_slice(record);
    }

    if !burst.is_empty() {
        tcp.write_all(&burst).await?;
        tcp.flush().await?;
    }
    debug!("Sent Noise response (e, ee) wrapped in Application Data");

    let noise = crate::common::NoiseTransport::new(
        noise_state
            .take()
            .ok_or_else(|| anyhow::anyhow!("Noise handshake state already consumed"))?
            .into_stateless_transport_mode()?,
    );
    Ok(noise)
}

/// 回放序列中 **第 `idx` 条 app-data 记录之前** 的间隔（微秒）。
///
/// 下标推导（前置小记录与 Noise/ghost 记录被合并成同一条下标轴之后重新做过
/// 一遍，避免 off-by-one）：`early_app_data_gap_us[j]` 的定义是「第 j 条与第
/// j+1 条 app-data 之间的间隔」，即它**紧接在** `app_records[j]` 之后。取反
/// 得到「某条记录之前的间隔」：
///
///   * `idx == 0`：ServerHello 到达 → 首条 app-data，即 `first_app_data_delay_us`；
///   * `idx >= 1`：`early_app_data_gap_us[idx - 1]`；
///   * 越界（采样时 gap 数少于记录数）：0，即并入同一次突发。
///
/// 与合并前的两段循环逐项等价：旧 prefix 循环在写完 `prefix[i]` 后 sleep
/// `gap[i]`，旧 noise 循环在写完 `noise[i]` 后判断 `gap[prefix_count + i]`
/// —— 两者都是「记录 j 之后 = gap[j]」，因此「记录 j 之前 = gap[j-1]」。
pub(super) fn replay_gap_before_us(profile: &CamouflageProfile, idx: usize) -> u32 {
    match idx.checked_sub(1) {
        None => profile.first_app_data_delay_us,
        Some(prev) => profile
            .early_app_data_gap_us
            .get(prev)
            .copied()
            .unwrap_or(0),
    }
}

/// 围绕 `base_us`（微秒）的 ±20% 对称抖动。
///
/// 旧实现 `base + jitter.saturating_sub(jitter_max)` 中两个操作数都是 u64，
/// `saturating_sub` 把负半边整体压到 0，实际分布退化为：
///   * 约 50% 的样本恰好等于 `base`（一个可测的点质量）；
///   * 取值永不低于 `base`（单边）；
///   * 且被 `Duration::from_millis` 量化到整毫秒。
///
/// 真实网络到达间隔既无原子、也不是单边均匀分布，这三点合起来是一个
/// 稳定的时序指纹。
///
/// 入参量纲随 profile 从毫秒改为微秒（见 `CamouflageProfile`），分布语义
/// 不变（对称、连续、非单边）。两点随之调整：
///   * 输出改用 `from_nanos`，否则 `sampled` 的小数部分会被微秒量化重新
///     引入格点——±20% 的抖动本就是为了消除格点；
///   * 下限从「0.05 ms」改为「50 ns」。它只是防御性钳制：`spread` 恒为
///     `base` 的 20%，所以 `base_us >= 1` 时 `sampled >= 0.8` µs，钳制不可达。
pub(super) fn jitter_iat(base_us: u32) -> Duration {
    use rand::Rng;
    if base_us == 0 {
        return Duration::ZERO;
    }
    let base = base_us as f64;
    let spread = base * 0.2;
    let sampled = base + rand::thread_rng().gen_range(-spread..=spread);
    Duration::from_nanos((sampled.max(0.05) * 1000.0).round() as u64)
}

pub(super) fn build_noise_response_sequence(
    noise: &mut snow::HandshakeState,
    derived_psk: &[u8],
    client_noise_tag: &[u8; 16],
    remaining_17_sizes: &[usize],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut records: Vec<Vec<u8>> = Vec::new();
    if remaining_17_sizes.is_empty() {
        return Ok(records);
    }

    let first_size = remaining_17_sizes[0];
    let ghost_count = (remaining_17_sizes.len() - 1) as u16;

    let dummy_len = first_size.saturating_sub(NOISE_RESPONSE_OVERHEAD_LEN);
    if dummy_len < HANDSHAKE_CONTROL_LEN {
        anyhow::bail!("Noise response target too short for control payload");
    }
    let mut dummy_payload = vec![0u8; dummy_len];
    dummy_payload[..HANDSHAKE_CONTROL_LEN].copy_from_slice(&make_control_payload(ghost_count));

    let mut noise_payload = vec![0u8; dummy_len + 64];
    let reply_len = noise.write_message(&dummy_payload, &mut noise_payload)?;
    if reply_len < MIN_NOISE_RESPONSE_RECORD_LEN {
        anyhow::bail!(
            "Noise response record too short: {} < {}",
            reply_len,
            MIN_NOISE_RESPONSE_RECORD_LEN
        );
    }
    let server_e_mask = derive_noise_e_mask(derived_psk, client_noise_tag);
    xor_in_place(&mut noise_payload[..32], &server_e_mask);

    let mut noise_record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + reply_len);
    noise_record.extend_from_slice(&[0x17, 0x03, 0x03]);
    noise_record.extend_from_slice(&(reply_len as u16).to_be_bytes());
    noise_record.extend_from_slice(&noise_payload[..reply_len]);
    records.push(noise_record);

    // Ghost record 冒充的是 NewSessionTicket——在 TLS 1.3 中它位于加密
    // record 内，线上就是均匀随机的 AEAD 密文。因此 payload 必须逐连接、
    // 逐字节新鲜随机：
    //   * 任何固定字节（此前这里有一个 16 字节的 `22 00…00` 伪 ticket 头）
    //     都是一次 memcmp 即可命中、误报率 2^-128 的判别特征；
    //   * 复用同一缓冲（此前是 8 MiB 全局熵池循环读）会让不同连接的
    //     payload 出现逐字节相同的长片段，可被跨流拼接识别——真实密文
    //     永不重复。
    for &size in &remaining_17_sizes[1..] {
        let mut record = vec![0u8; TLS_RECORD_HEADER_LEN + size];
        record[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
        record[3..5].copy_from_slice(&(size as u16).to_be_bytes());
        rand::thread_rng().fill_bytes(&mut record[TLS_RECORD_HEADER_LEN..]);
        records.push(record);
    }

    Ok(records)
}

pub(super) fn camouflage_profile_key(host: &str, port: u16, fingerprint_hex: &str) -> String {
    format!("{}:{}:{}", host, port, fingerprint_hex)
}

pub(super) fn camouflage_baseline_key(host: &str, port: u16, family: &str) -> String {
    format!("{}:{}:baseline:{}", host, port, family)
}

pub(super) fn camouflage_refresh_cooldown_key(host: &str, port: u16, family: &str) -> String {
    format!("{}:{}:refresh:{}", host, port, family)
}

pub(super) fn camouflage_refresh_gate_key(host: &str, port: u16, family: &str) -> String {
    format!("{}:{}:gate:{}", host, port, family)
}

/// 取一个缓存 key 对应的变体。**单次加锁**，且只克隆中选的那一个变体。
///
/// 此前是 `get_cached_camouflage_profile_pool(key)` → `profiles.get(key).cloned()`
/// 深拷贝**整个池**（最多 4 个变体，各含两个真实 `Vec` 分配加一次
/// `Arc<[usize]>` 重建），出锁后再 `sample_camouflage_profile` 对每个变体
/// `sanitize + clone` 一遍。于是每次「有没有 rank-3 条目」的查询要付两轮
/// 全池克隆，而 `fetch_camouflage_flight` 在一次已认证握手上要查 4 次。
/// 现在锁内直接对引用算 rank、只克隆中选者（见 `sample_camouflage_profile`
/// 的等价性论证），临界区反而更短：进锁做的分配从 ~2×N 降到 1。
pub(super) async fn get_cached_camouflage_profile_entry(key: &str) -> Option<CamouflageProfile> {
    let mut profiles = CAMOUFLAGE_PROFILES.lock().await;
    let pool = profiles.get(key)?;
    sample_camouflage_profile(pool)
}

/// 按 key 查缓存 profile：指纹 key → 指纹族 baseline key → probe baseline key，
/// 任一命中 rank 3 立即返回，否则留下 rank 最高者。
///
/// **此前它的签名是 `(host, port, client_hello)`，自己从 ClientHello 重新推导
/// 指纹与 key。** 而唯一的生产调用者 `fetch_camouflage_flight` 在调用它之前
/// 已经算过同一份指纹与同一批 key，于是 `stable_client_hello_fingerprint`
/// 在同一次握手里对同一条约 1 KB 的 ClientHello 跑两遍——release 实测
/// 1.60 µs/次，占 `fetch_camouflage_flight` 缓存命中总耗时（6.61 µs）的近一半，
/// 比它全部 4 次全局锁加起来还贵。改成接收 key 之后，指纹只算一次。
///
/// 查找顺序 / rank 优先级 / 提前返回条件 / LRU 命中顺序与此前逐字相同。指纹化
/// 失败时前两个 key 传 None，与此前 `if let Some(fingerprint)` 整块被跳过等价。
pub(super) async fn lookup_cached_camouflage_profile(
    profile_key: Option<&str>,
    family_baseline_key: Option<&str>,
    probe_baseline_key: &str,
) -> Option<CamouflageProfile> {
    let mut best_profile = None;
    let mut best_rank = 0;

    for key in [profile_key, family_baseline_key, Some(probe_baseline_key)]
        .into_iter()
        .flatten()
    {
        let Some(profile) = get_cached_camouflage_profile_entry(key).await else {
            continue;
        };
        let rank = camouflage_profile_rank(&profile);
        if rank == 3 {
            return Some(profile);
        }
        if rank > best_rank {
            best_rank = rank;
            best_profile = Some(profile);
        }
    }
    best_profile
}

/// 一条连接在伪装缓存里用到的全部 key。
///
/// 抽成一个结构体是为了让「ClientHello → key」的推导只存在**一处**：此前
/// `fetch_camouflage_flight` 与 `lookup_cached_camouflage_profile` 各推导一遍，
/// 两份逻辑必须逐字一致却没有任何机制保证，而且白付一次指纹计算。
pub(super) struct CamouflageCacheKeys {
    /// 逐指纹的 profile key。
    pub(super) profile: String,
    /// 指纹族（指纹前 8 个 hex 字符）的 baseline key。
    pub(super) family_baseline: String,
    /// 启动期探针写入的 baseline key，与指纹无关。
    pub(super) probe_baseline: String,
    pub(super) refresh_cooldown: String,
    pub(super) refresh_gate: String,
}

/// 由 ClientHello 推出本连接的全部缓存 key；指纹化失败返回 None。
pub(super) fn camouflage_cache_keys(
    host: &str,
    port: u16,
    client_hello: &[u8],
) -> Option<CamouflageCacheKeys> {
    let fingerprint = stable_client_hello_fingerprint(client_hello)?;
    let mut hex_buf = [0u8; 64];
    let fingerprint_hex = hex_encode_fingerprint(&fingerprint, &mut hex_buf);
    // 指纹族 key：指纹哈希前 8 个 hex 字符，不足则退回 "probe"。
    let family = if fingerprint_hex.len() >= 8 {
        &fingerprint_hex[..8]
    } else {
        "probe"
    };
    Some(CamouflageCacheKeys {
        profile: camouflage_profile_key(host, port, fingerprint_hex),
        family_baseline: camouflage_baseline_key(host, port, family),
        probe_baseline: camouflage_baseline_key(host, port, "probe"),
        refresh_cooldown: camouflage_refresh_cooldown_key(host, port, family),
        refresh_gate: camouflage_refresh_gate_key(host, port, family),
    })
}

pub(super) async fn store_camouflage_profile(key: String, profile: CamouflageProfile) {
    let mut profiles = CAMOUFLAGE_PROFILES.lock().await;
    let pool = push_profile_variant(profiles.get(&key).cloned(), profile);
    profiles.put(key, pool);
}

pub(super) async fn camouflage_refresh_is_cooling_down(key: &str) -> bool {
    let mut failures = CAMOUFLAGE_REFRESH_FAILURES.lock().await;
    let Some(failed_at) = failures.get(key).copied() else {
        return false;
    };
    if Instant::now().duration_since(failed_at)
        <= Duration::from_secs(CAMOUFLAGE_REFRESH_FAILURE_COOLDOWN_SECS)
    {
        return true;
    }
    let _ = failures.pop(key);
    false
}

pub(super) async fn note_camouflage_refresh_failure(key: String) {
    let mut failures = CAMOUFLAGE_REFRESH_FAILURES.lock().await;
    failures.put(key, Instant::now());
}

pub(super) async fn clear_camouflage_refresh_failure(key: &str) {
    let mut failures = CAMOUFLAGE_REFRESH_FAILURES.lock().await;
    let _ = failures.pop(key);
}

pub(super) async fn acquire_camouflage_refresh_gate(
    key: &str,
) -> (Arc<CamouflageRefreshGate>, bool) {
    let mut inflight = CAMOUFLAGE_REFRESH_INFLIGHT.lock().await;
    if let Some(existing) = inflight.get(key).cloned() {
        if existing.completed.load(Ordering::Acquire) {
            let _ = inflight.pop(key);
        } else {
            return (existing, false);
        }
    }

    let gate = Arc::new(CamouflageRefreshGate {
        notify: tokio::sync::Notify::new(),
        completed: AtomicBool::new(false),
    });
    inflight.put(key.to_string(), gate.clone());
    (gate, true)
}

pub(super) async fn wait_for_camouflage_refresh_gate(gate: Arc<CamouflageRefreshGate>) {
    if gate.completed.load(Ordering::Acquire) {
        return;
    }

    loop {
        let notified = gate.notify.notified();
        if gate.completed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
        if gate.completed.load(Ordering::Acquire) {
            return;
        }
    }
}

impl Drop for CamouflageRefreshGateLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }

        self.gate.completed.store(true, Ordering::Release);
        self.gate.notify.notify_waiters();
        cleanup_camouflage_refresh_gate(self.key.clone(), self.gate.clone());
    }
}

impl CamouflageRefreshGateLease {
    pub(super) fn release_now(&mut self) {
        if self.released {
            return;
        }

        self.released = true;
        self.gate.completed.store(true, Ordering::Release);
        self.gate.notify.notify_waiters();
        cleanup_camouflage_refresh_gate(self.key.clone(), self.gate.clone());
    }
}

pub(super) fn cleanup_camouflage_refresh_gate(key: String, gate: Arc<CamouflageRefreshGate>) {
    if let Ok(mut inflight) = CAMOUFLAGE_REFRESH_INFLIGHT.try_lock() {
        if inflight
            .peek(&key)
            .map(|current| Arc::ptr_eq(current, &gate))
            .unwrap_or(false)
        {
            let _ = inflight.pop(&key);
        }
        return;
    }

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut inflight = CAMOUFLAGE_REFRESH_INFLIGHT.lock().await;
            if inflight
                .peek(&key)
                .map(|current| Arc::ptr_eq(current, &gate))
                .unwrap_or(false)
            {
                let _ = inflight.pop(&key);
            }
        });
    }
}

pub(super) async fn read_camouflage_server_records(
    host: &str,
    port: u16,
    client_hello: &[u8],
    fast: bool,
    expected_first_app_data_size: Option<usize>,
) -> anyhow::Result<(Arc<[u8]>, CamouflageProfile)> {
    let camouflage_addr = tokio::time::timeout(
        std::time::Duration::from_secs(CAMOUFLAGE_IO_TIMEOUT_SECS),
        resolve_allowed_camouflage(host, port),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout resolving camouflage host"))??;
    let mut camo_tcp = tokio::time::timeout(
        std::time::Duration::from_secs(CAMOUFLAGE_IO_TIMEOUT_SECS),
        TcpStream::connect(camouflage_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout connecting camouflage server"))??;
    camo_tcp.set_nodelay(true)?;
    let _ = apply_tcp_keepalive(&camo_tcp);

    camo_tcp.write_all(client_hello).await?;

    let mut camo_record = Vec::new();
    let mut camo_read_state = TlsRecordReadState::new();
    let mut server_records = Vec::new();
    let mut found_server_hello = false;
    let mut prefix_app_data_sizes = Vec::new();
    let mut in_prefix_run = true;
    let mut app_data_sizes = Vec::new();
    let mut total_records = 0usize;
    let mut visible_server_record_count = 0u16;
    let mut has_ccs = false;
    // 首条 app-data 的延迟必须相对 **ServerHello 到达时刻** 度量，而不是
    // 相对「向源站发完 ClientHello」的时刻——后者包含一整个 RTT-to-origin
    // 加 ServerHello 传输时间。回放时这个延迟被插在本机 SH+CCS 已冲刷之后
    // （且 socket 开了 TCP_NODELAY，分段边界独立），于是服务端会在自己的
    // CCS 与自己的首条 app-data 之间停顿约一整个 RTT；真实 TLS 1.3 服务器
    // 把 SH/CCS/EE/CERT/CV/FIN 连续突发写出，此处零间隔。
    let mut server_hello_seen: Option<Instant> = None;
    let sample_deadline =
        tokio::time::Instant::now() + Duration::from_secs(CAMOUFLAGE_IO_TIMEOUT_SECS);
    let mut first_app_data_delay_us = None;
    let mut last_app_data_seen = None;
    let mut early_app_data_gap_us = Vec::new();

    loop {
        let timeout_dur = std::time::Duration::from_secs(CAMOUFLAGE_SAMPLE_IDLE_TIMEOUT_SECS);

        let limits = TlsRecordReadLimits {
            max_records: MAX_CAMOUFLAGE_TOTAL_RECORDS,
            max_bytes: MAX_CAMOUFLAGE_TOTAL_RECORD_BYTES,
            deadline: Some(sample_deadline),
        };
        match tokio::time::timeout(
            timeout_dur,
            read_tls_record_bounded(
                &mut camo_tcp,
                &mut camo_record,
                limits,
                &mut camo_read_state,
            ),
        )
        .await
        {
            Ok(Ok((c_typ, c_rec_len))) => {
                total_records = total_records.saturating_add(1);
                if total_records > MAX_CAMOUFLAGE_TOTAL_RECORDS {
                    debug!(
                        "stopping camouflage sampling after {} records",
                        MAX_CAMOUFLAGE_TOTAL_RECORDS
                    );
                    break;
                }

                let record = camo_record.as_slice();
                if c_typ == 0x16 && is_server_hello(record) {
                    // HRR flight 不可缓存回放：缺第二个 ClientHello，回放会产生
                    // 异常流。中止本次采样，由上层走失败/冷却路径。
                    //
                    // 注（未实现 HRR 重试的原因）：HRR 意味着站点要求模板未
                    // 提供的 key_share 组（如 P-384 / ML-KEM）。即使采样端换组
                    // 重试拿到无 HRR 的 flight，该 flight 也与真实站点对客户端
                    // 原始 CH 的应答（HRR）不一致，回放反而引入 CH↔flight 不
                    // 自洽；且 ML-KEM 在当前依赖下无法生成。正确处置是更新
                    // 模板或更换伪装站点。
                    if is_hello_retry_request(record) {
                        anyhow::bail!(
                            "camouflage server returned HelloRetryRequest (endpoint requires a key_share group the ClientHello template does not offer); HRR flights cannot be cached for replay — refresh the template with update_firefox_template.py or choose a different camouflage endpoint"
                        );
                    }
                    found_server_hello = true;
                    server_hello_seen = Some(Instant::now());
                }
                if c_typ == 0x14 {
                    has_ccs = true;
                }

                if found_server_hello && c_typ == 0x17 {
                    // 前置小记录 = flight 开头连续的、装不下 Noise 响应的那
                    // 一段。此前的判据是 `app_data_sizes.is_empty()`，而每条
                    // 0x17 记录随后都会被推入 app_data_sizes，因此实际最多
                    // 只能采到 1 条，MAX_CAMOUFLAGE_PREFIX_APP_DATA_RECORDS
                    // 不可达；端点若发 ≥2 条前置小记录，回放条数就比参考少。
                    if in_prefix_run && c_rec_len < MIN_NOISE_RESPONSE_RECORD_LEN {
                        if prefix_app_data_sizes.len() < MAX_CAMOUFLAGE_PREFIX_APP_DATA_RECORDS {
                            prefix_app_data_sizes.push(c_rec_len);
                        } else {
                            in_prefix_run = false;
                        }
                    } else {
                        in_prefix_run = false;
                    }
                    if app_data_sizes.len() >= MAX_CAMOUFLAGE_APP_DATA_RECORDS {
                        debug!(
                            "stopping camouflage sampling after {} app-data records",
                            MAX_CAMOUFLAGE_APP_DATA_RECORDS
                        );
                        break;
                    }
                    let now = Instant::now();
                    // 微秒而非毫秒：`as_millis()` 向下截断，会把真实端点绝大
                    // 多数 0–1 ms 的帧内间隔整体压成 0，活下来的间隔又全部落
                    // 在整毫秒格点上（见 CamouflageProfile 的说明）。采样侧的
                    // 10 s 上限远小于 u32 微秒的 ~71 分钟量程，饱和不可达。
                    if first_app_data_delay_us.is_none() {
                        // 相对 ServerHello 到达时刻的真实帧内间隔（见上方注释）。
                        first_app_data_delay_us = Some(
                            server_hello_seen
                                .map(|seen| {
                                    now.duration_since(seen).as_micros().min(u32::MAX as u128)
                                        as u32
                                })
                                .unwrap_or(0),
                        );
                    }
                    if let Some(last_seen) = last_app_data_seen {
                        early_app_data_gap_us.push(
                            now.duration_since(last_seen)
                                .as_micros()
                                .min(u32::MAX as u128) as u32,
                        );
                    }
                    last_app_data_seen = Some(now);
                    app_data_sizes.push(c_rec_len);
                    let first_matches_cache = expected_first_app_data_size
                        .map(|expected| expected == c_rec_len)
                        .unwrap_or(true);
                    if fast && !first_matches_cache {
                        debug!(
                            "cached camouflage profile first record mismatch: expected {:?}, got {}",
                            expected_first_app_data_size,
                            c_rec_len
                        );
                    }
                    let should_stop_early = fast && first_matches_cache;
                    if should_stop_early {
                        break;
                    }
                } else {
                    visible_server_record_count = visible_server_record_count.saturating_add(1);
                    let new_len = server_records.len().saturating_add(record.len());
                    if new_len > MAX_CAMOUFLAGE_SERVER_RECORD_BYTES {
                        debug!(
                            "stopping camouflage sampling after {} visible handshake bytes",
                            MAX_CAMOUFLAGE_SERVER_RECORD_BYTES
                        );
                        break;
                    }
                    server_records.extend_from_slice(record);
                }
            }
            Ok(Err(e)) => {
                debug!("Error reading from camouflage: {}", e);
                break;
            }
            Err(_) => break,
        }
    }

    if !found_server_hello {
        anyhow::bail!("camouflage server did not return ServerHello (requires a TLS 1.3 endpoint)");
    }

    let server_records_arc: Arc<[u8]> = Arc::from(server_records.into_boxed_slice());
    let app_data_sizes_arc: Arc<[usize]> = Arc::from(app_data_sizes.into_boxed_slice());
    Ok((
        Arc::clone(&server_records_arc),
        CamouflageProfile {
            server_records: server_records_arc,
            prefix_app_data_sizes,
            first_app_data_size: app_data_sizes_arc.first().copied(),
            early_app_data_count: app_data_sizes_arc.len().min(u8::MAX as usize) as u8,
            has_ccs,
            visible_server_record_count,
            first_app_data_delay_us: first_app_data_delay_us.unwrap_or_default(),
            early_app_data_gap_us,
            app_data_sizes: app_data_sizes_arc,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条最小 ServerHello 记录（handshake type 0x02，random 可指定），
    /// session_id echo 长度为 0。
    fn server_hello_record_with_random(random: &[u8; 32]) -> Vec<u8> {
        let mut record = vec![0u8; 5 + 4 + 2 + 32 + 1];
        record[0] = 0x16;
        record[1] = 0x03;
        record[2] = 0x03;
        let body_len = (record.len() - 5) as u16;
        record[3..5].copy_from_slice(&body_len.to_be_bytes());
        record[5] = 0x02;
        record[9] = 0x03;
        record[10] = 0x03;
        record[11..43].copy_from_slice(random);
        record
    }

    #[test]
    fn hello_retry_request_random_is_detected() {
        let hrr = server_hello_record_with_random(&HELLO_RETRY_REQUEST_RANDOM);
        assert!(is_hello_retry_request(&hrr));

        let normal = server_hello_record_with_random(&[7u8; 32]);
        assert!(!is_hello_retry_request(&normal));

        let mut not_server_hello = hrr.clone();
        not_server_hello[5] = 0x01;
        assert!(!is_hello_retry_request(&not_server_hello));
    }

    #[test]
    fn hello_retry_request_magic_matches_rfc8446() {
        // RFC 8446 §4.1.3: SHA-256("HelloRetryRequest") 的前 8 字节。
        assert_eq!(&HELLO_RETRY_REQUEST_RANDOM[..4], &[0xcf, 0x21, 0xad, 0x74]);
        assert_eq!(&HELLO_RETRY_REQUEST_RANDOM[4..8], &[0xe5, 0x9a, 0x61, 0x11]);
    }

    #[test]
    fn patch_server_hello_random_skips_hello_retry_request() {
        let mut records = server_hello_record_with_random(&HELLO_RETRY_REQUEST_RANDOM);
        patch_server_hello_random(&mut records);
        assert_eq!(
            &records[11..43],
            &HELLO_RETRY_REQUEST_RANDOM,
            "HRR random 不得被重写"
        );

        let mut normal = server_hello_record_with_random(&[7u8; 32]);
        patch_server_hello_random(&mut normal);
        assert_ne!(&normal[11..43], &[7u8; 32], "普通 SH random 必须被重写");
    }

    #[test]
    fn probe_client_hello_shares_firefox_template_fingerprint() {
        // 探针 CH 与客户端 Firefox 模板 CH 的稳定指纹必须一致：启动验证
        // 采样因此直接存入客户端连接查询的 profile key，而非仅 probe 兜底。
        let probe = build_probe_client_hello("example.com").expect("probe ClientHello");
        let template = crate::template::get_or_build_client_hello_template(
            "example.com",
            Some("firefox"),
            None,
            true,
        )
        .expect("firefox template");
        let client_ch = template
            .instantiate(&[9u8; 32], &[7u8; 48], 42)
            .expect("client ClientHello");

        let probe_fp =
            crate::utils::stable_client_hello_fingerprint(&probe).expect("probe fingerprint");
        let client_fp =
            crate::utils::stable_client_hello_fingerprint(&client_ch).expect("client fingerprint");
        assert_eq!(
            probe_fp, client_fp,
            "探针 CH 与客户端 Firefox CH 的稳定指纹必须一致"
        );
    }
}
