use lazy_static::lazy_static;
use lru::LruCache;
use rand::Rng;
use rand::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::common::{
    self, apply_tcp_keepalive, derive_psk, max_flight3_total_wire_len, SnowyStream, AEAD_TAG_LEN,
    FLIGHT3_CCS_RECORD, FLIGHT3_FINISHED_PLAINTEXT_LEN, FLIGHT3_FINISHED_RECORD_LEN,
    HANDSHAKE_CONTROL_LEN, HANDSHAKE_CONTROL_MAGIC, MIN_NOISE_RESPONSE_RECORD_LEN,
    NOISE_RESPONSE_OVERHEAD_LEN, TLS_RECORD_HEADER_LEN,
};
use crate::utils::{
    client_hello_key_share_range, client_hello_random_and_session_id_ranges, constant_time_eq,
    derive_counter_cache_key, derive_counter_mac, derive_counter_mask, derive_noise_e_mask,
    extract_client_hello_server_name, hex_encode_fingerprint, is_server_hello, mask_mac_flags,
    read_tls_record_bounded, stable_client_hello_fingerprint,     unmask_noise_ephemeral_key,
    xor_in_place, xor_u64_bytes,
    TlsRecordReadLimits, TlsRecordReadState, MAX_TLS_RECORD_PAYLOAD_LEN,
};

const MAX_COUNTER_CACHE_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug)]
struct SlidingWindow {
    highest_seq: u64,
    bitmap: u64,
}

impl SlidingWindow {
    fn new(seq: u64) -> Self {
        SlidingWindow {
            highest_seq: seq,
            bitmap: 1u64,
        }
    }

    fn check(&self, seq: u64) -> bool {
        if seq > self.highest_seq {
            return true;
        }
        if self.highest_seq - seq >= 64 {
            return false;
        }
        let offset = self.highest_seq - seq;
        (self.bitmap & (1u64 << offset)) == 0
    }

    fn commit(&mut self, seq: u64) -> bool {
        if seq > self.highest_seq {
            let diff = seq - self.highest_seq;
            if diff >= 64 {
                self.bitmap = 1u64;
            } else {
                self.bitmap = (self.bitmap << diff) | 1u64;
            }
            self.highest_seq = seq;
            true
        } else if self.highest_seq - seq >= 64 {
            false
        } else {
            let offset = self.highest_seq - seq;
            let bit = 1u64 << offset;
            if (self.bitmap & bit) != 0 {
                false
            } else {
                self.bitmap |= bit;
                true
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ReplayCheck {
    cache_key: [u8; 16],
    sequence: u64,
}
const REPLAY_RETENTION_SECS: u64 = 600;
const MAX_HANDSHAKES: usize = 512;
const MAX_ACTIVE_SESSIONS: usize = 4096;
const MAX_REPLAY_CACHE_ENTRIES: usize = 65536;
const MAX_CAMOUFLAGE_PROFILES: usize = 1024;
const MAX_CAMOUFLAGE_PROFILE_VARIANTS: usize = 4;
const MAX_CAMOUFLAGE_REFRESH_FAILURES: usize = 1024;
const STARTUP_CAMOUFLAGE_SAMPLE_COUNT: usize = 4;
const CAMOUFLAGE_IO_TIMEOUT_SECS: u64 = 10;
const CAMOUFLAGE_REFRESH_FAILURE_COOLDOWN_SECS: u64 = 30;
const MAX_CAMOUFLAGE_SERVER_RECORD_BYTES: usize = 256 * 1024;
const MAX_CAMOUFLAGE_TOTAL_RECORD_BYTES: usize = 512 * 1024;
const MAX_CAMOUFLAGE_APP_DATA_RECORDS: usize = 256;
const MAX_CAMOUFLAGE_TOTAL_RECORDS: usize = 512;
const MAX_CAMOUFLAGE_PREFIX_APP_DATA_RECORDS: usize = 4;
const MAX_SERVER_INITIAL_RECORD_BYTES: usize = MAX_TLS_RECORD_PAYLOAD_LEN + TLS_RECORD_HEADER_LEN;
const SERVER_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const CAMOUFLAGE_SAMPLE_IDLE_TIMEOUT_SECS: u64 = 5;
const MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN: usize = 23;
const MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN: usize = 16401;

struct FallbackLimits {
    max_pre_auth_fallbacks: usize,
    max_pre_auth_fallbacks_per_ip: usize,
    pre_auth_fallback_connect_timeout_secs: u64,
    ip_reputation_cooldown_secs: u64,
    ip_reputation_reset_secs: u64,
    ip_reputation_max_fallbacks_per_window: u64,
}

impl FallbackLimits {
    fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Self {
            max_pre_auth_fallbacks: rng.gen_range(384..=768),
            max_pre_auth_fallbacks_per_ip: rng.gen_range(12..=24),
            pre_auth_fallback_connect_timeout_secs: rng.gen_range(2..=5),
            ip_reputation_cooldown_secs: rng.gen_range(240..=420),
            ip_reputation_reset_secs: rng.gen_range(3000..=4200),
            ip_reputation_max_fallbacks_per_window: rng.gen_range(75..=150),
        }
    }
}

static FALLBACK_LIMITS: OnceLock<FallbackLimits> = OnceLock::new();

fn fallback_limits() -> &'static FallbackLimits {
    FALLBACK_LIMITS.get_or_init(FallbackLimits::new)
}

const CAMOUFLAGE_REFRESH_DAEMON_MIN_SECS: u64 = 300;
const CAMOUFLAGE_REFRESH_DAEMON_MAX_SECS: u64 = 3000;

const TLS12_DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
const TLS11_DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

const ENTROPY_POOL_SIZE: usize = 8 * 1024 * 1024;

static ENTROPY_POOL: OnceLock<Vec<u8>> = OnceLock::new();

pub fn init_entropy_pool() {
    ENTROPY_POOL.get_or_init(|| {
        let mut pool = vec![0u8; ENTROPY_POOL_SIZE];
        rand::thread_rng().fill_bytes(&mut pool);
        pool
    });
}


lazy_static! {
    static ref HANDSHAKE_LIMITER: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    static ref ACTIVE_SESSION_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_ACTIVE_SESSIONS));
    static ref PRE_AUTH_FALLBACK_LIMITER: Arc<Semaphore> =
        Arc::new(Semaphore::new(fallback_limits().max_pre_auth_fallbacks));
    static ref REPLAY_CACHE: std::sync::Mutex<LruCache<[u8; 32], Instant>> =
        std::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_REPLAY_CACHE_ENTRIES).expect("non-zero replay cache size")
        ));
    static ref COUNTER_CACHE: std::sync::Mutex<LruCache<[u8; 16], SlidingWindow>> =
        std::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_COUNTER_CACHE_ENTRIES)
                .expect("non-zero counter cache size")
        ));
    static ref PRE_AUTH_FALLBACK_PEER_COUNTS: std::sync::Mutex<HashMap<IpAddr, usize>> =
        std::sync::Mutex::new(HashMap::new());
    static ref IP_REPUTATIONS: std::sync::Mutex<HashMap<IpAddr, IpReputation>> =
        std::sync::Mutex::new(HashMap::new());
    static ref CAMOUFLAGE_PROFILES: tokio::sync::Mutex<LruCache<String, CamouflageProfilePool>> =
        tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_CAMOUFLAGE_PROFILES).expect("non-zero camouflage profile size")
        ));
    static ref CAMOUFLAGE_REFRESH_FAILURES: tokio::sync::Mutex<LruCache<String, Instant>> =
        tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_CAMOUFLAGE_REFRESH_FAILURES)
                .expect("non-zero camouflage refresh failure size")
        ));
    static ref CAMOUFLAGE_REFRESH_INFLIGHT: tokio::sync::Mutex<LruCache<String, Arc<CamouflageRefreshGate>>> =
        tokio::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_CAMOUFLAGE_REFRESH_FAILURES)
                .expect("non-zero camouflage inflight size")
        ));
    static ref CAMOUFLAGE_REFRESH_DAEMONS: std::sync::Mutex<std::collections::HashSet<String>> =
        std::sync::Mutex::new(std::collections::HashSet::new());
}

struct CamouflageRefreshGate {
    notify: tokio::sync::Notify,
    completed: AtomicBool,
}

struct CamouflageRefreshGateLease {
    key: String,
    gate: Arc<CamouflageRefreshGate>,
    released: bool,
}

struct PreAuthFallbackPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    peer_ip: IpAddr,
}

#[derive(Clone, Debug)]
struct IpReputation {
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

#[derive(Clone, Debug)]
struct CamouflageProfile {
    server_records: Arc<[u8]>,
    prefix_app_data_sizes: Vec<usize>,
    app_data_sizes: Arc<[usize]>,
    first_app_data_size: Option<usize>,
    early_app_data_count: u8,
    has_ccs: bool,
    visible_server_record_count: u16,
    first_app_data_delay_ms: u16,
    early_app_data_gap_ms: Vec<u16>,
}

#[derive(Clone, Debug)]
struct CamouflageProfilePool {
    profiles: Vec<CamouflageProfile>,
}

#[derive(Clone, Copy, Debug)]
enum FailureClass {
    // Pre-auth fallback eligible when initial bytes are available: these paths
    // have not committed any kanotls-only response and can safely expose the
    // configured camouflage endpoint's natural behavior. Oversized records and
    // empty reads fail closed instead to avoid resource abuse.
    NonTlsFirstRecord,
    AuthFailed,
    HandshakeTimeout,
    InvalidFirstRecord,
    MissingSni,
    SniMismatch,
    CapacityLimited,
}

fn make_control_payload(ghost_count: u16) -> [u8; HANDSHAKE_CONTROL_LEN] {
    let mut payload = [0u8; HANDSHAKE_CONTROL_LEN];
    payload[..4].copy_from_slice(HANDSHAKE_CONTROL_MAGIC);
    payload[4..6].copy_from_slice(&ghost_count.to_be_bytes());
    payload
}

fn fallback_noise_response_record_len(_sampled_sizes: &[usize]) -> usize {
    300
}

fn sanitize_camouflage_profile(mut profile: CamouflageProfile) -> CamouflageProfile {
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
        .early_app_data_gap_ms
        .truncate(profile.app_data_sizes.len().saturating_sub(1));

    profile
}

fn merge_camouflage_profile(
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
            cached_profile.early_app_data_gap_ms = sampled_profile.early_app_data_gap_ms;
        }
        cached_profile.first_app_data_delay_ms = sampled_profile.first_app_data_delay_ms;
    }
    sanitize_camouflage_profile(cached_profile)
}

fn camouflage_profile_rank(profile: &CamouflageProfile) -> u8 {
    match (
        !profile.server_records.is_empty(),
        !profile.app_data_sizes.is_empty(),
    ) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

fn is_complete_camouflage_profile(profile: &CamouflageProfile) -> bool {
    camouflage_profile_rank(profile) == 3
}

fn pick_best_camouflage_profile(
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

fn pick_refresh_base_profile(
    cached_specific_profile: Option<CamouflageProfile>,
    cached_family_profile: Option<CamouflageProfile>,
) -> Option<CamouflageProfile> {
    pick_best_camouflage_profile(
        [cached_specific_profile, cached_family_profile]
            .into_iter()
            .flatten(),
    )
}

fn sample_camouflage_profile(pool: &CamouflageProfilePool) -> Option<CamouflageProfile> {
    let mut usable: Vec<CamouflageProfile> = pool
        .profiles
        .iter()
        .cloned()
        .map(sanitize_camouflage_profile)
        .filter(|profile| camouflage_profile_rank(profile) > 0)
        .collect();
    if usable.is_empty() {
        return None;
    }
    let max_rank = usable
        .iter()
        .map(camouflage_profile_rank)
        .max()
        .unwrap_or(0);
    usable.retain(|profile| camouflage_profile_rank(profile) == max_rank);
    let idx = rand::thread_rng().gen_range(0..usable.len());
    Some(usable.swap_remove(idx))
}

fn push_profile_variant(
    pool: Option<CamouflageProfilePool>,
    profile: CamouflageProfile,
) -> CamouflageProfilePool {
    let mut profiles = pool.map(|pool| pool.profiles).unwrap_or_default();
    let profile = sanitize_camouflage_profile(profile);

    if let Some(existing) = profiles.iter_mut().find(|existing| {
        existing.server_records == profile.server_records
            && existing.prefix_app_data_sizes == profile.prefix_app_data_sizes
            && existing.app_data_sizes == profile.app_data_sizes
            && existing.early_app_data_gap_ms == profile.early_app_data_gap_ms
            && existing.first_app_data_delay_ms == profile.first_app_data_delay_ms
            && existing.has_ccs == profile.has_ccs
    }) {
        *existing = profile;
    } else {
        profiles.push(profile);
        if profiles.len() > MAX_CAMOUFLAGE_PROFILE_VARIANTS {
            let drop_idx = rand::thread_rng().gen_range(0..profiles.len());
            profiles.swap_remove(drop_idx);
        }
    }

    CamouflageProfilePool { profiles }
}

fn sanitize_waste_record_sizes(sizes: &[usize]) -> Vec<usize> {
    sizes
        .iter()
        .copied()
        .filter(|&size| {
            (MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN..=MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN)
                .contains(&size)
        })
        .collect()
}

fn extract_client_hello_session_id(client_hello: &[u8]) -> Option<&[u8]> {
    let (_, session_id_range) = client_hello_random_and_session_id_ranges(client_hello)?;
    Some(&client_hello[session_id_range])
}

fn patch_server_hello_session_id_echo(server_records: &mut [u8], client_session_id: &[u8]) -> bool {
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

fn check_counter_replay(
    derived_psk: &[u8],
    random_copy: &[u8; 32],
    masked_counter: [u8; 8],
) -> Option<ReplayCheck> {
    let mask = derive_counter_mask(derived_psk, random_copy);
    let raw_counter = u64::from_be_bytes(xor_u64_bytes(masked_counter, mask));

    let session_id = raw_counter >> 24;
    let sequence = raw_counter & 0x00FF_FFFF;

    let mut key_material = derived_psk.to_vec();
    key_material.extend_from_slice(&session_id.to_be_bytes());
    let cache_key = derive_counter_cache_key(&key_material);

    match COUNTER_CACHE.lock() {
        Ok(mut cache) => {
            if let Some(window) = cache.get(&cache_key) {
                if !window.check(sequence) {
                    debug!(
                        "counter replay or out-of-window for session 0x{:X}: seq {}",
                        session_id, sequence
                    );
                    return None;
                }
            }
            Some(ReplayCheck { cache_key, sequence })
        }
        Err(_) => {
            warn!("counter cache mutex poisoned during check, rejecting");
            None
        }
    }
}

fn commit_counter_replay(check: &ReplayCheck) -> bool {
    match COUNTER_CACHE.lock() {
        Ok(mut cache) => {
            if let Some(window) = cache.get_mut(&check.cache_key) {
                if !window.commit(check.sequence) {
                    debug!(
                        "counter commit rejected for key {:?}: seq {} already consumed",
                        check.cache_key, check.sequence
                    );
                    return false;
                }
            } else {
                cache.put(check.cache_key, SlidingWindow::new(check.sequence));
            }
            true
        }
        Err(_) => {
            warn!("counter cache mutex poisoned during commit, rejecting");
            false
        }
    }
}

fn patch_server_hello_random(server_records: &mut [u8]) {
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
            use rand::RngCore;
            rng.fill_bytes(&mut fresh_random);
            let last8: &[u8] = &server_records[random_start + 24..random_start + 32];
            if last8 == TLS12_DOWNGRADE_SENTINEL || last8 == TLS11_DOWNGRADE_SENTINEL {
                server_records[random_start..random_start + 24]
                    .copy_from_slice(&fresh_random[..24]);
            } else {
                server_records[random_start..random_start + 32]
                    .copy_from_slice(&fresh_random);
            }
        }
        offset += record_total;
    }
}



pub async fn server_accept(
    mut tcp: TcpStream,
    psk: &[u8],
    camouflage_host: &str,
    camouflage_port: u16,
) -> Result<SnowyStream, anyhow::Error> {
    tcp.set_nodelay(true)?;
    let _ = apply_tcp_keepalive(&tcp);
    let handshake_permit = match HANDSHAKE_LIMITER.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            emit_shaped_failure(
                tcp,
                Vec::new(),
                camouflage_host,
                camouflage_port,
                FailureClass::CapacityLimited,
            )
            .await;
            anyhow::bail!("server handshake limit reached")
        }
    };
    let peer_addr = tcp.peer_addr()?;
    debug!("new connection from {}", peer_addr);

    let derived_psk = derive_psk(psk);
    let builder = snow::Builder::new(common::NOISE_PARAMS.clone()).psk(0, &derived_psk)?;
    let mut noise = builder.build_responder()?;
    let mut client_noise_tag = [0u8; 16];

    let mut rx_buf = Vec::new();
    let initial_deadline =
        tokio::time::Instant::now() + Duration::from_secs(SERVER_HANDSHAKE_TIMEOUT_SECS);
    let (typ, rec_len) = match read_initial_client_record(&mut tcp, &mut rx_buf, initial_deadline)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            let class = if e.kind() == std::io::ErrorKind::TimedOut {
                FailureClass::HandshakeTimeout
            } else {
                FailureClass::InvalidFirstRecord
            };
            drop(handshake_permit);
            if !rx_buf.is_empty() && !is_oversized_initial_record_error(&e) {
                emit_pre_auth_failure(tcp, rx_buf, camouflage_host, camouflage_port, class).await;
            } else {
                emit_shaped_failure(tcp, rx_buf, camouflage_host, camouflage_port, class).await;
            }
            anyhow::bail!("Failed to read initial TLS record: {}", e)
        }
    };

    if typ != 0x16 {
        drop(handshake_permit);
        emit_pre_auth_failure(
            tcp,
            rx_buf,
            camouflage_host,
            camouflage_port,
            FailureClass::NonTlsFirstRecord,
        )
        .await;
        anyhow::bail!("First record is not a TLS Handshake");
    }

    if rx_buf.len() != TLS_RECORD_HEADER_LEN + rec_len {
        anyhow::bail!("unexpected initial record buffer length");
    }
    let client_hello_server_name = extract_client_hello_server_name(&rx_buf).map(str::to_owned);
    let pld = &mut rx_buf[..];
    let _key_share_range = client_hello_key_share_range(pld);
    let mut replay_check: Option<ReplayCheck> = None;

    let is_auth_valid = if let Some((random_range, session_id_range)) =
        client_hello_random_and_session_id_ranges(pld)
    {
        let random = &pld[random_range];
        let session_id = &pld[session_id_range];
        if session_id.len() >= 32 {
            let mut random_copy = [0u8; 32];
            random_copy.copy_from_slice(random);
            client_noise_tag.copy_from_slice(&session_id[..16]);

            let _flags = session_id[31];

            let recovered_e = unmask_noise_ephemeral_key(&random_copy, &derived_psk, &client_noise_tag);

            if recovered_e == [0u8; 32] {
                false
            } else {
                let mut noise_init = [0u8; 48];
                noise_init[..32].copy_from_slice(&recovered_e);
                noise_init[32..48].copy_from_slice(&session_id[..16]);

                match noise.read_message(&noise_init, &mut []) {
                    Ok(0) => {
                        let mut masked_counter = [0u8; 8];
                        masked_counter.copy_from_slice(&session_id[16..24]);
                        let mut got_mac = [0u8; 8];
                        got_mac.copy_from_slice(&session_id[24..32]);
                        mask_mac_flags(&mut got_mac);
                        let random_prefix: &[u8] = &random_copy[..16];
                        let want_mac = derive_counter_mac(
                            &derived_psk,
                            &random_copy,
                            &masked_counter,
                            random_prefix,
                        );
                        let mut want_mac_masked = want_mac;
                        mask_mac_flags(&mut want_mac_masked);
                        if !constant_time_eq(&got_mac, &want_mac_masked) {
                            debug!("counter MAC verification failed");
                            false
                        } else {
                            let check = check_counter_replay(
                                &derived_psk,
                                &random_copy,
                                masked_counter,
                            );
                            if check.is_none() {
                                false
                            } else if is_replay(&random_copy) {
                                warn!(
                                    "replayed Noise client ephemeral rejected from {}",
                                    peer_addr
                                );
                                false
                            } else {
                                replay_check = check;
                                true
                            }
                        }
                    }
                    Ok(len) => {
                        debug!("unexpected Noise init plaintext length: {}", len);
                        false
                    }
                    Err(_) => false,
                }
            }
        } else {
            debug!(
                "session_id too short for Noise auth: {} bytes (need >= 32)",
                session_id.len()
            );
            false
        }
    } else {
        debug!("failed to extract random/session_id from ClientHello");
        false
    };

    if !is_auth_valid {
        debug!("Noise authentication failed or missing, rejecting handshake");
        drop(handshake_permit);
        emit_pre_auth_failure(
            tcp,
            rx_buf,
            camouflage_host,
            camouflage_port,
            FailureClass::AuthFailed,
        )
        .await;
        anyhow::bail!("Noise authentication failed");
    }

    let client_hello_server_name = match client_hello_server_name {
        Some(server_name) => server_name,
        None => {
            debug!("client hello missing valid SNI, rejecting handshake");
            drop(handshake_permit);
            emit_pre_auth_failure(
                tcp,
                rx_buf,
                camouflage_host,
                camouflage_port,
                FailureClass::MissingSni,
            )
            .await;
            anyhow::bail!("ClientHello missing valid SNI")
        }
    };
    if !client_hello_server_name.eq_ignore_ascii_case(camouflage_host) {
        debug!(
            "client hello SNI '{}' does not match configured camouflage host '{}', rejecting handshake",
            client_hello_server_name,
            camouflage_host
        );
        drop(handshake_permit);
        emit_pre_auth_failure(
            tcp,
            rx_buf,
            camouflage_host,
            camouflage_port,
            FailureClass::SniMismatch,
        )
        .await;
        anyhow::bail!(
            "client hello SNI '{}' does not match configured camouflage host '{}'",
            client_hello_server_name,
            camouflage_host
        )
    }

    debug!("Noise authentication successful, proxying ClientHello to camouflage server");
    drop(handshake_permit);

    let _session_permit = match ACTIVE_SESSION_LIMITER.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            emit_pre_auth_failure(
                tcp,
                rx_buf,
                camouflage_host,
                camouflage_port,
                FailureClass::CapacityLimited,
            )
            .await;
            anyhow::bail!("server active session limit reached")
        }
    };

    let mut noise_state = Some(noise);
    let _has_cache = has_complete_camouflage_cache(camouflage_host, camouflage_port, &rx_buf).await;

    if let Some(ref check) = replay_check {
        if !commit_counter_replay(check) {
            anyhow::bail!("counter commit rejected: window advanced past sequence");
        }
    }

    let mut noise = establish_synthetic_camouflage_tunnel(
        &mut tcp,
        &rx_buf,
        camouflage_host,
        camouflage_port,
        &mut noise_state,
        &derived_psk,
        &client_noise_tag,
    )
    .await?;

    maybe_spawn_camouflage_refresh_daemon(
        camouflage_host.to_owned(),
        camouflage_port,
        rx_buf.clone(),
    );

    let pre_read_tls = consume_client_flight3_ghost(&mut tcp, &mut noise).await?;

    Ok(SnowyStream::new_with_permit_and_pre_read_tls(
        tcp,
        noise,
        Some(_session_permit),
        pre_read_tls,
    ))
}

pub async fn validate_camouflage_endpoint(host: &str, port: u16) -> anyhow::Result<()> {
    let _ = resolve_allowed_camouflage(host, port).await?;
    validate_camouflage_tls13_flight(host, port).await?;
    Ok(())
}

async fn validate_camouflage_tls13_flight(host: &str, port: u16) -> anyhow::Result<()> {
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
            camouflage_profile_key(host, port, hex_encode_fingerprint(&fingerprint, &mut hex_buf)),
            profile.clone(),
        )
        .await;
        store_camouflage_profile(camouflage_baseline_key(host, port, "probe"), profile).await;
    }
    Ok(())
}

fn build_probe_client_hello(host: &str) -> anyhow::Result<Vec<u8>> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| anyhow::anyhow!("failed to build camouflage probe config: {}", e))?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid camouflage host {}: {:?}", host, e))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut bytes = Vec::new();
    let mut writer = std::io::Cursor::new(&mut bytes);
    conn.write_tls(&mut writer)?;
    Ok(bytes)
}

fn is_replay(client_ephemeral: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(client_ephemeral) else {
        return true;
    };
    let Ok(mut cache) = REPLAY_CACHE.lock() else {
        warn!("replay cache mutex poisoned, rejecting handshake fail-closed");
        return true;
    };
    let now = Instant::now();
    while let Some((_, seen_at)) = cache.peek_lru() {
        if now.duration_since(*seen_at) <= Duration::from_secs(REPLAY_RETENTION_SECS) {
            break;
        }
        cache.pop_lru();
    }
    if cache.contains(&key) {
        true
    } else {
        cache.put(key, now);
        false
    }
}

async fn fetch_camouflage_flight(
    host: &str,
    port: u16,
    client_hello: &[u8],
) -> anyhow::Result<(Arc<[u8]>, Arc<[usize]>, CamouflageProfile)> {
    let fingerprint = stable_client_hello_fingerprint(client_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to fingerprint ClientHello"))?;
    let mut hex_buf = [0u8; 64];
    let fingerprint_hex = hex_encode_fingerprint(&fingerprint, &mut hex_buf);
    let profile_key = camouflage_profile_key(host, port, fingerprint_hex);
    let family = if fingerprint_hex.len() >= 8 {
        &fingerprint_hex[..8]
    } else {
        "probe"
    };
    let baseline_key = camouflage_baseline_key(host, port, family);
    let probe_baseline_key = camouflage_baseline_key(host, port, "probe");
    let refresh_cooldown_key = camouflage_refresh_cooldown_key(host, port, family);
    let refresh_gate_key = camouflage_refresh_gate_key(host, port, family);
    let cached_profile = lookup_cached_camouflage_profile(host, port, client_hello).await;
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
    if cached_handshake_profile.is_some()
        && camouflage_refresh_is_cooling_down(&refresh_cooldown_key).await
    {
        if let Some(profile) = cached_handshake_profile.clone() {
            debug!(
                host,
                port, family, "camouflage refresh cooldown active, using cached handshake profile"
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
        let cached_after_wait = lookup_cached_camouflage_profile(host, port, client_hello).await;
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
        if cached_handshake_profile.is_some()
            && camouflage_refresh_is_cooling_down(&refresh_cooldown_key).await
        {
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
            if cached_handshake_profile.is_some() {
                note_camouflage_refresh_failure(refresh_cooldown_key).await;
            } else {
                clear_camouflage_refresh_failure(&refresh_cooldown_key).await;
            }
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
                Arc::from(sanitize_waste_record_sizes(&merged_profile.app_data_sizes).into_boxed_slice()),
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

async fn has_complete_camouflage_cache(host: &str, port: u16, client_hello: &[u8]) -> bool {
    if let Some(profile) = lookup_cached_camouflage_profile(host, port, client_hello).await {
        is_complete_camouflage_profile(&profile)
    } else {
        false
    }
}

fn maybe_spawn_camouflage_refresh_daemon(host: String, port: u16, client_hello: Vec<u8>) {
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
            let random_interval =
                rand::thread_rng().gen_range(CAMOUFLAGE_REFRESH_DAEMON_MIN_SECS..=CAMOUFLAGE_REFRESH_DAEMON_MAX_SECS);
            tokio::time::sleep(Duration::from_secs(random_interval)).await;
            match read_camouflage_server_records(&host, port, &client_hello, true, None).await {
                Ok((_server_records, profile)) => {
                    if let Some(fingerprint) = stable_client_hello_fingerprint(&client_hello) {
                        let mut hex_buf = [0u8; 64];
                        let fingerprint_hex = hex_encode_fingerprint(&fingerprint, &mut hex_buf);
                        let key = camouflage_profile_key(&host, port, fingerprint_hex);
                        store_camouflage_profile(key, profile).await;
                    }
                }
                Err(e) => {
                    debug!("background camouflage refresh failed for {}:{}: {}", host, port, e);
                }
            }
        }
    });
}

async fn establish_synthetic_camouflage_tunnel(
    tcp: &mut TcpStream,
    client_hello: &[u8],
    camouflage_host: &str,
    camouflage_port: u16,
    noise_state: &mut Option<snow::HandshakeState>,
    derived_psk: &[u8],
    client_noise_tag: &[u8; 16],
) -> anyhow::Result<snow::TransportState> {
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
    if let Some(client_session_id) = extract_client_hello_session_id(client_hello) {
        patch_server_hello_session_id_echo(&mut patched_server_records, client_session_id);
    }
    patch_server_hello_random(&mut patched_server_records);

    let pool = ENTROPY_POOL
        .get()
        .expect("entropy pool not initialized");
    let pool_len = pool.len();
    let mut entropy_offset = rand::thread_rng().gen_range(0..pool_len);

    let noise_sequence = build_noise_response_sequence(
        noise_state
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Noise handshake state already consumed"))?,
        derived_psk,
        client_noise_tag,
        &remaining_17_sizes,
        pool,
        &mut entropy_offset,
    )?;

    tcp.write_all(&patched_server_records).await?;
    tcp.flush().await?;

    let first_delay = camo_profile.first_app_data_delay_ms;
    if first_delay > 0 {
        let jittered = jitter_iat_ms(first_delay);
        tokio::time::sleep(Duration::from_millis(jittered)).await;
    }

    for (idx, &size) in camo_profile.prefix_app_data_sizes.iter().enumerate() {
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + size);
        record.extend_from_slice(&[0x17, 0x03, 0x03]);
        record.extend_from_slice(&(size as u16).to_be_bytes());
        if entropy_offset + size <= pool_len {
            record.extend_from_slice(&pool[entropy_offset..entropy_offset + size]);
        } else {
            let tail = pool_len - entropy_offset;
            record.extend_from_slice(&pool[entropy_offset..]);
            record.extend_from_slice(&pool[..size - tail]);
        }
        entropy_offset = (entropy_offset + size) % pool_len;
        tcp.write_all(&record).await?;
        tcp.flush().await?;

        if let Some(&gap) = camo_profile.early_app_data_gap_ms.get(idx) {
            if gap > 0 {
                let jittered = jitter_iat_ms(gap);
                tokio::time::sleep(Duration::from_millis(jittered)).await;
            }
        }
    }

    tcp.write_all(&noise_sequence).await?;
    tcp.flush().await?;
    debug!("Sent Noise response (e, ee) wrapped in Application Data");

    let noise = noise_state
        .take()
        .ok_or_else(|| anyhow::anyhow!("Noise handshake state already consumed"))?
        .into_transport_mode()?;
    Ok(noise)
}

fn jitter_iat_ms(base_ms: u16) -> u64 {
    use rand::Rng;
    let base = base_ms as u64;
    if base == 0 {
        return 0;
    }
    let mut rng = rand::thread_rng();
    let jitter_max = (base / 5).max(1);
    let jitter = rng.gen_range(0..=jitter_max * 2);
    (base + jitter.saturating_sub(jitter_max)).max(1)
}

fn build_noise_response_sequence(
    noise: &mut snow::HandshakeState,
    derived_psk: &[u8],
    client_noise_tag: &[u8; 16],
    remaining_17_sizes: &[usize],
    pool: &[u8],
    entropy_offset: &mut usize,
) -> anyhow::Result<Vec<u8>> {
    let mut sequence = Vec::new();
    if remaining_17_sizes.is_empty() {
        return Ok(sequence);
    }

    let first_size = remaining_17_sizes[0];
    let ghost_count = (remaining_17_sizes.len() - 1) as u16;

    let dummy_len = first_size.saturating_sub(NOISE_RESPONSE_OVERHEAD_LEN);
    if dummy_len < HANDSHAKE_CONTROL_LEN {
        anyhow::bail!("Noise response target too short for control payload");
    }
    let mut dummy_payload = vec![0u8; dummy_len];
    dummy_payload[..HANDSHAKE_CONTROL_LEN]
        .copy_from_slice(&make_control_payload(ghost_count));

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

    sequence.extend_from_slice(&[0x17, 0x03, 0x03]);
    sequence.extend_from_slice(&(reply_len as u16).to_be_bytes());
    sequence.extend_from_slice(&noise_payload[..reply_len]);

    let pool_len = pool.len();
    const GHOST_TICKET_HEADER: [u8; 16] = [
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for &size in &remaining_17_sizes[1..] {
        sequence.extend_from_slice(&[0x17, 0x03, 0x03]);
        sequence.extend_from_slice(&(size as u16).to_be_bytes());

        if size >= GHOST_TICKET_HEADER.len() {
            sequence.extend_from_slice(&GHOST_TICKET_HEADER);
            let header_len = GHOST_TICKET_HEADER.len();
            let ent_len = size - header_len;
            let mut written = 0usize;
            while written < ent_len {
                let chunk = std::cmp::min(ent_len - written, pool_len - *entropy_offset);
                sequence.extend_from_slice(&pool[*entropy_offset..*entropy_offset + chunk]);
                *entropy_offset = (*entropy_offset + chunk) % pool_len;
                written += chunk;
            }
        } else {
            let mut written = 0usize;
            while written < size {
                let chunk = std::cmp::min(size - written, pool_len - *entropy_offset);
                sequence.extend_from_slice(&pool[*entropy_offset..*entropy_offset + chunk]);
                *entropy_offset = (*entropy_offset + chunk) % pool_len;
                written += chunk;
            }
        }
    }

    Ok(sequence)
}

fn camouflage_profile_key(host: &str, port: u16, fingerprint_hex: &str) -> String {
    format!("{}:{}:{}", host, port, fingerprint_hex)
}

fn camouflage_baseline_key(host: &str, port: u16, family: &str) -> String {
    format!("{}:{}:baseline:{}", host, port, family)
}

fn camouflage_refresh_cooldown_key(host: &str, port: u16, family: &str) -> String {
    format!("{}:{}:refresh:{}", host, port, family)
}

fn camouflage_refresh_gate_key(host: &str, port: u16, family: &str) -> String {
    format!("{}:{}:gate:{}", host, port, family)
}

async fn get_cached_camouflage_profile_pool(key: &str) -> Option<CamouflageProfilePool> {
    let mut profiles = CAMOUFLAGE_PROFILES.lock().await;
    profiles.get(key).cloned()
}

async fn get_cached_camouflage_profile_entry(key: &str) -> Option<CamouflageProfile> {
    get_cached_camouflage_profile_pool(key)
        .await
        .as_ref()
        .and_then(sample_camouflage_profile)
}

async fn lookup_cached_camouflage_profile(
    host: &str,
    port: u16,
    client_hello: &[u8],
) -> Option<CamouflageProfile> {
    let mut best_profile = None;
    let mut best_rank = 0;

    if let Some(fingerprint) = stable_client_hello_fingerprint(client_hello) {
        let mut hex_buf = [0u8; 64];
        let fingerprint_hex = hex_encode_fingerprint(&fingerprint, &mut hex_buf);
        let profile_key = camouflage_profile_key(host, port, fingerprint_hex);
        if let Some(profile) = get_cached_camouflage_profile_entry(&profile_key).await {
            let rank = camouflage_profile_rank(&profile);
            if rank == 3 {
                return Some(profile);
            }
            if rank > best_rank {
                best_rank = rank;
                best_profile = Some(profile);
            }
        }
        let family = if fingerprint_hex.len() >= 8 {
            &fingerprint_hex[..8]
        } else {
            "probe"
        };
        let family_key = camouflage_baseline_key(host, port, family);
        if let Some(profile) = get_cached_camouflage_profile_entry(&family_key).await {
            let rank = camouflage_profile_rank(&profile);
            if rank == 3 {
                return Some(profile);
            }
            if rank > best_rank {
                best_rank = rank;
                best_profile = Some(profile);
            }
        }
    }
    if let Some(profile) =
        get_cached_camouflage_profile_entry(&camouflage_baseline_key(host, port, "probe")).await
    {
        let rank = camouflage_profile_rank(&profile);
        if rank == 3 {
            return Some(profile);
        }
        if rank > best_rank {
            best_profile = Some(profile);
        }
    }
    best_profile
}

async fn store_camouflage_profile(key: String, profile: CamouflageProfile) {
    let mut profiles = CAMOUFLAGE_PROFILES.lock().await;
    let pool = push_profile_variant(profiles.get(&key).cloned(), profile);
    profiles.put(key, pool);
}

async fn camouflage_refresh_is_cooling_down(key: &str) -> bool {
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

async fn note_camouflage_refresh_failure(key: String) {
    let mut failures = CAMOUFLAGE_REFRESH_FAILURES.lock().await;
    failures.put(key, Instant::now());
}

async fn clear_camouflage_refresh_failure(key: &str) {
    let mut failures = CAMOUFLAGE_REFRESH_FAILURES.lock().await;
    let _ = failures.pop(key);
}

async fn acquire_camouflage_refresh_gate(key: &str) -> (Arc<CamouflageRefreshGate>, bool) {
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

async fn wait_for_camouflage_refresh_gate(gate: Arc<CamouflageRefreshGate>) {
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

impl CamouflageRefreshGateLease {
    fn release_now(&mut self) {
        if self.released {
            return;
        }

        self.released = true;
        self.gate.completed.store(true, Ordering::Release);
        self.gate.notify.notify_waiters();
        cleanup_camouflage_refresh_gate(self.key.clone(), self.gate.clone());
    }
}

fn cleanup_camouflage_refresh_gate(key: String, gate: Arc<CamouflageRefreshGate>) {
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

async fn read_camouflage_server_records(
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
    let mut app_data_sizes = Vec::new();
    let mut total_records = 0usize;
    let mut visible_server_record_count = 0u16;
    let mut has_ccs = false;
    let sample_started = Instant::now();
    let sample_deadline =
        tokio::time::Instant::now() + Duration::from_secs(CAMOUFLAGE_IO_TIMEOUT_SECS);
    let mut first_app_data_delay_ms = None;
    let mut last_app_data_seen = None;
    let mut early_app_data_gap_ms = Vec::new();

    loop {
        let timeout_dur =
            std::time::Duration::from_secs(CAMOUFLAGE_SAMPLE_IDLE_TIMEOUT_SECS);

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
                    found_server_hello = true;
                }
                if c_typ == 0x14 {
                    has_ccs = true;
                }

                if found_server_hello && c_typ == 0x17 {
                    if app_data_sizes.is_empty()
                        && c_rec_len < MIN_NOISE_RESPONSE_RECORD_LEN
                        && prefix_app_data_sizes.len() < MAX_CAMOUFLAGE_PREFIX_APP_DATA_RECORDS
                    {
                        prefix_app_data_sizes.push(c_rec_len);
                    }
                    if app_data_sizes.len() >= MAX_CAMOUFLAGE_APP_DATA_RECORDS {
                        debug!(
                            "stopping camouflage sampling after {} app-data records",
                            MAX_CAMOUFLAGE_APP_DATA_RECORDS
                        );
                        break;
                    }
                    let now = Instant::now();
                    if first_app_data_delay_ms.is_none() {
                        first_app_data_delay_ms = Some(
                            now.duration_since(sample_started)
                                .as_millis()
                                .min(u16::MAX as u128) as u16,
                        );
                    }
                    if let Some(last_seen) = last_app_data_seen {
                        early_app_data_gap_ms.push(
                            now.duration_since(last_seen)
                                .as_millis()
                                .min(u16::MAX as u128) as u16,
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
            first_app_data_delay_ms: first_app_data_delay_ms.unwrap_or_default(),
            early_app_data_gap_ms,
            app_data_sizes: app_data_sizes_arc,
        },
    ))
}

async fn resolve_allowed_camouflage(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    if port == 0 {
        anyhow::bail!("invalid camouflage port 0");
    }

    let mut first_allowed = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        if is_blocked_camouflage_ip(addr.ip()) {
            debug!("skipping blocked camouflage address: {}", addr);
            continue;
        }
        first_allowed.get_or_insert(addr);
    }
    first_allowed.ok_or_else(|| anyhow::anyhow!("unable to resolve camouflage host"))
}

fn is_blocked_camouflage_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000)
                || ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.octets()[0] >= 240
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_blocked_camouflage_ip(IpAddr::V4(v4));
            }
            ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
    }
}

async fn emit_shaped_failure(
    mut client_stream: TcpStream,
    _initial_data: Vec<u8>,
    _host: &str,
    _port: u16,
    _class: FailureClass,
) {
    let _ = client_stream.shutdown().await;
}

async fn emit_pre_auth_failure(
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

    if should_try_pre_auth_fallback(class) {
        match try_pre_auth_fallback(&mut client_stream, &initial_data, host, port).await {
            Ok(()) => return,
            Err(err) => debug!("pre-auth fallback unavailable: {}", err),
        }
    }

    emit_shaped_failure(client_stream, Vec::new(), host, port, class).await;
}

fn should_try_pre_auth_fallback(class: FailureClass) -> bool {
    matches!(
        class,
        FailureClass::NonTlsFirstRecord
            | FailureClass::AuthFailed
            | FailureClass::InvalidFirstRecord
            | FailureClass::MissingSni
            | FailureClass::SniMismatch
            | FailureClass::HandshakeTimeout
            | FailureClass::CapacityLimited
    )
}

fn check_ip_reputation(ip: IpAddr) -> bool {
    let Ok(mut reps) = IP_REPUTATIONS.lock() else {
        return false;
    };
    let now = Instant::now();

    if let Some(reputation) = reps.get(&ip) {
        if let Some(cooldown) = reputation.cooldown_until {
            if now < cooldown {
                return false;
            }
        }
    }

    let entry = reps.entry(ip).or_insert_with(IpReputation::new);
    entry.fallback_count += 1;
    entry.last_seen = now;

    let limits = fallback_limits();
    if entry.fallback_count > limits.ip_reputation_max_fallbacks_per_window
        && entry.last_seen.duration_since(entry.first_seen)
            < Duration::from_secs(limits.ip_reputation_reset_secs)
    {
        entry.cooldown_until = Some(now + Duration::from_secs(limits.ip_reputation_cooldown_secs));
        warn!("IP {:?} placed in cooldown for excessive fallbacks", ip);
        return false;
    }

    let age = now.duration_since(entry.first_seen);
    if age > Duration::from_secs(limits.ip_reputation_reset_secs) {
        *entry = IpReputation::new();
        entry.fallback_count = 1;
    }

    true
}

async fn try_pre_auth_fallback(
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

    let connect_timeout = Duration::from_secs(fallback_limits().pre_auth_fallback_connect_timeout_secs);
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

async fn relay_pre_auth_fallback(
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

async fn try_capacity_limited_fallback(
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

    emit_shaped_failure(
        client_stream,
        Vec::new(),
        host,
        port,
        FailureClass::CapacityLimited,
    )
    .await;
}

fn try_acquire_pre_auth_fallback_permit(peer_ip: IpAddr) -> Option<PreAuthFallbackPermit> {
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

async fn read_initial_client_record(
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

fn is_oversized_initial_record_error(err: &std::io::Error) -> bool {
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

async fn consume_client_flight3_ghost(
    tcp: &mut TcpStream,
    noise: &mut snow::TransportState,
) -> anyhow::Result<Vec<u8>> {
    let max_wire = max_flight3_total_wire_len();
    let mut wire = vec![0u8; max_wire];
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(SERVER_HANDSHAKE_TIMEOUT_SECS);
    let remaining_timeout = deadline - tokio::time::Instant::now();

    let ccs_len = FLIGHT3_CCS_RECORD.len();
    let fin_record_len = FLIGHT3_FINISHED_RECORD_LEN;
    let minimum_needed = ccs_len + fin_record_len + TLS_RECORD_HEADER_LEN;

    let mut total_read = 0usize;
    while total_read < minimum_needed {
        let n = tokio::time::timeout(
            remaining_timeout,
            tcp.read(&mut wire[total_read..minimum_needed]),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading client Flight 3 ghost"))??;
        if n == 0 {
            anyhow::bail!("unexpected eof reading client Flight 3 ghost");
        }
        total_read += n;
    }

    if wire[..ccs_len] != FLIGHT3_CCS_RECORD {
        anyhow::bail!("invalid client Flight 3: CCS record mismatch");
    }

    let fin_start = ccs_len;
    if wire[fin_start] != 0x17 {
        anyhow::bail!("invalid client Flight 3: Finished record type mismatch");
    }
    let fin_payload_len =
        u16::from_be_bytes([wire[fin_start + 3], wire[fin_start + 4]]) as usize;
    if fin_payload_len != FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN {
        anyhow::bail!(
            "invalid client Flight 3: Finished payload length {} (expected {})",
            fin_payload_len,
            FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN
        );
    }
    let fin_end = fin_start + fin_record_len;
    let mut fin_plaintext = vec![0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN];
    noise
        .read_message(
            &wire[fin_start + TLS_RECORD_HEADER_LEN..fin_end],
            &mut fin_plaintext,
        )
        .map_err(|e| anyhow::anyhow!("failed to decrypt Flight 3 Finished ghost: {}", e))?;

    let h2_start = fin_end;
    while total_read < h2_start + TLS_RECORD_HEADER_LEN {
        let n = tokio::time::timeout(
            remaining_timeout,
            tcp.read(&mut wire[total_read..h2_start + TLS_RECORD_HEADER_LEN]),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading H2 ghost header"))??;
        if n == 0 {
            anyhow::bail!("unexpected eof reading H2 ghost");
        }
        total_read += n;
    }

    if wire[h2_start] != 0x17 {
        anyhow::bail!("invalid client Flight 3: H2 ghost record type mismatch");
    }
    let h2_payload_len =
        u16::from_be_bytes([wire[h2_start + 3], wire[h2_start + 4]]) as usize;
    if !(AEAD_TAG_LEN..=16384 + 256).contains(&h2_payload_len) {
        anyhow::bail!(
            "invalid client Flight 3: H2 ghost payload length {}",
            h2_payload_len
        );
    }
    let h2_total = TLS_RECORD_HEADER_LEN + h2_payload_len;
    let h2_end = h2_start + h2_total;
    let pre_read_tls = if total_read > h2_end {
        wire[h2_end..total_read].to_vec()
    } else {
        Vec::new()
    };
    wire.resize(h2_end, 0);

    while total_read < h2_end {
        let n = tokio::time::timeout(
            remaining_timeout,
            tcp.read(&mut wire[total_read..h2_end]),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading H2 ghost record"))??;
        if n == 0 {
            anyhow::bail!("unexpected eof reading H2 ghost record");
        }
        total_read += n;
    }

    let h2_plaintext_len = h2_payload_len - AEAD_TAG_LEN;
    let mut h2_plaintext = vec![0u8; h2_payload_len];
    noise
        .read_message(
            &wire[h2_start + TLS_RECORD_HEADER_LEN..h2_end],
            &mut h2_plaintext,
        )
        .map_err(|e| anyhow::anyhow!("failed to decrypt Flight 3 H2 ghost: {}", e))?;

    debug!(
        "Consumed client Flight 3 ghost: CCS(6) + Finished({}) + H2({})",
        FLIGHT3_FINISHED_RECORD_LEN, h2_plaintext_len
    );
    Ok(pre_read_tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    lazy_static! {
        static ref PRE_AUTH_FALLBACK_TEST_LOCK: tokio::sync::Mutex<()> =
            tokio::sync::Mutex::new(());
    }

    fn assert_pre_auth_fallback_state_clean() {
        assert_eq!(
            PRE_AUTH_FALLBACK_LIMITER.available_permits(),
            fallback_limits().max_pre_auth_fallbacks
        );
        let counts = PRE_AUTH_FALLBACK_PEER_COUNTS.lock().unwrap();
        assert!(counts.is_empty(), "expected no tracked fallback peers");
    }

    fn hold_pre_auth_fallback_peer_counts_lock(
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let guard = PRE_AUTH_FALLBACK_PEER_COUNTS.lock().unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
            drop(guard);
        });
        locked_rx.recv().unwrap();
        (release_tx, handle)
    }

    async fn connected_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(client, accept);
        (client.unwrap(), accepted.unwrap().0)
    }

    fn build_tls_app_record(noise: &mut snow::TransportState, payload: &[u8]) -> Vec<u8> {
        use crate::common::{
            BLOCK_LEN_PREFIX_SIZE, INNER_CONTENT_TYPE_APP_DATA, INNER_CONTENT_TYPE_LEN,
        };
        let mut block =
            vec![0u8; BLOCK_LEN_PREFIX_SIZE + payload.len() + INNER_CONTENT_TYPE_LEN];
        block[..BLOCK_LEN_PREFIX_SIZE]
            .copy_from_slice(&(payload.len() as u16).to_be_bytes());
        block[BLOCK_LEN_PREFIX_SIZE..BLOCK_LEN_PREFIX_SIZE + payload.len()].copy_from_slice(payload);
        let last_idx = block.len() - 1;
        block[last_idx] = INNER_CONTENT_TYPE_APP_DATA;

        let mut ciphertext = vec![0u8; block.len() + AEAD_TAG_LEN];
        let ct_len = noise.write_message(&block, &mut ciphertext).unwrap();

        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + ct_len);
        record.extend_from_slice(&[0x17, 0x03, 0x03]);
        record.extend_from_slice(&(ct_len as u16).to_be_bytes());
        record.extend_from_slice(&ciphertext[..ct_len]);
        record
    }

    fn build_client_flight3_and_upload(
        noise: &mut snow::TransportState,
        upload_payload: &[u8],
    ) -> Vec<u8> {
        let finished_plaintext = [0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN];
        let mut finished_ciphertext = vec![0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN];
        let finished_ct_len = noise
            .write_message(&finished_plaintext, &mut finished_ciphertext)
            .unwrap();

        let h2_plaintext = common::build_h2_ghost_plaintext(0);
        let mut h2_ciphertext = vec![0u8; h2_plaintext.len() + AEAD_TAG_LEN];
        let h2_ct_len = noise.write_message(&h2_plaintext, &mut h2_ciphertext).unwrap();

        let mut wire = Vec::new();
        wire.extend_from_slice(&FLIGHT3_CCS_RECORD);
        wire.extend_from_slice(&[0x17, 0x03, 0x03]);
        wire.extend_from_slice(&(finished_ct_len as u16).to_be_bytes());
        wire.extend_from_slice(&finished_ciphertext[..finished_ct_len]);
        wire.extend_from_slice(&[0x17, 0x03, 0x03]);
        wire.extend_from_slice(&(h2_ct_len as u16).to_be_bytes());
        wire.extend_from_slice(&h2_ciphertext[..h2_ct_len]);
        wire.extend_from_slice(&build_tls_app_record(noise, upload_payload));
        wire
    }

    fn established_noise_pair() -> (snow::TransportState, snow::TransportState) {
        let psk = derive_psk(b"flight3-overread-regression");
        let mut initiator = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &psk)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut init = [0u8; 48];
        let init_len = initiator.write_message(&[], &mut init).unwrap();
        responder.read_message(&init[..init_len], &mut []).unwrap();

        let mut response = [0u8; 48];
        let response_len = responder.write_message(&[], &mut response).unwrap();
        initiator
            .read_message(&response[..response_len], &mut [])
            .unwrap();

        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    #[tokio::test]
    async fn flight3_consume_preserves_immediate_upload_record_boundary() {
        let (mut client_noise, mut server_noise) = established_noise_pair();
        let upload_payload = b"upload bytes immediately after flight3";
        let wire = build_client_flight3_and_upload(&mut client_noise, upload_payload);
        let (mut client_tcp, mut server_tcp) = connected_tcp_pair().await;

        let writer = tokio::spawn(async move {
            client_tcp.write_all(&wire).await.unwrap();
            client_tcp.flush().await.unwrap();
        });

        let pre_read_tls = consume_client_flight3_ghost(&mut server_tcp, &mut server_noise)
            .await
            .unwrap();
        assert!(
            pre_read_tls.is_empty(),
            "Flight 3 reader should not over-read the first upload TLS record"
        );

        let mut stream = SnowyStream::new_with_permit_and_pre_read_tls(
            server_tcp,
            server_noise,
            None,
            pre_read_tls,
        );
        let mut got = vec![0u8; upload_payload.len()];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut got))
            .await
            .expect("SnowyStream read should not hang")
            .unwrap();
        assert_eq!(got, upload_payload);

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn close_notify_treated_as_eof_not_session_data() {
        let (client_noise, server_noise) = established_noise_pair();
        let (client_tcp, server_tcp) = connected_tcp_pair().await;

        let payload = b"data before close";
        let mut client_stream = SnowyStream::new(client_tcp, client_noise);

        let writer = tokio::spawn(async move {
            client_stream.write_all(payload).await.unwrap();
            client_stream.flush().await.unwrap();
            client_stream.shutdown().await.unwrap();
        });

        let mut server_stream =
            SnowyStream::new_with_permit_and_pre_read_tls(server_tcp, server_noise, None, vec![]);

        let mut got = vec![0u8; payload.len()];
        server_stream
            .read_exact(&mut got)
            .await
            .expect("server reads data before close");
        assert_eq!(got, payload);

        let mut tail = vec![0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(3), server_stream.read(&mut tail))
            .await
            .expect("server read after close should not hang")
            .unwrap();
        assert_eq!(
            n, 0,
            "close_notify alert must not appear as session data bytes"
        );

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_with_pending_bulk_does_not_corrupt_sequence() {
        let (client_noise, server_noise) = established_noise_pair();
        let (client_tcp, server_tcp) = connected_tcp_pair().await;

        let bulk = vec![0xabu8; 64 * 1024];
        let bulk_len = bulk.len();
        let mut client_stream = SnowyStream::new(client_tcp, client_noise);

        let writer = tokio::spawn(async move {
            client_stream.write_all(&bulk).await.unwrap();
            client_stream.shutdown().await.unwrap();
        });

        let mut server_stream =
            SnowyStream::new_with_permit_and_pre_read_tls(server_tcp, server_noise, None, vec![]);

        let mut total = 0usize;
        let mut buf = vec![0u8; 16384];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(3), server_stream.read(&mut buf))
                .await
                .expect("server read should not hang")
                .unwrap();
            if n == 0 {
                break;
            }
            for (i, &b) in buf[..n].iter().enumerate() {
                assert_eq!(
                    b, 0xab,
                    "byte {} corrupted: expected 0xab, got 0x{:02x}",
                    total + i,
                    b
                );
            }
            total += n;
        }
        assert!(
            total >= bulk_len,
            "expected at least {} bytes of bulk data, got {}",
            bulk_len,
            total
        );

        writer.await.unwrap();
    }

    async fn expect_shaped_close_or_alert(client: &mut TcpStream) {
        let mut buf = [0u8; 7];
        let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
            .await
            .expect("failure path should not hang indefinitely")
            .unwrap();
        if read == 0 {
            return;
        }
        if read >= 7 {
            assert_eq!(buf[..3], [0x15, 0x03, 0x03]);
            assert_eq!(buf[3..5], [0x00, 0x02]);
            assert_eq!(buf[5], 0x02);
        }
    }

    fn test_public_ip(idx: usize) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, (idx + 1) as u8))
    }

    fn test_camouflage_profile(
        server_records: Vec<u8>,
        app_data_sizes: Vec<usize>,
    ) -> CamouflageProfile {
        let first = app_data_sizes.first().copied();
        let count = app_data_sizes.len().min(u8::MAX as usize) as u8;
        CamouflageProfile {
            server_records: Arc::from(server_records.into_boxed_slice()),
            prefix_app_data_sizes: vec![],
            first_app_data_size: first,
            early_app_data_count: count,
            has_ccs: true,
            visible_server_record_count: 2,
            first_app_data_delay_ms: 0,
            early_app_data_gap_ms: vec![],
            app_data_sizes: Arc::from(app_data_sizes.into_boxed_slice()),
        }
    }

    #[test]
    fn blocks_camouflage_private_and_cgnat_ranges() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            let ip = raw.parse::<IpAddr>().unwrap();
            assert!(is_blocked_camouflage_ip(ip), "{} should be blocked", raw);
        }
    }

    #[test]
    fn allows_public_camouflage_addresses() {
        for raw in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            let ip = raw.parse::<IpAddr>().unwrap();
            assert!(!is_blocked_camouflage_ip(ip), "{} should be allowed", raw);
        }
    }

    #[tokio::test]
    async fn sample_camouflage_profile_prefers_complete_variants() {
        let profile = sample_camouflage_profile(&CamouflageProfilePool {
            profiles: vec![
                test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![]),
                test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![53, 1024]),
                test_camouflage_profile(vec![], vec![90]),
            ],
        })
        .unwrap();

        assert_eq!(camouflage_profile_rank(&profile), 3);
        assert_eq!(&*profile.app_data_sizes, &[53, 1024][..]);
    }

    #[tokio::test]
    async fn camouflage_profile_cache_evicts_old_entries() {
        for idx in 0..(MAX_CAMOUFLAGE_PROFILES + 10) {
            store_camouflage_profile(
                format!("key-{}", idx),
                test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![idx]),
            )
            .await;
        }

        let profiles = CAMOUFLAGE_PROFILES.lock().await;
        assert!(profiles.len() <= MAX_CAMOUFLAGE_PROFILES);
    }

    #[tokio::test]
    async fn lookup_cached_camouflage_profile_uses_stable_fingerprint() {
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x7d, 0x01, 0x00, 0x00, 0x79, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        let fingerprint = stable_client_hello_fingerprint(&client_hello).unwrap();
        let key = format!("example.com:443:{}", hex::encode(fingerprint));
        store_camouflage_profile(
            key,
            test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![53, 90]),
        )
        .await;

        let mut modified = client_hello.clone();
        modified[11..43].fill(0xaa);
        modified[44..76].fill(0xbb);
        modified[94..126].fill(0xcc);

        let profile = lookup_cached_camouflage_profile("example.com", 443, &modified).await;
        assert!(profile.is_some());
        assert_eq!(&*profile.unwrap().app_data_sizes, &[53, 90][..]);
    }

    #[tokio::test]
    async fn lookup_cached_camouflage_profile_falls_back_to_baseline_key() {
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x7d, 0x01, 0x00, 0x00, 0x79, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];

        store_camouflage_profile(
            camouflage_baseline_key("baseline.example", 443, "probe"),
            test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x00], vec![53, 90]),
        )
        .await;

        let profile =
            lookup_cached_camouflage_profile("baseline.example", 443, &client_hello).await;
        assert!(profile.is_some());
        let profile = profile.unwrap();
        assert_eq!(&*profile.app_data_sizes, &[53, 90][..]);
        assert_eq!(&*profile.server_records, &[0x16, 0x03, 0x03, 0x00, 0x00][..]);
    }

    #[tokio::test]
    async fn lookup_cached_camouflage_profile_uses_baseline_when_fingerprint_fails() {
        store_camouflage_profile(
            camouflage_baseline_key("baseline-no-fp.example", 443, "probe"),
            test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x00], vec![64]),
        )
        .await;

        let malformed = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let profile =
            lookup_cached_camouflage_profile("baseline-no-fp.example", 443, &malformed).await;

        assert!(profile.is_some());
        assert_eq!(profile.unwrap().app_data_sizes.to_vec(), vec![64]);
    }

    #[tokio::test]
    async fn lookup_cached_camouflage_profile_prefers_complete_baseline_over_partial_specific() {
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x7d, 0x01, 0x00, 0x00, 0x79, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        let fingerprint = stable_client_hello_fingerprint(&client_hello).unwrap();
        store_camouflage_profile(
            camouflage_profile_key("prefer.example", 443, &hex::encode(fingerprint)),
            test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x00], vec![]),
        )
        .await;
        store_camouflage_profile(
            camouflage_baseline_key("prefer.example", 443, &hex::encode(fingerprint)[..8]),
            test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x00], vec![53, 90]),
        )
        .await;

        let profile = lookup_cached_camouflage_profile("prefer.example", 443, &client_hello)
            .await
            .unwrap();

        assert_eq!(camouflage_profile_rank(&profile), 3);
        assert_eq!(&*profile.app_data_sizes, &[53, 90][..]);
    }

    #[tokio::test]
    async fn camouflage_refresh_failure_enters_and_exits_cooldown() {
        let key = camouflage_refresh_cooldown_key("cooldown.example", 443, "probe");
        assert!(!camouflage_refresh_is_cooling_down(&key).await);

        note_camouflage_refresh_failure(key.clone()).await;
        assert!(camouflage_refresh_is_cooling_down(&key).await);

        {
            let mut failures = CAMOUFLAGE_REFRESH_FAILURES.lock().await;
            failures.put(
                key.clone(),
                Instant::now() - Duration::from_secs(CAMOUFLAGE_REFRESH_FAILURE_COOLDOWN_SECS + 1),
            );
        }

        assert!(!camouflage_refresh_is_cooling_down(&key).await);
    }

    #[tokio::test]
    async fn camouflage_refresh_gate_serializes_followers() {
        let key = camouflage_refresh_gate_key("gate.example", 443, "probe");
        let (leader, leader_ok) = acquire_camouflage_refresh_gate(&key).await;
        assert!(leader_ok);
        let mut leader_lease = CamouflageRefreshGateLease {
            key: key.clone(),
            gate: leader.clone(),
            released: false,
        };

        let (follower, follower_ok) = acquire_camouflage_refresh_gate(&key).await;
        assert!(!follower_ok);
        assert!(Arc::ptr_eq(&leader, &follower));

        let waiter = wait_for_camouflage_refresh_gate(follower);
        leader_lease.release_now();
        tokio::time::timeout(Duration::from_millis(20), waiter)
            .await
            .expect("follower should be released");

        let (_next, next_ok) = acquire_camouflage_refresh_gate(&key).await;
        assert!(next_ok);
    }

    #[tokio::test]
    async fn camouflage_refresh_gate_releases_multiple_followers() {
        let key = camouflage_refresh_gate_key("multi-gate.example", 443, "probe");
        let (leader, leader_ok) = acquire_camouflage_refresh_gate(&key).await;
        assert!(leader_ok);
        let mut leader_lease = CamouflageRefreshGateLease {
            key: key.clone(),
            gate: leader,
            released: false,
        };

        let (follower_a, follower_a_ok) = acquire_camouflage_refresh_gate(&key).await;
        let (follower_b, follower_b_ok) = acquire_camouflage_refresh_gate(&key).await;
        assert!(!follower_a_ok);
        assert!(!follower_b_ok);

        let wait_a = wait_for_camouflage_refresh_gate(follower_a);
        let wait_b = wait_for_camouflage_refresh_gate(follower_b);
        leader_lease.release_now();

        tokio::time::timeout(Duration::from_millis(20), async {
            tokio::join!(wait_a, wait_b);
        })
        .await
        .expect("all followers should be released");
    }

    #[tokio::test]
    async fn probe_baseline_does_not_count_as_specific_cache_hit() {
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x7d, 0x01, 0x00, 0x00, 0x79, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];

        store_camouflage_profile(
            camouflage_baseline_key("probe-only.example", 443, "probe"),
            test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x00], vec![53, 90]),
        )
        .await;

        let fingerprint = stable_client_hello_fingerprint(&client_hello).unwrap();
        let profile_key =
            camouflage_profile_key("probe-only.example", 443, &hex::encode(fingerprint));
        let family_key =
            camouflage_baseline_key("probe-only.example", 443, &hex::encode(fingerprint)[..8]);

        assert!(get_cached_camouflage_profile_entry(&profile_key)
            .await
            .is_none());
        assert!(get_cached_camouflage_profile_entry(&family_key)
            .await
            .is_none());

        let profile = lookup_cached_camouflage_profile("probe-only.example", 443, &client_hello)
            .await
            .expect("probe fallback remains visible");
        assert_eq!(&*profile.app_data_sizes, &[53, 90][..]);
    }

    #[test]
    fn refresh_base_profile_ignores_probe_baseline_when_family_exists() {
        let family = test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x00], vec![]);
        let probe = test_camouflage_profile(vec![0x16, 0x03, 0x03, 0x00, 0x01], vec![53, 90]);

        let refresh_base = pick_refresh_base_profile(None, Some(family.clone()))
            .expect("family partial should be refresh base");
        let lookup_base =
            pick_best_camouflage_profile([Some(family), Some(probe)].into_iter().flatten())
                .expect("complete probe remains a serving fallback");

        assert_eq!(camouflage_profile_rank(&refresh_base), 2);
        assert!(refresh_base.app_data_sizes.is_empty());
        assert_eq!(camouflage_profile_rank(&lookup_base), 3);
        assert_eq!(&*lookup_base.app_data_sizes, &[53, 90][..]);
    }

    #[test]
    fn sanitize_camouflage_profile_drops_extreme_record_sizes() {
        let profile = sanitize_camouflage_profile(CamouflageProfile {
            server_records: Arc::from(vec![].into_boxed_slice()),
            prefix_app_data_sizes: vec![8, 53, 512, 20000],
            app_data_sizes: Arc::from(vec![8, 53, 512, 6000, 20000].into_boxed_slice()),
            first_app_data_size: Some(8),
            early_app_data_count: 5,
            has_ccs: true,
            visible_server_record_count: 2,
            first_app_data_delay_ms: 999,
            early_app_data_gap_ms: vec![400, 2, 999, 1],
        });

        assert_eq!(&*profile.app_data_sizes, &[53, 512, 6000][..]);
        assert_eq!(profile.prefix_app_data_sizes, vec![53, 512]);
        assert_eq!(profile.first_app_data_size, Some(53));
        assert_eq!(profile.early_app_data_count, 3);
        assert_eq!(profile.first_app_data_delay_ms, 999);
        assert_eq!(profile.early_app_data_gap_ms, vec![400, 2]);
    }

    #[test]
    fn sanitize_waste_record_sizes_drops_out_of_range_values() {
        let sizes = sanitize_waste_record_sizes(&[8, 23, 120, 8192, 16401, 20000]);
        assert_eq!(sizes, vec![23, 120, 8192, 16401]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_initial_record_fails_closed_without_fallback() {
        let _test_guard = PRE_AUTH_FALLBACK_TEST_LOCK.lock().await;
        assert_pre_auth_fallback_state_clean();

        let (release_tx, lock_thread) = hold_pre_auth_fallback_peer_counts_lock();
        let (mut client, server) = connected_tcp_pair().await;
        let server_task =
            tokio::spawn(async move { server_accept(server, b"test-psk", "localhost", 443).await });

        client
            .write_all(&[0x16, 0x03, 0x03, 0x41, 0x01])
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            PRE_AUTH_FALLBACK_LIMITER.available_permits(),
            fallback_limits().max_pre_auth_fallbacks
        );

        release_tx.send(()).unwrap();
        lock_thread.join().unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server_accept should finish the shaped failure path")
            .expect("server_accept task should join");
        assert!(result.is_err());
        expect_shaped_close_or_alert(&mut client).await;
        assert_pre_auth_fallback_state_clean();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_pre_auth_failures_remain_fallback_eligible() {
        let _test_guard = PRE_AUTH_FALLBACK_TEST_LOCK.lock().await;
        assert_pre_auth_fallback_state_clean();

        for initial_record in [
            vec![0x17, 0x03, 0x03, 0x00, 0x00],
            build_probe_client_hello("localhost").unwrap(),
        ] {
            let (release_tx, lock_thread) = hold_pre_auth_fallback_peer_counts_lock();
            let (mut client, server) = connected_tcp_pair().await;
            let server_task =
                tokio::spawn(
                    async move { server_accept(server, b"test-psk", "localhost", 443).await },
                );

            client.write_all(&initial_record).await.unwrap();

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!server_task.is_finished());
            assert_eq!(
                PRE_AUTH_FALLBACK_LIMITER.available_permits(),
                fallback_limits().max_pre_auth_fallbacks - 1
            );

            release_tx.send(()).unwrap();
            lock_thread.join().unwrap();

            let result = tokio::time::timeout(Duration::from_secs(2), server_task)
                .await
                .expect("server_accept should finish once fallback accounting unblocks")
                .expect("server_accept task should join");
            assert!(result.is_err());
            expect_shaped_close_or_alert(&mut client).await;
            assert_pre_auth_fallback_state_clean();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fallback_permit_releases_after_relay_ends() {
        let _test_guard = PRE_AUTH_FALLBACK_TEST_LOCK.lock().await;
        assert_pre_auth_fallback_state_clean();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fallback_addr = listener.local_addr().unwrap();
        let fallback_task = tokio::spawn(async move {
            let (mut accepted, _) = listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            accepted.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");
            accepted.write_all(b"world").await.unwrap();
        });

        let (mut client, mut server) = connected_tcp_pair().await;
        let relay_task = tokio::spawn(async move {
            let _permit = try_acquire_pre_auth_fallback_permit(server.peer_addr().unwrap().ip())
                .expect("permit should be available");
            let mut fallback = TcpStream::connect(fallback_addr).await.unwrap();
            fallback.write_all(b"hello").await.unwrap();
            relay_pre_auth_fallback(&mut server, &mut fallback).await
        });

        let mut response = [0u8; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        drop(client);

        relay_task.await.unwrap().unwrap();
        fallback_task.await.unwrap();
        assert_pre_auth_fallback_state_clean();
    }

    #[tokio::test]
    async fn pre_auth_fallback_permit_accounting_enforces_limits_and_releases() {
        let _test_guard = PRE_AUTH_FALLBACK_TEST_LOCK.lock().await;
        assert_pre_auth_fallback_state_clean();

        let peer_ip = test_public_ip(0);
        let per_ip_limit = fallback_limits().max_pre_auth_fallbacks_per_ip;
        let mut peer_permits = (0..per_ip_limit)
            .map(|_| try_acquire_pre_auth_fallback_permit(peer_ip).unwrap())
            .collect::<Vec<_>>();
        assert!(try_acquire_pre_auth_fallback_permit(peer_ip).is_none());
        assert_eq!(
            *PRE_AUTH_FALLBACK_PEER_COUNTS
                .lock()
                .unwrap()
                .get(&peer_ip)
                .unwrap(),
            per_ip_limit
        );

        drop(peer_permits.pop());
        let replacement = try_acquire_pre_auth_fallback_permit(peer_ip);
        assert!(replacement.is_some());

        drop(peer_permits);
        drop(replacement);
        assert!(PRE_AUTH_FALLBACK_PEER_COUNTS
            .lock()
            .unwrap()
            .get(&peer_ip)
            .is_none());

        let global_limit = fallback_limits().max_pre_auth_fallbacks;
        let mut global_permits = (0..global_limit)
            .map(|idx| try_acquire_pre_auth_fallback_permit(test_public_ip(idx + 1)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            PRE_AUTH_FALLBACK_LIMITER.available_permits(),
            0,
            "global limiter should be exhausted"
        );
        assert!(
            try_acquire_pre_auth_fallback_permit(test_public_ip(global_limit + 1))
                .is_none()
        );

        drop(global_permits.pop());
        let replacement =
            try_acquire_pre_auth_fallback_permit(test_public_ip(global_limit + 2));
        assert!(replacement.is_some());

        drop(global_permits);
        drop(replacement);
        assert_pre_auth_fallback_state_clean();
    }

    #[test]
    fn pre_auth_fallback_is_used_for_all_pre_commit_failures() {
        assert!(should_try_pre_auth_fallback(
            FailureClass::NonTlsFirstRecord
        ));
        assert!(should_try_pre_auth_fallback(
            FailureClass::InvalidFirstRecord
        ));
        assert!(should_try_pre_auth_fallback(FailureClass::MissingSni));
        assert!(should_try_pre_auth_fallback(FailureClass::SniMismatch));
        assert!(should_try_pre_auth_fallback(FailureClass::AuthFailed));
        assert!(should_try_pre_auth_fallback(FailureClass::HandshakeTimeout));
        assert!(should_try_pre_auth_fallback(FailureClass::CapacityLimited));
    }

    #[test]
    fn sni_mismatch_is_pre_auth_fallback_eligible() {
        assert!(should_try_pre_auth_fallback(FailureClass::SniMismatch));
    }

    #[test]
    fn counter_validation_accepts_monotonic_increments_within_session() {
        let psk = b"counter-incr-test";
        let derived_psk = derive_psk(psk);
        let random = [3u8; 32];
        let session_id: u64 = 0x00AABBCCDDEE;
        let seq1: u64 = 5;
        let seq2: u64 = 6;

        let counter1 = (session_id << 24) | seq1;
        let mask1 = derive_counter_mask(&derived_psk, &random);
        let masked1 = xor_u64_bytes(counter1.to_be_bytes(), mask1);
        let check1 = check_counter_replay(&derived_psk, &random, masked1);
        assert!(check1.is_some());
        assert!(commit_counter_replay(&check1.unwrap()));

        let counter2 = (session_id << 24) | seq2;
        let mask2 = derive_counter_mask(&derived_psk, &random);
        let masked2 = xor_u64_bytes(counter2.to_be_bytes(), mask2);
        let check2 = check_counter_replay(&derived_psk, &random, masked2);
        assert!(check2.is_some());
        assert!(commit_counter_replay(&check2.unwrap()));
    }

    #[test]
    fn counter_validation_rejects_duplicate_sequence_in_same_session() {
        let psk = b"counter-dup-test";
        let derived_psk = derive_psk(psk);
        let random = [3u8; 32];
        let session_id: u64 = 0x00DEADBEEF01;

        let counter10 = (session_id << 24) | 10;
        let mask10 = derive_counter_mask(&derived_psk, &random);
        let masked10 = xor_u64_bytes(counter10.to_be_bytes(), mask10);
        let check10 = check_counter_replay(&derived_psk, &random, masked10);
        assert!(check10.is_some());
        assert!(commit_counter_replay(&check10.unwrap()));

        let check_dup = check_counter_replay(&derived_psk, &random, masked10);
        assert!(check_dup.is_none());
    }

    #[test]
    fn counter_validation_rejects_sequence_outside_sliding_window() {
        let psk = b"counter-window-test";
        let derived_psk = derive_psk(psk);
        let random = [3u8; 32];
        let session_id: u64 = 0x00CAFEF00D00;

        let counter100 = (session_id << 24) | 100;
        let mask100 = derive_counter_mask(&derived_psk, &random);
        let masked100 = xor_u64_bytes(counter100.to_be_bytes(), mask100);
        let check100 = check_counter_replay(&derived_psk, &random, masked100);
        assert!(check100.is_some());
        assert!(commit_counter_replay(&check100.unwrap()));

        let far_behind_seq = 100u64.saturating_sub(64);
        let counter_far = (session_id << 24) | far_behind_seq;
        let mask_far = derive_counter_mask(&derived_psk, &random);
        let masked_far = xor_u64_bytes(counter_far.to_be_bytes(), mask_far);
        assert!(check_counter_replay(&derived_psk, &random, masked_far).is_none());
    }

    #[test]
    fn counter_validation_accepts_new_session_after_restart() {
        let psk = b"counter-restart-test";
        let derived_psk = derive_psk(psk);
        let random_a = [7u8; 32];
        let random_b = [8u8; 32];
        let session_a: u64 = 0x001111111111;
        let session_b: u64 = 0x002222222222;

        let counter_a = (session_a << 24) | 999;
        let mask_a = derive_counter_mask(&derived_psk, &random_a);
        let masked_a = xor_u64_bytes(counter_a.to_be_bytes(), mask_a);
        let check_a = check_counter_replay(&derived_psk, &random_a, masked_a);
        assert!(check_a.is_some());
        assert!(commit_counter_replay(&check_a.unwrap()));

        let counter_b = (session_b << 24) | 1;
        let mask_b = derive_counter_mask(&derived_psk, &random_b);
        let masked_b = xor_u64_bytes(counter_b.to_be_bytes(), mask_b);
        let check_b = check_counter_replay(&derived_psk, &random_b, masked_b);
        assert!(check_b.is_some());
        assert!(commit_counter_replay(&check_b.unwrap()));
    }

    #[test]
    fn counter_validation_accepts_high_initial_sequence_for_new_session() {
        let psk = b"counter-initseq-test";
        let derived_psk = derive_psk(psk);
        let random = [5u8; 32];
        let session_id: u64 = 0x003333333333;
        let large_seq = 1001u64;

        let counter = (session_id << 24) | large_seq;
        let mask = derive_counter_mask(&derived_psk, &random);
        let masked = xor_u64_bytes(counter.to_be_bytes(), mask);
        let check = check_counter_replay(&derived_psk, &random, masked);
        assert!(check.is_some());
        assert!(commit_counter_replay(&check.unwrap()));
    }

    #[test]
    fn auth_succeeds_with_independent_key_share() {
        use crate::template::{get_or_build_client_hello_template, ConnectionCounter};

        let psk = b"independent-ks-auth-test";
        let derived_psk = derive_psk(psk);
        let cache_key = derive_counter_cache_key(&derived_psk);

        {
            let mut cache = COUNTER_CACHE.lock().unwrap();
            let _ = cache.pop(&cache_key);
        }

        let mut initiator = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut noise_init = [0u8; 48];
        initiator.write_message(&[], &mut noise_init).unwrap();

        let counter = ConnectionCounter::new();
        let counter_val = counter.next();
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let ch = template
            .instantiate(&derived_psk, &noise_init, counter_val)
            .unwrap();

        let (random_range, session_id_range) =
            client_hello_random_and_session_id_ranges(&ch).unwrap();
        let ks_range = client_hello_key_share_range(&ch).unwrap();
        let random = &ch[random_range.clone()];
        let session_id = &ch[session_id_range.clone()];
        let key_share_data = &ch[ks_range.clone()];

        assert!(!constant_time_eq(key_share_data, &noise_init[..32]));

        let mut random_copy = [0u8; 32];
        random_copy.copy_from_slice(random);
        let recovered_e = unmask_noise_ephemeral_key(&random_copy, &derived_psk, &session_id[..16]);
        assert_eq!(&recovered_e[..], &noise_init[..32]);

        let mut recovered_noise_init = [0u8; 48];
        recovered_noise_init[..32].copy_from_slice(&recovered_e);
        recovered_noise_init[32..48].copy_from_slice(&session_id[..16]);
        assert_eq!(responder.read_message(&recovered_noise_init, &mut []).unwrap(), 0);

        let mut masked_counter = [0u8; 8];
        masked_counter.copy_from_slice(&session_id[16..24]);
        let mut got_mac = [0u8; 8];
        got_mac.copy_from_slice(&session_id[24..32]);
        crate::utils::mask_mac_flags(&mut got_mac);
        let random_prefix: &[u8] = &random[..16];
        let want_mac =
            derive_counter_mac(&derived_psk, &random_copy, &masked_counter, random_prefix);
        let mut want_mac_masked = want_mac;
        crate::utils::mask_mac_flags(&mut want_mac_masked);
        assert_eq!(got_mac, want_mac_masked);
    }
}
