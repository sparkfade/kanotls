use lazy_static::lazy_static;
use lru::LruCache;
use rand::Rng;
use std::collections::HashSet;
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
pub(super) const MIN_CAMOUFLAGE_APP_DATA_RECORD_LEN: usize = 23;
pub(super) const MAX_CAMOUFLAGE_APP_DATA_RECORD_LEN: usize = 16401;

pub(super) const CAMOUFLAGE_REFRESH_DAEMON_MIN_SECS: u64 = 300;
pub(super) const CAMOUFLAGE_REFRESH_DAEMON_MAX_SECS: u64 = 3000;

pub(super) const TLS12_DOWNGRADE_SENTINEL: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
pub(super) const TLS11_DOWNGRADE_SENTINEL: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

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

#[derive(Clone, Debug)]
pub(super) struct CamouflageProfile {
    pub(super) server_records: Arc<[u8]>,
    pub(super) prefix_app_data_sizes: Vec<usize>,
    pub(super) app_data_sizes: Arc<[usize]>,
    pub(super) first_app_data_size: Option<usize>,
    pub(super) early_app_data_count: u8,
    pub(super) has_ccs: bool,
    pub(super) visible_server_record_count: u16,
    pub(super) first_app_data_delay_ms: u16,
    pub(super) early_app_data_gap_ms: Vec<u16>,
}

#[derive(Clone, Debug)]
pub(super) struct CamouflageProfilePool {
    pub(super) profiles: Vec<CamouflageProfile>,
}

pub(super) fn make_control_payload(ghost_count: u16) -> [u8; HANDSHAKE_CONTROL_LEN] {
    let mut payload = [0u8; HANDSHAKE_CONTROL_LEN];
    payload[..4].copy_from_slice(HANDSHAKE_CONTROL_MAGIC);
    payload[4..6].copy_from_slice(&ghost_count.to_be_bytes());
    payload
}

pub(super) fn fallback_noise_response_record_len(_sampled_sizes: &[usize]) -> usize {
    300
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
        .early_app_data_gap_ms
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
            cached_profile.early_app_data_gap_ms = sampled_profile.early_app_data_gap_ms;
        }
        cached_profile.first_app_data_delay_ms = sampled_profile.first_app_data_delay_ms;
    }
    sanitize_camouflage_profile(cached_profile)
}

pub(super) fn camouflage_profile_rank(profile: &CamouflageProfile) -> u8 {
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

pub(super) fn sample_camouflage_profile(pool: &CamouflageProfilePool) -> Option<CamouflageProfile> {
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

pub(super) fn push_profile_variant(
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

pub(super) async fn fetch_camouflage_flight(
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

pub(super) async fn has_complete_camouflage_cache(
    host: &str,
    port: u16,
    client_hello: &[u8],
) -> bool {
    if let Some(profile) = lookup_cached_camouflage_profile(host, port, client_hello).await {
        is_complete_camouflage_profile(&profile)
    } else {
        false
    }
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

    let pool = crate::entropy::entropy_pool();
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

pub(super) fn jitter_iat_ms(base_ms: u16) -> u64 {
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

pub(super) fn build_noise_response_sequence(
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

    sequence.extend_from_slice(&[0x17, 0x03, 0x03]);
    sequence.extend_from_slice(&(reply_len as u16).to_be_bytes());
    sequence.extend_from_slice(&noise_payload[..reply_len]);

    let pool_len = pool.len();
    const GHOST_TICKET_HEADER: [u8; 16] = [
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
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

pub(super) async fn get_cached_camouflage_profile_pool(key: &str) -> Option<CamouflageProfilePool> {
    let mut profiles = CAMOUFLAGE_PROFILES.lock().await;
    profiles.get(key).cloned()
}

pub(super) async fn get_cached_camouflage_profile_entry(key: &str) -> Option<CamouflageProfile> {
    get_cached_camouflage_profile_pool(key)
        .await
        .as_ref()
        .and_then(sample_camouflage_profile)
}

pub(super) async fn lookup_cached_camouflage_profile(
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
