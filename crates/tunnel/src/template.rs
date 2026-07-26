use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use rand::{Rng, RngCore};
use tracing::warn;

use crate::fp;
use crate::templates;
use crate::utils::{
    client_hello_random_and_session_id_ranges, derive_counter_mac, derive_counter_mask,
    extract_client_hello_random_and_session_id, is_grease_value, mask_noise_ephemeral_key,
    xor_u64_bytes, GREASE_VALUES,
};

lazy_static! {
    static ref CLIENT_HELLO_TEMPLATES: Mutex<HashMap<String, Arc<ClientHelloTemplate>>> =
        Mutex::new(HashMap::new());
}

pub struct ConnectionCounter {
    counter: AtomicU64,
}

impl ConnectionCounter {
    pub fn new() -> Self {
        let random_64 = rand::random::<u64>();
        let session_id = random_64 & 0x0000_00FF_FFFF_FFFF;
        let initial = (session_id << 24) | 1;
        Self {
            counter: AtomicU64::new(initial),
        }
    }

    pub fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ConnectionCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ClientHelloTemplate {
    bytes: Vec<u8>,
    cipher_suites_range: Range<usize>,
    key_share_range: Range<usize>,
    auxiliary_key_share_ranges: Vec<Range<usize>>,
    extensions_len_range: Range<usize>,
}

#[derive(Debug, Clone)]
struct ClientHelloLayout {
    session_id_range: Range<usize>,
    cipher_suites_range: Range<usize>,
    key_share_range: Range<usize>,
    auxiliary_key_share_ranges: Vec<Range<usize>>,
    sni_range: Range<usize>,
    record_len_range: Range<usize>,
    handshake_len_range: Range<usize>,
    extensions_len_range: Range<usize>,
    sni_ext_len_range: Range<usize>,
    sni_list_len_range: Range<usize>,
    sni_name_len_range: Range<usize>,
}

impl ClientHelloTemplate {
    pub fn instantiate(
        &self,
        derived_psk: &[u8],
        psk_e: &[u8],
        counter: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if psk_e.len() != 48 {
            anyhow::bail!("unexpected Noise init template length: {}", psk_e.len());
        }

        let mut out = self.bytes.clone();
        {
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut out[self.key_share_range.clone()]);
            for range in &self.auxiliary_key_share_ranges {
                if range.end <= out.len() {
                    let share_data = &mut out[range.clone()];
                    if share_data.len() == 1216 {
                        // X25519MLKEM768 hybrid share (1184-byte ML-KEM.768
                        // encapsulation key + 32-byte X25519). Servers with
                        // ML-KEM support (OpenSSL 3.5+) validate the ek
                        // coefficient range on decode and alert
                        // illegal_parameter on random garbage, so the share
                        // must be structurally valid.
                        fill_mlkem768_hybrid_share(share_data);
                    } else if share_data.len() == 65 && share_data[0] == 0x04 {
                        // A 65-byte 0x04-prefixed share is an uncompressed SEC1
                        // P-256 point: emit a real public key so DPI point
                        // validation cannot tell the share apart from a genuine
                        // key_share. Fall back to random fill if ring key
                        // generation unexpectedly fails.
                        if !fill_p256_public_key(share_data) {
                            rng.fill_bytes(&mut share_data[1..]);
                        }
                    } else if !share_data.is_empty() && share_data[0] == 0x04 {
                        rng.fill_bytes(&mut share_data[1..]);
                    } else {
                        rng.fill_bytes(share_data);
                    }
                }
            }
        }
        let (random, session_id) = extract_client_hello_random_and_session_id(&mut out)
            .ok_or_else(|| anyhow::anyhow!("ClientHello template missing random/session_id"))?;
        session_id[..16].copy_from_slice(&psk_e[32..48]);
        let e_bytes: [u8; 32] = psk_e[..32].try_into().expect("psk_e length checked above");
        let masked_e = mask_noise_ephemeral_key(&e_bytes, derived_psk, &session_id[..16]);
        random.copy_from_slice(&masked_e);

        let counter_mask = derive_counter_mask(derived_psk, random);
        let masked_counter = xor_u64_bytes(counter.to_be_bytes(), counter_mask);
        let random_prefix: &[u8] = &random[..16];
        let mac = derive_counter_mac(derived_psk, random, &masked_counter, random_prefix);
        session_id[16..24].copy_from_slice(&masked_counter);
        session_id[24..32].copy_from_slice(&mac);
        session_id[31] &= !0x03;
        apply_client_hello_randomization(
            &mut out,
            &self.cipher_suites_range,
            &self.extensions_len_range,
        )?;
        Ok(out)
    }
}

/// Generate a real ephemeral P-256 public key into `share_data` (65-byte
/// uncompressed SEC1 point, 0x04 prefix — the exact shape ring emits).
/// Returns false on any failure so the caller can fall back to random fill.
/// Fill a 1216-byte X25519MLKEM768 hybrid key_share with structurally valid
/// material. Layout: 768 ML-KEM.768 coefficients packed two-per-three-bytes
/// as 12-bit values (1152 bytes), a 32-byte rho seed, then a 32-byte X25519
/// public key. Coefficients are sampled uniformly from [0, 3329) — the same
/// distribution as a genuine ML-KEM encapsulation key — so the share passes
/// server-side mod-q decode validation (OpenSSL 3.5+ alerts
/// illegal_parameter on out-of-range coefficients) while remaining
/// statistically indistinguishable from a real key.
fn fill_mlkem768_hybrid_share(share_data: &mut [u8]) {
    const MLKEM768_Q: u16 = 3329;
    debug_assert_eq!(share_data.len(), 1216);
    let mut rng = rand::thread_rng();
    for chunk in share_data[..1152].chunks_exact_mut(3) {
        let d0: u16 = rng.gen_range(0..MLKEM768_Q);
        let d1: u16 = rng.gen_range(0..MLKEM768_Q);
        chunk[0] = d0 as u8;
        chunk[1] = ((d0 >> 8) as u8) | (((d1 & 0x0F) as u8) << 4);
        chunk[2] = (d1 >> 4) as u8;
    }
    // rho seed + X25519 public key: opaque random bytes.
    rng.fill_bytes(&mut share_data[1152..]);
}

fn fill_p256_public_key(share_data: &mut [u8]) -> bool {
    let rng = ring::rand::SystemRandom::new();
    let Ok(private_key) =
        ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
    else {
        return false;
    };
    let Ok(public_key) = private_key.compute_public_key() else {
        return false;
    };
    let public_bytes = public_key.as_ref();
    if public_bytes.len() != share_data.len() {
        return false;
    }
    share_data.copy_from_slice(public_bytes);
    true
}

pub fn get_or_build_client_hello_template(
    sni: &str,
    fingerprint: Option<&str>,
    custom_template_bytes: Option<&[u8]>,
    insecure: bool,
) -> anyhow::Result<Arc<ClientHelloTemplate>> {
    validate_template_sni(sni)?;
    let key = format!(
        "{}:{}:{}",
        sni,
        fingerprint.unwrap_or("firefox").trim().to_ascii_lowercase(),
        insecure
    );

    match CLIENT_HELLO_TEMPLATES.lock() {
        Ok(cache) => {
            if let Some(template) = cache.get(&key) {
                return Ok(template.clone());
            }
        }
        Err(_) => {
            warn!("client hello template cache poisoned, rebuilding without cache lookup");
        }
    }

    let template = build_client_hello_template(sni, fingerprint, custom_template_bytes, insecure)?;
    match CLIENT_HELLO_TEMPLATES.lock() {
        Ok(mut cache) => {
            cache.insert(key, template.clone());
        }
        Err(_) => {
            warn!("client hello template cache poisoned, returning uncached template");
        }
    }
    Ok(template)
}

fn validate_template_sni(sni: &str) -> anyhow::Result<()> {
    if sni.ends_with('.') {
        anyhow::bail!("SNI must not have a trailing dot");
    }
    let host = sni;
    if host.is_empty() || host.len() > 253 {
        anyhow::bail!("invalid SNI hostname length");
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        anyhow::bail!("IP literals are not supported for camouflage SNI");
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("invalid SNI DNS label length");
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            anyhow::bail!("SNI DNS labels must not start or end with '-'");
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            anyhow::bail!("SNI hostname must be ASCII LDH form");
        }
    }
    Ok(())
}

fn build_client_hello_template(
    sni: &str,
    fingerprint: Option<&str>,
    custom_template_bytes: Option<&[u8]>,
    _insecure: bool,
) -> anyhow::Result<Arc<ClientHelloTemplate>> {
    fp::validate_fingerprint(fingerprint)?;

    let raw = custom_template_bytes
        .map(|b| b.to_vec())
        .unwrap_or_else(|| templates::FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec());
    let mut bytes = strip_client_hello_extensions(&raw)?;

    let mut layout = parse_client_hello_layout(&bytes)?;
    if std::str::from_utf8(&bytes[layout.sni_range.clone()]).ok() != Some(sni) {
        set_sni_in_place(&mut bytes, &layout, sni)?;
        // Re-parse after SNI patching so hardcoded templates keep authoritative
        // ranges even if extension layout shifts in ways the local patch logic
        // does not explicitly model.
        layout = parse_client_hello_layout(&bytes)?;
    }
    validate_padding_extension_zero(&bytes, &layout.extensions_len_range)?;

    let session_len = layout.session_id_range.end - layout.session_id_range.start;
    if session_len < 32 {
        anyhow::bail!(
            "ClientHello session_id length < 32, cannot inject Noise: {}",
            session_len
        );
    }
    if layout.key_share_range.end - layout.key_share_range.start != 32 {
        anyhow::bail!(
            "ClientHello key_share length must be 32 for X25519 injection: {}",
            layout.key_share_range.end - layout.key_share_range.start
        );
    }

    Ok(Arc::new(ClientHelloTemplate {
        bytes,
        cipher_suites_range: layout.cipher_suites_range,
        key_share_range: layout.key_share_range,
        auxiliary_key_share_ranges: layout.auxiliary_key_share_ranges,
        extensions_len_range: layout.extensions_len_range,
    }))
}

pub fn invalidate_client_hello_template_cache() {
    match CLIENT_HELLO_TEMPLATES.lock() {
        Ok(mut cache) => {
            let count = cache.len();
            cache.clear();
            tracing::info!(
                count,
                "invalidated ClientHello template cache for hot-reload"
            );
        }
        Err(_) => {
            tracing::warn!(
                "ClientHello template cache poisoned, unable to invalidate for hot-reload"
            );
        }
    }
}

/// Extensions removed from every ClientHello template at load time —
/// embedded and custom hex alike. ECH (0xFE0D encrypted_client_hello,
/// 0x014A), early_data (0x0119), use_srtp (0x001C) and 0x0022 are dropped:
/// they either break interoperability with ordinary TLS 1.3 endpoints or
/// carry no camouflage value for the probe/handshake.
const STRIPPED_EXTENSION_TYPES: [u16; 5] = [0xFE0D, 0x014A, 0x0119, 0x001C, 0x0022];

/// Return a copy of the ClientHello record with every extension in
/// [`STRIPPED_EXTENSION_TYPES`] removed and all three length fields (record,
/// handshake, extensions block) rewritten to stay self-consistent.
fn strip_client_hello_extensions(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    if bytes.len() < 9 || bytes[0] != 0x16 || bytes[5] != 0x01 {
        anyhow::bail!("template is not a TLS ClientHello record");
    }
    let mut cursor = 9 + 2 + 32; // handshake header + client_version + random
    if bytes.len() <= cursor {
        anyhow::bail!("truncated ClientHello before session_id");
    }
    let session_id_len = bytes[cursor] as usize;
    cursor += 1 + session_id_len;
    let cipher_suites_len = read_u16(bytes, cursor)? as usize;
    cursor += 2 + cipher_suites_len;
    if bytes.len() <= cursor {
        anyhow::bail!("truncated ClientHello before compression methods");
    }
    let compression_methods_len = bytes[cursor] as usize;
    cursor += 1 + compression_methods_len;
    let extensions_len_range = cursor..cursor + 2;
    let extensions_len = read_u16(bytes, cursor)? as usize;
    cursor += 2;
    let extensions_end = cursor + extensions_len;
    if extensions_end > bytes.len() {
        anyhow::bail!("truncated ClientHello extensions");
    }

    let mut removed = 0usize;
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..cursor]);
    let mut ecursor = cursor;
    while ecursor + 4 <= extensions_end {
        let ext_type = read_u16(bytes, ecursor)?;
        let ext_len = read_u16(bytes, ecursor + 2)? as usize;
        let ext_end = ecursor + 4 + ext_len;
        if ext_end > extensions_end {
            anyhow::bail!("truncated ClientHello extension {:#06x}", ext_type);
        }
        if STRIPPED_EXTENSION_TYPES.contains(&ext_type) {
            removed += 4 + ext_len;
        } else {
            out.extend_from_slice(&bytes[ecursor..ext_end]);
        }
        ecursor = ext_end;
    }
    if removed == 0 {
        return Ok(bytes.to_vec());
    }
    out.extend_from_slice(&bytes[extensions_end..]);

    let delta = -(removed as isize);
    let new_record_len = adjust_u16(read_u16(&out, 3)?, delta)?;
    let new_handshake_len = adjust_u24(read_u24(&out, 6)?, delta)?;
    write_u16(&mut out, 3..5, new_record_len)?;
    write_u24(&mut out, 6..9, new_handshake_len)?;
    write_u16(
        &mut out,
        extensions_len_range,
        (extensions_len - removed) as u16,
    )?;
    Ok(out)
}

fn validate_padding_extension_zero(
    bytes: &[u8],
    extensions_len_range: &Range<usize>,
) -> anyhow::Result<()> {
    const PADDING_EXTENSION_TYPE: u16 = 0x0015;
    if let Some(extension) = find_extension(bytes, extensions_len_range, PADDING_EXTENSION_TYPE)? {
        ensure_padding_extension_data_zero(bytes, &extension.data_range)?;
    }
    Ok(())
}

fn ensure_padding_extension_data_zero(
    bytes: &[u8],
    data_range: &Range<usize>,
) -> anyhow::Result<()> {
    if data_range.end > bytes.len() {
        anyhow::bail!("truncated TLS padding extension data");
    }
    if bytes[data_range.clone()].iter().any(|&b| b != 0) {
        anyhow::bail!(
            "invalid TLS padding extension: RFC 7685 requires padding extension_data to be all zero"
        );
    }
    Ok(())
}

fn apply_client_hello_randomization(
    bytes: &mut [u8],
    cipher_suites_range: &Range<usize>,
    extensions_len_range: &Range<usize>,
) -> anyhow::Result<()> {
    // Always rotate GREASE values per instantiation. GREASE rotation only
    // replaces the 2-byte value at each GREASE position, never lengths or
    // content. Real Firefox/NSS uses a single GREASE value for every GREASE
    // position within one ClientHello (extension types, cipher_suites,
    // supported_groups) and re-randomizes it per ClientHello; freezing it
    // enables cross-deployment clustering.
    let mut rng = rand::thread_rng();
    let grease_value = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
    rotate_grease_extensions(bytes, extensions_len_range, grease_value)?;
    rotate_grease_cipher_suites(bytes, cipher_suites_range, grease_value)?;
    rotate_grease_supported_groups(bytes, extensions_len_range, grease_value)?;

    Ok(())
}

fn rotate_grease_extensions(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
    grease_value: u16,
) -> anyhow::Result<()> {
    let mut cursor = extensions_len_range.end;
    let extensions_end = cursor + read_u16(bytes, extensions_len_range.start)? as usize;

    while cursor + 4 <= extensions_end {
        let ext_type = read_u16(bytes, cursor)?;
        let ext_len = read_u16(bytes, cursor + 2)? as usize;
        let ext_end = cursor + 4 + ext_len;
        if ext_end > extensions_end {
            anyhow::bail!("truncated extension during GREASE rotation");
        }
        if is_grease_value(ext_type) {
            bytes[cursor..cursor + 2].copy_from_slice(&grease_value.to_be_bytes());
        }
        cursor = ext_end;
    }
    Ok(())
}

fn rotate_grease_cipher_suites(
    bytes: &mut [u8],
    cipher_suites_range: &Range<usize>,
    grease_value: u16,
) -> anyhow::Result<()> {
    if cipher_suites_range.end > bytes.len() {
        anyhow::bail!("truncated cipher_suites during GREASE rotation");
    }
    let mut cursor = cipher_suites_range.start;
    while cursor + 2 <= cipher_suites_range.end {
        if is_grease_value(read_u16(bytes, cursor)?) {
            bytes[cursor..cursor + 2].copy_from_slice(&grease_value.to_be_bytes());
        }
        cursor += 2;
    }
    Ok(())
}

fn rotate_grease_supported_groups(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
    grease_value: u16,
) -> anyhow::Result<()> {
    const SUPPORTED_GROUPS_EXTENSION_TYPE: u16 = 0x000a;
    let Some(extension) = find_extension(bytes, extensions_len_range, SUPPORTED_GROUPS_EXTENSION_TYPE)? else {
        return Ok(());
    };
    let data_range = extension.data_range;
    if data_range.end > bytes.len() || data_range.end - data_range.start < 2 {
        anyhow::bail!("truncated supported_groups during GREASE rotation");
    }
    let groups_len = read_u16(bytes, data_range.start)? as usize;
    let groups_end = (data_range.start + 2 + groups_len).min(data_range.end);
    let mut cursor = data_range.start + 2;
    while cursor + 2 <= groups_end {
        if is_grease_value(read_u16(bytes, cursor)?) {
            bytes[cursor..cursor + 2].copy_from_slice(&grease_value.to_be_bytes());
        }
        cursor += 2;
    }
    Ok(())
}

struct ExtensionLocation {
    data_range: Range<usize>,
}

fn find_extension(
    bytes: &[u8],
    extensions_len_range: &Range<usize>,
    extension_type: u16,
) -> anyhow::Result<Option<ExtensionLocation>> {
    let mut cursor = extensions_len_range.end;
    let extensions_end = cursor + read_u16(bytes, extensions_len_range.start)? as usize;
    while cursor + 4 <= extensions_end {
        let ext_type = read_u16(bytes, cursor)?;
        let ext_len = read_u16(bytes, cursor + 2)? as usize;
        let ext_end = cursor + 4 + ext_len;
        if ext_end > extensions_end {
            anyhow::bail!("truncated ClientHello extension {:#06x}", ext_type);
        }
        if ext_type == extension_type {
            return Ok(Some(ExtensionLocation {
                data_range: cursor + 4..ext_end,
            }));
        }
        cursor = ext_end;
    }
    Ok(None)
}

#[cfg(test)]
fn adjust_handshake_lengths(
    bytes: &mut [u8],
    record_len_range: &Range<usize>,
    handshake_len_range: &Range<usize>,
    extensions_len_range: &Range<usize>,
    added_total: usize,
) -> anyhow::Result<()> {
    let delta = added_total as isize;
    let new_record_len = adjust_u16(read_u16(bytes, record_len_range.start)?, delta)?;
    if new_record_len as usize > crate::utils::MAX_TLS_RECORD_PAYLOAD_LEN {
        anyhow::bail!(
            "padded ClientHello record too large: {} > {}",
            new_record_len,
            crate::utils::MAX_TLS_RECORD_PAYLOAD_LEN
        );
    }
    let new_handshake_len = adjust_u24(read_u24(bytes, handshake_len_range.start)?, delta)?;
    let new_extensions_len = adjust_u16(read_u16(bytes, extensions_len_range.start)?, delta)?;

    write_u16(bytes, record_len_range.clone(), new_record_len)?;
    write_u24(bytes, handshake_len_range.clone(), new_handshake_len)?;
    write_u16(bytes, extensions_len_range.clone(), new_extensions_len)?;
    Ok(())
}

fn parse_client_hello_layout(bytes: &[u8]) -> anyhow::Result<ClientHelloLayout> {
    let (_, session_id_range) = client_hello_random_and_session_id_ranges(bytes)
        .ok_or_else(|| anyhow::anyhow!("failed to locate ClientHello random/session_id"))?;
    if bytes.len() < 9 || bytes[0] != 0x16 || bytes[5] != 0x01 {
        anyhow::bail!("template is not a TLS ClientHello record");
    }

    let mut cursor = session_id_range.end;
    let cipher_suites_len = read_u16(bytes, cursor)? as usize;
    let cipher_suites_range = cursor + 2..cursor + 2 + cipher_suites_len;
    cursor += 2 + cipher_suites_len;
    if bytes.len() <= cursor {
        anyhow::bail!("truncated ClientHello before compression methods");
    }

    let compression_methods_len = bytes[cursor] as usize;
    cursor += 1 + compression_methods_len;
    let extensions_len_range = cursor..cursor + 2;
    let extensions_len = read_u16(bytes, cursor)? as usize;
    cursor += 2;
    let extensions_end = cursor + extensions_len;
    if extensions_end > bytes.len() {
        anyhow::bail!("truncated ClientHello extensions");
    }

    let mut sni_range = None;
    let mut sni_ext_len_range = None;
    let mut sni_list_len_range = None;
    let mut sni_name_len_range = None;
    let mut key_share_range = None;
    let mut auxiliary_key_share_ranges = Vec::new();

    while cursor + 4 <= extensions_end {
        let ext_type = read_u16(bytes, cursor)?;
        let ext_len = read_u16(bytes, cursor + 2)? as usize;
        let ext_len_range = cursor + 2..cursor + 4;
        let ext_data = cursor + 4;
        let ext_end = ext_data + ext_len;
        if ext_end > extensions_end {
            anyhow::bail!("truncated ClientHello extension {:#06x}", ext_type);
        }

        match ext_type {
            0x0000 => {
                if ext_len < 5 {
                    anyhow::bail!("truncated server_name extension");
                }
                let list_len_range = ext_data..ext_data + 2;
                let name_len_range = ext_data + 3..ext_data + 5;
                let host_len = read_u16(bytes, ext_data + 3)? as usize;
                let host_start = ext_data + 5;
                let host_end = host_start + host_len;
                if host_end > ext_end {
                    anyhow::bail!("truncated server_name hostname");
                }
                sni_range = Some(host_start..host_end);
                sni_ext_len_range = Some(ext_len_range);
                sni_list_len_range = Some(list_len_range);
                sni_name_len_range = Some(name_len_range);
            }
            0x0033 => {
                if ext_len < 4 {
                    anyhow::bail!("truncated key_share extension");
                }
                let mut share_cursor = ext_data + 2;
                while share_cursor + 4 <= ext_end {
                    let group = read_u16(bytes, share_cursor)?;
                    let share_len = read_u16(bytes, share_cursor + 2)? as usize;
                    let share_start = share_cursor + 4;
                    let share_end = share_start + share_len;
                    if share_end > ext_end {
                        anyhow::bail!("truncated key_share entry");
                    }
                    if group == 0x001d {
                        key_share_range = Some(share_start..share_end);
                    } else {
                        auxiliary_key_share_ranges.push(share_start..share_end);
                    }
                    share_cursor = share_end;
                }
            }
            _ => {}
        }

        cursor = ext_end;
    }

    Ok(ClientHelloLayout {
        session_id_range,
        cipher_suites_range,
        key_share_range: key_share_range
            .ok_or_else(|| anyhow::anyhow!("failed to locate key_share extension"))?,
        auxiliary_key_share_ranges,
        sni_range: sni_range.ok_or_else(|| anyhow::anyhow!("failed to locate SNI extension"))?,
        record_len_range: 3..5,
        handshake_len_range: 6..9,
        extensions_len_range,
        sni_ext_len_range: sni_ext_len_range
            .ok_or_else(|| anyhow::anyhow!("failed to locate SNI extension length"))?,
        sni_list_len_range: sni_list_len_range
            .ok_or_else(|| anyhow::anyhow!("failed to locate SNI list length"))?,
        sni_name_len_range: sni_name_len_range
            .ok_or_else(|| anyhow::anyhow!("failed to locate SNI hostname length"))?,
    })
}

fn set_sni_in_place(
    bytes: &mut Vec<u8>,
    layout: &ClientHelloLayout,
    sni: &str,
) -> anyhow::Result<()> {
    let old_range = layout.sni_range.clone();
    let old_len = old_range.end - old_range.start;
    let new_bytes = sni.as_bytes();
    if new_bytes.len() > u16::MAX as usize {
        anyhow::bail!("SNI too long: {}", new_bytes.len());
    }

    bytes.splice(old_range.clone(), new_bytes.iter().copied());
    let delta = new_bytes.len() as isize - old_len as isize;

    let record_len = adjust_u16(read_u16(bytes, layout.record_len_range.start)?, delta)?;
    let handshake_len = adjust_u24(read_u24(bytes, layout.handshake_len_range.start)?, delta)?;
    let extensions_len = adjust_u16(read_u16(bytes, layout.extensions_len_range.start)?, delta)?;
    let sni_ext_len = adjust_u16(read_u16(bytes, layout.sni_ext_len_range.start)?, delta)?;
    let sni_list_len = adjust_u16(read_u16(bytes, layout.sni_list_len_range.start)?, delta)?;

    write_u16(bytes, layout.record_len_range.clone(), record_len)?;
    write_u24(bytes, layout.handshake_len_range.clone(), handshake_len)?;
    write_u16(bytes, layout.extensions_len_range.clone(), extensions_len)?;
    write_u16(bytes, layout.sni_ext_len_range.clone(), sni_ext_len)?;
    write_u16(bytes, layout.sni_list_len_range.clone(), sni_list_len)?;
    write_u16(
        bytes,
        layout.sni_name_len_range.clone(),
        new_bytes.len() as u16,
    )?;

    // The caller re-parses the layout from the patched bytes, so the layout's
    // ranges are deliberately not shifted here.
    Ok(())
}

fn adjust_u16(value: u16, delta: isize) -> anyhow::Result<u16> {
    let value = value as isize + delta;
    if !(0..=u16::MAX as isize).contains(&value) {
        anyhow::bail!("u16 length overflow after patch: {}", value);
    }
    Ok(value as u16)
}

fn adjust_u24(value: usize, delta: isize) -> anyhow::Result<usize> {
    let value = value as isize + delta;
    if !(0..=0x00ff_ffff).contains(&value) {
        anyhow::bail!("u24 length overflow after patch: {}", value);
    }
    Ok(value as usize)
}

fn read_u16(bytes: &[u8], start: usize) -> anyhow::Result<u16> {
    if start + 2 > bytes.len() {
        anyhow::bail!("truncated u16 at {}", start);
    }
    Ok(u16::from_be_bytes([bytes[start], bytes[start + 1]]))
}

fn read_u24(bytes: &[u8], start: usize) -> anyhow::Result<usize> {
    if start + 3 > bytes.len() {
        anyhow::bail!("truncated u24 at {}", start);
    }
    Ok(((bytes[start] as usize) << 16)
        | ((bytes[start + 1] as usize) << 8)
        | bytes[start + 2] as usize)
}

fn write_u16(bytes: &mut [u8], range: Range<usize>, value: u16) -> anyhow::Result<()> {
    if range.end - range.start != 2 || range.end > bytes.len() {
        anyhow::bail!("invalid u16 patch range {:?}", range);
    }
    bytes[range.start..range.end].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u24(bytes: &mut [u8], range: Range<usize>, value: usize) -> anyhow::Result<()> {
    if range.end - range.start != 3 || range.end > bytes.len() {
        anyhow::bail!("invalid u24 patch range {:?}", range);
    }
    bytes[range.start] = ((value >> 16) & 0xff) as u8;
    bytes[range.start + 1] = ((value >> 8) & 0xff) as u8;
    bytes[range.start + 2] = (value & 0xff) as u8;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common;
    use crate::templates::FIREFOX_BOOTSTRAP_CLIENT_HELLO;
    use crate::utils::{
        client_hello_key_share_range, client_hello_random_and_session_id_ranges, constant_time_eq,
        derive_counter_mac, derive_counter_mask, mask_mac_flags, stable_client_hello_fingerprint,
        unmask_noise_ephemeral_key,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn extension_types(bytes: &[u8]) -> Vec<u16> {
        let layout = parse_client_hello_layout(bytes).unwrap();
        let mut cursor = layout.extensions_len_range.end;
        let extensions_end =
            cursor + read_u16(bytes, layout.extensions_len_range.start).unwrap() as usize;
        let mut types = Vec::new();
        while cursor + 4 <= extensions_end {
            let ext_type = read_u16(bytes, cursor).unwrap();
            let ext_len = read_u16(bytes, cursor + 2).unwrap() as usize;
            types.push(ext_type);
            cursor += 4 + ext_len;
        }
        types
    }

    fn is_ja3_grease(value: u16) -> bool {
        (value & 0x0f0f) == 0x0a0a && ((value >> 8) as u8) == (value as u8)
    }

    fn ja3_extensions_field(bytes: &[u8]) -> String {
        extension_types(bytes)
            .into_iter()
            .filter(|ext_type| !is_ja3_grease(*ext_type))
            .map(|ext_type| ext_type.to_string())
            .collect::<Vec<_>>()
            .join("-")
    }

    fn format_extension_list(types: &[u16]) -> String {
        types
            .iter()
            .map(|ext_type| ext_type.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn format_distribution(distribution: &BTreeMap<usize, usize>) -> String {
        distribution
            .iter()
            .map(|(len, count)| format!("{}: {}", len, count))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn padding_extension(bytes: &[u8]) -> Option<(usize, Range<usize>)> {
        let layout = parse_client_hello_layout(bytes).unwrap();
        let mut cursor = layout.extensions_len_range.end;
        let extensions_end =
            cursor + read_u16(bytes, layout.extensions_len_range.start).unwrap() as usize;
        while cursor + 4 <= extensions_end {
            let ext_type = read_u16(bytes, cursor).unwrap();
            let ext_len = read_u16(bytes, cursor + 2).unwrap() as usize;
            let data_start = cursor + 4;
            let data_end = data_start + ext_len;
            if ext_type == 0x0015 {
                return Some((cursor, data_start..data_end));
            }
            cursor = data_end;
        }
        None
    }

    fn append_zero_padding_extension(bytes: &mut Vec<u8>, data_len: usize) {
        let layout = parse_client_hello_layout(bytes).unwrap();
        let added_total = 4 + data_len;
        bytes.extend_from_slice(&0x0015u16.to_be_bytes());
        bytes.extend_from_slice(&(data_len as u16).to_be_bytes());
        bytes.resize(bytes.len() + data_len, 0);
        adjust_handshake_lengths(
            bytes,
            &layout.record_len_range,
            &layout.handshake_len_range,
            &layout.extensions_len_range,
            added_total,
        )
        .unwrap();
    }

    /// Intentional file side effect: writes a human-readable distribution
    /// report to `target/outer-tls-standardity-regression.md` so the sampled
    /// statistics can be inspected outside test logs.
    #[test]
    fn outer_tls_standardity_regression_report() {
        const SAMPLES: usize = 100;
        const SNI: &str = "example.com";
        let derived_psk = [7u8; 32];
        let mut psk_e = [0u8; 48];
        for (idx, byte) in psk_e.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(3).wrapping_add(1);
        }

        let original = crate::templates::FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        let original_extensions = extension_types(&original);
        let original_has_padding = original_extensions.contains(&0x0015);
        let template =
            get_or_build_client_hello_template(SNI, Some("firefox"), None, true).unwrap();

        let mut instantiated_extension_lists = BTreeSet::new();
        let mut instantiated_ja3_extensions = BTreeSet::new();
        let mut firefox_record_lengths = BTreeMap::new();
        let mut firefox_padding_samples = 0usize;
        for sample in 0..SAMPLES {
            let client_hello = template
                .instantiate(&derived_psk, &psk_e, 1_700_000_000 + sample as u64)
                .unwrap();
            let extensions = extension_types(&client_hello);
            if extensions.contains(&0x0015) {
                firefox_padding_samples += 1;
            }
            instantiated_extension_lists.insert(format_extension_list(&extensions));
            instantiated_ja3_extensions.insert(ja3_extensions_field(&client_hello));
            *firefox_record_lengths
                .entry(client_hello.len())
                .or_insert(0) += 1;
        }

        let instantiated_extensions_stable = instantiated_extension_lists.len() == 1;
        let ja3_extensions_stable = instantiated_ja3_extensions.len() == 1;
        let no_unexpected_firefox_padding = original_has_padding || firefox_padding_samples == 0;
        let no_firefox_micro_jumps = firefox_record_lengths.len() == 1;

        let instantiated_extension_list = instantiated_extension_lists
            .iter()
            .next()
            .cloned()
            .unwrap_or_default();
        let ja3_extensions_field = instantiated_ja3_extensions
            .iter()
            .next()
            .cloned()
            .unwrap_or_default();

        let report = format!(
            "# kanotls outer TLS standardity regression\n\n\
             - Samples: {SAMPLES}\n\
             - SNI: `{SNI}`\n\n\
             ## firefox/custom capture\n\n\
             - Original template extension list: `{}`\n\
             - Instantiated extension list: `{}`\n\
             - Extension list stable across instantiation: `{}`\n\
             - Original template has padding(21): `{}`\n\
             - Instantiated padding(21) samples: `{}/{SAMPLES}`\n\
             - Padding status: `{}`\n\
             - ClientHello record length distribution: `{}`\n\
             - JA3 extensions field: `{}`\n\
             - JA3 extensions stable across runs: `{}`\n\n\
             ## Risk notes\n\n\
             - firefox/custom capture uses `PreserveCaptured`, so the captured extension order and record length remain invariant after Noise field injection.\n\
             - No firefox/custom micro-padding length ladder was observed; the record length distribution must stay single-valued to avoid base/base+5/base+6/base+7 learnable features.\n",
            format_extension_list(&original_extensions),
            instantiated_extension_list,
            instantiated_extensions_stable,
            original_has_padding,
            firefox_padding_samples,
            no_unexpected_firefox_padding,
            format_distribution(&firefox_record_lengths),
            ja3_extensions_field,
            ja3_extensions_stable,
        );

        let report_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/outer-tls-standardity-regression.md");
        std::fs::create_dir_all(report_path.parent().unwrap()).unwrap();
        std::fs::write(&report_path, report).unwrap();
        eprintln!("wrote {}", report_path.display());

        assert!(
            instantiated_extensions_stable,
            "firefox/custom extension list changed: {:?}",
            instantiated_extension_lists
        );
        assert!(
            no_unexpected_firefox_padding,
            "firefox/custom added padding(21) although original template had none"
        );
        assert!(
            no_firefox_micro_jumps,
            "firefox/custom record length jumped: {:?}",
            firefox_record_lengths
        );
        assert!(
            ja3_extensions_stable,
            "firefox/custom JA3 extensions changed: {:?}",
            instantiated_ja3_extensions
        );
    }

    fn template_from_bytes(bytes: Vec<u8>) -> ClientHelloTemplate {
        let layout = parse_client_hello_layout(&bytes).unwrap();
        validate_padding_extension_zero(&bytes, &layout.extensions_len_range).unwrap();
        ClientHelloTemplate {
            bytes,
            cipher_suites_range: layout.cipher_suites_range,
            key_share_range: layout.key_share_range,
            auxiliary_key_share_ranges: layout.auxiliary_key_share_ranges,
            extensions_len_range: layout.extensions_len_range,
        }
    }

    fn assert_template_round_trips_noise_auth(fingerprint: Option<&str>) {
        let psk = b"template-round-trip-psk";
        let derived_psk = common::derive_psk(psk);
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
        let init_len = initiator.write_message(&[], &mut noise_init).unwrap();
        assert_eq!(init_len, noise_init.len());

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&noise_init[..32]);

        let counter_val: u64 = 1_700_000_000;
        let template =
            get_or_build_client_hello_template("example.com", fingerprint, None, true).unwrap();
        let client_hello = template
            .instantiate(&derived_psk, &noise_init, counter_val)
            .unwrap();

        let (random_range, session_id_range) =
            client_hello_random_and_session_id_ranges(&client_hello).unwrap();
        let random = &client_hello[random_range.clone()];
        let session_id = &client_hello[session_id_range.clone()];
        assert_eq!(random.len(), 32);
        assert!(session_id.len() >= 32);

        let noise_tag = &session_id[..16];
        let mut random_arr = [0u8; 32];
        random_arr.copy_from_slice(random);

        let recovered_e = unmask_noise_ephemeral_key(&random_arr, &derived_psk, noise_tag);
        assert_eq!(&recovered_e[..], &noise_init[..32]);

        let key_share_range = client_hello_key_share_range(&client_hello).unwrap();
        assert!(!constant_time_eq(
            &client_hello[key_share_range],
            &recovered_e
        ));

        let mut recovered_noise_init = [0u8; 48];
        recovered_noise_init[..32].copy_from_slice(&recovered_e);
        recovered_noise_init[32..48].copy_from_slice(noise_tag);
        assert_eq!(
            responder
                .read_message(&recovered_noise_init, &mut [])
                .unwrap(),
            0
        );

        let mut masked_counter = [0u8; 8];
        masked_counter.copy_from_slice(&session_id[16..24]);
        let mut got_mac = [0u8; 8];
        got_mac.copy_from_slice(&session_id[24..32]);
        mask_mac_flags(&mut got_mac);
        let random_prefix: &[u8] = &random[..16];
        let want_mac = derive_counter_mac(&derived_psk, random, &masked_counter, random_prefix);
        let mut want_mac_masked = want_mac;
        mask_mac_flags(&mut want_mac_masked);
        assert_eq!(got_mac, want_mac_masked);

        let mask = derive_counter_mask(&derived_psk, random);
        let recovered_counter =
            u64::from_be_bytes(crate::utils::xor_u64_bytes(masked_counter, mask));
        assert_eq!(recovered_counter, counter_val);
    }

    #[test]
    fn template_instantiate_injects_noise_auth_fields() {
        let mut bytes = vec![0u8; 120];
        // instantiate locates random/session_id by parsing the record, so the
        // synthetic bytes must be a well-formed ClientHello (session_id_len 32).
        bytes[0] = 0x16;
        bytes[5] = 0x01;
        bytes[43] = 32;
        write_u16(&mut bytes, 3..5, 115).unwrap();
        write_u24(&mut bytes, 6..9, 111).unwrap();
        write_u16(&mut bytes, 112..114, 0).unwrap();
        let template = ClientHelloTemplate {
            bytes,
            cipher_suites_range: 76..78,
            key_share_range: 80..112,
            auxiliary_key_share_ranges: Vec::new(),
            extensions_len_range: 112..114,
        };
        let derived_psk = [7u8; 32];
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(secret);
        let base = curve25519_dalek::EdwardsPoint::mul_base(&scalar);
        let public = base.to_montgomery().to_bytes();
        let mut psk_e = [0u8; 48];
        psk_e[..32].copy_from_slice(&public);
        psk_e[32..].fill(9);

        let out = template.instantiate(&derived_psk, &psk_e, 123).unwrap();
        assert_eq!(&out[44..59], &[9u8; 15]);
        assert_eq!(out[59] & !1, 8, "session_id[15] lower 7 bits");
        assert_ne!(&out[11..43], &[0u8; 32]);
        assert_ne!(&out[80..112], &public);
        assert_ne!(&out[80..112], &[0u8; 32]);
        assert_ne!(&out[60..68], &[0u8; 8]);
        assert_ne!(&out[68..76], &[0u8; 8]);
        assert_eq!(out.len(), 120);
    }

    #[test]
    fn set_sni_updates_lengths_and_ranges() {
        let mut bytes = vec![0u8; 90];
        bytes[0] = 0x16;
        bytes[5] = 0x01;
        write_u16(&mut bytes, 3..5, 85).unwrap();
        write_u24(&mut bytes, 6..9, 81).unwrap();
        write_u16(&mut bytes, 20..22, 40).unwrap();
        write_u16(&mut bytes, 30..32, 10).unwrap();
        write_u16(&mut bytes, 34..36, 8).unwrap();
        write_u16(&mut bytes, 37..39, 3).unwrap();
        bytes[39..42].copy_from_slice(b"old");

        let layout = ClientHelloLayout {
            session_id_range: 44..76,
            cipher_suites_range: 76..78,
            key_share_range: 50..82,
            auxiliary_key_share_ranges: Vec::new(),
            sni_range: 39..42,
            record_len_range: 3..5,
            handshake_len_range: 6..9,
            extensions_len_range: 20..22,
            sni_ext_len_range: 30..32,
            sni_list_len_range: 34..36,
            sni_name_len_range: 37..39,
        };

        set_sni_in_place(&mut bytes, &layout, "example.com").unwrap();
        assert_eq!(&bytes[39..50], b"example.com");
        assert_eq!(read_u16(&bytes, 3).unwrap(), 93);
        assert_eq!(read_u24(&bytes, 6).unwrap(), 89);
        assert_eq!(read_u16(&bytes, 20).unwrap(), 48);
        assert_eq!(read_u16(&bytes, 30).unwrap(), 18);
        assert_eq!(read_u16(&bytes, 34).unwrap(), 16);
        assert_eq!(read_u16(&bytes, 37).unwrap(), 11);
    }

    #[test]
    fn firefox_template_round_trips_noise_auth() {
        assert_template_round_trips_noise_auth(Some("firefox"));
    }

    #[test]
    fn unsupported_fingerprint_is_rejected() {
        assert!(get_or_build_client_hello_template("example.com", Some("rustls"), None, true).is_err());
        assert!(get_or_build_client_hello_template("example.com", Some("python-openssl"), None, true).is_err());
        assert!(get_or_build_client_hello_template("example.com", Some("chrome"), None, true).is_err());
    }

    #[test]
    fn strip_removes_target_extensions_and_keeps_lengths_consistent() {
        let stripped = strip_client_hello_extensions(FIREFOX_BOOTSTRAP_CLIENT_HELLO).unwrap();
        assert!(stripped.len() < FIREFOX_BOOTSTRAP_CLIENT_HELLO.len());
        let types = extension_types(&stripped);
        for dropped in STRIPPED_EXTENSION_TYPES {
            assert!(
                !types.contains(&dropped),
                "extension {:#06x} must be stripped",
                dropped
            );
        }
        // Kept fingerprint essentials.
        for kept in [0x0000u16, 0x0033, 0x002B, 0x000D, 0x000A, 0x0010] {
            assert!(
                types.contains(&kept),
                "extension {:#06x} must be preserved",
                kept
            );
        }
        assert_eq!(read_u16(&stripped, 3).unwrap() as usize + 5, stripped.len());
        assert_eq!(read_u24(&stripped, 6).unwrap() + 9, stripped.len());
        // Layout must still parse: extensions block is self-consistent.
        parse_client_hello_layout(&stripped).unwrap();
        // Idempotent: stripping an already-clean template changes nothing.
        let twice = strip_client_hello_extensions(&stripped).unwrap();
        assert_eq!(stripped, twice);
    }

    #[test]
    fn mlkem768_hybrid_share_is_structurally_valid() {
        let mut share = [0u8; 1216];
        fill_mlkem768_hybrid_share(&mut share);
        // Every 12-bit coefficient must be < q = 3329 (mod-q decode check
        // performed by ML-KEM-capable servers).
        for chunk in share[..1152].chunks_exact(3) {
            let d0 = chunk[0] as u16 | (((chunk[1] & 0x0F) as u16) << 8);
            let d1 = ((chunk[1] >> 4) as u16) | ((chunk[2] as u16) << 4);
            assert!(d0 < 3329, "coefficient {} out of range", d0);
            assert!(d1 < 3329, "coefficient {} out of range", d1);
        }
        // rho + X25519 trailing bytes must not be all zero.
        assert!(share[1152..].iter().any(|&b| b != 0));
        // Two fills must differ (per-connection freshness).
        let mut other = [0u8; 1216];
        fill_mlkem768_hybrid_share(&mut other);
        assert_ne!(share, other);
    }

    #[test]
    fn build_template_strips_custom_bytes() {
        // A custom template (e.g. raw Firefox capture with ECH) must go
        // through the same stripping path as the embedded one.
        let template = get_or_build_client_hello_template(
            "custom-strip.example",
            Some("firefox"),
            Some(FIREFOX_BOOTSTRAP_CLIENT_HELLO),
            true,
        )
        .unwrap();
        let derived_psk = [7u8; 32];
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);
        let out = template
            .instantiate(&derived_psk, &noise_init, 1)
            .unwrap();
        let types = extension_types(&out);
        for dropped in STRIPPED_EXTENSION_TYPES {
            assert!(
                !types.contains(&dropped),
                "custom template extension {:#06x} must be stripped",
                dropped
            );
        }
    }

    #[test]
    fn firefox_template_uses_captured_bootstrap_shape() {
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"firefox-tail-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let out = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();
        let _layout = parse_client_hello_layout(&out).unwrap();

        let _captured_layout = parse_client_hello_layout(FIREFOX_BOOTSTRAP_CLIENT_HELLO).unwrap();

        let base_len = strip_client_hello_extensions(FIREFOX_BOOTSTRAP_CLIENT_HELLO)
            .unwrap()
            .len();
        assert_eq!(out.len(), base_len);
        assert_eq!(read_u16(&out, 3).unwrap() as usize + 5, out.len());
        assert_eq!(read_u24(&out, 6).unwrap() + 9, out.len());
    }

    #[test]
    fn firefox_template_instantiates_with_stable_extension_type_list() {
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"firefox-jitter-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);
        let baseline = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();
        let baseline_types = extension_types(&baseline);
        let base_len = strip_client_hello_extensions(FIREFOX_BOOTSTRAP_CLIENT_HELLO)
            .unwrap()
            .len();

        for _ in 0..100 {
            let out = template
                .instantiate(&derived_psk, &noise_init, 1_700_000_000)
                .unwrap();
            assert_eq!(out.len(), base_len);
            assert_eq!(read_u16(&out, 3).unwrap() as usize + 5, out.len());
            assert_eq!(read_u24(&out, 6).unwrap() + 9, out.len());
            parse_client_hello_layout(&out).unwrap();
            assert_eq!(extension_types(&out), baseline_types);
        }
    }

    #[test]
    fn firefox_template_without_captured_padding_does_not_add_padding() {
        assert!(!extension_types(FIREFOX_BOOTSTRAP_CLIENT_HELLO).contains(&0x0015));
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"firefox-no-padding-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let out = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();
        assert!(!extension_types(&out).contains(&0x0015));
    }

    #[test]
    fn captured_padding_is_preserved_in_place_and_zero_filled() {
        let mut bytes = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        append_zero_padding_extension(&mut bytes, 7);
        let captured_padding = padding_extension(&bytes).unwrap();
        let template = template_from_bytes(bytes);
        let derived_psk = common::derive_psk(b"firefox-preserve-padding-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let out = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();
        let instantiated_padding = padding_extension(&out).unwrap();
        assert_eq!(instantiated_padding.0, captured_padding.0);
        assert_eq!(instantiated_padding.1, captured_padding.1);
        assert!(out[instantiated_padding.1].iter().all(|&b| b == 0));
    }

    #[test]
    fn captured_non_zero_padding_is_rejected() {
        let mut bytes = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        append_zero_padding_extension(&mut bytes, 3);
        let (_, padding_data) = padding_extension(&bytes).unwrap();
        bytes[padding_data.start] = 1;
        let layout = parse_client_hello_layout(&bytes).unwrap();

        let err =
            validate_padding_extension_zero(&bytes, &layout.extensions_len_range).unwrap_err();
        assert!(err.to_string().contains("RFC 7685"));
    }

    #[test]
    fn key_share_and_random_use_independent_keys() {
        let derived_psk = common::derive_psk(b"independent-keys-test");
        let mut initiator = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut noise_init = [0u8; 48];
        initiator.write_message(&[], &mut noise_init).unwrap();

        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let ch1 = template.instantiate(&derived_psk, &noise_init, 1).unwrap();
        let ch2 = template.instantiate(&derived_psk, &noise_init, 2).unwrap();

        let (random_range1, _) = client_hello_random_and_session_id_ranges(&ch1).unwrap();
        let ks_range1 = client_hello_key_share_range(&ch1).unwrap();
        let (random_range2, _) = client_hello_random_and_session_id_ranges(&ch2).unwrap();
        let ks_range2 = client_hello_key_share_range(&ch2).unwrap();

        assert!(!constant_time_eq(
            &ch1[ks_range1.clone()],
            &ch1[random_range1.clone()]
        ));
        assert!(!constant_time_eq(
            &ch2[ks_range2.clone()],
            &ch2[random_range2.clone()]
        ));
        assert!(!constant_time_eq(
            &ch1[ks_range1.clone()],
            &noise_init[..32]
        ));
        assert!(!constant_time_eq(&ch2[ks_range2], &noise_init[..32]));
        assert!(!constant_time_eq(&ch1[ks_range1], &ch2[random_range2]));
    }

    #[test]
    fn session_id_has_no_absolute_time_correlation() {
        let derived_psk = common::derive_psk(b"no-time-correlation-test");
        let mut initiator = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut noise_init = [0u8; 48];
        initiator.write_message(&[], &mut noise_init).unwrap();

        // 第二个连接必须有独立的临时密钥（与线上一致）——复用同一个
        // noise_init 会使两侧的 counter_mask 相同，(200^m)-(100^m)==100
        // 以约 1/256 的概率成立，导致断言偶发失败。
        let mut initiator2 = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut noise_init2 = [0u8; 48];
        initiator2.write_message(&[], &mut noise_init2).unwrap();

        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let ch1 = template
            .instantiate(&derived_psk, &noise_init, 100)
            .unwrap();
        let ch2 = template
            .instantiate(&derived_psk, &noise_init2, 200)
            .unwrap();

        let (_, sid_range1) = client_hello_random_and_session_id_ranges(&ch1).unwrap();
        let (_, sid_range2) = client_hello_random_and_session_id_ranges(&ch2).unwrap();
        let sid1 = &ch1[sid_range1];
        let sid2 = &ch2[sid_range2];

        let mut val1 = [0u8; 8];
        let mut val2 = [0u8; 8];
        val1.copy_from_slice(&sid1[16..24]);
        val2.copy_from_slice(&sid2[16..24]);
        let v1 = u64::from_be_bytes(val1);
        let v2 = u64::from_be_bytes(val2);
        let diff = v2.abs_diff(v1);
        assert_ne!(
            diff, 100,
            "session_id leaked absolute counter difference directly"
        );
    }

    fn instantiated_grease_values(bytes: &[u8]) -> Vec<u16> {
        let layout = parse_client_hello_layout(bytes).unwrap();
        let mut values: Vec<u16> = extension_types(bytes)
            .into_iter()
            .filter(|ext_type| is_grease_value(*ext_type))
            .collect();

        let mut cursor = layout.cipher_suites_range.start;
        while cursor + 2 <= layout.cipher_suites_range.end {
            let value = read_u16(bytes, cursor).unwrap();
            if is_grease_value(value) {
                values.push(value);
            }
            cursor += 2;
        }

        if let Some(extension) = find_extension(bytes, &layout.extensions_len_range, 0x000a).unwrap()
        {
            let groups_len = read_u16(bytes, extension.data_range.start).unwrap() as usize;
            let groups_end = (extension.data_range.start + 2 + groups_len).min(extension.data_range.end);
            let mut cursor = extension.data_range.start + 2;
            while cursor + 2 <= groups_end {
                let value = read_u16(bytes, cursor).unwrap();
                if is_grease_value(value) {
                    values.push(value);
                }
                cursor += 2;
            }
        }

        values
    }

    #[test]
    fn instantiated_p256_auxiliary_key_share_is_a_valid_point() {
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"p256-aux-share-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let out = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();
        let layout = parse_client_hello_layout(&out).unwrap();
        let p256_share = layout
            .auxiliary_key_share_ranges
            .iter()
            .find(|range| range.end - range.start == 65)
            .expect("firefox template must carry a 65-byte P-256 auxiliary share");
        let share = &out[p256_share.clone()];
        assert_eq!(share[0], 0x04, "P-256 share must keep the SEC1 prefix");

        // A successful ECDH agreement against the extracted share proves the
        // bytes form a valid P-256 point (ring rejects invalid points).
        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                .unwrap();
        let peer_public =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, share);
        ring::agreement::agree_ephemeral(private_key, &peer_public, |_shared_secret| ())
            .expect("instantiated P-256 share must be a valid curve point");
    }

    #[test]
    fn grease_positions_rotate_to_single_per_connection_value() {
        let mut bytes = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        let layout = parse_client_hello_layout(&bytes).unwrap();

        // Inject one GREASE value per position class (same-length patches):
        // cipher_suites[0], supported_groups[0], and one extension type slot.
        bytes[layout.cipher_suites_range.start..layout.cipher_suites_range.start + 2]
            .copy_from_slice(&0x0A0Au16.to_be_bytes());
        let groups_extension = find_extension(&bytes, &layout.extensions_len_range, 0x000a)
            .unwrap()
            .expect("firefox template must carry supported_groups");
        let first_group_offset = groups_extension.data_range.start + 2;
        bytes[first_group_offset..first_group_offset + 2]
            .copy_from_slice(&0x1A1Au16.to_be_bytes());
        let ems_extension = find_extension(&bytes, &layout.extensions_len_range, 0x0017)
            .unwrap()
            .expect("firefox template must carry extended_master_secret");
        let ems_type_offset = ems_extension.data_range.start - 4;
        bytes[ems_type_offset..ems_type_offset + 2].copy_from_slice(&0x2A2Au16.to_be_bytes());

        let template = template_from_bytes(bytes);
        let derived_psk = common::derive_psk(b"grease-rotation-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let grease_value_of = |counter: u64| {
            let out = template
                .instantiate(&derived_psk, &noise_init, counter)
                .unwrap();
            let values = instantiated_grease_values(&out);
            assert_eq!(
                values.len(),
                3,
                "expected GREASE at all three injected positions, got {:?}",
                values
            );
            let first = values[0];
            assert!(
                GREASE_VALUES.contains(&first),
                "rotated GREASE value {:#06x} must stay a valid GREASE value",
                first
            );
            assert!(
                values.iter().all(|&value| value == first),
                "all GREASE positions must share one value per ClientHello: {:?}",
                values
            );
            first
        };

        let first = grease_value_of(1_700_000_000);
        let mut second = grease_value_of(1_700_000_001);
        if second == first {
            // 1/16 collision chance per draw; retry once before failing.
            second = grease_value_of(1_700_000_002);
        }
        assert_ne!(
            first, second,
            "GREASE value must be re-randomized across connections"
        );
    }

    #[test]
    fn stable_fingerprint_is_connection_invariant() {
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"fingerprint-stability-psk");
        let mut psk_e = [0u8; 48];
        for (idx, byte) in psk_e.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(7).wrapping_add(1);
        }

        let ch1 = template.instantiate(&derived_psk, &psk_e, 1).unwrap();
        let ch2 = template.instantiate(&derived_psk, &psk_e, 2).unwrap();
        assert_ne!(ch1, ch2, "两次实例化必须存在每连接随机字段");

        let fp1 = stable_client_hello_fingerprint(&ch1).expect("fingerprint first ClientHello");
        let fp2 = stable_client_hello_fingerprint(&ch2).expect("fingerprint second ClientHello");
        assert_eq!(
            fp1, fp2,
            "random/session_id/GREASE/key_share 归一化后指纹必须跨连接稳定"
        );
    }

    #[test]
    fn stable_fingerprint_distinguishes_sni() {
        let derived_psk = common::derive_psk(b"fingerprint-distinct-psk");
        let mut psk_e = [0u8; 48];
        psk_e[..32].fill(3);
        psk_e[32..48].fill(4);

        let template_a =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let template_b =
            get_or_build_client_hello_template("example.org", Some("firefox"), None, true).unwrap();
        let ch_a = template_a.instantiate(&derived_psk, &psk_e, 1).unwrap();
        let ch_b = template_b.instantiate(&derived_psk, &psk_e, 1).unwrap();

        let fp_a = stable_client_hello_fingerprint(&ch_a).expect("fingerprint example.com");
        let fp_b = stable_client_hello_fingerprint(&ch_b).expect("fingerprint example.org");
        assert_ne!(fp_a, fp_b, "不同 SNI 的模板指纹必须不同");
    }
}
