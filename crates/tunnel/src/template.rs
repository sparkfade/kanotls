use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use rand::{Rng, RngCore};
use tracing::warn;

use crate::fp;
use crate::fp::FingerprintPreset;
use crate::templates;
use crate::utils::{
    client_hello_random_and_session_id_ranges, derive_counter_mac, derive_counter_mask,
    derive_noise_e_mask, xor_32_bytes, xor_u64_bytes,
};

lazy_static! {
    static ref CLIENT_HELLO_TEMPLATES: Mutex<HashMap<String, Vec<Arc<ClientHelloTemplate>>>> =
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
    random_range: Range<usize>,
    session_id_range: Range<usize>,
    key_share_range: Range<usize>,
    auxiliary_key_share_ranges: Vec<Range<usize>>,
    record_len_range: Range<usize>,
    handshake_len_range: Range<usize>,
    extensions_len_range: Range<usize>,
    padding_strategy: ClientHelloPaddingStrategy,
    append_psk_key_exchange_modes: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientHelloPaddingStrategy {
    PreserveCaptured,
    Disabled,
}

#[derive(Debug, Clone)]
struct ClientHelloLayout {
    random_range: Range<usize>,
    session_id_range: Range<usize>,
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
                    if !share_data.is_empty() && share_data[0] == 0x04 {
                        rng.fill_bytes(&mut share_data[1..]);
                    } else {
                        rng.fill_bytes(share_data);
                    }
                }
            }
        }
        let random_start = self.random_range.start;
        let random_len = self.random_range.end - self.random_range.start;
        let session_start = self.session_id_range.start;
        let session_len = self.session_id_range.end - self.session_id_range.start;

        let (_, after_random_start) = out.split_at_mut(random_start);
        let (random, after_random) = after_random_start.split_at_mut(random_len);
        let session_offset = session_start - self.random_range.end;
        let (_, after_session_start) = after_random.split_at_mut(session_offset);
        let (session_id, _) = after_session_start.split_at_mut(session_len);
        session_id[..16].copy_from_slice(&psk_e[32..48]);
        let e_public = &psk_e[..32];
        let mut e_bytes = [0u8; 32];
        e_bytes.copy_from_slice(e_public);

        let e_mask = derive_noise_e_mask(derived_psk, &session_id[..16]);
        let masked_e = xor_32_bytes(e_public, &e_mask);
        random.copy_from_slice(&masked_e);

        let counter_mask = derive_counter_mask(derived_psk, random);
        let masked_counter = xor_u64_bytes(counter.to_be_bytes(), counter_mask);
        let random_prefix: &[u8] = &random[..16];
        let mac = derive_counter_mac(derived_psk, random, &masked_counter, random_prefix);
        session_id[16..24].copy_from_slice(&masked_counter);
        session_id[24..32].copy_from_slice(&mac);
        session_id[31] &= !0x03;
        apply_padding_strategy(
            &mut out,
            &self.record_len_range,
            &self.handshake_len_range,
            &self.extensions_len_range,
            self.append_psk_key_exchange_modes,
        )?;
        apply_client_hello_randomization(
            &mut out,
            &self.extensions_len_range,
            self.padding_strategy,
        )?;
        Ok(out)
    }
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
            if let Some(templates) = cache.get(&key) {
                return select_template(templates, &key)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("template pool is empty"));
            }
        }
        Err(_) => {
            warn!("client hello template cache poisoned, rebuilding without cache lookup");
        }
    }

    let templates =
        build_client_hello_template_pool(sni, fingerprint, custom_template_bytes, insecure)?;
    let template = select_template(&templates, &key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("template pool is empty"))?;
    match CLIENT_HELLO_TEMPLATES.lock() {
        Ok(mut cache) => {
            cache.insert(key, templates);
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

fn build_client_hello_template_pool(
    sni: &str,
    fingerprint: Option<&str>,
    custom_template_bytes: Option<&[u8]>,
    insecure: bool,
) -> anyhow::Result<Vec<Arc<ClientHelloTemplate>>> {
    let preset = fp::fingerprint_preset(fingerprint)?;

    let custom_bytes = custom_template_bytes.map(|b| b.to_vec());

    let mut bytes = match preset {
        FingerprintPreset::Firefox => {
            custom_bytes.unwrap_or_else(|| templates::FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec())
        }
        FingerprintPreset::PythonOpenSsl => custom_bytes
            .unwrap_or_else(|| templates::PYTHON_OPENSSL_BOOTSTRAP_CLIENT_HELLO.to_vec()),
        FingerprintPreset::Rustls => build_rustls_template_bytes(sni, fingerprint, insecure)?,
    };

    let mut layout = parse_client_hello_layout(&bytes)?;
    if std::str::from_utf8(&bytes[layout.sni_range.clone()]).ok() != Some(sni) {
        set_sni_in_place(&mut bytes, &mut layout, sni)?;
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

    let append_psk_key_exchange_modes = matches!(preset, FingerprintPreset::Rustls);
    let padding_strategy = padding_strategy_for_preset(preset);

    Ok(vec![Arc::new(ClientHelloTemplate {
        bytes,
        random_range: layout.random_range,
        session_id_range: layout.session_id_range,
        key_share_range: layout.key_share_range,
        auxiliary_key_share_ranges: layout.auxiliary_key_share_ranges,
        record_len_range: layout.record_len_range,
        handshake_len_range: layout.handshake_len_range,
        extensions_len_range: layout.extensions_len_range,
        padding_strategy,
        append_psk_key_exchange_modes,
    })])
}

fn padding_strategy_for_preset(preset: FingerprintPreset) -> ClientHelloPaddingStrategy {
    match preset {
        FingerprintPreset::Firefox | FingerprintPreset::PythonOpenSsl => {
            ClientHelloPaddingStrategy::PreserveCaptured
        }
        FingerprintPreset::Rustls => ClientHelloPaddingStrategy::Disabled,
    }
}

fn select_template<'a>(
    templates: &'a [Arc<ClientHelloTemplate>],
    _cache_key: &str,
) -> Option<&'a Arc<ClientHelloTemplate>> {
    templates.first()
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

fn apply_padding_strategy(
    bytes: &mut Vec<u8>,
    record_len_range: &Range<usize>,
    handshake_len_range: &Range<usize>,
    extensions_len_range: &Range<usize>,
    append_psk_key_exchange_modes: bool,
) -> anyhow::Result<()> {
    const PADDING_EXTENSION_TYPE: u16 = 0x0015;
    const PSK_KEY_EXCHANGE_MODES_EXTENSION: [u8; 6] = [0x00, 0x2D, 0x00, 0x02, 0x01, 0x00];

    let existing_padding_extension =
        find_extension(bytes, extensions_len_range, PADDING_EXTENSION_TYPE)?;
    if let Some(extension) = &existing_padding_extension {
        ensure_padding_extension_data_zero(bytes, &extension.data_range)?;
    }
    if append_psk_key_exchange_modes {
        bytes.extend_from_slice(&PSK_KEY_EXCHANGE_MODES_EXTENSION);
        adjust_handshake_lengths(
            bytes,
            record_len_range,
            handshake_len_range,
            extensions_len_range,
            6,
        )?;
    }

    Ok(())
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

const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

fn is_grease_value(ext_type: u16) -> bool {
    GREASE_VALUES.contains(&ext_type)
}

fn apply_client_hello_randomization(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
    _padding_strategy: ClientHelloPaddingStrategy,
) -> anyhow::Result<()> {
    // Always rotate GREASE extension type values per instantiation, even for
    // PreserveCaptured (Firefox) preset. GREASE rotation only replaces the
    // 2-byte extension type, not the extension length or content, so it is
    // safe regardless of padding strategy. Real Firefox randomizes GREASE
    // values per ClientHello; freezing them enables cross-deployment clustering.
    rotate_grease_extensions(bytes, extensions_len_range)?;

    Ok(())
}

fn rotate_grease_extensions(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
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
            let mut rng = rand::thread_rng();
            let new_grease = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
            bytes[cursor..cursor + 2].copy_from_slice(&new_grease.to_be_bytes());
        }
        cursor = ext_end;
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

fn adjust_handshake_lengths(
    bytes: &mut [u8],
    record_len_range: &Range<usize>,
    handshake_len_range: &Range<usize>,
    extensions_len_range: &Range<usize>,
    added_total: usize,
) -> anyhow::Result<()> {
    const MAX_TLS_RECORD_PAYLOAD_LEN: usize = 16384 + 256;

    let delta = added_total as isize;
    let new_record_len = adjust_u16(read_u16(bytes, record_len_range.start)?, delta)?;
    if new_record_len as usize > MAX_TLS_RECORD_PAYLOAD_LEN {
        anyhow::bail!(
            "padded ClientHello record too large: {} > {}",
            new_record_len,
            MAX_TLS_RECORD_PAYLOAD_LEN
        );
    }
    let new_handshake_len = adjust_u24(read_u24(bytes, handshake_len_range.start)?, delta)?;
    let new_extensions_len = adjust_u16(read_u16(bytes, extensions_len_range.start)?, delta)?;

    write_u16(bytes, record_len_range.clone(), new_record_len)?;
    write_u24(bytes, handshake_len_range.clone(), new_handshake_len)?;
    write_u16(bytes, extensions_len_range.clone(), new_extensions_len)?;
    Ok(())
}

fn build_rustls_template_bytes(
    sni: &str,
    fingerprint: Option<&str>,
    insecure: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut config = if insecure {
        fp::make_dangerous_client_config(fingerprint)?
    } else {
        fp::make_verified_client_config(fingerprint)?
    };
    config.alpn_protocols = fp::alpn_protocols_for_fingerprint(fingerprint)?;

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| anyhow::anyhow!("invalid sni {}: {:?}", sni, e))?;
    let mut tlsconn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let mut bytes = Vec::new();
    let mut writer = std::io::Cursor::new(&mut bytes);
    tlsconn.write_tls(&mut writer)?;
    Ok(bytes)
}

fn parse_client_hello_layout(bytes: &[u8]) -> anyhow::Result<ClientHelloLayout> {
    let (random_range, session_id_range) = client_hello_random_and_session_id_ranges(bytes)
        .ok_or_else(|| anyhow::anyhow!("failed to locate ClientHello random/session_id"))?;
    if bytes.len() < 9 || bytes[0] != 0x16 || bytes[5] != 0x01 {
        anyhow::bail!("template is not a TLS ClientHello record");
    }

    let mut cursor = session_id_range.end;
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
        random_range,
        session_id_range,
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
    layout: &mut ClientHelloLayout,
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

    layout.sni_range.end = layout.sni_range.start + new_bytes.len();
    shift_layout_after(layout, old_range.end, delta);
    Ok(())
}

fn shift_layout_after(layout: &mut ClientHelloLayout, pivot: usize, delta: isize) {
    shift_range_after(&mut layout.key_share_range, pivot, delta);
    shift_range_after(&mut layout.sni_range, pivot, delta);
    for range in &mut layout.auxiliary_key_share_ranges {
        shift_range_after(range, pivot, delta);
    }
}

fn shift_range_after(range: &mut Range<usize>, pivot: usize, delta: isize) {
    if delta == 0 {
        return;
    }
    if range.start >= pivot {
        range.start = shift_index(range.start, delta);
        range.end = shift_index(range.end, delta);
    }
}

fn shift_index(index: usize, delta: isize) -> usize {
    if delta >= 0 {
        index + delta as usize
    } else {
        index - (-delta) as usize
    }
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
        derive_counter_mac, derive_counter_mask, mask_mac_flags, unmask_noise_ephemeral_key,
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

        let mut rustls_record_lengths = BTreeMap::new();
        let mut rustls_padding_samples = 0usize;
        let mut rustls_ja3_extensions = BTreeSet::new();
        for sample in 0..SAMPLES {
            let rustls_template =
                get_or_build_client_hello_template(SNI, Some("rustls"), None, true).unwrap();
            let client_hello = rustls_template
                .instantiate(&derived_psk, &psk_e, 1_700_000_000 + sample as u64)
                .unwrap();
            if extension_types(&client_hello).contains(&0x0015) {
                rustls_padding_samples += 1;
            }
            rustls_ja3_extensions.insert(ja3_extensions_field(&client_hello));
            *rustls_record_lengths.entry(client_hello.len()).or_insert(0) += 1;
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
             ## rustls/baseline synthetic padding\n\n\
             - Padding(21) samples: `{}/{SAMPLES}`\n\
             - ClientHello record length distribution: `{}`\n\
             - Distinct JA3 extensions fields: `{}`\n\n\
             ## Risk notes\n\n\
             - firefox/custom capture uses `PreserveCaptured`, so the captured extension order and record length remain invariant after Noise field injection.\n\
             - No firefox/custom micro-padding length ladder was observed; the record length distribution must stay single-valued to avoid base/base+5/base+6/base+7 learnable features.\n\
             - rustls/baseline synthetic padding is intentionally isolated to the rustls preset and must not affect firefox/custom capture.\n",
            format_extension_list(&original_extensions),
            instantiated_extension_list,
            instantiated_extensions_stable,
            original_has_padding,
            firefox_padding_samples,
            no_unexpected_firefox_padding,
            format_distribution(&firefox_record_lengths),
            ja3_extensions_field,
            ja3_extensions_stable,
            rustls_padding_samples,
            format_distribution(&rustls_record_lengths),
            rustls_ja3_extensions.len(),
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
        assert!(
            !rustls_record_lengths.is_empty(),
            "rustls/baseline statistics were not collected"
        );
    }

    fn template_from_bytes(
        bytes: Vec<u8>,
        padding_strategy: ClientHelloPaddingStrategy,
    ) -> ClientHelloTemplate {
        let layout = parse_client_hello_layout(&bytes).unwrap();
        validate_padding_extension_zero(&bytes, &layout.extensions_len_range).unwrap();
        ClientHelloTemplate {
            bytes,
            random_range: layout.random_range,
            session_id_range: layout.session_id_range,
            key_share_range: layout.key_share_range,
            auxiliary_key_share_ranges: layout.auxiliary_key_share_ranges,
            record_len_range: layout.record_len_range,
            handshake_len_range: layout.handshake_len_range,
            extensions_len_range: layout.extensions_len_range,
            padding_strategy,
            append_psk_key_exchange_modes: false,
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
        write_u16(&mut bytes, 3..5, 115).unwrap();
        write_u24(&mut bytes, 6..9, 111).unwrap();
        write_u16(&mut bytes, 112..114, 0).unwrap();
        let template = ClientHelloTemplate {
            bytes,
            random_range: 11..43,
            session_id_range: 44..76,
            key_share_range: 80..112,
            auxiliary_key_share_ranges: Vec::new(),
            record_len_range: 3..5,
            handshake_len_range: 6..9,
            extensions_len_range: 112..114,
            padding_strategy: ClientHelloPaddingStrategy::Disabled,
            append_psk_key_exchange_modes: true,
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
        assert_eq!(out.len(), 126);
        assert_eq!(&out[120..126], &[0x00, 0x2D, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn select_template_returns_first_member() {
        let first_template = Arc::new(ClientHelloTemplate {
            bytes: vec![],
            random_range: 0..0,
            session_id_range: 0..0,
            key_share_range: 0..0,
            auxiliary_key_share_ranges: Vec::new(),
            record_len_range: 0..0,
            handshake_len_range: 0..0,
            extensions_len_range: 0..0,
            padding_strategy: ClientHelloPaddingStrategy::Disabled,
            append_psk_key_exchange_modes: true,
        });
        let second_template = Arc::new(ClientHelloTemplate {
            bytes: vec![1],
            random_range: 0..0,
            session_id_range: 0..0,
            key_share_range: 0..0,
            auxiliary_key_share_ranges: Vec::new(),
            record_len_range: 0..0,
            handshake_len_range: 0..0,
            extensions_len_range: 0..0,
            padding_strategy: ClientHelloPaddingStrategy::Disabled,
            append_psk_key_exchange_modes: true,
        });
        let pool = vec![first_template.clone(), second_template.clone()];

        let selected = select_template(&pool, "example:rustls:false").unwrap();
        assert!(Arc::ptr_eq(selected, &first_template));
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

        let mut layout = ClientHelloLayout {
            random_range: 11..43,
            session_id_range: 44..76,
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

        set_sni_in_place(&mut bytes, &mut layout, "example.com").unwrap();
        assert_eq!(&bytes[layout.sni_range.clone()], b"example.com");
        assert_eq!(read_u16(&bytes, 3).unwrap(), 93);
        assert_eq!(read_u24(&bytes, 6).unwrap(), 89);
        assert_eq!(read_u16(&bytes, 20).unwrap(), 48);
        assert_eq!(read_u16(&bytes, 30).unwrap(), 18);
        assert_eq!(read_u16(&bytes, 34).unwrap(), 16);
        assert_eq!(read_u16(&bytes, 37).unwrap(), 11);
        assert_eq!(layout.key_share_range, 58..90);
    }

    #[test]
    fn rustls_style_template_round_trips_noise_auth() {
        assert_template_round_trips_noise_auth(Some("rustls"));
    }

    #[test]
    fn firefox_template_round_trips_noise_auth() {
        assert_template_round_trips_noise_auth(Some("firefox"));
    }

    #[test]
    fn python_openssl_template_round_trips_noise_auth() {
        assert_template_round_trips_noise_auth(Some("python-openssl"));
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

        let base_len = FIREFOX_BOOTSTRAP_CLIENT_HELLO.len();
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
        let base_len = FIREFOX_BOOTSTRAP_CLIENT_HELLO.len();

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
        let template = template_from_bytes(bytes, ClientHelloPaddingStrategy::PreserveCaptured);
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
    fn python_openssl_template_preserves_captured_record_length() {
        let template = get_or_build_client_hello_template(
            "www.bilibili.com",
            Some("python-openssl"),
            None,
            true,
        )
        .unwrap();
        let derived_psk = common::derive_psk(b"python-openssl-jitter-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);
        let base_len = crate::templates::PYTHON_OPENSSL_BOOTSTRAP_CLIENT_HELLO.len();

        for _ in 0..64 {
            let out = template
                .instantiate(&derived_psk, &noise_init, 1_700_000_000)
                .unwrap();
            assert_eq!(out.len(), base_len);
            assert_eq!(read_u16(&out, 3).unwrap() as usize, out.len() - 5);
            assert_eq!(read_u24(&out, 6).unwrap(), out.len() - 9);
            parse_client_hello_layout(&out).unwrap();
        }
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

        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let ch1 = template
            .instantiate(&derived_psk, &noise_init, 100)
            .unwrap();
        let ch2 = template
            .instantiate(&derived_psk, &noise_init, 200)
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
}
