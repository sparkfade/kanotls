use blake2::Digest;
use subtle::ConstantTimeEq as _;

const CLIENT_HELLO_FP_CONTEXT: &[u8] = b"kanotls-client-hello-fp-v1";
const NOISE_E_MASK_CONTEXT: &[u8] = b"kanotls-noise-e-mask-v1";
const COUNTER_MASK_CONTEXT: &[u8] = b"kanotls-counter-mask-v1";
const COUNTER_MAC_CONTEXT: &[u8] = b"kanotls-counter-mac-v1";
const COUNTER_CACHE_KEY_CONTEXT: &[u8] = b"kanotls-counter-cache-key-v1";

pub fn hash_with_key(context: &[u8], key: &[u8]) -> [u8; 32] {
    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    blake2::digest::Update::update(&mut hasher, context);
    blake2::digest::Update::update(&mut hasher, key);
    let result: [u8; 32] = blake2::digest::FixedOutput::finalize_fixed(hasher).into();
    result
}

pub fn derive_noise_e_mask(derived_psk: &[u8], noise_tag: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 48];
    let len = noise_tag.len() + derived_psk.len();
    buf[..noise_tag.len()].copy_from_slice(noise_tag);
    buf[noise_tag.len()..len].copy_from_slice(derived_psk);
    hash_with_key(NOISE_E_MASK_CONTEXT, &buf[..len])
}

pub fn derive_counter_mask(derived_psk: &[u8], client_random: &[u8]) -> [u8; 8] {
    let mut buf = [0u8; 64];
    let len = client_random.len() + derived_psk.len();
    buf[..client_random.len()].copy_from_slice(client_random);
    buf[client_random.len()..len].copy_from_slice(derived_psk);
    let digest = hash_with_key(COUNTER_MASK_CONTEXT, &buf[..len]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn derive_counter_mac(
    derived_psk: &[u8],
    client_random: &[u8],
    counter_bytes: &[u8; 8],
    random_prefix: &[u8],
) -> [u8; 8] {
    let mut buf = [0u8; 104];
    let mut pos = 0;
    buf[pos..pos + client_random.len()].copy_from_slice(client_random);
    pos += client_random.len();
    buf[pos..pos + 8].copy_from_slice(counter_bytes);
    pos += 8;
    buf[pos..pos + random_prefix.len()].copy_from_slice(random_prefix);
    pos += random_prefix.len();
    buf[pos..pos + derived_psk.len()].copy_from_slice(derived_psk);
    pos += derived_psk.len();
    let digest = hash_with_key(COUNTER_MAC_CONTEXT, &buf[..pos]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn derive_counter_cache_key(derived_psk: &[u8]) -> [u8; 16] {
    let digest = hash_with_key(COUNTER_CACHE_KEY_CONTEXT, derived_psk);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn xor_32_bytes(a: &[u8], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn xor_in_place(data: &mut [u8], mask: &[u8; 32]) {
    for i in 0..32 {
        data[i] ^= mask[i];
    }
}

pub(crate) fn xor_u64_bytes(a: [u8; 8], b: [u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn mask_mac_flags(mac: &mut [u8]) {
    mac[7] &= !0x03;
}

pub fn hex_encode_fingerprint<'a>(fingerprint: &[u8], buf: &'a mut [u8]) -> &'a str {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let len = fingerprint.len();
    debug_assert!(buf.len() >= len * 2);
    for i in 0..len {
        let b = fingerprint[i];
        buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS[(b & 0x0f) as usize];
    }
    std::str::from_utf8(&buf[..len * 2]).unwrap()
}

pub fn stable_client_hello_fingerprint(record: &[u8]) -> Option<[u8; 32]> {
    let mut normalized = record.to_vec();
    let (random, session_id) = extract_client_hello_random_and_session_id(&mut normalized)?;
    random.fill(0);
    session_id.fill(0);
    normalize_client_hello_key_shares(&mut normalized)?;
    normalize_client_hello_grease_positions(&mut normalized)?;
    normalize_client_hello_padding_extension(&mut normalized)?;
    Some(hash_with_key(CLIENT_HELLO_FP_CONTEXT, &normalized))
}

/// RFC 8701 GREASE 值表：pattern 0x?A?A 且高低字节相同，共 16 个。
/// template.rs 实例化时按连接轮换这些值，指纹归一化需将其全部置零。
pub(crate) const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub(crate) fn is_grease_value(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

/// 将 key_share(0x0033) 扩展中所有 share 条目的 key 字节全部置零（不动任何
/// 长度字段）。实例化每连接随机化 X25519 与辅助 P-256 share，只置零单个
/// share 会使每条连接指纹唯一。share 结构截断时返回 None。
fn normalize_client_hello_key_shares(record: &mut [u8]) -> Option<()> {
    let mut share_ranges = Vec::new();
    let mut malformed = false;
    walk_client_hello_extensions(record, |ext_type, entry| {
        if ext_type != 0x0033 || malformed {
            return;
        }
        let ext_data = entry.start + 4;
        let ext_end = entry.end;
        if ext_end - ext_data < 2 {
            malformed = true;
            return;
        }
        let mut share_cursor = ext_data + 2;
        while share_cursor + 4 <= ext_end {
            let share_len =
                u16::from_be_bytes([record[share_cursor + 2], record[share_cursor + 3]]) as usize;
            let share_start = share_cursor + 4;
            let Some(share_end) = share_start.checked_add(share_len) else {
                malformed = true;
                return;
            };
            if share_end > ext_end {
                malformed = true;
                return;
            }
            share_ranges.push(share_start..share_end);
            share_cursor = share_end;
        }
    })?;
    if malformed {
        return None;
    }
    for range in share_ranges {
        record[range].fill(0);
    }
    Some(())
}

/// 将所有 GREASE 出现位置置零：cipher_suites 列表中的 2 字节值、每个扩展的
/// 2 字节 ext_type 字段（GREASE 扩展 len 通常为 0，置零 type 不影响遍历）、
/// supported_groups(0x000a) 扩展 data 内的 group 列表。长度字段一律不动。
fn normalize_client_hello_grease_positions(record: &mut [u8]) -> Option<()> {
    const SUPPORTED_GROUPS_EXTENSION_TYPE: u16 = 0x000a;

    let (_, session_id_range) = client_hello_random_and_session_id_ranges(record)?;
    let cipher_suites_len_start = session_id_range.end;
    let cipher_suites_len = u16::from_be_bytes([
        *record.get(cipher_suites_len_start)?,
        *record.get(cipher_suites_len_start + 1)?,
    ]) as usize;
    let suites_start = cipher_suites_len_start.checked_add(2)?;
    let suites_end = suites_start.checked_add(cipher_suites_len)?;
    if suites_end > record.len() {
        return None;
    }
    let mut cursor = suites_start;
    while cursor + 2 <= suites_end {
        if is_grease_value(u16::from_be_bytes([record[cursor], record[cursor + 1]])) {
            record[cursor..cursor + 2].fill(0);
        }
        cursor += 2;
    }

    let mut zero_ranges = Vec::new();
    let mut malformed = false;
    walk_client_hello_extensions(record, |ext_type, entry| {
        if malformed {
            return;
        }
        if is_grease_value(ext_type) {
            zero_ranges.push(entry.start..entry.start + 2);
            return;
        }
        if ext_type != SUPPORTED_GROUPS_EXTENSION_TYPE {
            return;
        }
        let ext_data = entry.start + 4;
        let ext_end = entry.end;
        if ext_end - ext_data < 2 {
            malformed = true;
            return;
        }
        let groups_len = u16::from_be_bytes([record[ext_data], record[ext_data + 1]]) as usize;
        let Some(groups_end) = ext_data.checked_add(2).and_then(|v| v.checked_add(groups_len))
        else {
            malformed = true;
            return;
        };
        if groups_end > ext_end {
            malformed = true;
            return;
        }
        let mut cursor = ext_data + 2;
        while cursor + 2 <= groups_end {
            if is_grease_value(u16::from_be_bytes([record[cursor], record[cursor + 1]])) {
                zero_ranges.push(cursor..cursor + 2);
            }
            cursor += 2;
        }
    })?;
    if malformed {
        return None;
    }
    for range in zero_ranges {
        record[range].fill(0);
    }
    Some(())
}

/// Validate the ClientHello record shape and walk its extension entries,
/// invoking `visit(ext_type, entry_range)` for each entry (`entry_range` spans
/// the 2-byte type, 2-byte length, and data). Returns the offset of the
/// extensions-length u16 field, or None on any truncation. Shared by all
/// ClientHello extension scanners below.
fn walk_client_hello_extensions(
    record: &[u8],
    mut visit: impl FnMut(u16, std::ops::Range<usize>),
) -> Option<usize> {
    if record.len() < 9 || record[0] != 0x16 || record[5] != 0x01 {
        return None;
    }
    let (_, session_id_range) = client_hello_random_and_session_id_ranges(record)?;
    let mut cursor = session_id_range.end;
    let cipher_suites_len =
        u16::from_be_bytes([*record.get(cursor)?, *record.get(cursor + 1)?]) as usize;
    cursor = cursor.checked_add(2 + cipher_suites_len)?;
    let compression_methods_len = *record.get(cursor)? as usize;
    cursor = cursor.checked_add(1 + compression_methods_len)?;
    let extensions_len_start = cursor;
    let extensions_len =
        u16::from_be_bytes([*record.get(cursor)?, *record.get(cursor + 1)?]) as usize;
    cursor = cursor.checked_add(2)?;
    let extensions_end = cursor.checked_add(extensions_len)?;
    if extensions_end > record.len() {
        return None;
    }

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([record[cursor], record[cursor + 1]]);
        let ext_len = u16::from_be_bytes([record[cursor + 2], record[cursor + 3]]) as usize;
        let ext_end = cursor.checked_add(4 + ext_len)?;
        if ext_end > extensions_end {
            return None;
        }
        visit(ext_type, cursor..ext_end);
        cursor = ext_end;
    }

    Some(extensions_len_start)
}

fn normalize_client_hello_padding_extension(record: &mut Vec<u8>) -> Option<()> {
    const PADDING_EXTENSION_TYPE: u16 = 0x0015;
    let mut padding_entry = None;
    let extensions_len_start = walk_client_hello_extensions(record, |ext_type, entry| {
        if ext_type == PADDING_EXTENSION_TYPE && padding_entry.is_none() {
            padding_entry = Some(entry);
        }
    })?;
    let Some(entry) = padding_entry else {
        return Some(());
    };

    let removed = entry.end - entry.start;
    record.drain(entry);
    let extensions_len =
        u16::from_be_bytes([record[extensions_len_start], record[extensions_len_start + 1]])
            as usize;
    let new_extensions_len = extensions_len.checked_sub(removed)? as u16;
    record[extensions_len_start..extensions_len_start + 2]
        .copy_from_slice(&new_extensions_len.to_be_bytes());
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let new_record_len = record_len.checked_sub(removed)? as u16;
    record[3..5].copy_from_slice(&new_record_len.to_be_bytes());
    let handshake_len =
        ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    let new_handshake_len = handshake_len.checked_sub(removed)?;
    record[6] = ((new_handshake_len >> 16) & 0xff) as u8;
    record[7] = ((new_handshake_len >> 8) & 0xff) as u8;
    record[8] = (new_handshake_len & 0xff) as u8;
    Some(())
}

pub fn client_hello_key_share_range(record: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut result = None;
    let mut malformed = false;
    walk_client_hello_extensions(record, |ext_type, entry| {
        if ext_type != 0x0033 || result.is_some() || malformed {
            return;
        }
        let ext_data = entry.start + 4;
        let ext_end = entry.end;
        if ext_end - ext_data < 4 {
            malformed = true;
            return;
        }
        let mut share_cursor = ext_data + 2;
        let mut first_share_range = None;
        while share_cursor + 4 <= ext_end {
            let group = u16::from_be_bytes([record[share_cursor], record[share_cursor + 1]]);
            let share_len =
                u16::from_be_bytes([record[share_cursor + 2], record[share_cursor + 3]]) as usize;
            let share_start = share_cursor + 4;
            let Some(share_end) = share_start.checked_add(share_len) else {
                malformed = true;
                return;
            };
            if share_end > ext_end {
                malformed = true;
                return;
            }
            if first_share_range.is_none() {
                first_share_range = Some(share_start..share_end);
            }
            if group == 0x001d {
                result = Some(share_start..share_end);
                return;
            }
            share_cursor = share_end;
        }
        if result.is_none() {
            result = first_share_range;
        }
    })?;
    if malformed {
        return None;
    }
    result
}

#[derive(Debug)]
pub struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

pub const MAX_TLS_RECORD_PAYLOAD_LEN: usize = 16384 + 256;

#[derive(Clone, Copy, Debug)]
pub struct TlsRecordReadLimits {
    pub max_records: usize,
    pub max_bytes: usize,
    pub deadline: Option<tokio::time::Instant>,
}

#[derive(Default, Debug)]
pub struct TlsRecordReadState {
    records: usize,
    bytes: usize,
}

impl TlsRecordReadState {
    pub fn new() -> Self {
        Self::default()
    }
}

pub async fn read_tls_record_bounded(
    stream: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
    limits: TlsRecordReadLimits,
    state: &mut TlsRecordReadState,
) -> std::io::Result<(u8, usize)> {
    if state.records >= limits.max_records {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record count limit exceeded",
        ));
    }

    let mut header = [0u8; 5];
    read_exact_with_deadline(stream, &mut header, limits.deadline).await?;
    let typ = header[0];
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_TLS_RECORD_PAYLOAD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record too large",
        ));
    }
    let record_len = 5 + len;
    if state.bytes.saturating_add(record_len) > limits.max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record byte limit exceeded",
        ));
    }

    buf.clear();
    buf.extend_from_slice(&header);
    buf.resize(record_len, 0);
    read_exact_with_deadline(stream, &mut buf[5..record_len], limits.deadline).await?;
    state.records += 1;
    state.bytes += record_len;

    Ok((typ, len))
}

async fn read_exact_with_deadline(
    stream: &mut tokio::net::TcpStream,
    buf: &mut [u8],
    deadline: Option<tokio::time::Instant>,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline, stream.read_exact(buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS read deadline exceeded")
            })??;
    } else {
        stream.read_exact(buf).await?;
    }
    Ok(())
}

pub fn extract_client_hello_random_and_session_id(
    record: &mut [u8],
) -> Option<(&mut [u8], &mut [u8])> {
    let (random_range, session_range) = client_hello_random_and_session_id_ranges(record)?;
    let (_, after_random_start) = record.split_at_mut(random_range.start);
    let (random, after_random) =
        after_random_start.split_at_mut(random_range.end - random_range.start);
    let session_offset = session_range.start - random_range.end;
    let session_len = session_range.end - session_range.start;
    let (_, after_session_start) = after_random.split_at_mut(session_offset);
    let (session_id, _) = after_session_start.split_at_mut(session_len);
    Some((random, session_id))
}

pub fn client_hello_random_and_session_id_ranges(
    record: &[u8],
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    if record.len() < 5 + 44 {
        return None;
    }
    if record[0] != 0x16 {
        return None;
    }
    if record[5] != 0x01 {
        return None;
    }

    let session_id_len = record[43] as usize;
    if record.len() < 44 + session_id_len {
        return None;
    }

    Some((11..43, 44..44 + session_id_len))
}

pub fn extract_client_hello_server_name(record: &[u8]) -> Option<&str> {
    let mut result = None;
    let mut malformed = false;
    walk_client_hello_extensions(record, |ext_type, entry| {
        if ext_type != 0x0000 || result.is_some() || malformed {
            return;
        }
        let ext_data = entry.start + 4;
        let ext_end = entry.end;
        if ext_end - ext_data < 5 {
            malformed = true;
            return;
        }
        if record[ext_data + 2] != 0x00 {
            malformed = true;
            return;
        }
        let host_len = u16::from_be_bytes([record[ext_data + 3], record[ext_data + 4]]) as usize;
        let host_start = ext_data + 5;
        let Some(host_end) = host_start.checked_add(host_len) else {
            malformed = true;
            return;
        };
        if host_end > ext_end {
            malformed = true;
            return;
        }
        result = std::str::from_utf8(&record[host_start..host_end]).ok();
    })?;
    if malformed {
        return None;
    }
    result
}

pub fn is_server_hello(record: &[u8]) -> bool {
    if record.len() < 9 {
        return false;
    }
    record[0] == 0x16 && record[5] == 0x02
}

/// Noise ephemeral key XOR masking: encodes a 32-byte public key by XORing with a PSK-derived mask.
/// Returns the masked key bytes. The same mask is used by the peer to recover the original key.
pub fn mask_noise_ephemeral_key(key: &[u8; 32], derived_psk: &[u8], noise_tag: &[u8]) -> [u8; 32] {
    let mask = derive_noise_e_mask(derived_psk, noise_tag);
    xor_32_bytes(key, &mask)
}

/// Unmask a Noise ephemeral key from the XOR-masked bytes in the ClientHello random field.
pub fn unmask_noise_ephemeral_key(
    masked: &[u8; 32],
    derived_psk: &[u8],
    noise_tag: &[u8],
) -> [u8; 32] {
    let mask = derive_noise_e_mask(derived_psk, noise_tag);
    xor_32_bytes(masked, &mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_e_mask_is_reversible() {
        let psk = [7u8; 32];
        let tag = [9u8; 16];
        let e = [3u8; 32];
        let mask = derive_noise_e_mask(&psk, &tag);
        let masked = xor_32_bytes(&e, &mask);
        let unmasked = xor_32_bytes(&masked, &mask);

        assert_eq!(unmasked, e);
    }

    #[test]
    fn constant_time_eq_checks_all_bytes() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }

    #[test]
    fn stable_client_hello_fingerprint_ignores_random_and_session_bytes() {
        let mut record_a = vec![0u8; 80];
        record_a[0] = 0x16;
        record_a[5] = 0x01;
        record_a[43] = 32;
        for i in 0..32 {
            record_a[11 + i] = i as u8;
            record_a[44 + i] = (31 - i) as u8;
        }

        let mut record_b = record_a.clone();
        record_b[11..43].fill(0xaa);
        record_b[44..76].fill(0x55);

        assert_eq!(
            stable_client_hello_fingerprint(&record_a),
            stable_client_hello_fingerprint(&record_b)
        );
    }

    #[test]
    fn stable_client_hello_fingerprint_ignores_key_share_bytes() {
        let mut record_a = vec![0u8; 130];
        record_a[0] = 0x16;
        record_a[5] = 0x01;
        record_a[43] = 32;
        record_a[76] = 0x00;
        record_a[77] = 0x02;
        record_a[78] = 0x13;
        record_a[79] = 0x01;
        record_a[80] = 0x01;
        record_a[81] = 0x00;
        record_a[82] = 0x00;
        record_a[83] = 0x2a;
        record_a[84] = 0x00;
        record_a[85] = 0x33;
        record_a[86] = 0x00;
        record_a[87] = 0x26;
        record_a[88] = 0x00;
        record_a[89] = 0x24;
        record_a[90] = 0x00;
        record_a[91] = 0x1d;
        record_a[92] = 0x00;
        record_a[93] = 0x20;
        for i in 0..32 {
            record_a[94 + i] = i as u8;
        }

        let mut record_b = record_a.clone();
        record_b[94..126].fill(0xaa);

        assert_eq!(
            stable_client_hello_fingerprint(&record_a),
            stable_client_hello_fingerprint(&record_b)
        );
    }

    #[test]
    fn stable_client_hello_fingerprint_ignores_grease_and_all_key_shares() {
        // 合成 ClientHello：cipher_suites、扩展 type、supported_groups 各含一个
        // GREASE 位置；key_share 含 X25519(32B) 与 P-256(65B) 两个 share。
        fn build(grease: u16, x25519_share: u8, p256_share: u8) -> Vec<u8> {
            let mut r = vec![0u8; 211];
            r[0] = 0x16;
            r[5] = 0x01;
            r[43] = 32;
            r[76] = 0x00;
            r[77] = 0x04;
            r[78..80].copy_from_slice(&grease.to_be_bytes());
            r[80] = 0x13;
            r[81] = 0x01;
            r[82] = 0x01;
            r[84] = 0x00;
            r[85] = 125;
            r[86..88].copy_from_slice(&grease.to_be_bytes());
            r[90] = 0x00;
            r[91] = 0x0a;
            r[92] = 0x00;
            r[93] = 0x06;
            r[94] = 0x00;
            r[95] = 0x04;
            r[96..98].copy_from_slice(&grease.to_be_bytes());
            r[98] = 0x00;
            r[99] = 0x1d;
            r[100] = 0x00;
            r[101] = 0x33;
            r[102] = 0x00;
            r[103] = 0x6b;
            r[104] = 0x00;
            r[105] = 0x69;
            r[106] = 0x00;
            r[107] = 0x1d;
            r[108] = 0x00;
            r[109] = 0x20;
            r[110..142].fill(x25519_share);
            r[142] = 0x00;
            r[143] = 0x17;
            r[144] = 0x00;
            r[145] = 0x41;
            r[146..211].fill(p256_share);
            r
        }

        let record_a = build(0x0a0a, 0x11, 0x22);
        let record_b = build(0xfafa, 0x33, 0x44);
        assert_eq!(
            stable_client_hello_fingerprint(&record_a),
            stable_client_hello_fingerprint(&record_b)
        );

        // 非 GREASE 差异（cipher suite 0x1302）仍须改变指纹。
        let mut record_c = record_b.clone();
        record_c[81] = 0x02;
        assert_ne!(
            stable_client_hello_fingerprint(&record_a),
            stable_client_hello_fingerprint(&record_c)
        );
    }

    #[test]
    fn stable_client_hello_fingerprint_rejects_truncated_key_share() {
        let mut record = vec![0u8; 100];
        record[0] = 0x16;
        record[5] = 0x01;
        record[43] = 32;
        record[76] = 0x00;
        record[77] = 0x02;
        record[78] = 0x13;
        record[79] = 0x01;
        record[80] = 0x01;
        record[81] = 0x00;
        record[82] = 0x00;
        record[83] = 16;
        record[84] = 0x00;
        record[85] = 0x33;
        record[86] = 0x00;
        record[87] = 12;
        record[88] = 0x00;
        record[89] = 10;
        record[90] = 0x00;
        record[91] = 0x1d;
        record[92] = 0x00;
        record[93] = 0x20;

        assert_eq!(stable_client_hello_fingerprint(&record), None);
    }

    #[test]
    fn stable_client_hello_fingerprint_ignores_padding_extension() {
        let mut record_a = vec![0u8; 134];
        record_a[0] = 0x16;
        record_a[5] = 0x01;
        record_a[43] = 32;
        record_a[76] = 0x00;
        record_a[77] = 0x02;
        record_a[78] = 0x13;
        record_a[79] = 0x01;
        record_a[80] = 0x01;
        record_a[81] = 0x00;
        record_a[82] = 0x00;
        record_a[83] = 0x2e;
        record_a[84] = 0x00;
        record_a[85] = 0x33;
        record_a[86] = 0x00;
        record_a[87] = 0x26;
        record_a[88] = 0x00;
        record_a[89] = 0x24;
        record_a[90] = 0x00;
        record_a[91] = 0x1d;
        record_a[92] = 0x00;
        record_a[93] = 0x20;
        for i in 0..32 {
            record_a[94 + i] = i as u8;
        }
        record_a[126] = 0x00;
        record_a[127] = 0x15;
        record_a[128] = 0x00;
        record_a[129] = 0x00;
        record_a[3] = 0x00;
        record_a[4] = 129;
        record_a[6] = 0x00;
        record_a[7] = 0x00;
        record_a[8] = 125;

        let mut record_b = record_a.clone();
        record_b.resize(154, 0);
        record_b[128] = 0x00;
        record_b[129] = 0x14;
        record_b[130..154].fill(0);
        record_b[3] = 0x00;
        record_b[4] = 149;
        record_b[8] = 145;
        record_b[83] = 0x42;

        assert_eq!(
            stable_client_hello_fingerprint(&record_a),
            stable_client_hello_fingerprint(&record_b)
        );
    }

    #[test]
    fn extract_client_hello_server_name_reads_sni() {
        let mut record = vec![0u8; 98];
        record[0] = 0x16;
        record[5] = 0x01;
        record[9] = 0x03;
        record[10] = 0x03;
        record[43] = 32;
        record[76] = 0x00;
        record[77] = 0x02;
        record[78] = 0x13;
        record[79] = 0x01;
        record[80] = 0x01;
        record[81] = 0x00;
        record[82] = 0x00;
        record[83] = 0x0e;
        record[84] = 0x00;
        record[85] = 0x00;
        record[86] = 0x00;
        record[87] = 0x0a;
        record[88] = 0x00;
        record[89] = 0x08;
        record[90] = 0x00;
        record[91] = 0x00;
        record[92] = 0x05;
        record[93..98].copy_from_slice(b"hello");
        record[3] = 0x00;
        record[4] = 93;
        record[6] = 0x00;
        record[7] = 0x00;
        record[8] = 89;

        assert_eq!(extract_client_hello_server_name(&record), Some("hello"));
    }

    #[test]
    fn xor_mask_noise_ephemeral_key_roundtrip() {
        let psk = [7u8; 32];
        let noise_tag = [9u8; 16];
        let key = [3u8; 32];
        let derived_psk = hash_with_key(b"kanotls-secure-tunnel-v1", &psk);
        let masked = mask_noise_ephemeral_key(&key, &derived_psk, &noise_tag);
        let unmasked = unmask_noise_ephemeral_key(&masked, &derived_psk, &noise_tag);
        assert_eq!(unmasked, key);
    }

    #[test]
    fn counter_mask_is_deterministic() {
        let psk = [7u8; 32];
        let random = [3u8; 32];
        let mask1 = derive_counter_mask(&psk, &random);
        let mask2 = derive_counter_mask(&psk, &random);
        assert_eq!(mask1, mask2);
    }

    #[test]
    fn counter_mac_changes_with_counter() {
        let psk = [7u8; 32];
        let random = [3u8; 32];
        let random_prefix = &random[..16];
        let counter1 = 100u64.to_be_bytes();
        let counter2 = 200u64.to_be_bytes();
        let mac1 = derive_counter_mac(&psk, &random, &counter1, random_prefix);
        let mac2 = derive_counter_mac(&psk, &random, &counter2, random_prefix);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn counter_cache_key_is_psk_dependent() {
        let key1 = derive_counter_cache_key(&[1u8; 32]);
        let key2 = derive_counter_cache_key(&[2u8; 32]);
        assert_ne!(key1, key2);
    }
}
