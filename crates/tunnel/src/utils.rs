use blake2::Digest;
use subtle::ConstantTimeEq as _;

use crate::common::TLS_RECORD_HEADER_LEN;

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
    normalize_client_hello_ech_extension(&mut normalized)?;
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

/// `encrypted_client_hello`（draft-ietf-tls-esni）扩展类型。template.rs 逐连接
/// 刷新它的 `config_id`/`enc`/`payload`，本模块负责在指纹归一化时把同样三个
/// 字段置零 —— 两侧必须指向同一个扩展类型，故常量只定义一份。
pub(crate) const ECH_EXTENSION_TYPE: u16 = 0xFE0D;

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

/// 解析 ECHClientHello（draft-ietf-tls-esni §5）的逐连接可变字段：
/// `type(1)=0 (outer) ‖ kdf_id(2) ‖ aead_id(2) ‖ config_id(1) ‖ enc<0..2^16-1>
/// ‖ payload<1..2^16-1>`，返回 `(config_id 偏移, enc 范围, payload 范围)`。
///
/// 这是 template.rs 逐连接刷新（`parse_client_hello_layout`）与指纹归一化置零
/// **共用**的唯一解析器——两侧曾各有一份手动同步的拷贝，任何一侧改布局另一
/// 侧就会漂移：刷新侧认为 enc 从 data+8 开始、归一化侧按 data+8 置零，一旦
/// 其中一处偏移写错，指纹稳定性测试与线上行为会静默分叉。结构截断一律返回
/// None（fail closed）。
///
/// `type != 0`（inner）由调用方各自处理：指纹侧跳过（inner 是 Empty，没有逐
/// 连接字段），模板构建侧 fail closed（无法刷新的 ECH 会被逐字节重放成跨连接
/// 常量）。
pub(crate) fn ech_variable_field_ranges(
    record: &[u8],
    data_range: std::ops::Range<usize>,
) -> Option<(usize, std::ops::Range<usize>, std::ops::Range<usize>)> {
    let start = data_range.start;
    let end = data_range.end;
    if end == start {
        return None;
    }
    // type(1) ‖ kdf(2) ‖ aead(2) ‖ config_id(1) ‖ enc_len(2)
    if end - start < 8 {
        return None;
    }
    let enc_len = u16::from_be_bytes([record[start + 6], record[start + 7]]) as usize;
    let enc_start = start + 8;
    let enc_end = enc_start.checked_add(enc_len)?;
    if enc_end.saturating_add(2) > end {
        return None;
    }
    let payload_len = u16::from_be_bytes([record[enc_end], record[enc_end + 1]]) as usize;
    let payload_start = enc_end + 2;
    let payload_end = payload_start.checked_add(payload_len)?;
    if payload_end != end {
        return None;
    }
    Some((start + 5, enc_start..enc_end, payload_start..payload_end))
}

/// 将 GREASE ECH（`0xFE0D` encrypted_client_hello）中逐连接变化的字段置零：
/// `config_id`(1 B)、`enc`、`payload`。
///
/// 此前 ECH 被整份剥离，所以指纹侧无需处理。恢复 ECH 后这三个字段逐连接刷新
/// （template.rs `instantiate()`），若不归一化，每条连接的稳定指纹都不同 ⇒
/// 服务端按指纹 key 的伪装 profile 缓存退化成每连接一条 ⇒ 每条客户端连接都
/// 触发一次对伪装端点的实时 fetch。那既是巨大的性能回退，也是一个新的可观测
/// 行为（服务端对每个客户端连接都向伪装站点发起一次连接）。
///
/// `cipher_suite`(kdf‖aead)、`type` 与**所有长度字段**一律不动：真实端点的 HPKE
/// 套件是编译期常量、长度也恒定，它们携带真实的指纹信息，抹平反而丢信息。
/// 结构截断时返回 None（与 [`normalize_client_hello_key_shares`] 一致地 fail
/// closed）。
fn normalize_client_hello_ech_extension(record: &mut [u8]) -> Option<()> {
    let mut zero_ranges = Vec::new();
    let mut malformed = false;
    walk_client_hello_extensions(record, |ext_type, entry| {
        if ext_type != ECH_EXTENSION_TYPE || malformed {
            return;
        }
        let data = entry.start + 4;
        let end = entry.end;
        if end == data {
            malformed = true;
            return;
        }
        // ECHClientHello.type: outer(0) 才有 config_id/enc/payload；
        // inner(1) 是 Empty，没有任何逐连接字段可归一化。
        if record[data] != 0 {
            return;
        }
        let Some((config_id, enc, payload)) = ech_variable_field_ranges(record, data..end) else {
            malformed = true;
            return;
        };
        zero_ranges.push(config_id..config_id + 1);
        zero_ranges.push(enc);
        zero_ranges.push(payload);
    })?;
    if malformed {
        return None;
    }
    for range in zero_ranges {
        record[range].fill(0);
    }
    Some(())
}

/// 将所有 GREASE 出现位置置零：cipher_suites 列表中的 2 字节值、每个扩展的
/// 2 字节 ext_type 字段（GREASE 扩展 len 通常为 0，置零 type 不影响遍历）、
/// supported_groups(0x000a) 与 supported_versions(0x002b) 扩展 data 内的列表项。
/// 长度字段一律不动。
///
/// supported_versions 此前未被覆盖：Chrome/BoringSSL 在该列表里也放一个独立的
/// GREASE 版本号，而 template.rs 新增了对它的逐连接轮换，两侧必须成对存在 ——
/// 只轮换不归一化会让指纹每连接唯一。
fn normalize_client_hello_grease_positions(record: &mut [u8]) -> Option<()> {
    const SUPPORTED_GROUPS_EXTENSION_TYPE: u16 = 0x000a;
    const SUPPORTED_VERSIONS_EXTENSION_TYPE: u16 = 0x002b;

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
        let ext_data = entry.start + 4;
        let ext_end = entry.end;
        // supported_groups 的列表长度是 u16，supported_versions 是 u8。
        let (list_start, list_end) = match ext_type {
            SUPPORTED_GROUPS_EXTENSION_TYPE => {
                if ext_end - ext_data < 2 {
                    malformed = true;
                    return;
                }
                let list_len =
                    u16::from_be_bytes([record[ext_data], record[ext_data + 1]]) as usize;
                let Some(list_end) =
                    ext_data.checked_add(2).and_then(|v| v.checked_add(list_len))
                else {
                    malformed = true;
                    return;
                };
                (ext_data + 2, list_end)
            }
            SUPPORTED_VERSIONS_EXTENSION_TYPE => {
                if ext_end == ext_data {
                    malformed = true;
                    return;
                }
                let list_len = record[ext_data] as usize;
                let Some(list_end) =
                    ext_data.checked_add(1).and_then(|v| v.checked_add(list_len))
                else {
                    malformed = true;
                    return;
                };
                (ext_data + 1, list_end)
            }
            _ => return,
        };
        if list_end > ext_end {
            malformed = true;
            return;
        }
        let mut cursor = list_start;
        while cursor + 2 <= list_end {
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

/// Locate the `key_share` (0x0033) extension inside the first ServerHello found
/// in `server_records`, returning `(named_group, key_exchange_range)`.
///
/// ServerHello has a different shape from ClientHello — no cipher-suite list and
/// no compression-method list — so this cannot reuse
/// [`walk_client_hello_extensions`]. `server_records` may hold several
/// concatenated records (ServerHello + ChangeCipherSpec); non-ServerHello
/// records are skipped.
///
/// Returns `None` on any truncation or malformed length, so callers fail closed.
pub fn server_hello_key_share_range(
    server_records: &[u8],
) -> Option<(u16, std::ops::Range<usize>)> {
    const KEY_SHARE_EXTENSION_TYPE: u16 = 0x0033;
    let mut offset = 0usize;
    while offset + TLS_RECORD_HEADER_LEN <= server_records.len() {
        let rec_len =
            u16::from_be_bytes([server_records[offset + 3], server_records[offset + 4]]) as usize;
        let record_end = offset + TLS_RECORD_HEADER_LEN + rec_len;
        if record_end > server_records.len() {
            return None;
        }
        // 0x16 handshake record whose first body byte is 0x02 == ServerHello.
        if server_records[offset] != 0x16 || rec_len == 0 || server_records[offset + 5] != 0x02 {
            offset = record_end;
            continue;
        }

        // handshake header (msg_type 1 + length 3), legacy_version 2, random 32
        let mut cursor = offset.checked_add(TLS_RECORD_HEADER_LEN + 4 + 2 + 32)?;
        if cursor >= record_end {
            return None;
        }
        let session_id_len = server_records[cursor] as usize;
        // legacy_session_id_echo, cipher_suite 2, legacy_compression_method 1
        cursor = cursor.checked_add(1 + session_id_len + 2 + 1)?;
        if cursor + 2 > record_end {
            return None;
        }
        let extensions_len =
            u16::from_be_bytes([server_records[cursor], server_records[cursor + 1]]) as usize;
        cursor += 2;
        let extensions_end = cursor.checked_add(extensions_len)?;
        if extensions_end > record_end {
            return None;
        }

        while cursor + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([server_records[cursor], server_records[cursor + 1]]);
            let ext_len =
                u16::from_be_bytes([server_records[cursor + 2], server_records[cursor + 3]]) as usize;
            let data_start = cursor + 4;
            let data_end = data_start.checked_add(ext_len)?;
            if data_end > extensions_end {
                return None;
            }
            if ext_type == KEY_SHARE_EXTENSION_TYPE {
                // ServerHello KeyShareEntry: group(2) ‖ key_exchange(len 2 ‖ data).
                // (HelloRetryRequest carries only selected_group(2), but HRR
                // flights are rejected at sampling time.)
                if ext_len < 4 {
                    return None;
                }
                let group =
                    u16::from_be_bytes([server_records[data_start], server_records[data_start + 1]]);
                let ke_len = u16::from_be_bytes([
                    server_records[data_start + 2],
                    server_records[data_start + 3],
                ]) as usize;
                let ke_start = data_start + 4;
                let ke_end = ke_start.checked_add(ke_len)?;
                if ke_end > data_end {
                    return None;
                }
                return Some((group, ke_start..ke_end));
            }
            cursor = data_end;
        }
        return None;
    }
    None
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

/// Box-Muller 标准正态采样：`z ~ N(0,1)`。`u1 <= 0.0` 的 guard 保证 `ln` 的
/// 参数严格为正。曾有三份逐字节相同的 Box-Muller 块（shaper 的 IAT 模型、
/// session 的合成 H2 交换间隔、`control_size` 的截断正态），统一收拢到此处。
pub(crate) fn sample_standard_normal() -> f64 {
    use rand::Rng;
    use std::f64::consts::PI;
    let mut rng = rand::thread_rng();
    loop {
        let u1: f64 = rng.gen_range(0.0..1.0);
        let u2: f64 = rng.gen_range(0.0..1.0);
        if u1 <= 0.0 {
            continue;
        }
        return (-2.0_f64 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
    }
}

/// 对数正态采样：`mu` 是对数空间的位置参数（即 `ln(中位数)`）、`sigma` 是
/// 形状参数。三处调用方曾各存一份逐字节相同的实现，统一收拢到此处。
pub fn sample_log_normal(mu: f64, sigma: f64) -> f64 {
    (mu + sigma * sample_standard_normal()).exp()
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

    /// 合成一条带 GREASE ECH（0xFE0D）的最小 ClientHello。
    /// extension_data = type(1)=0 ‖ kdf(2) ‖ aead(2) ‖ config_id(1)
    ///                  ‖ enc_len(2)=4 ‖ enc(4) ‖ payload_len(2)=6 ‖ payload(6)
    fn client_hello_with_ech(config_id: u8, enc: [u8; 4], payload: [u8; 6]) -> Vec<u8> {
        let mut ech_data = vec![0x00, 0x00, 0x01, 0x00, 0x01, config_id];
        ech_data.extend_from_slice(&4u16.to_be_bytes());
        ech_data.extend_from_slice(&enc);
        ech_data.extend_from_slice(&6u16.to_be_bytes());
        ech_data.extend_from_slice(&payload);
        assert_eq!(ech_data.len(), 20);

        let mut record = vec![0u8; 84];
        record[0] = 0x16;
        record[5] = 0x01;
        record[43] = 32; // session_id_len
        record[76] = 0x00; // cipher_suites_len = 2
        record[77] = 0x02;
        record[78] = 0x13;
        record[79] = 0x01;
        record[80] = 0x01; // compression_methods_len = 1
        record[81] = 0x00;
        // extensions_len
        let extensions_len = (4 + ech_data.len()) as u16;
        record[82..84].copy_from_slice(&extensions_len.to_be_bytes());
        record.extend_from_slice(&0xfe0du16.to_be_bytes());
        record.extend_from_slice(&(ech_data.len() as u16).to_be_bytes());
        record.extend_from_slice(&ech_data);
        let total = record.len();
        record[3..5].copy_from_slice(&((total - 5) as u16).to_be_bytes());
        record[6] = 0;
        record[7..9].copy_from_slice(&((total - 9) as u16).to_be_bytes());
        record
    }

    /// 恢复 ECH 后 `config_id`/`enc`/`payload` 逐连接刷新，若不归一化则每条连接
    /// 指纹唯一 ⇒ 伪装 profile 缓存退化成每连接一条 ⇒ 每条连接都对伪装端点发起
    /// 一次实时 fetch。
    #[test]
    fn stable_client_hello_fingerprint_ignores_ech_variable_fields() {
        let a = client_hello_with_ech(0x4a, [1, 2, 3, 4], [9, 9, 9, 9, 9, 9]);
        let b = client_hello_with_ech(0xf1, [0xaa, 0xbb, 0xcc, 0xdd], [1, 2, 3, 4, 5, 6]);
        assert_ne!(a, b, "前提：两条记录的 ECH 可变字段确实不同");
        assert_eq!(
            stable_client_hello_fingerprint(&a),
            stable_client_hello_fingerprint(&b)
        );

        // cipher_suite（kdf‖aead）不是逐连接字段，必须仍然改变指纹 —— 真实端点的
        // HPKE 套件是编译期常量，抹平它会丢掉真实的指纹信息。
        let mut c = a.clone();
        let ech_data_start = c.len() - 22;
        c[ech_data_start + 3] = 0x00;
        c[ech_data_start + 4] = 0x02; // aead 0x0001 -> 0x0002
        assert_ne!(
            stable_client_hello_fingerprint(&a),
            stable_client_hello_fingerprint(&c)
        );
    }

    /// 归一化只置零 config_id/enc/payload，不动任何长度字段 —— 记录/握手/扩展三处
    /// 长度以及 ECH 内部的 enc_len/payload_len 都必须保持自洽。
    #[test]
    fn normalize_ech_extension_touches_only_variable_fields() {
        let record = client_hello_with_ech(0x4a, [1, 2, 3, 4], [9, 9, 9, 9, 9, 9]);
        let mut normalized = record.clone();
        normalize_client_hello_ech_extension(&mut normalized).expect("well-formed ECH");

        assert_eq!(normalized.len(), record.len());
        let ech_data_start = record.len() - 20;
        let mut expected = record.clone();
        expected[ech_data_start + 5] = 0; // config_id
        expected[ech_data_start + 8..ech_data_start + 12].fill(0); // enc
        expected[ech_data_start + 14..ech_data_start + 20].fill(0); // payload
        assert_eq!(normalized, expected);

        // 长度自洽未被破坏。
        assert_eq!(
            u16::from_be_bytes([normalized[3], normalized[4]]) as usize + 5,
            normalized.len()
        );
        assert_eq!(
            u16::from_be_bytes([normalized[ech_data_start + 6], normalized[ech_data_start + 7]]),
            4
        );
        assert_eq!(
            u16::from_be_bytes([normalized[ech_data_start + 12], normalized[ech_data_start + 13]]),
            6
        );
        // 归一化幂等。
        let mut twice = normalized.clone();
        normalize_client_hello_ech_extension(&mut twice).unwrap();
        assert_eq!(twice, normalized);
    }

    /// 结构截断的 ECH 与截断的 key_share 一样 fail closed（返回 None），调用方据此
    /// 走 baseline 兜底而不是用一个半解析的偏移集做归一化。
    #[test]
    fn stable_client_hello_fingerprint_rejects_truncated_ech() {
        let mut record = client_hello_with_ech(0x4a, [1, 2, 3, 4], [9, 9, 9, 9, 9, 9]);
        let ech_data_start = record.len() - 20;
        // enc_len 5 ⇒ payload 无法填满 extension_data。
        record[ech_data_start + 6..ech_data_start + 8].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(stable_client_hello_fingerprint(&record), None);
    }

    /// supported_versions 里的 GREASE 版本号此前既不轮换也不归一化。template.rs 新增
    /// 了轮换，归一化必须同步覆盖，否则自定义 Chrome 模板的指纹会每连接唯一。
    #[test]
    fn stable_client_hello_fingerprint_ignores_supported_versions_grease() {
        fn build(grease: u16) -> Vec<u8> {
            let mut record = vec![0u8; 84];
            record[0] = 0x16;
            record[5] = 0x01;
            record[43] = 32;
            record[76] = 0x00;
            record[77] = 0x02;
            record[78] = 0x13;
            record[79] = 0x01;
            record[80] = 0x01;
            record[81] = 0x00;
            record[82..84].copy_from_slice(&11u16.to_be_bytes());
            record.extend_from_slice(&0x002bu16.to_be_bytes());
            record.extend_from_slice(&7u16.to_be_bytes());
            record.push(6); // supported_versions list length (u8)
            record.extend_from_slice(&grease.to_be_bytes());
            record.extend_from_slice(&0x0304u16.to_be_bytes());
            record.extend_from_slice(&0x0303u16.to_be_bytes());
            let total = record.len();
            record[3..5].copy_from_slice(&((total - 5) as u16).to_be_bytes());
            record[7..9].copy_from_slice(&((total - 9) as u16).to_be_bytes());
            record
        }

        assert_eq!(
            stable_client_hello_fingerprint(&build(0x0a0a)),
            stable_client_hello_fingerprint(&build(0xfafa))
        );
        // 非 GREASE 版本号差异仍须改变指纹。
        assert_ne!(
            stable_client_hello_fingerprint(&build(0x0a0a)),
            stable_client_hello_fingerprint(&build(0x0305))
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
