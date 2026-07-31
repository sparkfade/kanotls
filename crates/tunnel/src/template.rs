use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use lazy_static::lazy_static;
use rand::{Rng, RngCore};
use tracing::warn;

use crate::fp;
use crate::templates;
use crate::utils::{
    client_hello_random_and_session_id_ranges, derive_counter_mac, derive_counter_mask,
    ech_variable_field_ranges, extract_client_hello_random_and_session_id, is_grease_value,
    mask_noise_ephemeral_key, xor_u64_bytes, ECH_EXTENSION_TYPE, GREASE_VALUES,
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

/// GREASE ECH（0xFE0D）扩展中必须逐连接刷新的三个字段的偏移。
///
/// 此前 ECH 被整份剥离，理由是 281 字节 extension_data 逐字节重放就是跨连接
/// 常量（§2.3 痛斥的那类特征）。但删除同时把 JA3/JA4 打成了「不对应任何已
/// 发布 Firefox 版本」的形状，正解是刷新而非删除：`config_id`/`enc`/`payload`
/// 逐连接重取，`type`/`cipher_suite`/所有长度字段保持恒定。
#[derive(Debug, Clone)]
struct EchGreaseRanges {
    /// 1 字节 config_id。真实 Firefox 每次 GREASE ECH 都重取。
    config_id: usize,
    /// HPKE `enc`。长度字段不在此范围内，只刷新内容。
    enc: Range<usize>,
    /// 冒充 HPKE AEAD 密文的 `payload`。同样只刷新内容。
    payload: Range<usize>,
}

#[derive(Debug)]
pub struct ClientHelloTemplate {
    bytes: Vec<u8>,
    cipher_suites_range: Range<usize>,
    key_share_range: Range<usize>,
    auxiliary_key_share_ranges: Vec<Range<usize>>,
    extensions_len_range: Range<usize>,
    ech_grease_ranges: Option<EchGreaseRanges>,
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
    ech_grease_ranges: Option<EchGreaseRanges>,
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
            // 此前 0x001d 主份额与混合份额尾部 32 字节都用 `fill_bytes` 填充，
            // 于是产生了两个可观测特征：
            //
            // 1. 真实 X25519 公钥是 mod 2^255-19 归约后的 u 坐标，小端序下
            //    byte 31 最高位恒为 0；均匀随机字节有一半概率置位。每条连接
            //    泄漏 1 bit（两处同值时），误报率严格为 0，censor 每流只需读
            //    ClientHello 里的 1 个字节。
            // 2. 两处独立随机 ⇒ 二者必然不同。而真实 Firefox 在同时提供
            //    x25519 与 X25519MLKEM768 时**复用同一个 X25519 密钥对**
            //    （NSS bug 1902119，NSS 3.103：“reuse X25519 share when
            //    offering both X25519 and Xyber768d00”）；本仓库的捕获模板
            //    也逐字节印证：hybrid[1184..1216) == 0x001d 份额。真实
            //    Firefox 两处恒等、我们两处恒不等，单条连接一次 32 字节
            //    memcmp 即零误报判定。
            //
            // 现改为：每条连接生成**一个**真实 X25519 临时公钥，同时写入
            // 0x001d 份额与每个混合份额的 X25519 半部。fail closed —— ring
            // 生成失败时返回 Err，绝不回退到 `fill_bytes`：发出一个带判别
            // 特征的 ClientHello 比连接失败更糟（与 §2.3「遇到不支持的组时
            // fail closed」同一条理由）。
            let x25519_public = generate_x25519_public_key().ok_or_else(|| {
                anyhow::anyhow!("failed to generate the per-connection X25519 key_share")
            })?;
            let key_share = &mut out[self.key_share_range.clone()];
            if key_share.len() != x25519_public.len() {
                anyhow::bail!(
                    "ClientHello key_share length must be 32 for X25519 injection: {}",
                    key_share.len()
                );
            }
            key_share.copy_from_slice(&x25519_public);
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
                        fill_mlkem768_hybrid_share(share_data, &x25519_public);
                    } else if share_data.len() == 65 && share_data[0] == 0x04 {
                        // A 65-byte 0x04-prefixed share is an uncompressed SEC1
                        // P-256 point: emit a real public key so DPI point
                        // validation cannot tell the share apart from a genuine
                        // key_share.
                        //
                        // 此前 ring 生成失败时回退到 `rng.fill_bytes(&mut
                        // share_data[1..])`，那同样是错的：64 个随机字节几乎
                        // 必定不是合法 P-256 点，做点校验的服务器会回
                        // illegal_parameter，而 DPI 只要验一次曲线方程就能
                        // 零误报命中。改为 fail closed。
                        if !fill_p256_public_key(share_data) {
                            anyhow::bail!(
                                "failed to generate the per-connection P-256 auxiliary key_share"
                            );
                        }
                    } else if !share_data.is_empty() && share_data[0] == 0x04 {
                        // 其他 0x04 前缀（P-384 97 B / P-521 133 B）只出现在
                        // 自定义模板里；ring 不提供这两条曲线，无法生成合法点。
                        // 加载期校验（`validate_auxiliary_key_share_shapes`）
                        // 已拒绝这类模板，这里是同一道保险：任何绕过校验的
                        // 模板都 fail closed——随机字节几乎必定不是合法曲线点，
                        // 做点校验的服务器会回 illegal_parameter、DPI 验一次
                        // 曲线方程即可零误报命中，与 P-256 分支此前消除的判别
                        // 器同类。
                        anyhow::bail!(
                            "unsupported {}0x04-prefixed auxiliary key_share (only 65-byte \
                             P-256 is supported)",
                            share_data.len()
                        );
                    } else {
                        anyhow::bail!(
                            "unsupported auxiliary key_share shape ({} bytes; supported: \
                             1216-byte X25519MLKEM768 hybrid, 65-byte 0x04 P-256)",
                            share_data.len()
                        );
                    }
                }
            }
            // GREASE ECH 的逐连接刷新。⚠️ 与上面的 X25519 结论**恰好相反**：
            // 捕获模板的 `enc` 第 31 字节最高位是 1（0x98），真实 X25519 公钥
            // 该位恒为 0 —— 也就是说 Firefox 的 GREASE ECH `enc` 本来就是均匀
            // 随机字节，不是真实 HPKE 封装公钥（GREASE ECH 不做真实封装）。
            // 所以这里必须 `fill_bytes`。后来的维护者请不要「顺手修正」成
            // `fill_x25519_public_key`，那会**引入**一个判别特征。
            // `payload` 冒充 AEAD 密文、`config_id` 真实 Firefox 逐连接随机，
            // 两者同样是随机正确。cipher_suite 与所有长度字段不动（真实实现
            // 在这两个维度上恒定，随机化它们本身就是判别特征）。
            if let Some(ech) = &self.ech_grease_ranges {
                out[ech.config_id] = rng.gen();
                rng.fill_bytes(&mut out[ech.enc.clone()]);
                rng.fill_bytes(&mut out[ech.payload.clone()]);
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
        // 低 2 位不参与 MAC 校验（服务端 `mask_mac_flags` 比较前会清零），
        // 因此这里必须填随机位而不是清零：真实 session_id 是 32 字节均匀
        // 随机，任何被钉死的比特都是被动观察者可统计的富集特征
        // （单样本 4×，同一客户端 k 条连接即 4^-k）。填随机后线上恢复均匀，
        // 且旧版服务端同样先 mask 再比较，故向后兼容。
        session_id[31] = (session_id[31] & !0x03) | (rand::random::<u8>() & 0x03);
        apply_client_hello_randomization(
            &mut out,
            &self.cipher_suites_range,
            &self.extensions_len_range,
        )?;
        Ok(out)
    }
}

/// Fill a 1216-byte X25519MLKEM768 hybrid key_share with structurally valid
/// material. Layout: 768 ML-KEM.768 coefficients packed two-per-three-bytes
/// as 12-bit values (1152 bytes), a 32-byte rho seed, then a 32-byte X25519
/// public key. Coefficients are sampled uniformly from [0, 3329) — the same
/// distribution as a genuine ML-KEM encapsulation key — so the share passes
/// server-side mod-q decode validation (OpenSSL 3.5+ alerts
/// illegal_parameter on out-of-range coefficients) while remaining
/// statistically indistinguishable from a real key.
///
/// `x25519_public` 是本 ClientHello 的**唯一** X25519 临时公钥，同时也写在
/// 0x001d 独立份额里 —— 见 `instantiate()` 中关于 NSS bug 1902119 的说明。
/// 此前尾部 64 字节整段 `fill_bytes`，把本该是真实公钥的 [1184..1216) 也随机
/// 化了；rho 是不透明种子，`fill_bytes` 才正确，故只有 [1152..1184) 保持随机。
fn fill_mlkem768_hybrid_share(share_data: &mut [u8], x25519_public: &[u8; 32]) {
    const MLKEM768_Q: u16 = 3329;
    /// ML-KEM-768 encapsulation key: 768 coefficients at 12 bits (1152 B) 后接
    /// 32 字节 rho 种子。
    const MLKEM768_THAT_LEN: usize = 1152;
    const MLKEM768_EK_LEN: usize = MLKEM768_THAT_LEN + 32;
    debug_assert_eq!(share_data.len(), MLKEM768_EK_LEN + 32);
    let mut rng = rand::thread_rng();
    for chunk in share_data[..MLKEM768_THAT_LEN].chunks_exact_mut(3) {
        let d0: u16 = rng.gen_range(0..MLKEM768_Q);
        let d1: u16 = rng.gen_range(0..MLKEM768_Q);
        chunk[0] = d0 as u8;
        chunk[1] = ((d0 >> 8) as u8) | (((d1 & 0x0F) as u8) << 4);
        chunk[2] = (d1 >> 4) as u8;
    }
    // rho seed: 真实 ek 里就是 32 字节不透明种子，均匀随机即正确。
    rng.fill_bytes(&mut share_data[MLKEM768_THAT_LEN..MLKEM768_EK_LEN]);
    // X25519 半部：真实公钥，且与 0x001d 份额同值。
    share_data[MLKEM768_EK_LEN..].copy_from_slice(x25519_public);
}

/// 复用同一个 `SystemRandom`。此前 `fill_p256_public_key` /
/// `fill_x25519_public_key` 每次调用都 `SystemRandom::new()`，而每条客户端连接
/// 现在要做 1 次 X25519 + 1 次 P-256 生成（在连接建立路径上，由连接池摊销）。
fn system_random() -> &'static ring::rand::SystemRandom {
    static SYSTEM_RANDOM: OnceLock<ring::rand::SystemRandom> = OnceLock::new();
    SYSTEM_RANDOM.get_or_init(ring::rand::SystemRandom::new)
}

/// Generate a real ephemeral P-256 public key into `share_data` (65-byte
/// uncompressed SEC1 point, 0x04 prefix — the exact shape ring emits).
/// Returns false on any failure so the caller can fail closed — random bytes
/// are not a valid curve point, so there is no acceptable fallback.
pub(crate) fn fill_p256_public_key(share_data: &mut [u8]) -> bool {
    let Ok(private_key) = ring::agreement::EphemeralPrivateKey::generate(
        &ring::agreement::ECDH_P256,
        system_random(),
    ) else {
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

/// Generate a real ephemeral X25519 public key into `share_data` (32 bytes).
///
/// A real X25519 public key is a u-coordinate reduced mod 2^255-19, so its most
/// significant bit is always clear; 32 uniformly random bytes would set it half
/// the time. Filling this with `fill_bytes` would therefore *introduce* a
/// distinguisher rather than remove one — always derive a genuine key.
/// Returns false on any failure so the caller can fail closed.
pub(crate) fn fill_x25519_public_key(share_data: &mut [u8]) -> bool {
    if share_data.len() != 32 {
        return false;
    }
    let Some(public) = generate_x25519_public_key() else {
        return false;
    };
    share_data.copy_from_slice(&public);
    true
}

/// 生成一个真实的 X25519 临时公钥。ClientHello 侧需要把同一个值写到多个份额
/// 里（0x001d 与混合份额的 X25519 半部），所以这里返回值而不是就地填充。
fn generate_x25519_public_key() -> Option<[u8; 32]> {
    let private_key = ring::agreement::EphemeralPrivateKey::generate(
        &ring::agreement::X25519,
        system_random(),
    )
    .ok()?;
    let public_key = private_key.compute_public_key().ok()?;
    let public_bytes = public_key.as_ref();
    if public_bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(public_bytes);
    Some(out)
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
    validate_auxiliary_key_share_shapes(&bytes, &layout.auxiliary_key_share_ranges)?;

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
        ech_grease_ranges: layout.ech_grease_ranges,
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

/// Extensions removed from every ClientHello template at load time — embedded
/// and custom hex alike. **Empty by design.**
///
/// 此前这张表是 `[0xFE0D, 0x014A, 0x0119, 0x001C, 0x0022]`，于是内嵌模板从捕获
/// 的 15 个扩展被剥成 12 个、1884 → 1579 字节。逐扩展重解捕获字节后，这张表
/// 的每一条都站不住脚：
///
/// - `0x0119` / `0x014A` **在捕获里根本不存在**。它们是把 ECH 扩展头误读出来的
///   产物：原始字节是 `fe 0d 01 19 | 00 00 01 00 01 4a 00 20 …`，其中 `0x0119`
///   = 281 是 ECH 的 extension_length，`0x014a` 落在 ECH 结构体内部
///   （`config_id=0x4a ‖ enc_len=0x0020`）。注释把 `0x0119` 标为 early_data 也
///   是错的 —— early_data 是 `0x002A`。
/// - `0x001C` 是 **record_size_limit** (RFC 8449)，不是注释里写的 use_srtp
///   （use_srtp 是 `0x000E`）。捕获值 `4001` = 16385 = 2^14+1，正是 TLS 1.3
///   TLSInnerPlaintext 的默认上限（RFC 8449 §4：该值含 content type 与 padding），
///   也正好等于本项目的 `common::BLOCK_PLAINTEXT_SIZE`（16384 + 1）。换言之它
///   不施加任何额外约束，双向都完全兼容：伪装端点按它限制记录尺寸的结果与不
///   发这个扩展时一致，而这正是真实 Firefox 得到的待遇。
/// - `0x0022` 是 **delegated_credentials** (RFC 9345)，extension_data
///   `00080403050306030203` 是纯签名算法能力声明，无任何副作用。
/// - `0xFE0D` 是 **GREASE ECH**。整份重放确实是跨连接常量，但正解是逐连接刷新
///   `config_id`/`enc`/`payload`（见 [`EchGreaseRanges`] 与 `instantiate()`），
///   而不是删除 —— 删掉它使上线扩展数变成 12 个，不对应任何已发布的 Firefox
///   版本，JA4 的扩展计数与排序哈希直接失配。
///
/// 保留这套机制（而不是删掉函数）是因为它是唯一能在**自定义**模板里中和某个
/// 无法处理的扩展、并同步重写记录/握手/扩展三处长度的地方。新增条目必须有
/// 实测依据，不要凭猜测往里写。
const STRIPPED_EXTENSION_TYPES: [u16; 0] = [];

/// Return a copy of the ClientHello record with every extension in
/// [`STRIPPED_EXTENSION_TYPES`] removed and all three length fields (record,
/// handshake, extensions block) rewritten to stay self-consistent.
fn strip_client_hello_extensions(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    strip_named_client_hello_extensions(bytes, &STRIPPED_EXTENSION_TYPES)
}

/// [`strip_client_hello_extensions`] 的实现，剥离集合作为参数传入，使剥离机制
/// 本身可以在剥离表为空的情况下继续被测试覆盖。
fn strip_named_client_hello_extensions(
    bytes: &[u8],
    stripped: &[u16],
) -> anyhow::Result<Vec<u8>> {
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
        if stripped.contains(&ext_type) {
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

/// Rotate every RFC 8701 GREASE value in the ClientHello. Rotation only replaces
/// the 2-byte value at each GREASE position, never a length or any content.
///
/// **对内嵌 Firefox 预设这条路径是 no-op。** 实测捕获模板
/// （`FIREFOX_BOOTSTRAP_CLIENT_HELLO`，见 `firefox_template_has_no_grease_positions`）：
/// cipher_suites 16 项、supported_groups 7 项、扩展类型 15 项、supported_versions
/// 2 项，**GREASE 值 0 个**。Firefox/NSS 不在 ClientHello 里做 GREASE —— 那是
/// Chrome/BoringSSL 的行为。此前这里的注释断言「Real Firefox/NSS uses a single
/// GREASE value for every GREASE position within one ClientHello … and
/// re-randomizes it per ClientHello」，两半都是错的：Firefox 根本不 GREASE，而
/// 「所有位置同值」是 BoringSSL 明确避免的形状。该路径只对 `template_path`
/// 提供的自定义模板（例如 Chrome 捕获）生效。
///
/// 此前所有 GREASE 位置被写入**同一个**值，于是对 Chrome 模板产生了两个问题：
///
/// 1. 不真实。BoringSSL 的 `ssl_get_grease_value` 从每连接 `grease_seed` 里按
///    索引（cipher / group / extension1 / extension2 / version…）取**互相独立**
///    的值，并对第二个 GREASE 扩展强制 `ret ^= 0x1010`，保证同一 ClientHello
///    里两个 GREASE 扩展类型必不相同。
/// 2. 不合法。RFC 8446 §4.2 要求同一 extension block 内不得出现两个相同类型的
///    扩展；把两个 GREASE 扩展写成同值直接违反该条，严格的服务器会拒绝。
///
/// 现改为逐位置独立取值，并沿用 BoringSSL 的去重规则。归一化侧
/// （`utils::normalize_client_hello_grease_positions`）把**任意** GREASE 值一律
/// 置零，因此逐位置独立取值仍与指纹稳定性自洽。
fn apply_client_hello_randomization(
    bytes: &mut [u8],
    cipher_suites_range: &Range<usize>,
    extensions_len_range: &Range<usize>,
) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    rotate_grease_extensions(bytes, extensions_len_range, &mut rng)?;
    rotate_grease_cipher_suites(bytes, cipher_suites_range, &mut rng)?;
    rotate_grease_supported_groups(bytes, extensions_len_range, &mut rng)?;
    rotate_grease_supported_versions(bytes, extensions_len_range, &mut rng)?;

    Ok(())
}

/// 取一个未被 `used` 占用的 GREASE 值。首选均匀随机；碰撞时先按 BoringSSL 的
/// `ret ^= 0x1010` 翻转（GREASE 值形如 0xNANA，XOR 0x1010 后仍是合法 GREASE
/// 值），再退化为线性扫描 —— 后者只有在自定义模板带 >2 个 GREASE 扩展时才会
/// 触发，真实客户端里不存在。
fn take_grease_value(rng: &mut impl Rng, used: &mut Vec<u16>) -> u16 {
    let mut value = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
    if used.contains(&value) {
        let flipped = value ^ 0x1010;
        if used.contains(&flipped) {
            if let Some(free) = GREASE_VALUES.iter().find(|v| !used.contains(v)) {
                value = *free;
            }
        } else {
            value = flipped;
        }
    }
    used.push(value);
    value
}

fn rotate_grease_extensions(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
    rng: &mut impl Rng,
) -> anyhow::Result<()> {
    let mut cursor = extensions_len_range.end;
    let extensions_end = cursor + read_u16(bytes, extensions_len_range.start)? as usize;
    // 扩展类型必须互不相同（RFC 8446 §4.2），因此按槽位独立取值并去重。
    let mut used = Vec::new();

    while cursor + 4 <= extensions_end {
        let ext_type = read_u16(bytes, cursor)?;
        let ext_len = read_u16(bytes, cursor + 2)? as usize;
        let ext_end = cursor + 4 + ext_len;
        if ext_end > extensions_end {
            anyhow::bail!("truncated extension during GREASE rotation");
        }
        if is_grease_value(ext_type) {
            let value = take_grease_value(rng, &mut used);
            bytes[cursor..cursor + 2].copy_from_slice(&value.to_be_bytes());
        }
        cursor = ext_end;
    }
    Ok(())
}

fn rotate_grease_cipher_suites(
    bytes: &mut [u8],
    cipher_suites_range: &Range<usize>,
    rng: &mut impl Rng,
) -> anyhow::Result<()> {
    if cipher_suites_range.end > bytes.len() {
        anyhow::bail!("truncated cipher_suites during GREASE rotation");
    }
    let mut used = Vec::new();
    let mut cursor = cipher_suites_range.start;
    while cursor + 2 <= cipher_suites_range.end {
        if is_grease_value(read_u16(bytes, cursor)?) {
            let value = take_grease_value(rng, &mut used);
            bytes[cursor..cursor + 2].copy_from_slice(&value.to_be_bytes());
        }
        cursor += 2;
    }
    Ok(())
}

fn rotate_grease_supported_groups(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
    rng: &mut impl Rng,
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
    let mut used = Vec::new();
    let mut cursor = data_range.start + 2;
    while cursor + 2 <= groups_end {
        if is_grease_value(read_u16(bytes, cursor)?) {
            let value = take_grease_value(rng, &mut used);
            bytes[cursor..cursor + 2].copy_from_slice(&value.to_be_bytes());
        }
        cursor += 2;
    }
    Ok(())
}

/// 此前完全没有覆盖 supported_versions(0x002B)：Chrome/BoringSSL 在这里也放一个
/// 独立的 GREASE 版本号，自定义 Chrome 模板的该值会被逐字节重放，成为跨连接
/// 常量（原则 1）。`utils::normalize_client_hello_grease_positions` 同步新增了
/// 该位置的置零，两侧必须成对存在，否则指纹会退化成每连接唯一。
fn rotate_grease_supported_versions(
    bytes: &mut [u8],
    extensions_len_range: &Range<usize>,
    rng: &mut impl Rng,
) -> anyhow::Result<()> {
    const SUPPORTED_VERSIONS_EXTENSION_TYPE: u16 = 0x002B;
    let Some(extension) =
        find_extension(bytes, extensions_len_range, SUPPORTED_VERSIONS_EXTENSION_TYPE)?
    else {
        return Ok(());
    };
    let data_range = extension.data_range;
    if data_range.end > bytes.len() || data_range.end == data_range.start {
        anyhow::bail!("truncated supported_versions during GREASE rotation");
    }
    let versions_len = bytes[data_range.start] as usize;
    let versions_end = (data_range.start + 1 + versions_len).min(data_range.end);
    let mut used = Vec::new();
    let mut cursor = data_range.start + 1;
    while cursor + 2 <= versions_end {
        if is_grease_value(read_u16(bytes, cursor)?) {
            let value = take_grease_value(rng, &mut used);
            bytes[cursor..cursor + 2].copy_from_slice(&value.to_be_bytes());
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
    let mut ech_grease_ranges = None;

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
            ECH_EXTENSION_TYPE => {
                ech_grease_ranges = Some(parse_ech_grease_ranges(bytes, ext_data, ext_end)?);
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
        ech_grease_ranges,
    })
}

/// 辅助 key_share 只允许两种可以**保真刷新**的形状：1216 字节的
/// X25519MLKEM768 混合份额（ML-KEM 系数密装 + 32 字节 X25519）与 65 字节
/// 0x04 前缀的 P-256 SEC1 点。其余形状（P-384 97 B / P-521 133 B 等，只出现
/// 在自定义模板里）ring 无法生成合法曲线点，随机填充会留下「非法曲线点」
/// 判别器——做点校验的服务器回 illegal_parameter，DPI 验一次曲线方程即可
/// 零误报命中，与 P-256 分支刚消除的同类。与 §2.3「不支持的组 fail closed」
/// 同一政策：操作员在启动时（或模板热重载时）拿到错误，而不是把带特征的
/// 模板发上线。
fn validate_auxiliary_key_share_shapes(
    bytes: &[u8],
    ranges: &[Range<usize>],
) -> anyhow::Result<()> {
    for range in ranges {
        let share = &bytes[range.clone()];
        let supported = share.len() == 1216
            || (share.len() == 65 && !share.is_empty() && share[0] == 0x04);
        if !supported {
            anyhow::bail!(
                "unsupported auxiliary key_share ({} bytes; supported: 1216-byte \
                 X25519MLKEM768 hybrid, 65-byte 0x04 P-256)",
                share.len()
            );
        }
    }
    Ok(())
}

/// 定位 GREASE ECH 里三个必须逐连接刷新的字段。
///
/// ECHClientHello（draft-ietf-tls-esni §5）：
/// ```text
/// type(1) = 0 (outer)
///   ‖ cipher_suite { kdf_id(2) ‖ aead_id(2) }
///   ‖ config_id(1)
///   ‖ enc<0..2^16-1>
///   ‖ payload<1..2^16-1>
/// ```
/// 捕获模板：`1 + 4 + 1 + (2+32) + (2+239) = 281` 字节，与 extension_length
/// 精确吻合。
///
/// 布局解析由 `utils::ech_variable_field_ranges` 提供（与指纹归一化共用，避免
/// 两侧手动同步漂移）；本函数只做调用方语义：inner(1) 类型 fail closed —— 一个
/// 我们无法刷新的 ECH 扩展会被逐字节重放到每条连接上，那正是 §2.3 所说的
/// 跨连接常量。让操作员在启动时就拿到错误，而不是把这份指纹发上线。
fn parse_ech_grease_ranges(
    bytes: &[u8],
    data_start: usize,
    data_end: usize,
) -> anyhow::Result<EchGreaseRanges> {
    if data_end <= data_start {
        anyhow::bail!("empty encrypted_client_hello extension_data");
    }
    if bytes[data_start] != 0 {
        anyhow::bail!(
            "unsupported ECHClientHello type {}: only outer(0) GREASE ECH carries \
             per-connection variable fields",
            bytes[data_start]
        );
    }
    let Some((config_id, enc, payload)) = ech_variable_field_ranges(bytes, data_start..data_end)
    else {
        anyhow::bail!("malformed encrypted_client_hello extension");
    };
    Ok(EchGreaseRanges {
        config_id,
        enc,
        payload,
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

    fn append_extension(bytes: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
        let layout = parse_client_hello_layout(bytes).unwrap();
        let added_total = 4 + data.len();
        bytes.extend_from_slice(&ext_type.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
        adjust_handshake_lengths(
            bytes,
            &layout.record_len_range,
            &layout.handshake_len_range,
            &layout.extensions_len_range,
            added_total,
        )
        .unwrap();
    }

    fn append_zero_padding_extension(bytes: &mut Vec<u8>, data_len: usize) {
        append_extension(bytes, 0x0015, &vec![0u8; data_len]);
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
        // 此前剥离 0x0022/0x001C/0xFE0D 使上线扩展从捕获的 15 个变成 12 个，
        // 不对应任何已发布的 Firefox 版本，JA4 的扩展计数与排序哈希直接失配。
        let extensions_match_capture =
            instantiated_extension_lists.len() == 1 && {
                let instantiated = instantiated_extension_lists.iter().next().unwrap();
                *instantiated == format_extension_list(&original_extensions)
            };
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
             - Instantiated extension list identical to capture: `{}`\n\
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
            extensions_match_capture,
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
            extensions_match_capture,
            "上线扩展列表必须与捕获逐项相同（JA3/JA4 门禁）：instantiated={:?} capture={}",
            instantiated_extension_lists,
            format_extension_list(&original_extensions)
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
            ech_grease_ranges: layout.ech_grease_ranges,
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

    /// ClientHello 的 `random` 与 `session_id` 在真实 TLS 里是 32 字节均匀
    /// 随机；任何被钉死的比特都是被动观察者可直接统计的富集特征。
    ///
    /// 具体来说，`session_id[24..32]` 承载 counter MAC，而其低 2 位不参与
    /// 校验（服务端 `mask_mac_flags` 比较前会清零）。此前生成侧写的是
    /// `session_id[31] &= !0x03`，于是每个 ClientHello 的该字节低 2 位恒为
    /// 0：单个样本即带来 4× 富集，同一客户端 k 条连接则是 4^-k——而客户端
    /// 连接池常驻 4–16 条连接并周期性轮换，几分钟内就能被确定性识别。
    ///
    /// 本测试对这两个区域做逐位平衡检验，任何常量位都会被抓出。
    #[test]
    fn client_hello_random_and_session_id_are_bitwise_uniform() {
        const SAMPLES: usize = 512;
        let derived_psk = crate::common::derive_psk(b"uniformity");
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();

        // 每个采样用独立的 Noise ephemeral 与 counter，模拟不同连接。
        let mut random_ones = [0usize; 32 * 8];
        let mut session_ones = [0usize; 32 * 8];
        for sample in 0..SAMPLES {
            let mut initiator = snow::Builder::new(crate::common::NOISE_PARAMS.clone())
                .psk(0, &derived_psk)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut noise_init = [0u8; 48];
            initiator.write_message(&[], &mut noise_init).unwrap();
            let ch = template
                .instantiate(&derived_psk, &noise_init, sample as u64 + 1)
                .unwrap();

            let (random_range, session_range) =
                client_hello_random_and_session_id_ranges(&ch).unwrap();
            for (byte_idx, &byte) in ch[random_range].iter().enumerate() {
                for bit in 0..8 {
                    if byte >> bit & 1 == 1 {
                        random_ones[byte_idx * 8 + bit] += 1;
                    }
                }
            }
            for (byte_idx, &byte) in ch[session_range].iter().enumerate() {
                for bit in 0..8 {
                    if byte >> bit & 1 == 1 {
                        session_ones[byte_idx * 8 + bit] += 1;
                    }
                }
            }
        }

        // 512 次伯努利(0.5)：|ones - 256| > 96 的概率远低于 1e-12，
        // 而任何常量位会给出 0 或 512，必然越界。
        let tolerance = 96usize;
        let expected = SAMPLES / 2;
        for (label, counts) in [("random", &random_ones), ("session_id", &session_ones)] {
            for (idx, &ones) in counts.iter().enumerate() {
                let deviation = ones.abs_diff(expected);
                assert!(
                    deviation <= tolerance,
                    "{} bit {} (byte {}, bit {}) was 1 in {}/{} samples — a pinned or \
                     biased bit in a field that must be uniformly random is directly \
                     testable by a passive observer",
                    label,
                    idx,
                    idx / 8,
                    idx % 8,
                    ones,
                    SAMPLES
                );
            }
        }
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
            ech_grease_ranges: None,
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
            ech_grease_ranges: None,
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

    /// 捕获模板的 15 个扩展类型（顺序即上线顺序）。JA3 的扩展字段与 JA4 的扩展
    /// 计数/排序哈希都直接由这张表决定，任何偏离都不再对应任何已发布的 Firefox。
    const CAPTURED_EXTENSION_TYPES: [u16; 15] = [
        0x0000, // server_name
        0x0017, // extended_master_secret
        0xff01, // renegotiation_info
        0x000a, // supported_groups
        0x000b, // ec_point_formats
        0x0010, // application_layer_protocol_negotiation
        0x0005, // status_request
        0x0022, // delegated_credentials (RFC 9345)
        0x0012, // signed_certificate_timestamp
        0x0033, // key_share
        0x002b, // supported_versions
        0x000d, // signature_algorithms
        0x001c, // record_size_limit (RFC 8449)
        0x001b, // compress_certificate
        0xfe0d, // encrypted_client_hello (GREASE ECH)
    ];

    /// 此前剥离表把捕获的 15 个扩展砍成 12 个（`0x0022` delegated_credentials、
    /// `0x001C` record_size_limit、`0xFE0D` GREASE ECH），CH 长度 1884 → 1579。
    /// 现在剥离表为空（依据见 [`STRIPPED_EXTENSION_TYPES`]），本测试固化「剥离
    /// 对捕获模板是恒等变换」以及机制本身仍然自洽可用。
    #[test]
    fn strip_removes_target_extensions_and_keeps_lengths_consistent() {
        let stripped = strip_client_hello_extensions(FIREFOX_BOOTSTRAP_CLIENT_HELLO).unwrap();
        assert_eq!(
            stripped, FIREFOX_BOOTSTRAP_CLIENT_HELLO,
            "剥离表为空，捕获模板必须逐字节不变"
        );
        assert_eq!(extension_types(&stripped), CAPTURED_EXTENSION_TYPES.to_vec());
        assert_eq!(read_u16(&stripped, 3).unwrap() as usize + 5, stripped.len());
        assert_eq!(read_u24(&stripped, 6).unwrap() + 9, stripped.len());
        // Layout must still parse: extensions block is self-consistent.
        parse_client_hello_layout(&stripped).unwrap();

        // 机制自身仍须正确：给一个人工加了 use_srtp(0x000E) 的模板做剥离，
        // 三处长度字段都要同步重写、扩展块仍自洽。
        let mut with_extra = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        append_extension(&mut with_extra, 0x000E, &[0x00, 0x00]);
        let removed = strip_named_client_hello_extensions(&with_extra, &[0x000E]).unwrap();
        assert_eq!(removed, FIREFOX_BOOTSTRAP_CLIENT_HELLO);
        assert_eq!(read_u16(&removed, 3).unwrap() as usize + 5, removed.len());
        assert_eq!(read_u24(&removed, 6).unwrap() + 9, removed.len());
        parse_client_hello_layout(&removed).unwrap();
        // Idempotent: stripping an already-clean template changes nothing.
        let twice = strip_named_client_hello_extensions(&removed, &[0x000E]).unwrap();
        assert_eq!(removed, twice);
    }

    #[test]
    fn mlkem768_hybrid_share_is_structurally_valid() {
        let x25519 = [0x5au8; 32];
        let mut share = [0u8; 1216];
        fill_mlkem768_hybrid_share(&mut share, &x25519);
        // Every 12-bit coefficient must be < q = 3329 (mod-q decode check
        // performed by ML-KEM-capable servers).
        for chunk in share[..1152].chunks_exact(3) {
            let d0 = chunk[0] as u16 | (((chunk[1] & 0x0F) as u16) << 8);
            let d1 = ((chunk[1] >> 4) as u16) | ((chunk[2] as u16) << 4);
            assert!(d0 < 3329, "coefficient {} out of range", d0);
            assert!(d1 < 3329, "coefficient {} out of range", d1);
        }
        // rho seed must be random, not all zero.
        assert!(share[1152..1184].iter().any(|&b| b != 0));
        // X25519 半部必须原样写入调用方传进来的公钥（与 0x001d 份额同值）。
        assert_eq!(&share[1184..1216], &x25519);
        // Two fills must differ in the ML-KEM/rho part (per-connection freshness).
        let mut other = [0u8; 1216];
        fill_mlkem768_hybrid_share(&mut other, &x25519);
        assert_ne!(share[..1184], other[..1184]);
    }

    /// 自定义模板（这里就用捕获原样）必须与内嵌路径走同一套规范化。剥离表为空，
    /// 因此上线扩展列表必须与捕获逐项相同 —— 此前这条测试断言的是「ECH 等被剥
    /// 掉」，语义已随剥离表一起反转。
    #[test]
    fn build_template_keeps_custom_bytes_extension_shape() {
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
        let out = template.instantiate(&derived_psk, &noise_init, 1).unwrap();
        assert_eq!(
            extension_types(&out),
            CAPTURED_EXTENSION_TYPES.to_vec(),
            "自定义模板的扩展列表必须与捕获逐项相同"
        );
        assert!(STRIPPED_EXTENSION_TYPES.is_empty());
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

        // 剥离表为空 ⇒ 实例化长度只随 SNI 长度变化，与捕获的 1884 字节差值就是
        // SNI 长度差。此前剥离 3 个扩展让 CH 变成 1579 字节。
        let sni_delta = "example.com".len() as isize - "io-wiki.org".len() as isize;
        assert_eq!(
            out.len() as isize,
            FIREFOX_BOOTSTRAP_CLIENT_HELLO.len() as isize + sni_delta
        );
        assert_eq!(read_u16(&out, 3).unwrap() as usize + 5, out.len());
        assert_eq!(read_u24(&out, 6).unwrap() + 9, out.len());
    }

    /// **本任务最重要的回归门禁。** 实例化出的 ClientHello 必须与捕获的真实
    /// Firefox ClientHello 逐字节相同，唯一允许不同的就是逐连接必须新鲜的那些
    /// 字段。这一条同时把 JA3（cipher_suites / 扩展列表 / supported_groups /
    /// ec_point_formats）与 JA4（扩展计数 + 排序哈希 + sigalg 哈希）钉在捕获值上。
    ///
    /// 用与捕获相同的 SNI（`io-wiki.org`）实例化，这样偏移不发生位移，可以直接
    /// 逐字节比。
    #[test]
    fn instantiated_client_hello_matches_capture_outside_variable_fields() {
        const CAPTURED_SNI: &str = "io-wiki.org";
        let template =
            get_or_build_client_hello_template(CAPTURED_SNI, Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"capture-identity-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);
        let out = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();

        assert_eq!(out.len(), FIREFOX_BOOTSTRAP_CLIENT_HELLO.len());
        assert_eq!(
            extension_types(&out),
            extension_types(FIREFOX_BOOTSTRAP_CLIENT_HELLO),
            "实例化的扩展类型列表必须与捕获逐项相同（顺序与类型都一致）"
        );
        assert_eq!(extension_types(&out), CAPTURED_EXTENSION_TYPES.to_vec());

        let layout = parse_client_hello_layout(&out).unwrap();
        let (random_range, session_id_range) =
            client_hello_random_and_session_id_ranges(&out).unwrap();
        let ech = layout
            .ech_grease_ranges
            .clone()
            .expect("捕获模板必须带 GREASE ECH");
        let mut variable = vec![random_range, session_id_range, layout.key_share_range.clone()];
        variable.extend(layout.auxiliary_key_share_ranges.iter().cloned());
        variable.push(ech.config_id..ech.config_id + 1);
        variable.push(ech.enc.clone());
        variable.push(ech.payload.clone());

        let mut expected = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        let mut actual = out.clone();
        for range in &variable {
            expected[range.clone()].fill(0);
            actual[range.clone()].fill(0);
        }
        assert_eq!(
            actual, expected,
            "除逐连接可变字段外，实例化的 ClientHello 必须与捕获逐字节相同"
        );
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
        assert_eq!(
            baseline_types,
            CAPTURED_EXTENSION_TYPES.to_vec(),
            "上线扩展列表必须是捕获的 15 个（此前被剥成 12 个，JA4 失配）"
        );
        let base_len = baseline.len();

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

        // supported_versions 的列表长度是 u8（不同于 supported_groups 的 u16）。
        if let Some(extension) = find_extension(bytes, &layout.extensions_len_range, 0x002b).unwrap()
        {
            let versions_len = bytes[extension.data_range.start] as usize;
            let versions_end =
                (extension.data_range.start + 1 + versions_len).min(extension.data_range.end);
            let mut cursor = extension.data_range.start + 1;
            while cursor + 2 <= versions_end {
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
    fn auxiliary_key_share_shapes_are_validated_at_load_time() {
        // 65 字节 0x04（P-256）与 1216 字节（X25519MLKEM768 混合）是仅有的
        // 合法形状。
        let mut p256 = [0u8; 65];
        p256[0] = 0x04;
        let ranges = vec![Range { start: 0, end: 65 }];
        assert!(validate_auxiliary_key_share_shapes(&p256, &ranges).is_ok());
        let ranges = vec![Range { start: 0, end: 1216 }];
        assert!(validate_auxiliary_key_share_shapes(&[0u8; 1216], &ranges).is_ok());

        // P-384（97 B）/ P-521（133 B）0x04 前缀份额：ring 无法生成合法点，
        // 必须 fail closed，绝不随机填充。
        for len in [97usize, 133] {
            let mut share = vec![0u8; len];
            share[0] = 0x04;
            let ranges = vec![Range { start: 0, end: len }];
            assert!(
                validate_auxiliary_key_share_shapes(&share, &ranges).is_err(),
                "{}0x04-prefixed share (P-384/P-521) must be rejected",
                len
            );
        }

        // 65 字节但非 0x04 前缀，以及未知形状：同样拒绝。
        let mut not_sec1 = [0u8; 65];
        not_sec1[0] = 0x03;
        let ranges = vec![Range { start: 0, end: 65 }];
        assert!(validate_auxiliary_key_share_shapes(&not_sec1, &ranges).is_err());
        let ranges = vec![Range { start: 0, end: 32 }];
        assert!(validate_auxiliary_key_share_shapes(&[0u8; 32], &ranges).is_err());
        assert!(validate_auxiliary_key_share_shapes(&[], &[]).is_ok());
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

    /// 实测：捕获的 Firefox ClientHello 里 GREASE 值 **0 个**（cipher_suites 16
    /// 项、supported_groups 7 项、扩展类型 15 项、supported_versions 2 项，全无
    /// 0x?A?A 形态的值）。Firefox/NSS 不在 ClientHello 做 GREASE，那是
    /// Chrome/BoringSSL 的行为。此前 `apply_client_hello_randomization` 的注释断言
    /// 「Real Firefox/NSS uses a single GREASE value for every GREASE position …」，
    /// 与实测相反。本测试把「Firefox 不 GREASE」这个事实固化下来 —— 顺带说明
    /// GREASE 轮换路径对默认预设完全无作用，只对自定义模板生效。
    #[test]
    fn firefox_template_has_no_grease_positions() {
        assert!(
            instantiated_grease_values(FIREFOX_BOOTSTRAP_CLIENT_HELLO).is_empty(),
            "捕获的 Firefox ClientHello 必须不含任何 GREASE 值"
        );
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"firefox-no-grease-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);
        let out = template
            .instantiate(&derived_psk, &noise_init, 1_700_000_000)
            .unwrap();
        assert!(
            instantiated_grease_values(&out).is_empty(),
            "实例化不得凭空引入 GREASE 值：Firefox 在此维度上恒定，随机化本身就是特征"
        );
    }

    /// GREASE 轮换的语义已从「一条 ClientHello 内所有位置同值」**反转**为「逐位置
    /// 独立取值」。依据：BoringSSL 的 `ssl_get_grease_value` 从每连接 grease_seed
    /// 里按索引（cipher / group / extension1 / extension2 / version）取互相独立的
    /// 值，并对第二个 GREASE 扩展强制 `ret ^= 0x1010`，保证同一 ClientHello 里两个
    /// GREASE 扩展类型必不相同 —— 后者同时也是 RFC 8446 §4.2 的硬要求（同一
    /// extension block 内不得有重复类型）。把所有位置写成同值既不像 Chrome，也会
    /// 产出非法的 ClientHello。
    ///
    /// 该测试跑在人工构造的字节数组上：内嵌 Firefox 模板不含 GREASE（见
    /// `firefox_template_has_no_grease_positions`），这条路径只覆盖自定义模板。
    #[test]
    fn grease_positions_rotate_independently_per_connection() {
        let mut bytes = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        let layout = parse_client_hello_layout(&bytes).unwrap();

        // Inject one GREASE value per position class (same-length patches):
        // cipher_suites[0], supported_groups[0], supported_versions[0], and two
        // extension type slots (BoringSSL emits exactly two GREASE extensions).
        bytes[layout.cipher_suites_range.start..layout.cipher_suites_range.start + 2]
            .copy_from_slice(&0x0A0Au16.to_be_bytes());
        let groups_extension = find_extension(&bytes, &layout.extensions_len_range, 0x000a)
            .unwrap()
            .expect("firefox template must carry supported_groups");
        let first_group_offset = groups_extension.data_range.start + 2;
        bytes[first_group_offset..first_group_offset + 2]
            .copy_from_slice(&0x1A1Au16.to_be_bytes());
        let versions_extension = find_extension(&bytes, &layout.extensions_len_range, 0x002b)
            .unwrap()
            .expect("firefox template must carry supported_versions");
        let first_version_offset = versions_extension.data_range.start + 1;
        bytes[first_version_offset..first_version_offset + 2]
            .copy_from_slice(&0x3A3Au16.to_be_bytes());
        for (ext_type, grease) in [(0x0017u16, 0x2A2Au16), (0x0012u16, 0x4A4Au16)] {
            let extension = find_extension(&bytes, &layout.extensions_len_range, ext_type)
                .unwrap()
                .unwrap_or_else(|| panic!("firefox template must carry {:#06x}", ext_type));
            let type_offset = extension.data_range.start - 4;
            bytes[type_offset..type_offset + 2].copy_from_slice(&grease.to_be_bytes());
        }

        let template = template_from_bytes(bytes);
        let derived_psk = common::derive_psk(b"grease-rotation-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        // 每次实例化：5 个 GREASE 位置全部保持合法 GREASE 值，两个 GREASE 扩展
        // 类型互不相同（RFC 8446 §4.2 + BoringSSL 的 ^0x1010 规则）。
        let sample = |counter: u64| {
            let out = template
                .instantiate(&derived_psk, &noise_init, counter)
                .unwrap();
            let values = instantiated_grease_values(&out);
            assert_eq!(
                values.len(),
                5,
                "expected GREASE at all five injected positions, got {:?}",
                values
            );
            for value in &values {
                assert!(
                    GREASE_VALUES.contains(value),
                    "rotated GREASE value {:#06x} must stay a valid GREASE value",
                    value
                );
            }
            let ext_values: Vec<u16> = extension_types(&out)
                .into_iter()
                .filter(|t| is_grease_value(*t))
                .collect();
            assert_eq!(ext_values.len(), 2);
            assert_ne!(
                ext_values[0], ext_values[1],
                "同一 ClientHello 内两个 GREASE 扩展类型必须不同（RFC 8446 §4.2）"
            );
            // 归一化必须能抹平任意 GREASE 取值 —— 逐位置独立取值与指纹稳定性
            // 自洽的前提。
            values
        };

        // 逐连接重新取值。此前这条断言只重试一次，两次撞上同一个值的概率不可
        // 忽略（16 个候选、多个位置，实测约 1/256 偶发变红）。现在按位置聚合
        // 多轮采样：只要任一位置在若干轮中出现过 ≥2 个不同取值即证明重新随机
        // 化；32 轮里某个位置全程恒定的概率是 16^-31，不可能偶发。
        const ROUNDS: usize = 32;
        let mut observed: Vec<BTreeSet<u16>> = vec![BTreeSet::new(); 5];
        for round in 0..ROUNDS {
            let values = sample(1_700_000_000 + round as u64);
            for (slot, value) in values.into_iter().enumerate() {
                observed[slot].insert(value);
            }
        }
        for (slot, values) in observed.iter().enumerate() {
            assert!(
                values.len() > 1,
                "GREASE 位置 {} 在 {} 轮里恒为 {:?}，必须逐连接重新随机化",
                slot,
                ROUNDS,
                values
            );
        }
    }

    /// GREASE 归一化必须把任意取值抹平，否则逐位置独立取值会让指纹每连接唯一。
    #[test]
    fn grease_rotation_stays_fingerprint_invariant() {
        let mut bytes = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        let layout = parse_client_hello_layout(&bytes).unwrap();
        bytes[layout.cipher_suites_range.start..layout.cipher_suites_range.start + 2]
            .copy_from_slice(&0x0A0Au16.to_be_bytes());
        let versions_extension = find_extension(&bytes, &layout.extensions_len_range, 0x002b)
            .unwrap()
            .unwrap();
        let first_version_offset = versions_extension.data_range.start + 1;
        bytes[first_version_offset..first_version_offset + 2]
            .copy_from_slice(&0x3A3Au16.to_be_bytes());
        let ems_extension = find_extension(&bytes, &layout.extensions_len_range, 0x0017)
            .unwrap()
            .unwrap();
        let ems_type_offset = ems_extension.data_range.start - 4;
        bytes[ems_type_offset..ems_type_offset + 2].copy_from_slice(&0x2A2Au16.to_be_bytes());

        let template = template_from_bytes(bytes);
        let derived_psk = common::derive_psk(b"grease-fingerprint-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let mut fingerprints = BTreeSet::new();
        for counter in 0..32u64 {
            let out = template
                .instantiate(&derived_psk, &noise_init, counter + 1)
                .unwrap();
            fingerprints.insert(
                stable_client_hello_fingerprint(&out).expect("fingerprint GREASE template"),
            );
        }
        assert_eq!(
            fingerprints.len(),
            1,
            "GREASE 逐位置独立取值后，归一化后的指纹仍必须跨连接唯一稳定"
        );
    }

    /// **C18 回归门禁。** 此前 0x001d 主份额与混合份额尾部 32 字节都用
    /// `fill_bytes` 填充，于是每条连接在 ClientHello 里泄漏可判别的比特：真实
    /// X25519 公钥是 mod 2^255-19 归约后的 u 坐标，小端序下 byte 31 最高位恒为 0，
    /// 而均匀随机字节有一半概率置位。误报率严格为 0，censor 每流只需读 1–2 字节。
    ///
    /// 注意：ring 的 X25519 `agree_ephemeral` 对任意 32 字节对端公钥都接受、不做
    /// 任何校验（不同于 P-256 的点校验），所以这里没有「用 ECDH 成功证明合法」
    /// 这条路 —— MSB 断言才是真正有效的检验。N 次采样偶然全部通过的概率是 2^-N。
    #[test]
    fn instantiated_x25519_key_shares_have_msb_clear_and_are_fresh() {
        const SAMPLES: usize = 64;
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"x25519-msb-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let mut main_shares = BTreeSet::new();
        let mut hybrid_tails = BTreeSet::new();
        for sample in 0..SAMPLES {
            let out = template
                .instantiate(&derived_psk, &noise_init, sample as u64 + 1)
                .unwrap();
            let layout = parse_client_hello_layout(&out).unwrap();

            let main = out[layout.key_share_range.clone()].to_vec();
            assert_eq!(main.len(), 32);
            assert_eq!(
                main[31] & 0x80,
                0,
                "sample {}: 0x001d key_share byte 31 MSB set — 真实 X25519 公钥该位恒为 0",
                sample
            );

            let hybrid_range = layout
                .auxiliary_key_share_ranges
                .iter()
                .find(|range| range.end - range.start == 1216)
                .expect("firefox template must carry a 1216-byte X25519MLKEM768 share");
            let hybrid = &out[hybrid_range.clone()];
            let tail = hybrid[1184..1216].to_vec();
            assert_eq!(
                tail[31] & 0x80,
                0,
                "sample {}: hybrid share[1215] MSB set — [1184..1216) 必须是真实 X25519 公钥",
                sample
            );

            // 真实 Firefox 在同时提供 x25519 与 X25519MLKEM768 时复用同一个 X25519
            // 密钥对（NSS bug 1902119 / NSS 3.103），捕获模板逐字节印证。两处独立
            // 生成会让「两份额不相等」成为单连接、零误报的判别特征。
            assert_eq!(
                tail, main,
                "sample {}: 混合份额的 X25519 半部必须与 0x001d 份额同值",
                sample
            );

            // ML-KEM 系数段必须仍全部落在 [0, 3329)。
            for chunk in hybrid[..1152].chunks_exact(3) {
                let d0 = chunk[0] as u16 | (((chunk[1] & 0x0F) as u16) << 8);
                let d1 = ((chunk[1] >> 4) as u16) | ((chunk[2] as u16) << 4);
                assert!(d0 < 3329 && d1 < 3329, "ML-KEM coefficient out of range");
            }

            main_shares.insert(main);
            hybrid_tails.insert(tail);
        }

        // 不能为了修 MSB 而退化成常量 —— 那会触发「能被稳定识别 = 会被封」。
        assert_eq!(
            main_shares.len(),
            SAMPLES,
            "0x001d key_share 必须逐连接不同"
        );
        assert_eq!(
            hybrid_tails.len(),
            SAMPLES,
            "混合份额的 X25519 半部必须逐连接不同"
        );
    }

    /// 捕获模板的 ECH `enc` 第 31 字节最高位是 1（0x98），真实 X25519 公钥该位恒为
    /// 0 —— 也就是说 Firefox 的 GREASE ECH `enc` 是均匀随机字节，不是真实 HPKE
    /// 封装公钥。本测试把这个反直觉的事实固化：`enc` 上不得出现 MSB 恒清零的偏置
    /// （那正是「顺手改成 fill_x25519_public_key」会引入的特征）。
    #[test]
    fn ech_grease_fields_are_uniform_random_not_x25519_keys() {
        const SAMPLES: usize = 128;
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"ech-grease-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let captured_layout = parse_client_hello_layout(FIREFOX_BOOTSTRAP_CLIENT_HELLO).unwrap();
        let captured_ech = captured_layout
            .ech_grease_ranges
            .clone()
            .expect("捕获模板必须带 GREASE ECH");
        assert_eq!(captured_ech.enc.end - captured_ech.enc.start, 32);
        assert_eq!(captured_ech.payload.end - captured_ech.payload.start, 239);
        assert_ne!(
            FIREFOX_BOOTSTRAP_CLIENT_HELLO[captured_ech.enc.end - 1] & 0x80,
            0,
            "捕获的 ECH enc byte 31 最高位是 1 —— 它不是真实 X25519 公钥"
        );

        let mut enc_msb_set = 0usize;
        let mut config_ids = BTreeSet::new();
        let mut encs = BTreeSet::new();
        let mut payloads = BTreeSet::new();
        for sample in 0..SAMPLES {
            let out = template
                .instantiate(&derived_psk, &noise_init, sample as u64 + 1)
                .unwrap();
            let layout = parse_client_hello_layout(&out).unwrap();
            let ech = layout.ech_grease_ranges.clone().expect("ECH must survive");
            // cipher_suite（kdf‖aead）与所有长度字段必须恒定 —— 真实端点的 HPKE
            // 套件是编译期常量，随机化它本身就是判别特征。
            assert_eq!(out[ech.config_id - 5], 0, "ECHClientHello.type 必须恒为 outer(0)");
            assert_eq!(&out[ech.config_id - 4..ech.config_id], &[0x00, 0x01, 0x00, 0x01]);
            assert_eq!(ech.enc.end - ech.enc.start, 32);
            assert_eq!(ech.payload.end - ech.payload.start, 239);

            if out[ech.enc.end - 1] & 0x80 != 0 {
                enc_msb_set += 1;
            }
            config_ids.insert(out[ech.config_id]);
            encs.insert(out[ech.enc.clone()].to_vec());
            payloads.insert(out[ech.payload.clone()].to_vec());
        }

        // 均匀随机 ⇒ 期望 SAMPLES/2 次置位。真实密钥会给 0；容差远宽于噪声。
        assert!(
            enc_msb_set > SAMPLES / 8 && enc_msb_set < SAMPLES * 7 / 8,
            "ECH enc byte 31 MSB 在 {}/{} 个样本中置位 —— GREASE ECH 的 enc 必须是均匀\
             随机字节，任何偏置（尤其是恒为 0，即误用真实 X25519 公钥）都是特征",
            enc_msb_set,
            SAMPLES
        );
        assert_eq!(encs.len(), SAMPLES, "ECH enc 必须逐连接刷新");
        assert_eq!(payloads.len(), SAMPLES, "ECH payload 必须逐连接刷新");
        assert!(
            config_ids.len() > 32,
            "ECH config_id 必须逐连接随机（{} 个不同值 / {} 样本）",
            config_ids.len(),
            SAMPLES
        );
    }

    /// **2c 强耦合门禁。** ECH 的三个字段逐连接刷新，若指纹归一化不同步扩展，
    /// 每条连接的稳定指纹都会不同 ⇒ 服务端按指纹 key 的伪装 profile 缓存退化成
    /// 每连接一条 ⇒ 每条客户端连接都触发一次对伪装端点的实时 fetch（既是性能
    /// 回退，也是一个新的可观测行为）。
    #[test]
    fn stable_fingerprint_is_invariant_across_ech_refresh() {
        const SAMPLES: usize = 32;
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        let derived_psk = common::derive_psk(b"ech-fingerprint-psk");
        let mut noise_init = [0u8; 48];
        noise_init[..32].fill(7);
        noise_init[32..48].fill(9);

        let mut fingerprints = BTreeSet::new();
        let mut ech_fields = BTreeSet::new();
        for sample in 0..SAMPLES {
            let out = template
                .instantiate(&derived_psk, &noise_init, sample as u64 + 1)
                .unwrap();
            let layout = parse_client_hello_layout(&out).unwrap();
            let ech = layout.ech_grease_ranges.clone().unwrap();
            ech_fields.insert(out[ech.config_id..ech.payload.end].to_vec());
            fingerprints
                .insert(stable_client_hello_fingerprint(&out).expect("fingerprint with ECH"));
        }
        assert_eq!(
            ech_fields.len(),
            SAMPLES,
            "前提：ECH 字段确实逐连接变化，否则本测试无意义"
        );
        assert_eq!(
            fingerprints.len(),
            1,
            "ECH 存在时，多次 instantiate 的 stable_client_hello_fingerprint 必须完全相同"
        );
    }

    /// ECH 归一化只允许动 `config_id`/`enc`/`payload`，长度字段与 cipher_suite 必须
    /// 原样保留 —— 长度自洽被破坏会让整条记录无法解析，抹平 cipher_suite 则丢失
    /// 真实的指纹信息。
    #[test]
    fn malformed_ech_extension_is_rejected_at_template_build() {
        // enc_len 被改成 33，payload 长度便无法填满 extension_data。
        let mut bytes = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        let layout = parse_client_hello_layout(&bytes).unwrap();
        let ech = layout.ech_grease_ranges.clone().unwrap();
        let enc_len_offset = ech.enc.start - 2;
        write_u16(&mut bytes, enc_len_offset..enc_len_offset + 2, 33).unwrap();
        let err = parse_client_hello_layout(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("encrypted_client_hello"),
            "无法刷新的 ECH 必须在模板构建期 fail closed，而不是逐字节重放：{}",
            err
        );

        // 非 outer(0) 类型同样 fail closed：inner(1) 没有可刷新的字段。
        let mut inner = FIREFOX_BOOTSTRAP_CLIENT_HELLO.to_vec();
        inner[ech.config_id - 5] = 1;
        assert!(parse_client_hello_layout(&inner).is_err());
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
