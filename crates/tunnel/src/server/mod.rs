mod auth;
mod camouflage;
mod fallback;
mod replay;
#[cfg(test)]
mod wire_tests;

pub use camouflage::validate_camouflage_endpoint;

use auth::*;
use camouflage::*;
use fallback::*;
use replay::*;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::common::{
    self, apply_tcp_keepalive, max_flight3_total_wire_len, SnowyStream, AEAD_TAG_LEN,
    FLIGHT3_CCS_RECORD, FLIGHT3_FINISHED_PLAINTEXT_LEN, FLIGHT3_FINISHED_RECORD_LEN,
    TLS_RECORD_HEADER_LEN,
};
use crate::utils::{
    client_hello_random_and_session_id_ranges, constant_time_eq, derive_counter_mac,
    extract_client_hello_server_name, mask_mac_flags, unmask_noise_ephemeral_key,
};

/// [`server_accept`] 的失败分类。
///
/// # 为什么必须是类型而不是错误文案
///
/// 调用方需要按「预期拒绝 vs 真正故障」选日志级别：对任何暴露在公网 443 的
/// 端口，pre-auth 失败（端口扫描、主动探测、误连、走错 SNI 的真实浏览器）都是
/// **常态**。若它们走 `error!`，扫描者每建一条 TCP 就能让服务端写下一行含其
/// 可控源 IP 的日志——日志放大 / 磁盘填满，而且日志写入在 tokio worker 上同步
/// 发生。
///
/// 此前这个分流是在 `kanotls/src/server.rs` 里用 `Error::to_string()` 的子串
/// 匹配做的，而这种做法已经**静默失效过一次**：needle `"session closed"` 与
/// 任何实际文案都不匹配（真实文案是 `"session is closed"`），把一类预期结束
/// 长期误判成 `error!` 且无人察觉。任一条 `bail!` 的文案被改动都会复现同样的
/// 静默失配，编译器不会给出任何提示。改成类型化之后，新增失败路径必须显式
/// 选一个变体，漏选不会编译。
#[derive(Debug)]
pub enum ServerAcceptError {
    /// **Noise 认证提交之前**的拒绝。对端已按 §5.2 得到透明回落或统一关闭
    /// 姿态，观察不到任何差异。这类结果由对端的输入完全决定、成本为零，
    /// 因此调用方必须记 `debug!`。
    PreAuth(anyhow::Error),
    /// 认证之后的内部故障（伪装采样失败、缓存 profile 与连接不自洽、
    /// Flight 3 校验失败、配置缺陷等）。运维需要看见，记 `error!`。
    Internal(anyhow::Error),
}

impl ServerAcceptError {
    fn pre_auth(err: impl Into<anyhow::Error>) -> Self {
        Self::PreAuth(err.into())
    }
}

impl std::fmt::Display for ServerAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreAuth(err) | Self::Internal(err) => std::fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for ServerAcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PreAuth(err) | Self::Internal(err) => Some(err.as_ref()),
        }
    }
}

/// 未显式分类的 `?` 一律落到 `Internal`。
///
/// 方向是刻意选的：漏标一条**预期**路径只会多写一行 `error!`（吵，但安全）；
/// 反过来把默认设成 `PreAuth` 则会让真正的故障静悄悄消失。
impl From<anyhow::Error> for ServerAcceptError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err)
    }
}

/// Classification of a pre-auth failure. Only `CapacityLimited` carries branch
/// semantics (it selects the dedicated capacity-limited path inside
/// `emit_pre_auth_failure`); the other variants just document which check
/// rejected the handshake and are otherwise handled identically.
#[derive(Clone, Copy, Debug)]
pub(super) enum FailureClass {
    NonTlsFirstRecord,
    AuthFailed,
    HandshakeTimeout,
    InvalidFirstRecord,
    MissingSni,
    SniMismatch,
    CapacityLimited,
}

/// Outcome of a successful multi-user ClientHello authentication: the matched
/// user index (into the PSK slice passed to [`server_accept`]), the Noise
/// responder state built with that user's PSK, and the anti-replay ticket to
/// commit once the handshake is fully accepted.
struct AuthSuccess {
    user_index: usize,
    derived_psk: [u8; common::PSK_LEN],
    noise: snow::HandshakeState,
    replay_check: Option<ReplayCheck>,
}

// 测试探针：本线程内「为某个候选 PSK 构建 Noise responder 状态」的次数。
//
// P2 重排（见 `authenticate_client_hello` 内的说明）的可观测代理指标：
// N 用户配置下，一次握手最多只应构建 1 次 Noise 状态。用 thread-local 而非
// 全局计数器，是因为 `authenticate_client_hello` 全程同步、不跨线程，
// 这样并发运行的其他测试（尤其 `server_accept` 跑在 tokio worker 线程上）
// 不会污染计数。
#[cfg(test)]
thread_local! {
    static NOISE_RESPONDER_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Probes every candidate derived PSK against the ClientHello in `pld` and
/// returns the first one that passes the counter MAC, ephemeral-key unmasking,
/// the Noise handshake message and the replay-window checks. Only a
/// MAC-matching candidate ever reaches the Noise probe, so a non-matching
/// candidate costs a few hashes and no asymmetric crypto.
fn authenticate_client_hello(
    pld: &[u8],
    derived_psks: &[[u8; common::PSK_LEN]],
    client_noise_tag: &mut [u8; 16],
    peer_addr: SocketAddr,
) -> Option<AuthSuccess> {
    let (random_range, session_id_range) = client_hello_random_and_session_id_ranges(pld)?;
    let random = &pld[random_range];
    let session_id = &pld[session_id_range];
    if session_id.len() < 32 {
        debug!(
            "session_id too short for Noise auth: {} bytes (need >= 32)",
            session_id.len()
        );
        return None;
    }

    let mut random_copy = [0u8; 32];
    random_copy.copy_from_slice(random);
    client_noise_tag.copy_from_slice(&session_id[..16]);

    let mut masked_counter = [0u8; 8];
    masked_counter.copy_from_slice(&session_id[16..24]);
    let mut got_mac = [0u8; 8];
    got_mac.copy_from_slice(&session_id[24..32]);
    mask_mac_flags(&mut got_mac);

    let random_prefix: &[u8] = &random_copy[..16];

    for (user_index, derived_psk) in derived_psks.iter().enumerate() {
        // counter-MAC 比对前置于 Noise 探测。
        //
        // 此前每个候选 PSK 的顺序是「解掩临时密钥 → build_responder →
        // read_message → 才比对 MAC」，于是**每一个**配置用户都要先付一次
        // 完整的 Noise 探测，而 counter-MAC 比对只要一次 keyed BLAKE2s。
        // release 实测（2000 次迭代）：Noise 探测 ≈6.3–8.0 µs/PSK
        // （其中 ≈7 µs 落在 `read_message`：NNpsk0 第一条消息要走
        // mix_key_and_hash(psk) + mix_hash(e) + mix_key(e) 三段 HKDF 链再加
        // 一次 AEAD 解密；此处**没有** X25519——`ee` 纯量乘在应答侧的
        // `write_message` 才发生），counter-MAC ≈0.2–0.3 µs/PSK，比值 22–32×。
        // 更要紧的是它是放大型 DoS 的杠杆：探测者用一个垃圾 ClientHello 就能
        // 迫使服务端对每个配置用户各跑一遍完整探测，`MAX_HANDSHAKES = 512`
        // 之下 50 用户配置每波 150–200 CPU-ms 全是无用功（重排后 5–10 CPU-ms）。
        //
        // 允许前置的依据：`derive_counter_mac` 的四个输入（derived_psk、
        // client random、masked counter、random[..16]）全部取自原始
        // ClientHello 字节，与 Noise 状态完全无关，不存在需要先跑
        // `read_message` 才能满足的前置条件。
        //
        // 合取条件未变 ⇒ 认证结果严格等价：仍按 user_index 升序取首个
        // **全部**检查通过者。MAC 命中（碰撞概率 2^-62 量级）而后续
        // Noise / counter / replay 检查失败时必须 `continue` 继续尝试下一个
        // PSK，不能提前返回 None——否则一次 MAC 碰撞就能顶掉真正的用户。
        // `check_counter_replay`（会 bump LRU 顺序）与 `is_replay`（命中即
        // 写入 REPLAY_CACHE）的调用条件集合也与重排前完全相同：两者仍然
        // 只在「MAC 通过且 Noise 通过」时被调用，因此副作用的次数与时机不变。
        let want_mac = derive_counter_mac(derived_psk, &random_copy, &masked_counter, random_prefix);
        let mut want_mac_masked = want_mac;
        mask_mac_flags(&mut want_mac_masked);
        if !constant_time_eq(&got_mac, &want_mac_masked) {
            continue;
        }

        let recovered_e = unmask_noise_ephemeral_key(&random_copy, derived_psk, client_noise_tag);
        if recovered_e == [0u8; 32] {
            continue;
        }

        let mut noise_init = [0u8; 48];
        noise_init[..32].copy_from_slice(&recovered_e);
        noise_init[32..48].copy_from_slice(&session_id[..16]);

        let Ok(builder) = snow::Builder::new(common::NOISE_PARAMS.clone()).psk(0, derived_psk)
        else {
            continue;
        };
        #[cfg(test)]
        NOISE_RESPONDER_BUILDS.with(|count| count.set(count.get() + 1));
        let Ok(mut noise) = builder.build_responder() else {
            continue;
        };
        match noise.read_message(&noise_init, &mut []) {
            Ok(0) => {}
            Ok(len) => {
                debug!("unexpected Noise init plaintext length: {}", len);
                continue;
            }
            Err(_) => continue,
        }

        let check = check_counter_replay(derived_psk, &random_copy, masked_counter);
        if check.is_none() {
            continue;
        }
        if is_replay(&random_copy) {
            warn!(
                "replayed Noise client ephemeral rejected from {}",
                peer_addr
            );
            continue;
        }

        return Some(AuthSuccess {
            user_index,
            derived_psk: *derived_psk,
            noise,
            replay_check: check,
        });
    }

    None
}

pub async fn server_accept(
    mut tcp: TcpStream,
    derived_psks: &[[u8; common::PSK_LEN]],
    camouflage_host: &str,
    camouflage_port: u16,
) -> Result<(SnowyStream, usize), ServerAcceptError> {
    // `set_nodelay` / `peer_addr` 作用在**刚 accept 出来的客户端 socket** 上，
    // 失败由对端掌控：`connect` 之后立刻 RST，socket 进入 TCP_CLOSE。此前这两条
    // 走的是 `?`，落到默认分类里被记成 `error!`——于是一次「connect + RST」的扫描
    // 就能按连接数写下等量的 error 行，和这次重构要堵的那个洞是同一类。归入 PreAuth。
    //
    // 实测（Linux，`SO_LINGER 0` 关闭后）只有 `peer_addr` 会失败：`getpeername(2)`
    // 返回 ENOTCONN，而 `setsockopt(TCP_NODELAY)` 仍然成功。两条都归 PreAuth 依然
    // 正确（客户端 socket 上的 IO 错误，无任何运维价值），但可被对端触发的只有后者。
    tcp.set_nodelay(true).map_err(ServerAcceptError::pre_auth)?;
    let _ = apply_tcp_keepalive(&tcp);
    let handshake_permit = match HANDSHAKE_LIMITER.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            // 限额耗尽是唯一走不到透明转发的分支（此处尚未读取任何字节，
            // 无法构造有意义的上游请求）。统一走「有界排空 + 立即关闭」的
            // 姿态，与其他限额耗尽路径不可区分——这也正是真实 nginx 在
            // worker_connections 耗尽时的行为（accept 之后立即关闭）。
            emit_indistinguishable_close(tcp).await;
            return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
                "server handshake limit reached"
            )));
        }
    };
    let peer_addr = tcp.peer_addr().map_err(ServerAcceptError::pre_auth)?;
    debug!("new connection from {}", peer_addr);

    if derived_psks.is_empty() {
        // 配置缺陷，不是对端造成的：服务端起来了却一个用户都没有。
        return Err(ServerAcceptError::Internal(anyhow::anyhow!(
            "server requires at least one user PSK"
        )));
    }
    let mut client_noise_tag = [0u8; 16];

    let mut rx_buf = Vec::new();
    let initial_deadlines = initial_record_deadlines();
    let (typ, _) = match read_initial_client_record(&mut tcp, &mut rx_buf, initial_deadlines).await
    {
        Ok(res) => res,
        Err(e) => {
            let class = if e.kind() == std::io::ErrorKind::TimedOut {
                FailureClass::HandshakeTimeout
            } else {
                FailureClass::InvalidFirstRecord
            };
            drop(handshake_permit);
            // 一律回落转发。`rx_buf` 只含客户端真实发送过的字节（可能为空），
            // 转发给伪装端点后由它自己决定如何回应——这正是直连时会发生的事。
            //
            // 此前这里按「rx_buf 是否为空」与「是否超长」分流到静默关闭，
            // 制造了两个 5 字节成本、零误报的主动探测特征：
            //   * 连上不发数据 → 恰好 T+10.000s 静默 FIN；
            //   * 发 `16 03 03 41 01` → 瞬时静默关闭（且因队列有未读数据发 RST）。
            emit_pre_auth_failure(tcp, rx_buf, camouflage_host, camouflage_port, class).await;
            return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
                "Failed to read initial TLS record: {}",
                e
            )));
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
        return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
            "First record is not a TLS Handshake"
        )));
    }

    let client_hello_server_name = extract_client_hello_server_name(&rx_buf).map(str::to_owned);
    let pld = &mut rx_buf[..];

    let auth = authenticate_client_hello(pld, derived_psks, &mut client_noise_tag, peer_addr);

    let Some(AuthSuccess {
        user_index,
        derived_psk,
        noise,
        replay_check,
    }) = auth
    else {
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
        return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
            "Noise authentication failed"
        )));
    };

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
            return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
                "ClientHello missing valid SNI"
            )));
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
        return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
            "client hello SNI '{}' does not match configured camouflage host '{}'",
            client_hello_server_name,
            camouflage_host
        )));
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
            return Err(ServerAcceptError::pre_auth(anyhow::anyhow!(
                "server active session limit reached"
            )));
        }
    };

    let mut noise_state = Some(noise);

    if let Some(ref check) = replay_check {
        if !commit_counter_replay(check) {
            // 认证已通过，但同一计数器被并发提交抢先——重放，或同一客户端的
            // 罕见竞态。对端持有有效凭据，不构成日志放大面，保持 Internal。
            return Err(ServerAcceptError::Internal(anyhow::anyhow!(
                "counter commit rejected: window advanced past sequence"
            )));
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

    consume_client_flight3_ghost(&mut tcp, &mut noise).await?;

    Ok((
        SnowyStream::new_with_permit(tcp, noise, Some(_session_permit)),
        user_index,
    ))
}

pub(super) async fn consume_client_flight3_ghost(
    tcp: &mut TcpStream,
    noise: &mut common::NoiseTransport,
) -> anyhow::Result<()> {
    let max_wire = max_flight3_total_wire_len();
    let mut wire = vec![0u8; max_wire];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(SERVER_HANDSHAKE_TIMEOUT_SECS);

    let ccs_len = FLIGHT3_CCS_RECORD.len();
    let fin_record_len = FLIGHT3_FINISHED_RECORD_LEN;
    let minimum_needed = ccs_len + fin_record_len + TLS_RECORD_HEADER_LEN;

    // Reads are capped at `minimum_needed`, so this loop never consumes a byte
    // of the first upload TLS record that may immediately follow Flight 3.
    let mut total_read = 0usize;
    while total_read < minimum_needed {
        let n = tokio::time::timeout_at(
            deadline,
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
    let fin_payload_len = u16::from_be_bytes([wire[fin_start + 3], wire[fin_start + 4]]) as usize;
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

    // total_read == minimum_needed == h2_start + TLS_RECORD_HEADER_LEN here,
    // so the H2 ghost record header is already in the buffer.
    let h2_start = fin_end;
    if wire[h2_start] != 0x17 {
        anyhow::bail!("invalid client Flight 3: H2 ghost record type mismatch");
    }
    let h2_payload_len = u16::from_be_bytes([wire[h2_start + 3], wire[h2_start + 4]]) as usize;
    if !(AEAD_TAG_LEN..=16384 + 256).contains(&h2_payload_len) {
        anyhow::bail!(
            "invalid client Flight 3: H2 ghost payload length {}",
            h2_payload_len
        );
    }
    let h2_total = TLS_RECORD_HEADER_LEN + h2_payload_len;
    let h2_end = h2_start + h2_total;
    wire.resize(h2_end, 0);

    while total_read < h2_end {
        let n = tokio::time::timeout_at(deadline, tcp.read(&mut wire[total_read..h2_end]))
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
    Ok(())
}

pub(super) async fn resolve_allowed_camouflage(
    host: &str,
    port: u16,
) -> anyhow::Result<SocketAddr> {
    if port == 0 {
        anyhow::bail!("invalid camouflage port 0");
    }

    // 走带 TTL 的共享解析缓存：本函数在每次 pre-auth 回落时都会调用，
    // 未缓存时一次端口扫描就会变成对本机解析器的等量放大。过滤留在此处，
    // 因为伪装端点的私网判定与代理出站的目的地判定是两套策略。
    let resolved = kanotls_proto::dns::resolve(host, port).await?;
    let mut first_allowed = None;
    for addr in resolved.iter().copied() {
        if is_blocked_camouflage_ip(addr.ip()) {
            debug!("skipping blocked camouflage address: {}", addr);
            continue;
        }
        first_allowed.get_or_insert(addr);
    }
    first_allowed.ok_or_else(|| anyhow::anyhow!("unable to resolve camouflage host"))
}

pub(super) fn is_blocked_camouflage_ip(ip: IpAddr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::common::derive_psk;
    use crate::utils::{
        client_hello_key_share_range, derive_counter_cache_key, derive_counter_mask,
        stable_client_hello_fingerprint, xor_u64_bytes,
    };

    fn test_psks(psk: &[u8]) -> Vec<[u8; common::PSK_LEN]> {
        vec![derive_psk(psk)]
    }

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

    fn build_tls_app_record(noise: &mut common::NoiseTransport, payload: &[u8]) -> Vec<u8> {
        use crate::common::{
            BLOCK_LEN_PREFIX_SIZE, INNER_CONTENT_TYPE_APP_DATA, INNER_CONTENT_TYPE_LEN,
        };
        let mut block = vec![0u8; BLOCK_LEN_PREFIX_SIZE + payload.len() + INNER_CONTENT_TYPE_LEN];
        block[..BLOCK_LEN_PREFIX_SIZE].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        block[BLOCK_LEN_PREFIX_SIZE..BLOCK_LEN_PREFIX_SIZE + payload.len()]
            .copy_from_slice(payload);
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

    fn write_bulk_via_shaper(stream: &mut SnowyStream, payload: &[u8]) {
        let cap = SnowyStream::data_record_capacity();
        let target_wire = SnowyStream::max_data_record_wire_len();
        for chunk in payload.chunks(cap) {
            stream
                .prepare_data_record(chunk, target_wire)
                .expect("prepare_data_record succeeded");
        }
    }

    fn build_client_flight3_and_upload(
        noise: &mut common::NoiseTransport,
        upload_payload: &[u8],
    ) -> Vec<u8> {
        let finished_plaintext = [0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN];
        let mut finished_ciphertext = vec![0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN];
        let finished_ct_len = noise
            .write_message(&finished_plaintext, &mut finished_ciphertext)
            .unwrap();

        let h2_plaintext = common::build_h2_ghost_plaintext(0);
        let mut h2_ciphertext = vec![0u8; h2_plaintext.len() + AEAD_TAG_LEN];
        let h2_ct_len = noise
            .write_message(&h2_plaintext, &mut h2_ciphertext)
            .unwrap();

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

    fn established_noise_pair() -> (common::NoiseTransport, common::NoiseTransport) {
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
            common::NoiseTransport::new(initiator.into_stateless_transport_mode().unwrap()),
            common::NoiseTransport::new(responder.into_stateless_transport_mode().unwrap()),
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

        consume_client_flight3_ghost(&mut server_tcp, &mut server_noise)
            .await
            .unwrap();

        // If the Flight 3 reader had consumed any byte of the first upload TLS
        // record, this read would hang or return corrupted data.
        let mut stream = SnowyStream::new_with_permit(server_tcp, server_noise, None);
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
            write_bulk_via_shaper(&mut client_stream, payload);
            client_stream.flush().await.unwrap();
            client_stream.shutdown().await.unwrap();
        });

        let mut server_stream = SnowyStream::new_with_permit(server_tcp, server_noise, None);

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
    async fn aead_failure_silently_closes_without_emitting_alert() {
        use crate::common::{AEAD_TAG_LEN, TLS_RECORD_HEADER_LEN};
        use std::time::Duration;

        let (mut client_noise, server_noise) = established_noise_pair();
        let (client_tcp, server_tcp) = connected_tcp_pair().await;

        // 1) 构造一条合法 0x17 application_data record。
        let payload = b"plaintext to be corrupted";
        let mut record = build_tls_app_record(&mut client_noise, payload);
        assert!(record.len() > TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN);

        // 2) 篡改密文最后 1 个字节 (AEAD tag 末位) —— 模拟偶发比特翻转 / 中间人篡改。
        let last = record.len() - 1;
        record[last] ^= 0xff;

        // 3) 通过 raw TcpStream 注入到 server 端,确保不会被 client 端 SnowyStream 加密封装。
        let mut injector = client_tcp;
        injector.write_all(&record).await.unwrap();
        injector.flush().await.unwrap();

        // 4) Server 端 SnowyStream 第一次 read 必须返回 InvalidData (AEAD 失败)。
        let mut server_stream = SnowyStream::new_with_permit(server_tcp, server_noise, None);
        let mut buf = vec![0u8; 256];
        let first = tokio::time::timeout(Duration::from_secs(3), server_stream.read(&mut buf))
            .await
            .expect("server read should not hang on corrupted AEAD");
        assert!(
            first.is_err(),
            "first read after AEAD corruption must error"
        );
        let err = first.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "AEAD failure must surface as InvalidData"
        );
        assert!(
            err.to_string().contains("noise decrypt"),
            "error message should mention noise decrypt, got: {}",
            err
        );

        // 5) 关键不变量:server 端不得向 client 回写任何字节 (无 Noise fatal alert,
        //    无 close_notify, 无 RST 之外的任何应用层语义信号)。
        //    给对端 100ms 读取窗口,任何静默关闭下"对端可读字节数"应当始终为 0。
        let mut probe = [0u8; 64];
        let probe_result =
            tokio::time::timeout(Duration::from_millis(100), injector.read(&mut probe)).await;
        match probe_result {
            Err(_) => {
                // 100ms 内未收到任何字节 —— 期望路径
            }
            Ok(Ok(0)) => {
                // FIN 优雅关闭,0 字节应用数据 —— 也接受
            }
            Ok(Ok(n)) => panic!(
                "server emitted {} bytes after AEAD failure (expected silent close/no alert): {:?}",
                n,
                &probe[..n]
            ),
            Ok(Err(e)) => panic!("unexpected error on probe read: {}", e),
        }

        // 6) 第二次 read 应返回 0 (Ok(0) 表示已进入 Closed 状态 / EOF),不 hang。
        let second = tokio::time::timeout(Duration::from_secs(2), server_stream.read(&mut buf))
            .await
            .expect("second read after AEAD failure must not hang");
        match second {
            Ok(0) => {}
            Ok(n) => panic!("second read returned {} bytes, expected EOF (0)", n),
            Err(e) => panic!("second read should return EOF (Ok(0)), got error: {}", e),
        }
    }

    #[tokio::test]
    async fn shutdown_with_pending_bulk_does_not_corrupt_sequence() {
        let (client_noise, server_noise) = established_noise_pair();
        let (client_tcp, server_tcp) = connected_tcp_pair().await;

        let bulk = vec![0xabu8; 64 * 1024];
        let bulk_len = bulk.len();
        let mut client_stream = SnowyStream::new(client_tcp, client_noise);

        let writer = tokio::spawn(async move {
            write_bulk_via_shaper(&mut client_stream, &bulk);
            client_stream.shutdown().await.unwrap();
        });

        let mut server_stream = SnowyStream::new_with_permit(server_tcp, server_noise, None);

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
                    b,
                    0xab,
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

    /// 限额耗尽路径以干净 FIN、零应用字节收尾（不发任何 TLS 告警）。
    /// 超时留足 `emit_indistinguishable_close` 的排空 + 随机延迟窗口
    /// （最长 200ms + 3000ms）。
    async fn expect_shaped_close(client: &mut TcpStream) {
        let mut buf = [0u8; 7];
        let read = tokio::time::timeout(Duration::from_secs(10), client.read(&mut buf))
            .await
            .expect("failure path should not hang indefinitely")
            .unwrap();
        assert_eq!(
            read, 0,
            "shaped failure must close silently without emitting any bytes"
        );
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
            first_app_data_delay_us: 0,
            early_app_data_gap_us: vec![],
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

    fn pooled(profile: CamouflageProfile) -> PooledProfile {
        PooledProfile {
            profile,
            fetched_at: Instant::now(),
        }
    }

    /// 测试用：走**生产路径**从 ClientHello 查缓存 profile。
    ///
    /// 生产代码里这两步分开是为了让指纹只算一次（`fetch_camouflage_flight`
    /// 先 `camouflage_cache_keys`，再把 key 交给 `lookup_cached_camouflage_profile`）。
    /// 这里把同样的两步串起来，因此这些测试仍然覆盖「ClientHello → key 推导」
    /// 与「查找顺序 / rank 优先级」的完整链路，且 key 的推导没有第二份实现。
    async fn lookup_cached_profile_for_client_hello(
        host: &str,
        port: u16,
        client_hello: &[u8],
    ) -> Option<CamouflageProfile> {
        let keys = camouflage_cache_keys(host, port, client_hello);
        lookup_cached_camouflage_profile(
            keys.as_ref().map(|k| k.profile.as_str()),
            keys.as_ref().map(|k| k.family_baseline.as_str()),
            &camouflage_baseline_key(host, port, "probe"),
        )
        .await
    }

    /// 变体的可比较身份（`CamouflageProfile` 未派生 `PartialEq`）。
    fn profile_identity(
        profile: &CamouflageProfile,
    ) -> (Vec<u8>, Vec<usize>, Vec<usize>, Vec<u32>, u32, bool) {
        (
            profile.server_records.to_vec(),
            profile.prefix_app_data_sizes.clone(),
            profile.app_data_sizes.to_vec(),
            profile.early_app_data_gap_us.clone(),
            profile.first_app_data_delay_us,
            profile.has_ccs,
        )
    }

    /// `sample_camouflage_profile` 的**旧实现**，逐字保留作为等价性参照：
    /// 先 `sanitize + clone` 每一个变体，再按 rank 过滤出候选集合，最后
    /// `gen_range(0..len)` 取一个。新实现只把「物化整池」换成「在引用上算
    /// rank、只克隆中选者」，因此只要候选集合（含顺序）一致，选取语义就
    /// 逐字一致——唯一的随机源仍是对该集合的一次均匀抽样。
    fn legacy_sample_candidates(pool: &CamouflageProfilePool) -> Vec<CamouflageProfile> {
        let mut usable: Vec<CamouflageProfile> = pool
            .profiles
            .iter()
            .map(|entry| sanitize_camouflage_profile(entry.profile.clone()))
            .filter(|profile| camouflage_profile_rank(profile) > 0)
            .collect();
        if usable.is_empty() {
            return Vec::new();
        }
        let max_rank = usable
            .iter()
            .map(camouflage_profile_rank)
            .max()
            .unwrap_or(0);
        usable.retain(|profile| camouflage_profile_rank(profile) == max_rank);
        usable
    }

    /// `sanitize_camouflage_profile` 必须幂等。
    ///
    /// 这是「在引用上算 rank 等价于在 sanitize 后的克隆上算 rank」的前提之一：
    /// 池中变体都是 sanitize 的输出，只有幂等才保证再 sanitize 一次不改变
    /// `app_data_sizes` 是否为空（rank 的两个输入之一）。
    #[test]
    fn sanitize_camouflage_profile_is_idempotent() {
        let cases = vec![
            CamouflageProfile {
                server_records: Arc::from(vec![0x16, 0x03, 0x03].into_boxed_slice()),
                prefix_app_data_sizes: vec![8, 23, 31, 40, 44, 50, 99999],
                app_data_sizes: Arc::from(vec![8, 23, 512, 6000, 20000].into_boxed_slice()),
                first_app_data_size: Some(8),
                early_app_data_count: 5,
                has_ccs: true,
                visible_server_record_count: 3,
                first_app_data_delay_us: 1234,
                early_app_data_gap_us: vec![1, 2, 3, 4, 5, 6],
            },
            // 全部尺寸越界 ⇒ sanitize 会把 app_data_sizes 清空（rank 因此下降）。
            test_camouflage_profile(vec![0x16], vec![1, 2, 99999]),
            test_camouflage_profile(vec![], vec![]),
        ];

        for profile in cases {
            let once = sanitize_camouflage_profile(profile);
            let twice = sanitize_camouflage_profile(once.clone());
            assert_eq!(
                profile_identity(&once),
                profile_identity(&twice),
                "sanitize 必须幂等"
            );
            assert_eq!(once.first_app_data_size, twice.first_app_data_size);
            assert_eq!(once.early_app_data_count, twice.early_app_data_count);
            assert_eq!(
                camouflage_profile_rank(&once),
                camouflage_profile_rank(&twice)
            );
        }
    }

    /// 入池的每个变体都必须**已经**是 sanitize 的输出。
    ///
    /// `push_profile_variant` 是 `CAMOUFLAGE_PROFILES` 的唯一写入路径；若哪天
    /// 有人绕开它直接塞入未 sanitize 的 profile，`sample_camouflage_profile`
    /// 在引用上算出的 rank 就可能高于它实际能提供的 rank。
    #[tokio::test]
    async fn pooled_profiles_are_stored_pre_sanitized() {
        let key = "pre-sanitized.example:443:deadbeef".to_string();
        // 越界尺寸 + 超量 prefix + 多余 gap：三处都会被 sanitize 削掉。
        let mut raw = test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![8, 53, 512, 99999]);
        raw.prefix_app_data_sizes = vec![8, 23, 31, 40, 44, 50];
        raw.early_app_data_gap_us = vec![10, 20, 30, 40, 50];
        store_camouflage_profile(key.clone(), raw).await;

        let mut profiles = CAMOUFLAGE_PROFILES.lock().await;
        let pool = profiles.get(&key).expect("pool stored");
        for entry in &pool.profiles {
            let resanitized = sanitize_camouflage_profile(entry.profile.clone());
            assert_eq!(
                profile_identity(&entry.profile),
                profile_identity(&resanitized),
                "池中变体必须已经是 sanitize 的输出"
            );
        }
    }

    /// **选取语义等价性**：新旧实现的候选集合（含顺序）逐项相同，且抽样确实
    /// 覆盖整个候选集合。
    ///
    /// 这是本次「单次加锁 + 只克隆中选者」重构的验收断言——它是纯性能改动，
    /// 哪个变体被选中、rank 如何优先、同 rank 如何轮换都必须逐字不变。
    #[tokio::test]
    async fn sample_camouflage_profile_selection_matches_legacy_candidate_set() {
        let pools = vec![
            // 混合 rank：rank3 ×1 / rank2 ×2（单条记录 [53] 与无尺寸 [0x16,0x02]
            // 都按 rank 2 计） / rank1 ⇒ 候选只能是那一个 rank3。
            vec![
                test_camouflage_profile(vec![0x16, 0x01], vec![53]),
                test_camouflage_profile(vec![0x16, 0x02], vec![]),
                test_camouflage_profile(vec![0x16, 0x03], vec![90, 128]),
                test_camouflage_profile(vec![], vec![256]),
            ],
            // 全 rank2。
            vec![
                test_camouflage_profile(vec![0x16, 0x01], vec![]),
                test_camouflage_profile(vec![0x16, 0x02], vec![]),
            ],
            // 全 rank0 ⇒ 无候选。
            vec![test_camouflage_profile(vec![], vec![])],
            // sanitize 后 app_data_sizes 被清空 ⇒ rank 从 3 掉到 2。
            vec![
                test_camouflage_profile(vec![0x16, 0x01], vec![1, 2]),
                test_camouflage_profile(vec![0x16, 0x02], vec![]),
            ],
            vec![],
        ];

        for profiles in pools {
            let mut pool = None;
            for profile in &profiles {
                pool = Some(push_profile_variant(pool, profile.clone()));
            }
            let pool = pool.unwrap_or(CamouflageProfilePool {
                profiles: Default::default(),
            });

            let legacy: Vec<_> = legacy_sample_candidates(&pool)
                .iter()
                .map(profile_identity)
                .collect();

            if legacy.is_empty() {
                assert!(
                    sample_camouflage_profile(&pool).is_none(),
                    "无可用变体时必须返回 None"
                );
                continue;
            }

            // 256 次抽样：既验证「结果恒在候选集合内」，也验证「每个候选都
            // 能被抽到」（同 rank 的轮换未被收窄成固定挑第一个）。
            let mut seen = std::collections::HashSet::new();
            for _ in 0..256 {
                let picked = sample_camouflage_profile(&pool).expect("候选集合非空");
                let identity = profile_identity(&picked);
                assert!(
                    legacy.contains(&identity),
                    "抽到了旧实现候选集合之外的变体：{:?}",
                    identity
                );
                seen.insert(identity);
            }
            assert_eq!(
                seen.len(),
                legacy.len(),
                "同 rank 的每个变体都必须可被抽到（旧实现是对候选集合的均匀抽样）"
            );
        }
    }

    #[tokio::test]
    async fn sample_camouflage_profile_prefers_complete_variants() {
        let profile = sample_camouflage_profile(&CamouflageProfilePool {
            profiles: vec![
                pooled(test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![])),
                pooled(test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![53, 1024])),
                pooled(test_camouflage_profile(vec![], vec![90])),
            ]
            .into_iter()
            .collect(),
        })
        .unwrap();

        assert_eq!(camouflage_profile_rank(&profile), 3);
        assert_eq!(&*profile.app_data_sizes, &[53, 1024][..]);
    }

    #[tokio::test]
    async fn camouflage_pool_lookup_returns_one_of_the_stored_variants() {
        let key = "pool-member.example:443:deadbeef";
        let expected: Vec<Vec<usize>> = vec![vec![53], vec![90, 128], vec![256, 512, 1024]];
        for sizes in &expected {
            store_camouflage_profile(
                key.to_string(),
                test_camouflage_profile(vec![0x16, 0x03, 0x03], sizes.clone()),
            )
            .await;
        }

        for _ in 0..16 {
            let profile = get_cached_camouflage_profile_entry(key)
                .await
                .expect("pool is populated");
            assert!(
                expected
                    .iter()
                    .any(|sizes| sizes.as_slice() == &*profile.app_data_sizes),
                "lookup must return one of the pooled samples, got {:?}",
                profile.app_data_sizes
            );
        }
    }

    #[tokio::test]
    async fn camouflage_pool_full_replaces_oldest_variant() {
        let mut pool = None;
        for idx in 0..MAX_CAMOUFLAGE_PROFILE_VARIANTS + 1 {
            pool = Some(push_profile_variant(
                pool,
                test_camouflage_profile(vec![0x16, 0x03, 0x03], vec![53 + idx]),
            ));
        }

        let pool = pool.unwrap();
        assert_eq!(pool.profiles.len(), MAX_CAMOUFLAGE_PROFILE_VARIANTS);
        let retained: Vec<usize> = pool
            .profiles
            .iter()
            .map(|entry| entry.profile.app_data_sizes[0])
            .collect();
        assert!(
            !retained.contains(&53),
            "the oldest sample must be evicted once the pool is full"
        );
        for idx in 1..MAX_CAMOUFLAGE_PROFILE_VARIANTS + 1 {
            assert!(
                retained.contains(&(53 + idx)),
                "newer sample {} must be retained",
                53 + idx
            );
        }
    }

    #[tokio::test]
    async fn camouflage_pool_lookup_miss_semantics_unchanged() {
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x7d, 0x01, 0x00, 0x00, 0x79, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];

        assert!(
            lookup_cached_profile_for_client_hello("never-cached.example", 443, &client_hello)
                .await
                .is_none(),
            "lookup against an uncached key must keep returning None"
        );
        assert!(
            get_cached_camouflage_profile_entry("never-cached.example:443:deadbeef")
                .await
                .is_none(),
            "empty pool must keep the existing miss semantics"
        );
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

        let profile = lookup_cached_profile_for_client_hello("example.com", 443, &modified).await;
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
            lookup_cached_profile_for_client_hello("baseline.example", 443, &client_hello).await;
        assert!(profile.is_some());
        let profile = profile.unwrap();
        assert_eq!(&*profile.app_data_sizes, &[53, 90][..]);
        assert_eq!(
            &*profile.server_records,
            &[0x16, 0x03, 0x03, 0x00, 0x00][..]
        );
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
            lookup_cached_profile_for_client_hello("baseline-no-fp.example", 443, &malformed).await;

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

        let profile = lookup_cached_profile_for_client_hello("prefer.example", 443, &client_hello)
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

        let profile = lookup_cached_profile_for_client_hello("probe-only.example", 443, &client_hello)
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
            first_app_data_delay_us: 999,
            early_app_data_gap_us: vec![400, 2, 999, 1],
        });

        assert_eq!(&*profile.app_data_sizes, &[53, 512, 6000][..]);
        assert_eq!(profile.prefix_app_data_sizes, vec![53, 512]);
        assert_eq!(profile.first_app_data_size, Some(53));
        assert_eq!(profile.early_app_data_count, 3);
        assert_eq!(profile.first_app_data_delay_us, 999);
        assert_eq!(profile.early_app_data_gap_us, vec![400, 2]);
    }

    #[test]
    fn sanitize_waste_record_sizes_drops_out_of_range_values() {
        let sizes = sanitize_waste_record_sizes(&[8, 23, 120, 8192, 16401, 20000]);
        assert_eq!(sizes, vec![23, 120, 8192, 16401]);
    }

    /// 兜底尺寸必须永远是一个固定点：最大采样尺寸（够大时）或最小可用尺寸，
    /// 绝不产生 [54, 512] 的均匀抽样——平直直方图不是真实 TLS 端点会发出的
    /// 记录尺寸分布。
    #[test]
    fn fallback_noise_response_len_reuses_largest_sample_or_minimum() {
        use crate::common::MIN_NOISE_RESPONSE_RECORD_LEN;
        use super::camouflage::fallback_noise_response_record_len;

        // 有可承载 Noise 响应的采样：复用最大尺寸（主分支，含上限钳制）。
        assert_eq!(fallback_noise_response_record_len(&[23, 200]), 200);
        assert_eq!(fallback_noise_response_record_len(&[23, 20_000]), 16_401);

        // 采样存在但都太小：钳到最小可用值，而不是随机。
        assert_eq!(fallback_noise_response_record_len(&[23, 31]), MIN_NOISE_RESPONSE_RECORD_LEN);

        // 完全没有采样：最小可用值。
        assert_eq!(fallback_noise_response_record_len(&[]), MIN_NOISE_RESPONSE_RECORD_LEN);

        // 固定点：多轮调用结果必须完全一致。
        let results: std::collections::HashSet<usize> = (0..64)
            .map(|_| fallback_noise_response_record_len(&[17, 23]))
            .collect();
        assert_eq!(results.len(), 1);
    }

    /// 输入驱动的 pre-auth 失败必须**全部**具备回落转发资格，彼此不可区分。
    ///
    /// 覆盖三类探测者可零成本构造的输入：
    ///   * 非 0x16 首记录（`17 03 03 00 00`）；
    ///   * 认证失败的合法 ClientHello；
    ///   * 声明长度超限的 5 字节记录头（`16 03 03 41 01`）——此前这一条会
    ///     fail-closed 并瞬时静默关闭，是 5 字节成本、零误报的判别特征。
    ///
    /// 判据是「是否取走了全局回落 permit」：测试持有 peer-counts 互斥量，
    /// 因此服务端会停在 permit 已取、per-IP 记账未完成的状态上。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_pre_auth_failures_remain_fallback_eligible() {
        let _test_guard = PRE_AUTH_FALLBACK_TEST_LOCK.lock().await;
        assert_pre_auth_fallback_state_clean();

        for initial_record in [
            vec![0x17, 0x03, 0x03, 0x00, 0x00],
            build_probe_client_hello("localhost").unwrap(),
            vec![0x16, 0x03, 0x03, 0x41, 0x01],
        ] {
            let (release_tx, lock_thread) = hold_pre_auth_fallback_peer_counts_lock();
            let (mut client, server) = connected_tcp_pair().await;
            let psks = test_psks(b"test-psk");
            let server_task =
                tokio::spawn(
                    async move { server_accept(server, &psks, "localhost", 443).await },
                );

            client.write_all(&initial_record).await.unwrap();

            // While the peer-counts mutex is held, the server task blocks a
            // runtime worker on that std mutex; awaiting a tokio timer here
            // could starve the runtime's timer driver and deadlock the test.
            // Sleep on the block_on thread instead — no runtime progress is
            // needed until the mutex is released below.
            std::thread::sleep(Duration::from_millis(100));
            assert!(!server_task.is_finished());
            assert_eq!(
                PRE_AUTH_FALLBACK_LIMITER.available_permits(),
                fallback_limits().max_pre_auth_fallbacks - 1
            );

            release_tx.send(()).unwrap();
            lock_thread.join().unwrap();

            // 超时留足 emit_indistinguishable_close 的排空窗口。
            let result = tokio::time::timeout(Duration::from_secs(10), server_task)
                .await
                .expect("server_accept should finish once fallback accounting unblocks")
                .expect("server_accept task should join");
            // 分类必须是 PreAuth：这三种输入探测者都能零成本构造，若它们落到
            // Internal，`kanotls/src/server.rs` 就会按 error! 记录，扫描者每建
            // 一条 TCP 就能让服务端写下一行含其可控源 IP 的日志。
            match result {
                Err(ServerAcceptError::PreAuth(_)) => {}
                Err(ServerAcceptError::Internal(e)) => panic!(
                    "input-driven pre-auth rejection classified as an internal fault ({}) — \
                     the caller logs those at error!, which hands a scanner one attacker-\
                     controlled log line per TCP connection",
                    e
                ),
                Ok(_) => panic!("handshake must not succeed"),
            }
            expect_shaped_close(&mut client).await;
            assert_pre_auth_fallback_state_clean();
        }
    }

    /// 配置缺陷（一个用户都没有）必须归为 `Internal`，运维要看得见。
    ///
    /// 与上一条测试成对：`PreAuth` / `Internal` 的边界是「这个失败是不是对端
    /// 免费就能造出来的」，两侧各锁一条，避免整表滑向任意一边。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_user_psks_is_an_internal_fault_not_a_pre_auth_rejection() {
        let (_client, server) = connected_tcp_pair().await;
        let err = server_accept(server, &[], "localhost", 443)
            .await
            .err()
            .expect("an inbound with zero users cannot accept");
        assert!(
            matches!(err, ServerAcceptError::Internal(_)),
            "a misconfigured inbound must stay visible at error!, got {:?}",
            err
        );
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
        assert!(try_acquire_pre_auth_fallback_permit(test_public_ip(global_limit + 1)).is_none());

        drop(global_permits.pop());
        let replacement = try_acquire_pre_auth_fallback_permit(test_public_ip(global_limit + 2));
        assert!(replacement.is_some());

        drop(global_permits);
        drop(replacement);
        assert_pre_auth_fallback_state_clean();
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
        crate::utils::mask_mac_flags(&mut got_mac);
        let random_prefix: &[u8] = &random[..16];
        let want_mac =
            derive_counter_mac(&derived_psk, &random_copy, &masked_counter, random_prefix);
        let mut want_mac_masked = want_mac;
        crate::utils::mask_mac_flags(&mut want_mac_masked);
        assert_eq!(got_mac, want_mac_masked);
    }

    fn build_auth_client_hello(psk: &[u8; 32]) -> Vec<u8> {
        use crate::template::{get_or_build_client_hello_template, ConnectionCounter};

        let cache_key = derive_counter_cache_key(psk);
        {
            let mut cache = COUNTER_CACHE.lock().unwrap();
            let _ = cache.pop(&cache_key);
        }

        let mut initiator = snow::Builder::new(common::NOISE_PARAMS.clone())
            .psk(0, psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut noise_init = [0u8; 48];
        initiator.write_message(&[], &mut noise_init).unwrap();

        let counter = ConnectionCounter::new();
        let template =
            get_or_build_client_hello_template("example.com", Some("firefox"), None, true).unwrap();
        template.instantiate(psk, &noise_init, counter.next()).unwrap()
    }

    #[test]
    fn authenticate_client_hello_identifies_matching_user() {
        let psk_a = derive_psk(b"multi-user-alice-password");
        let psk_b = derive_psk(b"multi-user-bob-password");
        let psks = vec![psk_a, psk_b];

        let ch = build_auth_client_hello(&psk_b);
        let mut tag = [0u8; 16];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let auth = authenticate_client_hello(&ch, &psks, &mut tag, peer)
            .expect("client hello should authenticate against the user list");

        assert_eq!(auth.user_index, 1);
        assert_eq!(auth.derived_psk, psk_b);
    }

    #[test]
    fn authenticate_client_hello_rejects_when_no_user_matches() {
        let psk_a = derive_psk(b"multi-user-carol-password");
        let psk_b = derive_psk(b"multi-user-dave-password");
        let wrong = vec![
            derive_psk(b"multi-user-wrong-1-password"),
            derive_psk(b"multi-user-wrong-2-password"),
        ];

        let ch = build_auth_client_hello(&psk_a);
        let mut tag = [0u8; 16];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(authenticate_client_hello(&ch, &wrong, &mut tag, peer).is_none());

        let ch = build_auth_client_hello(&psk_b);
        let single = vec![psk_b];
        let auth = authenticate_client_hello(&ch, &single, &mut tag, peer)
            .expect("single-user list should still authenticate");
        assert_eq!(auth.user_index, 0);
    }

    /// 非匹配 PSK 不得触发 Noise 状态构建。
    ///
    /// 这是「MAC 前置于 Noise 探测」的可观测代理指标。若哪天有人把顺序改回
    /// 去，每个配置用户都会重新各付一次非对称探测：22× 的认证浪费，并且让
    /// 一个垃圾 ClientHello 的 CPU 成本随用户数线性放大（`MAX_HANDSHAKES`
    /// = 512 × 50 用户 ≈ 153 CPU-ms/波）。
    #[test]
    fn authenticate_client_hello_probes_noise_only_for_mac_matching_psk() {
        let decoys: Vec<[u8; common::PSK_LEN]> = (0..15)
            .map(|idx| derive_psk(format!("noise-probe-decoy-{}", idx).as_bytes()))
            .collect();
        let real = derive_psk(b"noise-probe-real-password");

        let mut with_real = decoys.clone();
        with_real.push(real);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut tag = [0u8; 16];

        // 命中用户排在最后：重排前这里会构建 16 次 Noise 状态。
        let ch = build_auth_client_hello(&real);
        NOISE_RESPONDER_BUILDS.with(|count| count.set(0));
        let auth = authenticate_client_hello(&ch, &with_real, &mut tag, peer)
            .expect("last user in the list must still authenticate");
        assert_eq!(auth.user_index, decoys.len());
        assert_eq!(
            NOISE_RESPONDER_BUILDS.with(|count| count.get()),
            1,
            "只有 counter-MAC 命中的 PSK 才允许构建 Noise 状态；{} 个候选中\
             出现多次构建说明非对称探测又跑在 MAC 之前了",
            with_real.len()
        );

        // 完全不匹配的用户表：一次 Noise 状态都不该构建。
        let ch = build_auth_client_hello(&real);
        NOISE_RESPONDER_BUILDS.with(|count| count.set(0));
        assert!(authenticate_client_hello(&ch, &decoys, &mut tag, peer).is_none());
        assert_eq!(
            NOISE_RESPONDER_BUILDS.with(|count| count.get()),
            0,
            "无人命中 counter-MAC 时不得有任何非对称探测——否则垃圾 \
             ClientHello 的 CPU 成本随配置用户数线性放大"
        );
    }

    /// counter-MAC 命中之后的检查链必须仍然是「失败就换下一个 PSK」，
    /// 而不是「失败就整体返回 None」。
    ///
    /// 把 MAC 提到 Noise 之前后，MAC 是本轮的第一个筛子，很容易顺手写成
    /// 「MAC 不中就 continue、中了就直接决出胜负」。那是错的：MAC 只有
    /// 62 位有效长度，一次碰撞就能顶掉真正的用户。
    ///
    /// 这里用重放的 ClientHello 走通该路径——MAC 与 Noise 都会通过，只在
    /// `is_replay` 处被拒（临时公钥已在上一次调用中写入 REPLAY_CACHE），
    /// 因此它同时钉住了 `is_replay` 的副作用位置：仍然发生在 MAC 与 Noise
    /// 都通过之后，重排没有改变它的调用条件。
    #[test]
    fn authenticate_client_hello_keeps_scanning_after_a_mac_hit_fails_later_checks() {
        let psk = derive_psk(b"mac-hit-then-replay-rejected");
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut tag = [0u8; 16];

        // 同一个 PSK 列两次：两轮都会命中 MAC，因此第二次调用的两轮都必须
        // 走完整条链并各自被 is_replay 拒掉。
        let psks = vec![psk, psk];
        let ch = build_auth_client_hello(&psk);
        assert!(
            authenticate_client_hello(&ch, &psks, &mut tag, peer).is_some(),
            "first use of a fresh ClientHello must authenticate"
        );

        NOISE_RESPONDER_BUILDS.with(|count| count.set(0));
        assert!(
            authenticate_client_hello(&ch, &psks, &mut tag, peer).is_none(),
            "a replayed ClientHello must be rejected even though the counter MAC matches"
        );
        assert_eq!(
            NOISE_RESPONDER_BUILDS.with(|count| count.get()),
            2,
            "MAC 命中但后续检查失败时必须继续扫描下一个 PSK；只探测 1 次说明\
             提前 return 了，一次 MAC 碰撞就能顶掉真正的用户"
        );
    }
}
