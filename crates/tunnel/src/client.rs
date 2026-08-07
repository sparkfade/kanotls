use lazy_static::lazy_static;
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::{
    self, apply_tcp_keepalive, build_h2_ghost_plaintext, NoiseTransport, SnowyStream, AEAD_TAG_LEN,
    FLIGHT3_CCS_RECORD, FLIGHT3_FINISHED_PLAINTEXT_LEN, FLIGHT3_FINISHED_RECORD_LEN,
    HANDSHAKE_CONTROL_LEN, HANDSHAKE_CONTROL_MAGIC, TLS_RECORD_HEADER_LEN,
};
use crate::template::{get_or_build_client_hello_template, ConnectionCounter};
use crate::utils::{
    derive_noise_e_mask, is_server_hello, read_tls_record_bounded, xor_in_place,
    TlsRecordReadLimits, TlsRecordReadState, MAX_TLS_RECORD_PAYLOAD_LEN,
};

lazy_static! {
    static ref CONNECTION_COUNTER: ConnectionCounter = ConnectionCounter::new();
}

/// Flight-3 H2 幽灵记录的变体选择种子——**每进程采样一次**。
///
/// 此前该种子由 `client_noise_tag`、`derived_psk` 与连接计数器 `counter`
/// 逐字节相加得到。`counter` 每条连接递增、`client_noise_tag` 每条连接
/// 全新，于是 `build_h2_ghost_plaintext` 选出的变体**逐连接变化**，第三条
/// Flight-3 记录的线速尺寸在 {86, 92, 98} 之间跳动。
///
/// 这是「方差过剩」型特征，与 §2.3 修掉的 ServerHello key_share 问题恰好
/// 互为镜像：那边是同一条 ECDHE 公钥跨连接复用（方差不足），这边是同一个
/// 客户端的每条连接给出不同的 H2 preface + SETTINGS + WINDOW_UPDATE 尺寸
/// （方差过剩）。真实浏览器的 H2 SETTINGS 是编译期常量，一个 Firefox 实例
/// 的**每一条**连接都发完全相同尺寸的 H2 前导；而 KanoTLS 连接池一次开
/// 4–16 条连接，观察者从单一客户端 IP 就能看到这个尺寸在三个取值间抖动。
/// 判别成本与 key_share 那侧一样低：每流只需记住一个 u16。
///
/// 现改为进程级 `OnceLock`：一个进程 = 一个浏览器实例 = 一组固定的
/// SETTINGS。种子取自 CSPRNG 而**不是** PSK 派生——若从 PSK 派生，同一
/// 部署的所有客户端会收敛到同一变体，且线上可见的记录长度就成了密钥材料
/// 的一个 2 bit 函数，属于把秘密泄进明文可见字段。
static H2_GHOST_CONTEXT: OnceLock<u64> = OnceLock::new();

/// 取得（必要时初始化）本进程的 H2 幽灵变体种子。
fn h2_ghost_context_hash() -> u64 {
    *H2_GHOST_CONTEXT.get_or_init(rand::random::<u64>)
}

const CLIENT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const CLIENT_HANDSHAKE_MAX_RECORDS: usize = 64;
const CLIENT_HANDSHAKE_MAX_BYTES: usize = 256 * 1024;
const CLIENT_HANDSHAKE_MAX_CCS_RECORDS: usize = 1;
const CLIENT_HANDSHAKE_MAX_HANDSHAKE_RECORDS: usize = 8;
const CLIENT_HANDSHAKE_MAX_APP_DATA_PROBES: usize = 8;

fn resolve_outer_client_fingerprint(fingerprint: Option<&str>) -> Option<&str> {
    fingerprint.map(str::trim)
}

/// [`client_tunnel`] 的失败分类。
///
/// # 为什么必须是类型而不是错误文案
///
/// `kanotls/src/connector.rs` 需要把「PSK / SNI 与服务器不匹配」从普通建连
/// 失败里挑出来做只提示一次的诊断。此前用 `Error::to_string()` 的子串匹配
/// 实现，而这正是服务器侧已经弃用的反模式（见 `ServerAcceptError` 的注释）：
/// 任一条 `bail!` 的文案被改动就会静默失配，编译器不会给出任何提示。
/// 改成类型化之后，新增失败路径必须显式选一个变体，漏选不会编译。
#[derive(Debug)]
pub enum TunnelConnectError {
    /// 客户端收到了完整的真实 flight 却在其中找不到 Noise 响应——服务端
    /// 拒绝认证后把这条连接交给了 fallback 透明中继。只可能是 PSK 不匹配，
    /// 或 `tls.sni` 与服务端 `camouflage.host` 不一致。
    AuthRejected(String),
    /// 其余失败（连接被拒、超时、DNS、记录读取错误等），由连接池自身的
    /// 告警承载。
    Other(anyhow::Error),
}

impl TunnelConnectError {
    fn auth_rejected(msg: impl Into<String>) -> Self {
        Self::AuthRejected(msg.into())
    }
}

impl std::fmt::Display for TunnelConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthRejected(msg) => std::fmt::Display::fmt(msg, f),
            Self::Other(err) => std::fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for TunnelConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AuthRejected(_) => None,
            Self::Other(err) => Some(err.as_ref()),
        }
    }
}

/// 未显式分类的 `?` 一律落到 `Other`，与 `ServerAcceptError` 的默认方向一致。
impl From<anyhow::Error> for TunnelConnectError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

/// `std::io::Error`（连接被拒、超时、DNS、读写失败）与 `snow::Error`（密钥
/// 协商、加密）同样落 `Other`：这两类都不是「PSK / SNI 不匹配」的诊断。
impl From<std::io::Error> for TunnelConnectError {
    fn from(err: std::io::Error) -> Self {
        Self::Other(anyhow::Error::new(err))
    }
}

impl From<snow::Error> for TunnelConnectError {
    fn from(err: snow::Error) -> Self {
        Self::Other(anyhow::Error::new(err))
    }
}

pub async fn client_tunnel(
    server_addr: &str,
    sni: &str,
    psk: &[u8],
    insecure: bool,
    fingerprint: Option<&str>,
    custom_template_bytes: Option<&[u8]>,
) -> Result<SnowyStream, TunnelConnectError> {
    let mut tcp = TcpStream::connect(server_addr).await?;
    tcp.set_nodelay(true)?;
    let _ = apply_tcp_keepalive(&tcp);
    common::tune_tunnel_socket_buffers(&tcp);

    let derived_psk = common::derive_psk(psk);
    let builder = snow::Builder::new(common::NOISE_PARAMS.clone()).psk(0, &derived_psk)?;
    let mut noise = builder.build_initiator()?;

    let counter = CONNECTION_COUNTER.next();
    let mut msg_buf = [0u8; 48];
    let init_len = noise.write_message(&[], &mut msg_buf)?;
    if init_len != 48 {
        return Err(TunnelConnectError::Other(anyhow::anyhow!(
            "unexpected Noise init length: {}",
            init_len
        )));
    }
    let psk_e = &msg_buf[..48];
    let mut client_noise_tag = [0u8; 16];
    client_noise_tag.copy_from_slice(&psk_e[32..48]);

    let outer_fingerprint = resolve_outer_client_fingerprint(fingerprint);
    let template = get_or_build_client_hello_template(
        sni,
        outer_fingerprint,
        custom_template_bytes,
        insecure,
    )?;
    let ch_buf = template.instantiate(&derived_psk, psk_e, counter)?;
    debug!("Instantiated ClientHello template with Noise authentication");

    tcp.write_all(&ch_buf).await?;

    let mut rx_buf = Vec::new();
    let mut read_state = TlsRecordReadState::new();
    let handshake_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(CLIENT_HANDSHAKE_TIMEOUT_SECS);
    let handshake_limits = TlsRecordReadLimits {
        max_records: CLIENT_HANDSHAKE_MAX_RECORDS,
        max_bytes: CLIENT_HANDSHAKE_MAX_BYTES,
        deadline: Some(handshake_deadline),
    };
    let mut found_server_hello = false;
    let mut ccs_records = 0usize;
    let mut handshake_records = 0usize;
    let mut app_data_probes = 0usize;
    let mut ghost_count: usize = 0;
    // 0x17 探测用的堆缓冲在循环外复用：避免每次探测都在栈上 memset
    // 两个 MAX_TLS_RECORD_PAYLOAD_LEN 数组；只按实际 payload 长度处理。
    let mut unmasked_payload = vec![0u8; MAX_TLS_RECORD_PAYLOAD_LEN];
    let mut e_ee = vec![0u8; MAX_TLS_RECORD_PAYLOAD_LEN];
    loop {
        let (typ, _rec_len) =
            read_tls_record_bounded(&mut tcp, &mut rx_buf, handshake_limits, &mut read_state)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read TLS record: {}", e))?;

        let record = rx_buf.as_slice();
        let payload = &record[TLS_RECORD_HEADER_LEN..];

        match typ {
            0x16 => {
                handshake_records += 1;
                if handshake_records > CLIENT_HANDSHAKE_MAX_HANDSHAKE_RECORDS {
                    return Err(TunnelConnectError::auth_rejected(
                        "too many server handshake records before Noise response",
                    ));
                }
                if is_server_hello(record) {
                    found_server_hello = true;
                }
            }
            0x14 => {
                ccs_records += 1;
                if ccs_records > CLIENT_HANDSHAKE_MAX_CCS_RECORDS {
                    return Err(TunnelConnectError::auth_rejected(
                        "too many server CCS records before Noise response",
                    ));
                }
            }
            0x17 => {
                if found_server_hello {
                    app_data_probes += 1;
                    if app_data_probes > CLIENT_HANDSHAKE_MAX_APP_DATA_PROBES {
                        return Err(TunnelConnectError::auth_rejected(format!(
                            "failed to locate Noise response within {} application-data records",
                            CLIENT_HANDSHAKE_MAX_APP_DATA_PROBES
                        )));
                    }
                    if payload.len() < 32 {
                        debug!(
                            "skipping short pre-Noise 0x17 payload while waiting for handshake response: {} bytes",
                            payload.len()
                        );
                        continue;
                    }
                    let plen = payload.len();
                    unmasked_payload[..plen].copy_from_slice(payload);
                    let server_e_mask = derive_noise_e_mask(&derived_psk, &client_noise_tag);
                    xor_in_place(&mut unmasked_payload[..32], &server_e_mask);
                    match noise.read_message(&unmasked_payload[..plen], &mut e_ee) {
                        Ok(len) => {
                            if len >= HANDSHAKE_CONTROL_LEN
                                && &e_ee[..HANDSHAKE_CONTROL_MAGIC.len()] == HANDSHAKE_CONTROL_MAGIC
                            {
                                ghost_count = u16::from_be_bytes([e_ee[4], e_ee[5]]) as usize;
                                debug!(
                                    "Received Noise response (e, ee), len: {}, ghost_count: {}",
                                    len, ghost_count
                                );
                            }
                            break;
                        }
                        Err(_) => {
                            debug!(
                                "skipping non-Noise 0x17 record {} while waiting for handshake response",
                                app_data_probes
                            );
                            continue;
                        }
                    }
                } else {
                    return Err(TunnelConnectError::Other(anyhow::anyhow!(
                        "server sent application data before ServerHello"
                    )));
                }
            }
            _ => {
                return Err(TunnelConnectError::Other(anyhow::anyhow!(
                    "unexpected server handshake record type: {:#x}",
                    typ
                )))
            }
        }
    }

    if ghost_count > 0 {
        let drain_deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(CLIENT_HANDSHAKE_TIMEOUT_SECS);
        let drain_limits = TlsRecordReadLimits {
            max_records: ghost_count,
            max_bytes: ghost_count * (TLS_RECORD_HEADER_LEN + MAX_TLS_RECORD_PAYLOAD_LEN),
            deadline: Some(drain_deadline),
        };
        let mut drain_state = TlsRecordReadState::new();
        for i in 0..ghost_count {
            let (typ, rec_len) =
                read_tls_record_bounded(&mut tcp, &mut rx_buf, drain_limits, &mut drain_state)
                    .await
                    .map_err(|e| anyhow::anyhow!("ghost drain record {}: {}", i, e))?;

            if typ != 0x17 {
                return Err(TunnelConnectError::Other(anyhow::anyhow!(
                    "expected 0x17 ghost record {}, got type {:#x}",
                    i,
                    typ
                )));
            }
            debug!(
                "drained ghost 0x17 record {}/{} ({} bytes)",
                i + 1,
                ghost_count,
                rec_len
            );
        }
    }

    // 无状态传输态 + 外部 nonce：Flight-3 的两条消息用 n=0/1，随后原样
    // 交给 SnowyStream 继续从 n=2 递增——线上字节与 TransportState 完全一致
    // （论证见 `NoiseTransport`）。
    let mut noise = NoiseTransport::new(noise.into_stateless_transport_mode()?);

    // 变体选择必须与本连接的任何材料无关：见 `H2_GHOST_CONTEXT` 的说明。
    send_client_flight3_ghost(&mut tcp, &mut noise, h2_ghost_context_hash()).await?;

    debug!(
        "Tunnel established with fingerprint {:?}",
        outer_fingerprint
    );
    Ok(SnowyStream::new(tcp, noise))
}

async fn send_client_flight3_ghost(
    tcp: &mut TcpStream,
    noise: &mut NoiseTransport,
    context_hash: u64,
) -> Result<(), anyhow::Error> {
    let finished_plaintext = [0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN];
    let mut finished_ciphertext = vec![0u8; FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN];
    let finished_ct_len = noise.write_message(&finished_plaintext, &mut finished_ciphertext)?;
    if finished_ct_len != FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN {
        anyhow::bail!(
            "unexpected Finished ghost ciphertext length: {}",
            finished_ct_len
        );
    }

    let mut segment1 = Vec::with_capacity(FLIGHT3_CCS_RECORD.len() + FLIGHT3_FINISHED_RECORD_LEN);
    segment1.extend_from_slice(&FLIGHT3_CCS_RECORD);
    segment1.extend_from_slice(&[0x17, 0x03, 0x03]);
    segment1.extend_from_slice(&(finished_ct_len as u16).to_be_bytes());
    segment1.extend_from_slice(&finished_ciphertext[..finished_ct_len]);
    tcp.write_all(&segment1).await?;
    tcp.flush().await?;

    let h2_plaintext = build_h2_ghost_plaintext(context_hash);
    let h2_plaintext_len = h2_plaintext.len();
    let mut h2_ciphertext = vec![0u8; h2_plaintext_len + AEAD_TAG_LEN];
    let h2_ct_len = noise.write_message(&h2_plaintext, &mut h2_ciphertext)?;
    if h2_ct_len != h2_plaintext_len + AEAD_TAG_LEN {
        anyhow::bail!("unexpected H2 ghost ciphertext length: {}", h2_ct_len);
    }

    let h2_record_len = TLS_RECORD_HEADER_LEN + h2_ct_len;
    let mut segment2 = Vec::with_capacity(h2_record_len);
    segment2.extend_from_slice(&[0x17, 0x03, 0x03]);
    segment2.extend_from_slice(&(h2_ct_len as u16).to_be_bytes());
    segment2.extend_from_slice(&h2_ciphertext[..h2_ct_len]);
    tcp.write_all(&segment2).await?;
    tcp.flush().await?;

    debug!(
        "Sent Flight 3 ghost: CCS(6) + Finished(58) | H2 preamble({})",
        h2_plaintext_len
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{h2_ghost_context_hash, resolve_outer_client_fingerprint};
    use crate::common::{build_h2_ghost_plaintext, max_h2_ghost_plaintext_len};

    #[test]
    fn omitted_outer_fingerprint_keeps_default_template_path() {
        assert_eq!(resolve_outer_client_fingerprint(None), None);
    }

    #[test]
    fn explicit_outer_fingerprint_is_trimmed_and_preserved() {
        assert_eq!(
            resolve_outer_client_fingerprint(Some(" firefox ")),
            Some("firefox")
        );
    }

    // C4 回归：H2 幽灵变体种子必须是进程常量。此前它混入 counter 与
    // client_noise_tag，导致同一客户端的每条连接发出不同尺寸的 Flight-3
    // 第三条记录（{86, 92, 98} 抖动），而真实 Firefox 的 H2 SETTINGS 是
    // 编译期常量、跨连接恒定。
    #[test]
    fn h2_ghost_context_hash_is_process_constant() {
        let first = h2_ghost_context_hash();
        for _ in 0..64 {
            assert_eq!(
                h2_ghost_context_hash(),
                first,
                "H2 ghost variant seed drifted within one process"
            );
        }
    }

    // 由上一条推出的线上性质：本进程内每条连接的 H2 幽灵明文（因而线速
    // 记录长度）逐字节相同。
    #[test]
    fn h2_ghost_plaintext_is_identical_across_connections() {
        let baseline = build_h2_ghost_plaintext(h2_ghost_context_hash());
        assert!(!baseline.is_empty());
        assert!(baseline.len() <= max_h2_ghost_plaintext_len());
        for _ in 0..64 {
            assert_eq!(
                build_h2_ghost_plaintext(h2_ghost_context_hash()),
                baseline,
                "per-connection H2 ghost plaintext must not vary within a process"
            );
        }
    }
}
