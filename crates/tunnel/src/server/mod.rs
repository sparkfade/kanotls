mod auth;
mod camouflage;
mod fallback;
mod replay;

pub use camouflage::{init_entropy_pool, validate_camouflage_endpoint};

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
    self, apply_tcp_keepalive, derive_psk, max_flight3_total_wire_len, SnowyStream, AEAD_TAG_LEN,
    FLIGHT3_CCS_RECORD, FLIGHT3_FINISHED_PLAINTEXT_LEN, FLIGHT3_FINISHED_RECORD_LEN,
    TLS_RECORD_HEADER_LEN,
};
use crate::utils::{
    client_hello_key_share_range, client_hello_random_and_session_id_ranges, constant_time_eq,
    derive_counter_mac, extract_client_hello_server_name, mask_mac_flags,
    unmask_noise_ephemeral_key,
};

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

            let recovered_e =
                unmask_noise_ephemeral_key(&random_copy, &derived_psk, &client_noise_tag);

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
                            let check =
                                check_counter_replay(&derived_psk, &random_copy, masked_counter);
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

pub(super) async fn consume_client_flight3_ghost(
    tcp: &mut TcpStream,
    noise: &mut snow::TransportState,
) -> anyhow::Result<Vec<u8>> {
    let max_wire = max_flight3_total_wire_len();
    let mut wire = vec![0u8; max_wire];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(SERVER_HANDSHAKE_TIMEOUT_SECS);
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
    let h2_payload_len = u16::from_be_bytes([wire[h2_start + 3], wire[h2_start + 4]]) as usize;
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
        let n = tokio::time::timeout(remaining_timeout, tcp.read(&mut wire[total_read..h2_end]))
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

pub(super) async fn resolve_allowed_camouflage(
    host: &str,
    port: u16,
) -> anyhow::Result<SocketAddr> {
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

    use crate::utils::{
        derive_counter_cache_key, derive_counter_mask, stable_client_hello_fingerprint,
        xor_u64_bytes,
    };

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
        let mut server_stream =
            SnowyStream::new_with_permit_and_pre_read_tls(server_tcp, server_noise, None, vec![]);
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
        assert!(try_acquire_pre_auth_fallback_permit(test_public_ip(global_limit + 1)).is_none());

        drop(global_permits.pop());
        let replacement = try_acquire_pre_auth_fallback_permit(test_public_ip(global_limit + 2));
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
}
