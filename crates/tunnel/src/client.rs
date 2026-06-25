use lazy_static::lazy_static;
use snow::TransportState;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::{
    self, apply_tcp_keepalive, build_h2_ghost_plaintext, SnowyStream, AEAD_TAG_LEN,
    FLIGHT3_CCS_RECORD, FLIGHT3_FINISHED_PLAINTEXT_LEN, FLIGHT3_FINISHED_RECORD_LEN,
    HANDSHAKE_CONTROL_LEN,
    HANDSHAKE_CONTROL_MAGIC, TLS_RECORD_HEADER_LEN,
};
use crate::template::{get_or_build_client_hello_template, ConnectionCounter};
use crate::utils::{
    derive_noise_e_mask, is_server_hello, read_tls_record_bounded, xor_in_place,
    TlsRecordReadLimits, TlsRecordReadState, MAX_TLS_RECORD_PAYLOAD_LEN,
};

lazy_static! {
    static ref CONNECTION_COUNTER: ConnectionCounter = ConnectionCounter::new();
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

pub async fn client_tunnel(
    server_addr: &str,
    sni: &str,
    psk: &[u8],
    insecure: bool,
    fingerprint: Option<&str>,
    custom_template_bytes: Option<&[u8]>,
) -> Result<SnowyStream, anyhow::Error> {
    let mut tcp = TcpStream::connect(server_addr).await?;
    tcp.set_nodelay(true)?;
    let _ = apply_tcp_keepalive(&tcp);

    let derived_psk = common::derive_psk(psk);
    let builder = snow::Builder::new(common::NOISE_PARAMS.clone()).psk(0, &derived_psk)?;
    let mut noise = builder.build_initiator()?;

    let counter = CONNECTION_COUNTER.next();
    let mut msg_buf = [0u8; 48];
    let init_len = noise.write_message(&[], &mut msg_buf)?;
    if init_len != 48 {
        anyhow::bail!("unexpected Noise init length: {}", init_len);
    }
    let psk_e = &msg_buf[..48];
    let mut client_noise_tag = [0u8; 16];
    client_noise_tag.copy_from_slice(&psk_e[32..48]);

    let outer_fingerprint = resolve_outer_client_fingerprint(fingerprint);
    let template = get_or_build_client_hello_template(sni, outer_fingerprint, custom_template_bytes, insecure)?;
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
                    anyhow::bail!("too many server handshake records before Noise response");
                }
                if is_server_hello(record) {
                    found_server_hello = true;
                }
            }
            0x14 => {
                ccs_records += 1;
                if ccs_records > CLIENT_HANDSHAKE_MAX_CCS_RECORDS {
                    anyhow::bail!("too many server CCS records before Noise response");
                }
            }
            0x17 => {
                if found_server_hello {
                    app_data_probes += 1;
                    if app_data_probes > CLIENT_HANDSHAKE_MAX_APP_DATA_PROBES {
                        anyhow::bail!(
                            "failed to locate Noise response within {} application-data records",
                            CLIENT_HANDSHAKE_MAX_APP_DATA_PROBES
                        );
                    }
                    if payload.len() < 32 {
                        debug!(
                            "skipping short pre-Noise 0x17 payload while waiting for handshake response: {} bytes",
                            payload.len()
                        );
                        continue;
                    }
                    let mut unmasked_payload = payload.to_vec();
                    let server_e_mask = derive_noise_e_mask(&derived_psk, &client_noise_tag);
                    xor_in_place(&mut unmasked_payload[..32], &server_e_mask);
                    let mut e_ee = vec![0u8; 16384];
                    match noise.read_message(&unmasked_payload, &mut e_ee) {
                        Ok(len) => {
                            if len >= HANDSHAKE_CONTROL_LEN
                                && &e_ee[..HANDSHAKE_CONTROL_MAGIC.len()] == HANDSHAKE_CONTROL_MAGIC
                            {
                                ghost_count = u16::from_be_bytes([e_ee[4], e_ee[5]]) as usize;
                                debug!("Received Noise response (e, ee), len: {}, ghost_count: {}", len, ghost_count);
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
                    anyhow::bail!("server sent application data before ServerHello");
                }
            }
            _ => anyhow::bail!("unexpected server handshake record type: {:#x}", typ),
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
            let (typ, rec_len) = read_tls_record_bounded(
                &mut tcp, &mut rx_buf, drain_limits, &mut drain_state,
            )
            .await
            .map_err(|e| anyhow::anyhow!("ghost drain record {}: {}", i, e))?;

            if typ != 0x17 {
                anyhow::bail!("expected 0x17 ghost record {}, got type {:#x}", i, typ);
            }
            debug!("drained ghost 0x17 record {}/{} ({} bytes)", i + 1, ghost_count, rec_len);
        }
    }

    let mut noise = noise.into_transport_mode()?;

    let context_hash = {
        let mut hash = [0u8; 8];
        for i in 0..8 {
            hash[i] = client_noise_tag[i]
                .wrapping_add(derived_psk[i])
                .wrapping_add(derived_psk[i + 16])
                .wrapping_add(counter.to_be_bytes()[i]);
        }
        u64::from_be_bytes(hash)
    };
    send_client_flight3_ghost(&mut tcp, &mut noise, context_hash).await?;

    debug!(
        "Tunnel established with fingerprint {:?}",
        outer_fingerprint
    );
    Ok(SnowyStream::new(tcp, noise))
}

async fn send_client_flight3_ghost(
    tcp: &mut TcpStream,
    noise: &mut TransportState,
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
    use super::resolve_outer_client_fingerprint;

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
}
