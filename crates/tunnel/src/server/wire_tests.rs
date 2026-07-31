//! 线上不可区分性回归测试。
//!
//! 这些测试断言的不是「功能正确」，而是「审查者无法判别」：服务端在
//! ServerHello 之后写上线的每一个字节，在真实 TLS 1.3 里都是 AEAD 密文，
//! 因此必须逐连接新鲜、无常量、无跨连接重复。
//!
//! 历史上正是缺少这类断言，才让两个致命特征长期存活：
//!   * 每条 ghost record 固定偏移 5..21 处的 16 字节常量伪 ticket 头
//!     （一次 memcmp 即可命中，误报率 2^-128）；
//!   * ghost/prefix payload 取自一个进程级 8 MiB 熵池并循环复用
//!     （跨连接出现逐字节相同的长片段，可拼接识别）。
//!
//! 新增任何写明文上线的路径时，都应在此补一条断言。

use super::camouflage::{build_noise_response_sequence, patch_server_hello_key_share};
use crate::common::{self, TLS_RECORD_HEADER_LEN};

/// 采样条数：既要能稳定捕获常量字节，又要让测试保持毫秒级。
const SAMPLES: usize = 64;

/// 跨连接重复检测的窗口长度。真实密文中任意 16 字节窗口在两条连接里
/// 重合的概率为 2^-128；一旦命中即说明存在共享缓冲。
const REPEAT_WINDOW: usize = 16;

fn responder_handshake() -> (snow::HandshakeState, [u8; common::PSK_LEN]) {
    let derived_psk = common::derive_psk(b"kanotls-wire-indistinguishability");
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
    let mut init = [0u8; 48];
    let n = initiator.write_message(&[], &mut init).unwrap();
    responder.read_message(&init[..n], &mut []).unwrap();
    (responder, derived_psk)
}

/// 生成一条合成 flight，返回 (完整字节流, 各 record 的 payload 区间)。
///
/// `build_noise_response_sequence` 逐条返回记录（发送侧按记录间隔决定如何
/// 分批写），这里拼接回连续字节流以便做逐偏移的统计断言。
fn sample_flight(sizes: &[usize]) -> (Vec<u8>, Vec<std::ops::Range<usize>>) {
    let (mut noise, derived_psk) = responder_handshake();
    let client_noise_tag = [0x5au8; 16];
    let sequence: Vec<u8> =
        build_noise_response_sequence(&mut noise, &derived_psk, &client_noise_tag, sizes)
            .unwrap()
            .concat();

    // 切出 payload 区间：record 头 `17 03 03 <len>` 本就是 TLS 明文结构，
    // 不参与常量/重复断言。
    let mut payloads = Vec::new();
    let mut offset = 0usize;
    while offset + TLS_RECORD_HEADER_LEN <= sequence.len() {
        let len =
            u16::from_be_bytes([sequence[offset + 3], sequence[offset + 4]]) as usize;
        let start = offset + TLS_RECORD_HEADER_LEN;
        let end = start + len;
        assert!(end <= sequence.len(), "record overruns the generated flight");
        payloads.push(start..end);
        offset = end;
    }
    assert_eq!(offset, sequence.len(), "trailing bytes outside any record");
    (sequence, payloads)
}

/// 构造一条形状真实的 TLS 1.3 ServerHello（含 supported_versions 与
/// key_share 扩展），用于校验扩展解析与 key_share 重写。
fn synthetic_server_hello(group: u16, key_exchange_len: usize) -> Vec<u8> {
    let session_id = [0x11u8; 32];
    let key_share_ext_data_len = 2 + 2 + key_exchange_len;
    let extensions_len = (4 + 2) + (4 + key_share_ext_data_len);
    let body_len = 2 + 32 + 1 + session_id.len() + 2 + 1 + 2 + extensions_len;
    let handshake_len = 4 + body_len;

    let mut out = Vec::new();
    out.extend_from_slice(&[0x16, 0x03, 0x03]);
    out.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    out.push(0x02); // server_hello
    out.extend_from_slice(&[
        ((body_len >> 16) & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        (body_len & 0xff) as u8,
    ]);
    out.extend_from_slice(&[0x03, 0x03]); // legacy_version
    out.extend_from_slice(&[0x22u8; 32]); // random
    out.push(session_id.len() as u8);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    out.push(0x00); // legacy_compression_method
    out.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    // supported_versions
    out.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    // key_share
    out.extend_from_slice(&[0x00, 0x33]);
    out.extend_from_slice(&(key_share_ext_data_len as u16).to_be_bytes());
    out.extend_from_slice(&group.to_be_bytes());
    out.extend_from_slice(&(key_exchange_len as u16).to_be_bytes());
    out.extend_from_slice(&vec![0xAAu8; key_exchange_len]);
    out
}

fn key_exchange_bytes(records: &[u8]) -> Vec<u8> {
    let (_, range) = crate::utils::server_hello_key_share_range(records)
        .expect("synthetic ServerHello must parse");
    records[range].to_vec()
}

/// 解析器必须能在形状真实的 ServerHello 中定位 key_share。解析失败会让
/// `establish_synthetic_camouflage_tunnel` 对每条连接 fail closed，属于
/// 硬回归，因此覆盖三个组各自的编码长度。
#[test]
fn server_hello_key_share_parses_for_every_supported_group() {
    for (group, len) in [(0x001Du16, 32usize), (0x0017, 65), (0x11EC, 1088 + 32)] {
        let records = synthetic_server_hello(group, len);
        let (parsed_group, range) = crate::utils::server_hello_key_share_range(&records)
            .unwrap_or_else(|| panic!("group {:#06x} failed to parse", group));
        assert_eq!(parsed_group, group);
        assert_eq!(range.len(), len, "group {:#06x} key_exchange length", group);
        assert!(records[range].iter().all(|&b| b == 0xAA));
    }
}

/// ServerHello 后仍可能跟 ChangeCipherSpec 等记录；解析器要能跳过前置的
/// 非 ServerHello 记录并只认第一条 ServerHello。
#[test]
fn server_hello_key_share_skips_non_server_hello_records() {
    let mut records = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]; // CCS first
    records.extend_from_slice(&synthetic_server_hello(0x001D, 32));
    let (group, range) = crate::utils::server_hello_key_share_range(&records)
        .expect("ServerHello after CCS must still parse");
    assert_eq!(group, 0x001D);
    assert_eq!(range.len(), 32);
}

/// 截断/长度矛盾的输入必须返回 None（fail closed），不得 panic。
#[test]
fn server_hello_key_share_rejects_malformed_input() {
    let full = synthetic_server_hello(0x001D, 32);
    for cut in [5usize, 10, 40, 60, full.len() - 1] {
        assert!(
            crate::utils::server_hello_key_share_range(&full[..cut]).is_none(),
            "truncation at {} must fail closed",
            cut
        );
    }
    let mut bad_ext_len = full.clone();
    let n = bad_ext_len.len();
    bad_ext_len[n - 34] = 0xff; // 破坏 key_exchange 长度
    let _ = crate::utils::server_hello_key_share_range(&bad_ext_len);
}

/// 核心不变量：服务端 ECDHE 公钥必须逐连接互异。逐字节复用是「存 32 字节
/// 即可命中、零误报」的被动特征。
#[test]
fn server_hello_key_share_is_unique_per_connection() {
    for (group, len) in [(0x001Du16, 32usize), (0x0017, 65), (0x11EC, 1088 + 32)] {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..SAMPLES {
            let mut records = synthetic_server_hello(group, len);
            assert!(
                patch_server_hello_key_share(&mut records),
                "group {:#06x} must be patchable",
                group
            );
            let shared = key_exchange_bytes(&records);
            assert_ne!(
                shared,
                vec![0xAAu8; len],
                "group {:#06x} key_share was not rewritten",
                group
            );
            assert!(
                seen.insert(shared),
                "group {:#06x} produced a duplicate key_share across connections",
                group
            );
        }
    }
}

/// X25519 公钥是模 2^255-19 的 u 坐标，最高位恒为 0；若用随机字节填充，
/// 最高位会有一半概率置位，反而引入新特征。
#[test]
fn x25519_key_share_has_canonical_high_bit() {
    for _ in 0..SAMPLES {
        let mut records = synthetic_server_hello(0x001D, 32);
        assert!(patch_server_hello_key_share(&mut records));
        let ke = key_exchange_bytes(&records);
        assert_eq!(ke[31] & 0x80, 0, "X25519 public key must have MSB clear");
    }
    // 混合组的 X25519 分量同理。
    for _ in 0..SAMPLES {
        let mut records = synthetic_server_hello(0x11EC, 1088 + 32);
        assert!(patch_server_hello_key_share(&mut records));
        let ke = key_exchange_bytes(&records);
        assert_eq!(ke[1088 + 31] & 0x80, 0, "hybrid X25519 half must have MSB clear");
    }
}

/// 未知组必须 fail closed，而不是把复用的 key_share 原样发出去。
#[test]
fn unknown_key_share_group_fails_closed() {
    let mut records = synthetic_server_hello(0x0100, 32);
    assert!(!patch_server_hello_key_share(&mut records));
    // 长度与组不匹配时同样拒绝。
    let mut records = synthetic_server_hello(0x001D, 48);
    assert!(!patch_server_hello_key_share(&mut records));
}

/// ServerHello 之后的每一个明文字节都必须逐连接变化。任何在所有采样中
/// 取值相同的位置都是一次 memcmp 即可命中的判别特征。
#[test]
fn ghost_record_payloads_contain_no_constant_bytes() {
    let sizes = vec![120usize, 300, 512, 64];
    let mut flights = Vec::new();
    for _ in 0..SAMPLES {
        flights.push(sample_flight(&sizes));
    }

    let (_, reference_payloads) = &flights[0];
    for (record_idx, payload) in reference_payloads.iter().enumerate() {
        for offset in payload.clone() {
            let first = flights[0].0[offset];
            let all_same = flights.iter().all(|(bytes, _)| bytes[offset] == first);
            assert!(
                !all_same,
                "record {} offset {} (payload offset {}) is constant 0x{:02x} across {} \
                 connections — a censor identifies this with one memcmp",
                record_idx,
                offset,
                offset - payload.start,
                first,
                SAMPLES
            );
        }
    }
}

/// 跨连接不得出现逐字节重复的长片段。真实 AEAD 密文永不重复；共享缓冲
/// （如此前的全局熵池）会让审查者通过跨流子串拼接把连接归并到同一进程。
#[test]
fn ghost_record_payloads_never_repeat_across_connections() {
    let sizes = vec![256usize, 1024, 512];
    let mut windows: std::collections::HashMap<&[u8], usize> = std::collections::HashMap::new();
    let flights: Vec<_> = (0..SAMPLES).map(|_| sample_flight(&sizes)).collect();

    for (flight_idx, (bytes, payloads)) in flights.iter().enumerate() {
        // 同一条 flight 内部的窗口只登记一次，避免自重叠误报。
        let mut local = std::collections::HashSet::new();
        for payload in payloads {
            let region = &bytes[payload.clone()];
            for window in region.windows(REPEAT_WINDOW) {
                local.insert(window);
            }
        }
        for window in local {
            if let Some(previous) = windows.insert(window, flight_idx) {
                panic!(
                    "flights {} and {} share an identical {}-byte payload window — \
                     ghost payloads must be freshly generated per connection",
                    previous, flight_idx, REPEAT_WINDOW
                );
            }
        }
    }
}

/// ghost record 的尺寸必须严格复刻参考端点的采样值（回放保真度），
/// 且首条记录承载 Noise 响应。
#[test]
fn ghost_record_sizes_match_the_replayed_profile() {
    let sizes = vec![200usize, 77, 4096];
    let (_, payloads) = sample_flight(&sizes);
    let observed: Vec<usize> = payloads.iter().map(|range| range.len()).collect();
    assert_eq!(observed, sizes);
}

/// 构造一个只关心时间轴的 profile（尺寸字段取合法占位值）。
fn timing_profile(first_delay_us: u32, gaps_us: Vec<u32>) -> super::camouflage::CamouflageProfile {
    super::camouflage::CamouflageProfile {
        server_records: std::sync::Arc::from(vec![].into_boxed_slice()),
        prefix_app_data_sizes: vec![],
        app_data_sizes: std::sync::Arc::from(vec![].into_boxed_slice()),
        first_app_data_size: None,
        early_app_data_count: 0,
        has_ccs: true,
        visible_server_record_count: 2,
        first_app_data_delay_us: first_delay_us,
        early_app_data_gap_us: gaps_us,
    }
}

/// 写批次的划分必须只由**采样到的真实间隔**驱动，且下标映射不得 off-by-one。
///
/// 此前只有 Noise/ghost 记录那一段循环做合批；`ServerHello+CCS ↔ 首条 app-data`
/// 的接缝、以及每两条前置小记录之间都是各自独立的 `write_all + flush`。socket
/// 开了 TCP_NODELAY，于是即使采样到的间隔是 0，这些位置也**恒定**落在不同的
/// TCP 分段里——真实 TLS 1.3 服务端把 SH|CCS|EE|CERT|CV|FIN 连续突发写出、由
/// 内核按 MSS 分段，记录边界与分段边界并不对齐。
///
/// 合并两段后下标轴只剩一条，本测试正是为了固定那次重新推导的结果。
#[test]
fn replay_burst_breaks_only_on_sampled_significant_gaps() {
    use super::camouflage::{replay_gap_before_us, SIGNIFICANT_REPLAY_GAP_US};

    // early_app_data_gap_us[j] 紧接在第 j 条 app-data 之后，因此第 idx 条
    // 之前的间隔是 gap[idx-1]；第 0 条之前的是 first_app_data_delay_us。
    let profile = timing_profile(1_200, vec![0, 40_000, 900, 7_500]);
    assert_eq!(replay_gap_before_us(&profile, 0), 1_200);
    assert_eq!(replay_gap_before_us(&profile, 1), 0);
    assert_eq!(replay_gap_before_us(&profile, 2), 40_000);
    assert_eq!(replay_gap_before_us(&profile, 3), 900);
    assert_eq!(replay_gap_before_us(&profile, 4), 7_500);
    // 采样到的 gap 少于记录数时并入同一次突发，不得 panic。
    assert_eq!(replay_gap_before_us(&profile, 5), 0);
    assert_eq!(replay_gap_before_us(&profile, 99), 0);

    // 以上时间轴对应 6 条 app-data 记录 → 恰好 3 次 write+flush：
    //   [SH+CCS, rec0, rec1] | [rec2] | [rec3, rec4, rec5]
    // 断点只落在 40_000µs 与 7_500µs 两处，1_200µs / 0 / 900µs 全部合批。
    let breaks: Vec<usize> = (0..6)
        .filter(|&idx| replay_gap_before_us(&profile, idx) >= SIGNIFICANT_REPLAY_GAP_US)
        .collect();
    assert_eq!(
        breaks,
        vec![2, 4],
        "batch boundaries must track the sampled gaps, not the record boundaries"
    );

    // 全零时间轴（真实端点的常见情形）必须产生**恰好一次**写：任何断点都是
    // 我们自己凭空造出来的分段边界。
    let burst_profile = timing_profile(0, vec![0, 0, 0]);
    assert!(
        (0..4).all(|idx| replay_gap_before_us(&burst_profile, idx) < SIGNIFICANT_REPLAY_GAP_US),
        "a flight sampled with zero inter-record gaps must be replayed as one burst"
    );

    // 阈值本身不带随机抖动：断点位置由真实测量值决定，而不是由随机数决定。
    // （真实端点的突发形态是确定的；在这个维度上随机化本身就是判别特征。）
    let boundary = timing_profile(SIGNIFICANT_REPLAY_GAP_US, vec![SIGNIFICANT_REPLAY_GAP_US - 1]);
    for _ in 0..64 {
        assert!(replay_gap_before_us(&boundary, 0) >= SIGNIFICANT_REPLAY_GAP_US);
        assert!(replay_gap_before_us(&boundary, 1) < SIGNIFICANT_REPLAY_GAP_US);
    }
}

/// 跑一遍真正的合成回放发送路径，返回 (完整字节流, app-data payload 区间)。
///
/// 通过预置一个 rank-3 缓存 profile 让 `fetch_camouflage_flight` 直接命中缓存，
/// 因此不产生任何网络 I/O。
async fn replay_flight_over_socket(
    host: &str,
    prefix_sizes: Vec<usize>,
    app_data_sizes: Vec<usize>,
) -> (Vec<u8>, Vec<std::ops::Range<usize>>) {
    use super::camouflage::{
        camouflage_profile_key, establish_synthetic_camouflage_tunnel, store_camouflage_profile,
        CamouflageProfile,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let template =
        crate::template::get_or_build_client_hello_template(host, Some("firefox"), None, true)
            .unwrap();
    let (noise, derived_psk) = responder_handshake();
    let client_noise_tag = [0x5au8; 16];
    let client_hello = template.instantiate(&derived_psk, &[7u8; 48], 1).unwrap();

    let fingerprint = crate::utils::stable_client_hello_fingerprint(&client_hello).unwrap();
    // 缓存的 ServerHello 必须回显 32 字节 session_id（模板 CH 的长度）。
    let server_records = synthetic_server_hello(0x001D, 32);
    let server_records_len = server_records.len();
    let gaps = vec![0u32; app_data_sizes.len().saturating_sub(1)];
    store_camouflage_profile(
        camouflage_profile_key(host, 443, &hex::encode(fingerprint)),
        CamouflageProfile {
            server_records: std::sync::Arc::from(server_records.into_boxed_slice()),
            prefix_app_data_sizes: prefix_sizes.clone(),
            first_app_data_size: app_data_sizes.first().copied(),
            early_app_data_count: app_data_sizes.len() as u8,
            has_ccs: true,
            visible_server_record_count: 1,
            first_app_data_delay_us: 0,
            early_app_data_gap_us: gaps,
            app_data_sizes: std::sync::Arc::from(app_data_sizes.clone().into_boxed_slice()),
        },
    )
    .await;

    let expected_len = server_records_len
        + app_data_sizes
            .iter()
            .map(|&size| TLS_RECORD_HEADER_LEN + size)
            .sum::<usize>();

    let (mut client, mut server) = connected_pair().await;
    let mut state = Some(noise);
    let replay_host = host.to_owned();
    let server_task = tokio::spawn(async move {
        establish_synthetic_camouflage_tunnel(
            &mut server,
            &client_hello,
            &replay_host,
            443,
            &mut state,
            &derived_psk,
            &client_noise_tag,
        )
        .await
        .map(|_| ())
    });

    let mut wire = vec![0u8; expected_len];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_exact(&mut wire),
    )
    .await
    .expect("replay must not hang");
    let _ = client.shutdown().await;
    // 先看服务端的错误——它比 read 侧的 early-eof 有信息量得多。
    server_task.await.unwrap().expect("replay must succeed");
    read.expect("replay must deliver the full flight");

    // 只切 app-data 区间：ServerHello 记录组是 TLS 明文结构，不参与断言。
    let mut payloads = Vec::new();
    let mut offset = server_records_len;
    while offset + TLS_RECORD_HEADER_LEN <= wire.len() {
        assert_eq!(wire[offset], 0x17, "app-data record type at {}", offset);
        let len = u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
        let start = offset + TLS_RECORD_HEADER_LEN;
        payloads.push(start..start + len);
        offset = start + len;
    }
    assert_eq!(offset, wire.len(), "trailing bytes outside any record");
    (wire, payloads)
}

/// 合成回放的记录条数 / 尺寸 / 顺序必须严格复刻采样 profile，且**每一条**
/// app-data payload（含前置小记录）都逐连接新鲜随机。
///
/// 前置小记录此前完全没有被覆盖：它们在 `establish_synthetic_camouflage_tunnel`
/// 里就地生成，而现有的 ghost 断言只覆盖 `build_noise_response_sequence`。把
/// 三段（SH 记录组 / 前置记录 / Noise+ghost 记录）合并成同一次突发写时，最容易
/// 退化的正是「为了少一次分配而复用缓冲」——那会让不同连接的 payload 出现逐
/// 字节相同的长片段，可跨流拼接识别（真实 AEAD 密文永不重复）。
#[tokio::test]
async fn synthetic_replay_preserves_record_shape_and_freshens_every_payload() {
    // app_data_sizes 的开头两条 < MIN_NOISE_RESPONSE_RECORD_LEN(54)，正是被
    // 归入 prefix_app_data_sizes 的那一段；其余三条承载 Noise 响应 + ghost。
    let prefix_sizes = vec![23usize, 31];
    let app_data_sizes = vec![23usize, 31, 200, 77, 4096];

    let mut flights = Vec::new();
    for idx in 0..4 {
        flights.push(
            replay_flight_over_socket(
                &format!("burst-replay-{}.test", idx),
                prefix_sizes.clone(),
                app_data_sizes.clone(),
            )
            .await,
        );
    }

    for (bytes, payloads) in &flights {
        let observed: Vec<usize> = payloads.iter().map(|range| range.len()).collect();
        assert_eq!(
            observed, app_data_sizes,
            "replayed record sizes/count/order must match the sampled profile exactly"
        );
        assert_eq!(bytes[0], 0x16, "flight must open with the ServerHello record");
    }

    // 跨连接不得出现逐字节重复的 16 字节窗口（含前置小记录的 payload）。
    let mut windows: std::collections::HashMap<&[u8], usize> = std::collections::HashMap::new();
    for (flight_idx, (bytes, payloads)) in flights.iter().enumerate() {
        let mut local = std::collections::HashSet::new();
        for payload in payloads {
            for window in bytes[payload.clone()].windows(REPEAT_WINDOW) {
                local.insert(window);
            }
        }
        for window in local {
            if let Some(previous) = windows.insert(window, flight_idx) {
                panic!(
                    "flights {} and {} share an identical {}-byte payload window — every \
                     plaintext byte written after ServerHello must be freshly generated \
                     per connection",
                    previous, flight_idx, REPEAT_WINDOW
                );
            }
        }
    }
}

/// 回放抖动必须是围绕 base 的对称连续分布，不得有点质量、不得单边。
///
/// 旧实现用 `u64` 做 `jitter.saturating_sub(jitter_max)`，负半边被整体压到
/// 0，于是约 50% 的样本恰好等于 base、且永不低于 base，再叠加整毫秒量化。
/// 真实网络到达间隔没有原子，这个形状是稳定的时序指纹。
#[test]
fn replay_jitter_has_no_point_mass_and_is_two_sided() {
    use super::camouflage::jitter_iat;

    const BASE_US: u32 = 100_000;
    const ROUNDS: usize = 4000;
    let base = std::time::Duration::from_micros(BASE_US as u64);

    let mut below = 0usize;
    let mut above = 0usize;
    let mut histogram: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for _ in 0..ROUNDS {
        let sample = jitter_iat(BASE_US);
        match sample.cmp(&base) {
            std::cmp::Ordering::Less => below += 1,
            std::cmp::Ordering::Greater => above += 1,
            std::cmp::Ordering::Equal => {}
        }
        *histogram.entry(sample.as_micros() as u64).or_default() += 1;
        assert!(
            sample >= std::time::Duration::from_millis(80)
                && sample <= std::time::Duration::from_millis(120),
            "sample {:?} outside the ±20% window around {:?}",
            sample,
            base
        );
    }

    assert!(
        below > ROUNDS / 4 && above > ROUNDS / 4,
        "jitter must be two-sided (below={}, above={} of {}) — a one-sided \
         distribution never dips under the replayed base value",
        below,
        above,
        ROUNDS
    );

    let (peak_value, peak_count) = histogram
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(value, count)| (*value, *count))
        .unwrap();
    assert!(
        peak_count * 20 < ROUNDS,
        "value {}us carries {}/{} of the mass — a point mass at a fixed \
         integer-millisecond value is directly visible in a timing histogram",
        peak_value,
        peak_count,
        ROUNDS
    );
}

/// base 为 0 时不得引入任何延迟（参考端点连续突发的语义）。
#[test]
fn replay_jitter_of_zero_base_is_zero() {
    assert_eq!(super::camouflage::jitter_iat(0), std::time::Duration::ZERO);
}

/// 亚毫秒基值必须以亚毫秒精度存活。
///
/// 此前 profile 以整毫秒存储、采样端又用 `as_millis()` 向下截断：真实端点
/// 绝大多数 0–1 ms 的帧内间隔被整体压成 0，活下来的也全部落在整毫秒格点上，
/// `jitter_iat` 的 ±20% 只是围绕整毫秒中心散开。量纲改成微秒后，若输出仍被
/// 量化回格点，这次改动就等于没做。
#[test]
fn replay_jitter_preserves_sub_millisecond_bases() {
    use super::camouflage::jitter_iat;

    const BASE_US: u32 = 700;
    const ROUNDS: usize = 512;
    let mut distinct = std::collections::HashSet::new();
    for _ in 0..ROUNDS {
        let sample = jitter_iat(BASE_US);
        assert!(
            sample >= std::time::Duration::from_nanos(560_000)
                && sample <= std::time::Duration::from_nanos(840_000),
            "sample {:?} outside the ±20% window around {}us",
            sample,
            BASE_US
        );
        distinct.insert(sample.as_nanos());
    }
    assert!(
        distinct.len() * 2 > ROUNDS,
        "only {} distinct values out of {} draws — a sub-millisecond base must not be \
         re-quantized onto a grid",
        distinct.len(),
        ROUNDS
    );
}

/// 服务端自己引入的 pre-auth 时间常量必须**短**，且必须是**常量**。
///
/// 两条原则在这里同时生效，而此前的实现各违反一条：
///
///   * 「能被稳定识别 = 会被封」：读超时后走的是回落转发，探测者观察到的
///     关闭时刻 = 我们的超时 + 上游超时。8–15 s 的读超时叠在上游的精确
///     60.000 s 上，一次连接即可测出这个正偏移。
///   * 「全随机 = 会被封」：真实 nginx 的 `client_header_timeout` 是精确常量，
///     真实服务器没有随机超时。用抖动去「消除常量」，等于在一个真实实现恒定
///     的维度上引入随机性——那本身就是判别特征。
///
/// 正确解法是让我们那一项**不可观测**：取短的固定值，让上游的真实常量占绝对
/// 主导。因此这里断言「预算固定 + 足够短」，而不是断言它有分布。
#[tokio::test]
async fn initial_record_timeouts_are_short_and_constant() {
    use super::auth::initial_record_deadlines;

    const ROUNDS: usize = 64;
    let mut zero_byte = Vec::with_capacity(ROUNDS);
    let mut partial = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let origin = tokio::time::Instant::now();
        let deadlines = initial_record_deadlines();
        zero_byte.push(deadlines.zero_byte.saturating_duration_since(origin));
        partial.push(deadlines.partial.saturating_duration_since(origin));
    }

    let spread = |samples: &[std::time::Duration]| {
        *samples.iter().max().unwrap() - *samples.iter().min().unwrap()
    };
    // 调度噪声只有微秒量级；任何 gen_range 都会让跨度跳到秒量级。
    assert!(
        spread(&zero_byte) < std::time::Duration::from_millis(50),
        "zero-byte read budget varies by {:?} across connections — a randomized timeout is \
         itself a discriminator, real servers use an exact client_header_timeout",
        spread(&zero_byte)
    );
    assert!(
        spread(&partial) < std::time::Duration::from_millis(50),
        "partial-record read budget varies by {:?} across connections",
        spread(&partial)
    );

    // 上界留 100ms 松弛：measured = 常量 + 取 origin 与函数内 now() 之间的
    // 调度延迟，恒略大于常量本身。
    const SLACK: std::time::Duration = std::time::Duration::from_millis(100);
    let zero_byte_budget = zero_byte[0];
    let partial_budget = partial[0];
    assert!(
        zero_byte_budget <= std::time::Duration::from_secs(3) + SLACK,
        "zero-byte read budget {:?} is added on top of the upstream timeout and must stay \
         small enough to disappear into it",
        zero_byte_budget
    );
    assert!(
        partial_budget <= std::time::Duration::from_secs(5) + SLACK,
        "partial-record read budget {:?} is added on top of the upstream timeout",
        partial_budget
    );
    assert!(
        zero_byte_budget <= partial_budget,
        "a fragmented ClientHello must get at least as much time as a silent connection"
    );
}

async fn connected_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(client, accept);
    (client.unwrap(), accepted.unwrap().0)
}

/// 限额耗尽路径的关闭必须与「客户端发过什么」无关。
///
/// socket 上留有未读数据时 `close(2)` 会在 FIN 之后再发一个 RST，于是
/// 「发过 ClientHello」与「什么都没发」得到不同的关闭序列——这个分裂本身
/// 就是免费的判别信号。
///
/// 判据不能只看第一次 read：FIN 先到，客户端读到 EOF 时 RST 可能还在路上。
/// 必须在 EOF 之后再写一次——RST 已到达时写会得到 BrokenPipe / ConnectionReset，
/// 未发生 RST 时写正常返回。两种输入必须给出相同结果。
///
/// 关闭**时刻**同样不得随输入变化。删掉此前那段 200–3000 ms 随机延迟之后，
/// 关闭时刻就等于排空窗口本身，因此这条不变量从「被随机延迟盖住」变成
/// 「必须显式成立」：排空循环无论读到多少字节都跑满 `CLOSE_DRAIN_TIMEOUT`，
/// 于是「发过 ClientHello」与「什么都没发」得到同一个关闭时刻。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indistinguishable_close_drains_before_closing() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut observations = Vec::new();
    for payload in [Vec::new(), vec![0x16u8; 2048]] {
        let (mut client, server) = connected_pair().await;
        if !payload.is_empty() {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
        }

        let started = std::time::Instant::now();
        let closer = tokio::spawn(super::fallback::emit_indistinguishable_close(server));

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut buf))
            .await
            .expect("close must not hang")
            .expect("close must surface as a clean EOF");
        let elapsed = started.elapsed();
        assert_eq!(n, 0, "close must not emit any application bytes");

        // 给可能的 RST 留出到达时间，再用一次写探测连接是否已被重置。
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let post_eof_write = client.write_all(b"probe").await.map_err(|e| e.kind());
        observations.push((payload.len(), post_eof_write, elapsed));
        closer.await.unwrap();
    }

    assert_eq!(
        observations[0].1, observations[1].1,
        "close observable differs by what the client sent ({:?}) — an unread receive \
         queue makes close(2) emit RST after the FIN, and that FIN-vs-FIN+RST split \
         lets a prober classify the server with a single connection",
        observations
    );

    let timing_gap = observations[0]
        .2
        .abs_diff(observations[1].2);
    assert!(
        timing_gap <= std::time::Duration::from_millis(250),
        "close instant differs by {:?} between a silent client and one that sent a \
         ClientHello — the drain must run out its full budget either way, otherwise the \
         close time itself classifies the input ({:?})",
        timing_gap,
        observations
    );
}

/// 大载荷（超过曾经的 64 KiB 字节上限）不得让排空提前结束。
///
/// 此前排空循环同时受 `CLOSE_DRAIN_TIMEOUT` 与 `CLOSE_DRAIN_MAX_BYTES` 两个条件
/// 约束：快发送方会在读到约 64 KiB 时退出循环、立即 `shutdown()`——关闭时刻从
/// 恒定的 200 ms 退化成「发送速度的函数」，与「无论收到多少字节都跑满
/// `CLOSE_DRAIN_TIMEOUT`」的文档契约相悖。排空只应受时间窗口约束：窗口是成本
/// 上界，字节数不是。
///
/// 服务端启动在前、载荷分块写在后，因此 `elapsed` 就是排空窗口本身；只要
/// 载荷到达（或已在队列中）的速度快于 64 KiB / 200 ms，此前的字节上限就会让
/// 关闭显著提前。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indistinguishable_close_drains_fast_sender_for_full_budget() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut client, server) = connected_pair().await;
    let started = std::time::Instant::now();
    let closer = tokio::spawn(super::fallback::emit_indistinguishable_close(server));

    for _ in 0..(200 * 1024 / 8192) {
        client.write_all(&[0x16u8; 8192]).await.unwrap();
    }
    client.flush().await.unwrap();

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut buf))
        .await
        .expect("close must not hang")
        .expect("close must surface as a clean EOF");
    let elapsed = started.elapsed();
    assert_eq!(n, 0, "close must not emit any application bytes");

    // 给可能的 RST 留出到达时间，再用一次写探测连接是否已被重置。
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let post_eof_write = client.write_all(b"probe").await.map_err(|e| e.kind());
    closer.await.unwrap();

    assert!(
        elapsed >= std::time::Duration::from_millis(150),
        "200 KiB in flight closed the connection after only {:?} — the drain loop must \
         run out its full budget regardless of how fast the sender pushes bytes",
        elapsed
    );
    assert!(
        post_eof_write.is_ok(),
        "close of a connection with an undrained receive queue resets the connection \
         ({:?}) — the full payload must have been drained before shutdown",
        post_eof_write
    );
}

/// 限额耗尽路径的关闭必须是一个**短的常量**，不得是随机延迟。
///
/// 此前这条测试断言的是反面（「关闭必须带随机延迟」，`elapsed >= 150ms`），
/// 依据是「瞬时关闭是可测到毫秒的常量」。那个依据在当时成立，但它要掩盖的
/// 对象已经消失：随后 §5.2 把**全部输入驱动的失败**（读超时、非 TLS 首记录、
/// 认证失败、超长 record）都改走了透明转发，`emit_indistinguishable_close`
/// 只剩「服务端此刻没有容量」一种成因。于是 200–3000 ms 的均匀延迟不再是在
/// 抹平两个常量，而是在一个真实实现恒定的维度上凭空造出一个分布——正是原则 2
/// 点名的那类特征，且 `U[0.2, 3.0] s` 的直方图形状一眼可辨。
///
/// 反转后要锁的是两件事，缺一不可：
///   * **短**：关闭时刻必须落在排空窗口量级，不得有秒级尾巴。真实 nginx 在
///     `worker_connections` 耗尽时就是 accept 之后立即关闭。
///   * **常量**：跨连接的跨度必须小到只剩调度噪声。任何重新引入的随机化都会
///     把跨度顶到几百毫秒以上。
///
/// 采样并发进行，因此本测试的墙钟开销只有一个排空窗口。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indistinguishable_close_is_a_short_constant_not_a_random_delay() {
    use tokio::io::AsyncReadExt;

    const SAMPLES: usize = 10;
    let mut tasks = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (mut client, server) = connected_pair().await;
        tasks.push(tokio::spawn(async move {
            let started = std::time::Instant::now();
            let closer = tokio::spawn(super::fallback::emit_indistinguishable_close(server));
            let mut buf = [0u8; 16];
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut buf))
                .await
                .expect("close must not hang")
                .expect("close must surface as a clean EOF");
            let elapsed = started.elapsed();
            closer.await.unwrap();
            assert_eq!(n, 0, "close must not emit any application bytes");
            elapsed
        }));
    }

    let mut elapsed = Vec::with_capacity(SAMPLES);
    for task in tasks {
        elapsed.push(task.await.unwrap());
    }

    let slowest = *elapsed.iter().max().unwrap();
    let spread = slowest - *elapsed.iter().min().unwrap();
    assert!(
        slowest <= std::time::Duration::from_millis(900),
        "slowest close fired after {:?} — the only self-inflicted delay on this path is the \
         bounded receive-queue drain; a multi-second tail means a synthetic delay came back \
         (and it holds an fd exactly when the server is already out of capacity)",
        slowest
    );
    assert!(
        spread <= std::time::Duration::from_millis(250),
        "close time varies by {:?} across {} connections — a randomized close is itself the \
         discriminator: no real implementation samples its close instant from a distribution, \
         so the histogram of this branch would be a synthetic shape (samples: {:?})",
        spread,
        SAMPLES,
        elapsed
    );
}
