use super::{
    coalesce_encoded_frames, BufferedPayload, PendingData, Session, SessionConfig,
    STREAM_CHANNEL_CAPACITY,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::server::ServerSessionHandler;
use futures::poll;
use kanotls_tunnel::common::{derive_psk, NOISE_PARAMS};
use kanotls_tunnel::SnowyStream;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// `PendingData` 的总字节与每流字节改为运行计数（此前是每次入队全量求和）。
/// 计数一旦与真实内容脱节，背压限额就会失效或误伤，因此在一串混合操作后
/// 逐项校验计数与实际内容一致。
#[test]
fn pending_data_counters_track_contents_exactly() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut pending = PendingData::default();

    let payload = |len: usize| BufferedPayload::new(vec![0u8; len], &counter);

    // 交错入队三条流。
    for (sid, len) in [(1u32, 10usize), (2, 20), (1, 30), (3, 40), (2, 50)] {
        pending.push_back(sid, payload(len));
    }
    assert_eq!(pending.total_bytes(), 150);
    assert_eq!(pending.stream_bytes(1), 40);
    assert_eq!(pending.stream_bytes(2), 70);
    assert_eq!(pending.stream_bytes(3), 40);
    assert_eq!(pending.stream_frames(1), 2);
    assert_eq!(pending.len(), 3);

    // 出队按 FIFO，并同步扣减两级计数。
    assert_eq!(pending.pop_front(1).unwrap().len(), 10);
    assert_eq!(pending.total_bytes(), 140);
    assert_eq!(pending.stream_bytes(1), 30);

    // 队列排空即移除条目，使 contains()/len() 恒等于「有积压的流」。
    assert_eq!(pending.pop_front(1).unwrap().len(), 30);
    assert!(!pending.contains(1));
    assert_eq!(pending.len(), 2);
    assert_eq!(pending.stream_bytes(1), 0);
    assert_eq!(pending.stream_frames(1), 0);
    assert!(pending.pop_front(1).is_none());
    assert_eq!(pending.total_bytes(), 110);

    // 整流移除要扣掉该流的全部字节。
    let removed = pending.remove(2).unwrap();
    assert_eq!(removed.len(), 2);
    assert_eq!(pending.total_bytes(), 40);
    assert!(pending.remove(2).is_none());
    assert_eq!(pending.total_bytes(), 40);

    pending.clear();
    assert_eq!(pending.total_bytes(), 0);
    assert_eq!(pending.len(), 0);
}

/// 计数口径与 `buffered_stream_bytes` 的 RAII 记账保持一致：载荷被
/// `into_vec` 取走或被丢弃时恰好回账一次。
#[test]
fn pending_data_release_matches_buffered_byte_accounting() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut pending = PendingData::default();
    pending.push_back(7, BufferedPayload::new(vec![0u8; 100], &counter));
    pending.push_back(7, BufferedPayload::new(vec![0u8; 200], &counter));
    assert_eq!(counter.load(Ordering::Relaxed), 300);

    let taken = pending.pop_front(7).unwrap();
    assert_eq!(taken.into_bytes().len(), 100);
    assert_eq!(counter.load(Ordering::Relaxed), 200);

    // 丢弃整条流的积压，剩余载荷由 Drop 回账。
    pending.clear();
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

/// P3 回归：`PendingOpenStreams` 的总字节改为运行计数（此前
/// `store_pending_open_data` 每存一帧都对全部条目全量求和）。计数一旦与真实
/// 内容脱节，限额就会失效或误伤，因此在一串混合操作后逐项校验。
#[test]
fn pending_open_streams_counters_track_contents_exactly() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut pending = super::PendingOpenStreams::default();
    let payload = |len: usize| BufferedPayload::new(vec![0u8; len], &counter);

    pending.insert_new(1);
    pending.insert_new(2);
    assert!(pending.push_data(1, payload(10)));
    assert!(pending.push_data(1, payload(30)));
    assert!(pending.push_data(2, payload(20)));
    // 未登记的流不入队、也不建条目。
    assert!(!pending.push_data(9, payload(50)));
    assert!(!pending.contains(9));
    assert_eq!(pending.total_bytes(), 60);
    assert_eq!(pending.stream_frames(1), 2);
    assert_eq!(counter.load(Ordering::Relaxed), 60);

    // 取走：限额账立即扣减，RAII 账要等载荷被消费或丢弃。
    let (data, fin) = pending.take_ready(1).expect("entry exists");
    assert_eq!(data.len(), 2);
    assert!(!fin);
    assert_eq!(pending.total_bytes(), 20);
    assert_eq!(counter.load(Ordering::Relaxed), 60);
    drop(data);
    assert_eq!(counter.load(Ordering::Relaxed), 20);
    assert_eq!(pending.stream_frames(1), 0);
    assert!(pending.contains(1), "take_ready 不移除条目");

    // FIN 标记取走一次即清。
    assert!(pending.set_buffered_fin(1));
    assert!(pending.take_ready(1).expect("entry exists").1);
    assert!(!pending.take_ready(1).expect("entry exists").1);

    // 整条流丢弃：两本账同时扣减。
    pending.remove(2);
    assert_eq!(pending.total_bytes(), 0);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
    assert!(!pending.contains(2));
    pending.remove(2);
    assert_eq!(pending.total_bytes(), 0);

    // insert_new 覆盖旧条目时也要扣账。
    assert!(pending.push_data(1, payload(70)));
    assert_eq!(pending.total_bytes(), 70);
    pending.insert_new(1);
    assert_eq!(pending.total_bytes(), 0);
    assert_eq!(counter.load(Ordering::Relaxed), 0);

    // 入站流预留只释放一次。
    assert_eq!(pending.release_reservation(1), Some(true));
    assert_eq!(pending.release_reservation(1), Some(false));
    assert_eq!(pending.release_reservation(42), None);

    assert!(pending.push_data(1, payload(5)));
    pending.clear();
    assert_eq!(pending.total_bytes(), 0);
    assert!(pending.is_empty());
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn coalesce_encoded_frames_packs_adjacent_small_frames() {
    let frames = vec![vec![1u8; 7], vec![2u8; 7], vec![3u8; 7]];
    let out = coalesce_encoded_frames(frames, 32);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].len(), 21);
}

#[test]
fn coalesce_encoded_frames_respects_packet_limit() {
    let frames = vec![vec![1u8; 20], vec![2u8; 20], vec![3u8; 8]];
    let out = coalesce_encoded_frames(frames, 32);

    assert_eq!(out.len(), 2);
    assert_eq!(out[0].len(), 20);
    assert_eq!(out[1].len(), 28);
}

/// 线上观测类测试的互斥锁。
///
/// `H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES` / `H2_PING_IDLE_THRESHOLD_OVERRIDE_MS` /
/// `H2_EXCHANGE_INTERVAL_OVERRIDE_MS` 是**进程级**覆写点，而 cargo 默认并行跑
/// 测试：把 PING 间隔压到 50ms 的测试会让**同时**在跑的抓包测试看到一对
/// `41 / −41`（PING / PING-ACK）记录，那正好凑成 `(−L4, L1, −L1)`。凡是
/// 「设置覆写点」或「对线上记录序列做断言」的测试都必须先拿这把锁。
static WIRE_OBSERVATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn test_session_config(is_client: bool) -> SessionConfig {
    SessionConfig {
        is_client,
        max_streams_per_session: 32,
        idle_timeout_secs: 30,
        traffic_script: None,
        post_script_off: false,
    }
}

fn build_transport_pair() -> (kanotls_tunnel::NoiseTransport, kanotls_tunnel::NoiseTransport) {
    let derived_psk = derive_psk(b"session-open-path-tests");
    let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
        .psk(0, &derived_psk)
        .expect("psk accepted")
        .build_initiator()
        .expect("initiator builds");
    let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
        .psk(0, &derived_psk)
        .expect("psk accepted")
        .build_responder()
        .expect("responder builds");

    let mut client_hello = [0u8; 96];
    let client_hello_len = initiator
        .write_message(&[], &mut client_hello)
        .expect("initiator writes handshake");
    responder
        .read_message(&client_hello[..client_hello_len], &mut [])
        .expect("responder reads handshake");

    let mut server_hello = [0u8; 96];
    let server_hello_len = responder
        .write_message(&[], &mut server_hello)
        .expect("responder writes handshake");
    initiator
        .read_message(&server_hello[..server_hello_len], &mut [])
        .expect("initiator reads handshake");

    (
        kanotls_tunnel::NoiseTransport::new(
            initiator
                .into_stateless_transport_mode()
                .expect("initiator enters transport mode"),
        ),
        kanotls_tunnel::NoiseTransport::new(
            responder
                .into_stateless_transport_mode()
                .expect("responder enters transport mode"),
        ),
    )
}

async fn snowy_stream_pair() -> (SnowyStream, SnowyStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener binds");
    let addr = listener.local_addr().expect("listener has address");
    let client_task = tokio::spawn(async move {
        TcpStream::connect(addr)
            .await
            .expect("client connects to listener")
    });
    let (server_tcp, _) = listener.accept().await.expect("listener accepts client");
    let client_tcp = client_task.await.expect("client connect task completes");
    let (client_noise, server_noise) = build_transport_pair();
    (
        SnowyStream::new(client_tcp, client_noise),
        SnowyStream::new(server_tcp, server_noise),
    )
}

async fn session_pair() -> (Arc<Session>, ServerSessionHandler) {
    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let server = ServerSessionHandler::new(server_tunnel, test_session_config(false));

    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });

    let server_read_loop = server.session.clone();
    tokio::spawn(async move {
        let _ = server_read_loop.run_read_loop().await;
    });

    (client, server)
}

async fn session_pair_with_config(
    client_config: SessionConfig,
    server_config: SessionConfig,
) -> (Arc<Session>, ServerSessionHandler) {
    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    let client = Arc::new(Session::new(client_tunnel, client_config, None));
    let server = ServerSessionHandler::new(server_tunnel, server_config);

    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });

    let server_read_loop = server.session.clone();
    tokio::spawn(async move {
        let _ = server_read_loop.run_read_loop().await;
    });

    (client, server)
}

#[tokio::test]
async fn dropped_first_stream_does_not_poison_next_open() {
    let (client, server) = session_pair().await;

    let first = client.open_stream().await.expect("first stream opens");
    drop(first);

    assert!(client.pending_client_settings.lock().await.is_some());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.accept_stream())
            .await
            .is_err()
    );

    let mut second = client.open_stream().await.expect("second stream opens");
    second
        .write_early(b"example.com:443")
        .await
        .expect("second stream writes early target");

    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accept returns before timeout")
            .expect("server accepts stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"example.com:443".to_vec()))
    );

    server_stream
        .send_synack()
        .await
        .expect("server sends SYNACK");
    second.wait_open().await.expect("second stream opens");

    client.force_close();
    server.session.force_close();
}

#[tokio::test]
async fn early_open_rejection_remains_failed_on_retry() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"reject-me")
        .await
        .expect("stream writes early target");

    let (sid, _server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accept returns before timeout")
            .expect("server accepts stream");
    server
        .session
        .send_synack_rejection(sid, "reject")
        .await
        .expect("server sends rejection");

    let first = stream.wait_open().await.expect_err("wait_open should fail");
    assert!(first.to_string().contains("reject"));

    let second = stream
        .wait_open()
        .await
        .expect_err("wait_open should stay failed");
    assert!(second.to_string().contains("reject"));

    client.force_close();
    server.session.force_close();
}

#[tokio::test]
async fn cancelled_open_stream_does_not_leave_busy_handle() {
    let (client, server) = session_pair().await;

    let client_clone = client.clone();
    let open_task = tokio::spawn(async move { client_clone.open_stream().await });
    open_task.abort();
    let _ = open_task.await;

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(client.streams.read().await.len(), 0);

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_warm_open_stream_cleans_up_peer_orphan() {
    let (client, server) = session_pair().await;

    let mut warmup = client.open_stream().await.expect("warmup stream opens");
    warmup
        .write_early(b"warmup")
        .await
        .expect("warmup early write succeeds");
    let (_warm_sid, warm_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts warmup before timeout")
            .expect("server accepts warmup");
    warm_server_stream
        .send_synack()
        .await
        .expect("server sends warmup synack");
    warmup.wait_open().await.expect("warmup opens");
    warmup.close().await.expect("warmup closes");

    let client_clone = client.clone();
    let open_task = tokio::spawn(async move { client_clone.open_stream().await });
    tokio::task::yield_now().await;
    open_task.abort();
    let _ = open_task.await;

    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts aborted stream before timeout")
            .expect("server accepts aborted stream");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), server_stream.read())
            .await
            .expect("server sees orphan cleanup"),
        None
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(client.active_stream_count(), 0);
    assert_eq!(client.pending_data.lock().await.len(), 0);
    assert!(client.pending_fin.lock().await.is_empty());

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_open_stream_allows_immediate_retry_at_capacity_one() {
    let mut client_config = test_session_config(true);
    client_config.max_streams_per_session = 1;
    let mut server_config = test_session_config(false);
    server_config.max_streams_per_session = 1;
    let (client, server) = session_pair_with_config(client_config, server_config).await;

    let client_clone = client.clone();
    let open_task = tokio::spawn(async move { client_clone.open_stream().await });
    open_task.abort();
    let _ = open_task.await;

    tokio::task::yield_now().await;
    let mut retry = client.open_stream().await.expect("retry stream opens");
    retry
        .write_early(b"retry.example:443")
        .await
        .expect("retry early write succeeds");

    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts retry stream before timeout")
            .expect("server accepts retry stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"retry.example:443".to_vec()))
    );

    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    retry.wait_open().await.expect("retry opens");

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_warm_submitted_stream_allows_immediate_retry_at_capacity_one() {
    let mut client_config = test_session_config(true);
    client_config.max_streams_per_session = 1;
    let mut server_config = test_session_config(false);
    server_config.max_streams_per_session = 1;
    let (client, server) = session_pair_with_config(client_config, server_config).await;

    let mut warmup = client.open_stream().await.expect("warmup stream opens");
    warmup
        .write_early(b"warmup")
        .await
        .expect("warmup early write succeeds");
    let (_warm_sid, warm_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts warmup before timeout")
            .expect("server accepts warmup");
    warm_server_stream
        .send_synack()
        .await
        .expect("server sends warmup synack");
    warmup.wait_open().await.expect("warmup opens");
    warmup.close().await.expect("warmup closes");

    let first = client.open_stream().await.expect("submitted stream opens");
    drop(first);

    let mut retry = client.open_stream().await.expect("retry stream opens");
    retry
        .write_early(b"retry.example:443")
        .await
        .expect("retry early write succeeds");

    let (_old_sid, mut old_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts dropped submitted stream")
            .expect("server accepts dropped submitted stream");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), old_server_stream.read())
            .await
            .expect("server sees dropped stream FIN"),
        None
    );

    let (_retry_sid, mut retry_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts retry stream before timeout")
            .expect("server accepts retry stream");
    assert_eq!(
        retry_server_stream.read().await,
        Some(Bytes::from(b"retry.example:443".to_vec()))
    );
    retry_server_stream
        .send_synack()
        .await
        .expect("server sends retry synack");
    retry.wait_open().await.expect("retry opens");

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn pre_synack_fin_fails_open_without_closing_session() {
    let mut client_config = test_session_config(true);
    client_config.max_streams_per_session = 1;
    let mut server_config = test_session_config(false);
    server_config.max_streams_per_session = 1;
    let (client, server) = session_pair_with_config(client_config, server_config).await;

    let mut first = client.open_stream().await.expect("first stream opens");
    first
        .write_early(b"blocked.example:443")
        .await
        .expect("first stream sends target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts first stream")
            .expect("server accepts first stream");
    server_stream
        .close()
        .await
        .expect("server closes before synack");

    let err = tokio::time::timeout(Duration::from_secs(1), first.wait_open())
        .await
        .expect("pre-SYNACK FIN should fail promptly")
        .expect_err("open should fail");
    assert!(err.to_string().contains("stream open rejected"));
    assert!(client.is_alive());

    let mut retry = client.open_stream().await.expect("retry stream opens");
    retry
        .write_early(b"retry.example:443")
        .await
        .expect("retry stream sends target");
    let (_retry_sid, retry_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts retry stream")
            .expect("server accepts retry stream");
    retry_server_stream
        .send_synack()
        .await
        .expect("server sends retry synack");
    retry.wait_open().await.expect("retry opens");

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn data_queued_before_fin_is_delivered_before_eof() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"example.com:443")
        .await
        .expect("client sends target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    server_stream
        .write(b"last")
        .await
        .expect("server sends data");
    server_stream.close().await.expect("server sends fin");

    assert_eq!(stream.read().await, Some(Bytes::from(b"last".to_vec())));
    assert_eq!(stream.read().await, None);

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_wait_open_after_submission_still_waits_for_synack() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    {
        let wait_open = stream.wait_open();
        tokio::pin!(wait_open);
        assert!(poll!(&mut wait_open).is_pending());
    }

    let (_sid, server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accept returns before timeout")
            .expect("server accepts stream");

    assert!(
        tokio::time::timeout(Duration::from_millis(50), stream.wait_open())
            .await
            .is_err(),
        "retry should still wait for SYNACK"
    );

    server_stream
        .send_synack()
        .await
        .expect("server sends SYNACK");
    stream.wait_open().await.expect("retry opens stream");

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_submitted_stream_clears_pending_client_buffers() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    {
        let wait_open = stream.wait_open();
        tokio::pin!(wait_open);
        assert!(poll!(&mut wait_open).is_pending());
    }

    let (sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream before timeout")
            .expect("server accepts stream");
    server_stream
        .write(b"buffered")
        .await
        .expect("server buffers data before synack");
    server_stream
        .close()
        .await
        .expect("server sends fin before synack");

    drop(stream);
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(!client.pending_data.lock().await.contains(sid));
    assert!(!client.pending_fin.lock().await.contains(&sid));
    assert_eq!(client.active_stream_count(), 0);

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_write_early_after_submission_still_finishes_stream() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    {
        let write_early = stream.write_early(b"example.com:443");
        tokio::pin!(write_early);
        assert!(poll!(&mut write_early).is_pending());
    }
    drop(stream);

    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accept returns before timeout")
            .expect("server accepts stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"example.com:443".to_vec()))
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), server_stream.read())
            .await
            .expect("server sees client FIN"),
        None
    );

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn idle_session_times_out() {
    let client_config = SessionConfig {
        is_client: true,
        max_streams_per_session: 32,
        idle_timeout_secs: 1,
        traffic_script: None,
        post_script_off: false,
    };
    let server_config = SessionConfig {
        is_client: false,
        max_streams_per_session: 32,
        idle_timeout_secs: 1,
        traffic_script: None,
        post_script_off: false,
    };
    let (client, server) = session_pair_with_config(client_config, server_config).await;

    tokio::time::timeout(Duration::from_secs(3), async {
        while client.is_alive() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("client session should idle out without heartbeat");
    tokio::time::timeout(Duration::from_secs(3), async {
        while server.session.is_alive() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("server session should idle out without heartbeat");
}

#[tokio::test(flavor = "current_thread")]
async fn active_session_does_not_timeout_with_open_streams() {
    let client_config = SessionConfig {
        is_client: true,
        max_streams_per_session: 32,
        idle_timeout_secs: 1,
        traffic_script: None,
        post_script_off: false,
    };
    let server_config = SessionConfig {
        is_client: false,
        max_streams_per_session: 32,
        idle_timeout_secs: 1,
        traffic_script: None,
        post_script_off: false,
    };
    let (client, server) = session_pair_with_config(client_config, server_config).await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"idle.example:443")
        .await
        .expect("client sends target");
    let (_sid, server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens after synack");

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(client.is_alive());
    assert!(server.session.is_alive());

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn late_data_and_fin_after_local_close_are_ignored_without_warnings() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"example.com:443")
        .await
        .expect("client sends target");
    let (_sid, server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    let sid = server_stream.sid;
    let mut server_stream = server_stream;
    server_stream.close().await.expect("server closes stream");
    assert!(server.session.closing_streams.lock().await.contains(&sid));
    stream
        .write(b"late-data")
        .await
        .expect("client can still write tail data");
    stream.close().await.expect("client sends fin");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if server.session.closing_streams.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closing tombstone clears after peer fin");
    assert_eq!(server.session.active_stream_count(), 0);
    assert!(server.session.closing_streams.lock().await.is_empty());

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn established_stream_backpressures_instead_of_self_closing() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"example.com:443")
        .await
        .expect("client sends target");
    let (_sid, server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    let frame_count = STREAM_CHANNEL_CAPACITY + 8;
    let frame_size = 32 * 1024;
    let fill_target = frame_size * STREAM_CHANNEL_CAPACITY;
    let send_task = tokio::spawn(async move {
        let mut server_stream = server_stream;
        for idx in 0..frame_count {
            server_stream
                .write(&vec![idx as u8; frame_size])
                .await
                .expect("server writes frame");
        }
        server_stream.close().await.expect("server closes stream");
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        while client.buffered_stream_bytes() < fill_target {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client queue should fill before reads begin");

    for idx in 0..frame_count {
        let data = tokio::time::timeout(Duration::from_secs(5), stream.read())
            .await
            .expect("client read returns before timeout")
            .expect("stream stays open until all data is read");
        assert_eq!(data.len(), frame_size);
        assert_eq!(data[0], idx as u8);
    }
    assert_eq!(stream.read().await, None);
    send_task.await.expect("server send task completes");

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn client_close_releases_capacity_before_peer_fin_arrives() {
    let mut client_config = test_session_config(true);
    client_config.max_streams_per_session = 1;
    let mut server_config = test_session_config(false);
    server_config.max_streams_per_session = 1;
    let (client, server) = session_pair_with_config(client_config, server_config).await;

    let mut first = client.open_stream().await.expect("first stream opens");
    first
        .write_early(b"first.example:443")
        .await
        .expect("first stream sends target");
    let (_sid, mut first_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts first stream")
            .expect("server accepts first stream");
    first_server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    first.wait_open().await.expect("first stream opens");

    first.close().await.expect("client closes first stream");

    let mut second = client.open_stream().await.expect("second stream opens");
    second
        .write_early(b"second.example:443")
        .await
        .expect("second stream sends target");

    first_server_stream
        .write(b"tail")
        .await
        .expect("first stream writes late tail");
    first_server_stream
        .close()
        .await
        .expect("first stream closes late");

    let (_sid, second_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts second stream")
            .expect("server accepts second stream");
    second_server_stream
        .send_synack()
        .await
        .expect("server sends second synack");
    second.wait_open().await.expect("second stream opens");

    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "current_thread")]
async fn close_write_preserves_peer_to_local_tail_delivery() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"example.com:443")
        .await
        .expect("client sends target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"example.com:443".to_vec()))
    );
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    stream
        .close_write()
        .await
        .expect("client half-closes write side");
    server_stream
        .write(b"response")
        .await
        .expect("server writes response after client eof");
    server_stream.close().await.expect("server closes stream");

    assert_eq!(stream.read().await, Some(Bytes::from(b"response".to_vec())));
    assert_eq!(stream.read().await, None);

    client.force_close();
    server.session.force_close();
}

// Phase 1 validation: drive a large multi-record transfer through the active
// slicing engine (drive_shaper) and assert byte-exact reassembly with no
// deadlock. The payload dwarfs a single record capacity, so it exercises the
// slice/truncate path many times over.
#[tokio::test]
async fn high_throughput_bulk_transfer_preserves_stream_integrity() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"bulk.example:443")
        .await
        .expect("client sends target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"bulk.example:443".to_vec()))
    );
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    // 4 MiB with a deterministic non-trivial byte pattern that survives
    // arbitrary record boundaries.
    const TOTAL: usize = 4 * 1024 * 1024;
    let pattern = |i: usize| -> u8 { ((i * 31 + 7) % 251) as u8 };

    let reader = tokio::spawn(async move {
        let mut received = 0usize;
        let mut ok = true;
        while let Some(chunk) = server_stream.read().await {
            for (j, &b) in chunk.iter().enumerate() {
                if b != pattern(received + j) {
                    ok = false;
                    break;
                }
            }
            received += chunk.len();
            if !ok {
                break;
            }
        }
        (received, ok)
    });

    let writer = tokio::spawn(async move {
        let mut buf = vec![0u8; TOTAL];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = pattern(i);
        }
        // Write in mixed-size chunks to stress the slicer's boundary handling.
        let mut off = 0usize;
        let chunk_sizes = [1usize, 100, 16382, 16383, 65536, 200000];
        let mut k = 0usize;
        while off < TOTAL {
            let want = chunk_sizes[k % chunk_sizes.len()].min(TOTAL - off);
            stream
                .write(&buf[off..off + want])
                .await
                .expect("client writes bulk chunk");
            off += want;
            k += 1;
        }
        stream.close_write().await.expect("client half-closes");
        stream
    });

    let _stream = tokio::time::timeout(Duration::from_secs(30), writer)
        .await
        .expect("writer must not deadlock")
        .expect("writer task joins");

    let (received, ok) = tokio::time::timeout(Duration::from_secs(30), reader)
        .await
        .expect("reader must not deadlock")
        .expect("reader task joins");

    assert!(ok, "byte pattern corrupted during high-throughput transfer");
    assert_eq!(received, TOTAL, "received byte count must equal sent");

    client.force_close();
    server.session.force_close();
}

#[tokio::test]
async fn concurrent_bidirectional_bulk_transfer_keeps_session_usable() {
    let (client, server) = session_pair().await;

    async fn open_test_stream(
        client: &Arc<Session>,
        server: &ServerSessionHandler,
        target: &'static [u8],
    ) -> (crate::Stream, crate::server::ServerStream) {
        let mut client_stream = client.open_stream().await.expect("client stream opens");
        client_stream
            .write_early(target)
            .await
            .expect("client sends target");
        let (_sid, mut server_stream) =
            tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
                .await
                .expect("server accepts stream")
                .expect("server accepts stream");
        assert_eq!(server_stream.read().await, Some(Bytes::from(target.to_vec())));
        server_stream
            .send_synack()
            .await
            .expect("server sends synack");
        client_stream.wait_open().await.expect("stream opens");
        (client_stream, server_stream)
    }

    let (mut down_client_stream, mut down_server_stream) =
        open_test_stream(&client, &server, b"down.example:443").await;
    let (mut up_client_stream, mut up_server_stream) =
        open_test_stream(&client, &server, b"up.example:443").await;

    const EACH_WAY: usize = 2 * 1024 * 1024;
    let c2s_pattern = |i: usize| -> u8 { ((i * 17 + 11) % 251) as u8 };
    let s2c_pattern = |i: usize| -> u8 { ((i * 29 + 3) % 253) as u8 };

    let down_writer = tokio::spawn(async move {
        let mut sent = 0usize;
        let chunk_sizes = [32768usize, 98304, 5000, 131072];
        let mut k = 0usize;
        while sent < EACH_WAY {
            let n = chunk_sizes[k % chunk_sizes.len()].min(EACH_WAY - sent);
            let mut buf = vec![0u8; n];
            for (j, b) in buf.iter_mut().enumerate() {
                *b = s2c_pattern(sent + j);
            }
            down_server_stream
                .write(&buf)
                .await
                .expect("server writes bulk");
            sent += n;
            k += 1;
        }
        down_server_stream
            .close_write()
            .await
            .expect("server half closes");
        sent
    });

    let down_reader = tokio::spawn(async move {
        let mut received = 0usize;
        let mut ok = true;
        while let Some(data) = down_client_stream.read().await {
            for (j, &b) in data.iter().enumerate() {
                if b != s2c_pattern(received + j) {
                    ok = false;
                    break;
                }
            }
            received += data.len();
            if !ok || received >= EACH_WAY {
                break;
            }
        }
        (received, ok)
    });

    let up_writer = tokio::spawn(async move {
        let mut sent = 0usize;
        let chunk_sizes = [4096usize, 65536, 131072, 7777];
        let mut k = 0usize;
        while sent < EACH_WAY {
            let n = chunk_sizes[k % chunk_sizes.len()].min(EACH_WAY - sent);
            let mut buf = vec![0u8; n];
            for (j, b) in buf.iter_mut().enumerate() {
                *b = c2s_pattern(sent + j);
            }
            up_client_stream
                .write(&buf)
                .await
                .expect("client writes bulk");
            sent += n;
            k += 1;
        }
        up_client_stream
            .close_write()
            .await
            .expect("client half closes");
        sent
    });

    let up_reader = tokio::spawn(async move {
        let mut received = 0usize;
        let mut ok = true;
        while let Some(data) = up_server_stream.read().await {
            for (j, &b) in data.iter().enumerate() {
                if b != c2s_pattern(received + j) {
                    ok = false;
                    break;
                }
            }
            received += data.len();
            if !ok || received >= EACH_WAY {
                break;
            }
        }
        (received, ok)
    });

    let down_sent = tokio::time::timeout(Duration::from_secs(30), down_writer)
        .await
        .expect("down writer must not deadlock")
        .expect("down writer joins");
    let up_sent = tokio::time::timeout(Duration::from_secs(30), up_writer)
        .await
        .expect("up writer must not deadlock")
        .expect("up writer joins");
    let (down_received, down_ok) = tokio::time::timeout(Duration::from_secs(30), down_reader)
        .await
        .expect("down reader must not deadlock")
        .expect("down reader joins");
    let (up_received, up_ok) = tokio::time::timeout(Duration::from_secs(30), up_reader)
        .await
        .expect("up reader must not deadlock")
        .expect("up reader joins");

    assert!(down_ok, "client observed corrupted server->client bytes");
    assert!(up_ok, "server observed corrupted client->server bytes");
    assert_eq!(down_sent, EACH_WAY);
    assert_eq!(down_received, EACH_WAY);
    assert_eq!(up_sent, EACH_WAY);
    assert_eq!(up_received, EACH_WAY);

    let mut probe = client.open_stream().await.expect("probe stream opens");
    probe
        .write_early(b"probe.example:443")
        .await
        .expect("probe sends target");
    let (_probe_sid, mut probe_server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts probe stream")
            .expect("server accepts probe stream");
    assert_eq!(
        probe_server_stream.read().await,
        Some(Bytes::from(b"probe.example:443".to_vec()))
    );
    probe_server_stream
        .send_synack()
        .await
        .expect("probe synack");
    probe.wait_open().await.expect("probe opens");
    probe.write(b"ping").await.expect("probe writes ping");
    assert_eq!(probe_server_stream.read().await, Some(Bytes::from(b"ping".to_vec())));
    probe_server_stream
        .write(b"pong")
        .await
        .expect("probe writes pong");
    assert_eq!(probe.read().await, Some(Bytes::from(b"pong".to_vec())));

    client.force_close();
    server.session.force_close();
}

// Phase 2 CMD_PADDING integration: verify the fake-response engine works
// end-to-end — a request triggers M split replies on the peer, replies are
// silently discarded, and concurrent stream data is not corrupted.
#[tokio::test]
async fn cmd_padding_request_triggers_split_replies_and_preserves_stream_data() {
    use super::{FlushBehavior, TrafficClass};
    let (client, server) = session_pair().await;

    // Open a stream to have live channel capacity during the test.
    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"pad-test.example:443")
        .await
        .expect("client writes target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"pad-test.example:443".to_vec()))
    );
    server_stream
        .send_synack()
        .await
        .expect("server sends SYNACK");
    stream.wait_open().await.expect("stream opens");

    // Fire a CMD_PADDING request from server → client with m=2.
    // 客户端把两条应答各自作为独立 packet 排入同一个 control 写请求。
    let encoded = crate::frame::encode_padding_request_sized(2, super::PADDING_REQUEST_WIRE);
    server
        .session
        .write_encoded_payload(encoded, FlushBehavior::Immediate, TrafficClass::Control)
        .await
        .expect("server sends padding request");

    // Write stream data from client in the opposite direction while the
    // control path processes the padding burst.
    let payload = b"stream-data-after-padding";
    stream
        .write(payload)
        .await
        .expect("client writes stream data");

    let received = tokio::time::timeout(Duration::from_secs(2), server_stream.read())
        .await
        .expect("server receives stream data after padding handling");
    assert_eq!(received, Some(Bytes::from(payload.to_vec())));

    // Confirm the stream can still close cleanly — no corruption from the
    // CMD_PADDING reply frames that were silently discarded.
    stream.close_write().await.expect("client close write");
    assert_eq!(server_stream.read().await, None);

    client.force_close();
    server.session.force_close();
}

// Malformed / reply-flagged CMD_PADDING frames must be silently dropped by
// both peers without affecting any stream state.
#[tokio::test]
async fn cmd_padding_reply_flag_is_silently_absorbed() {
    use super::{FlushBehavior, TrafficClass};
    let (client, server) = session_pair().await;

    // Open a stream to confirm the data path stays clean.
    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"absorb.example:443")
        .await
        .expect("client writes target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    let _ = server_stream.read().await;
    server_stream
        .send_synack()
        .await
        .expect("server sends SYNACK");
    stream.wait_open().await.expect("stream opens");

    // Inject a reply-flagged CMD_PADDING into the data path (simulates a
    // stray reply that reached the sender's read loop). It must be ignored.
    let encoded = crate::frame::encode_padding_reply_sized(64);
    server
        .session
        .write_encoded_payload(encoded, FlushBehavior::Immediate, TrafficClass::Control)
        .await
        .expect("server injects stray reply");

    // Stream data should flow unimpeded.
    stream
        .write(b"healthy")
        .await
        .expect("client writes after stray padding");
    assert_eq!(server_stream.read().await, Some(Bytes::from(b"healthy".to_vec())));

    client.force_close();
    server.session.force_close();
}

// CMD_PADDING 请求里的 m 必须被钳制到 MAX_PADDING_REPLIES=2：真实 H2 没有
// 「一问 m 答」，一次交互里站得住脚的应答最多是「一个 ACK + 一条接收方本来
// 就要发的窗口更新」。从裸 tunnel 端注入 m=255 的请求，逐帧解码对端回包，
// 统计 reply（flag==1）数量必须恰好为 2。
#[tokio::test]
async fn cmd_padding_request_with_large_m_is_capped_at_two_replies() {
    use bytes::BytesMut;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    // 关闭稳态 H2 骨架：并行的 H2 测试会临时覆写全局 PING 间隔，
    // 骨架关闭后本测试的 padding 计数不受跨测试干扰。
    let mut config = test_session_config(true);
    config.post_script_off = true;
    let client = Arc::new(Session::new(client_tunnel, config, None));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });

    let (mut server_read, mut server_write) = server_tunnel.into_split();

    // Hand-inject a padding request with m=255 from the raw server end.
    let request = crate::frame::encode_padding_request_sized(255, super::PADDING_REQUEST_WIRE);
    let state = server_write.control_state();
    let size = server_write.next_control_size(state, FlowDirection::S2C);
    server_write
        .prepare_control_record(&request, size)
        .expect("server prepares padding request record");
    server_write.flush().await.expect("server flushes request");

    // The client must answer with at most MAX_PADDING_REPLIES replies.
    // Decode frames from the raw stream and count.
    let expected = super::MAX_PADDING_REPLIES;
    let mut buf = BytesMut::with_capacity(65536);
    let mut read_buf = vec![0u8; 16384];
    let mut replies = 0usize;
    let collect = async {
        loop {
            let n = server_read.read(&mut read_buf).await.expect("server reads");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&read_buf[..n]);
            while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
                if frame.cmd == crate::frame::CMD_PADDING && frame.payload.first() == Some(&1) {
                    replies += 1;
                }
            }
            if replies >= expected {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), collect).await;
    assert_eq!(
        replies, expected,
        "m=255 must be clamped to {} replies",
        expected
    );

    // No further padding frames may be in flight beyond the clamp.
    if let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(200), server_read.read(&mut read_buf)).await
    {
        buf.extend_from_slice(&read_buf[..n]);
        while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
            assert_ne!(
                frame.cmd,
                crate::frame::CMD_PADDING,
                "unexpected extra padding frame beyond the reply clamp"
            );
        }
    }

    client.force_close();
}

// Auto 应答解耦回归：Auto 写入只等写循环入队，不等本批数据的 socket
// 冲刷完成。取 64KB 块：低于 128KB bulk 阈值，脚本整形逐条小记录发出
// （含采样延迟），整批耗时应答路径百毫秒级；而入队应答是亚毫秒级。
#[tokio::test]
async fn auto_write_returns_before_shaped_emission_completes() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"auto-ack.example:443")
        .await
        .expect("client writes target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    assert_eq!(
        server_stream.read().await,
        Some(Bytes::from(b"auto-ack.example:443".to_vec()))
    );
    server_stream
        .send_synack()
        .await
        .expect("server sends SYNACK");
    stream.wait_open().await.expect("stream opens");

    // Drain the server side so socket buffers never stall the writer loop.
    let drain = tokio::spawn(async move {
        while server_stream.read().await.is_some() {}
    });

    let chunk = vec![0x5Au8; 64 * 1024];
    let started = std::time::Instant::now();
    stream.write(&chunk).await.expect("client writes chunk");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "auto write took {:?}; Auto acks must not wait for shaped emission",
        elapsed
    );

    client.force_close();
    server.session.force_close();
    drop(drain);
}

// M9 回归：buffered_stream_bytes 对 data channel 与 pending_data 采用同一
// 口径。填满 channel 后继续到达的帧进入 pending_data，两者都必须计入总量；
// 全部消费后计数器必须精确归零，不允许下溢回绕或滞留。
#[tokio::test(flavor = "current_thread")]
async fn buffered_stream_bytes_returns_to_zero_after_pending_drain() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"counter.example:443")
        .await
        .expect("client sends target");
    let (_sid, server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream before timeout")
            .expect("server accepts stream");
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    let frame_count = STREAM_CHANNEL_CAPACITY + 8;
    let frame_size = 32 * 1024;
    let total = frame_count * frame_size;
    let send_task = tokio::spawn(async move {
        let mut server_stream = server_stream;
        for idx in 0..frame_count {
            server_stream
                .write(&vec![idx as u8; frame_size])
                .await
                .expect("server writes frame");
        }
        server_stream.close().await.expect("server closes stream");
    });

    // channel 装满后仍有 8 帧滞留在 pending_data：总量必须覆盖两者。
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.buffered_stream_bytes() < total {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("channel and pending bytes are both accounted");

    for idx in 0..frame_count {
        let data = tokio::time::timeout(Duration::from_secs(5), stream.read())
            .await
            .expect("client read returns before timeout")
            .expect("stream stays open until all data is read");
        assert_eq!(data.len(), frame_size);
        assert_eq!(data[0], idx as u8);
    }
    assert_eq!(stream.read().await, None);
    assert_eq!(client.buffered_stream_bytes(), 0);
    send_task.await.expect("server send task completes");

    client.force_close();
    server.session.force_close();
}

// M9 回归：Stream 携带未读数据被 drop 时，已入账字节必须随清理释放，
// 不允许正向泄漏。
#[tokio::test(flavor = "current_thread")]
async fn buffered_stream_bytes_released_when_stream_dropped_unread() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"drop-counter.example:443")
        .await
        .expect("client sends target");
    let (_sid, server_stream) =
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .expect("server accepts stream before timeout")
            .expect("server accepts stream");
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    stream.wait_open().await.expect("stream opens");

    server_stream
        .write(&vec![7u8; 16 * 1024])
        .await
        .expect("server writes unread data");
    tokio::time::timeout(Duration::from_secs(2), async {
        while client.buffered_stream_bytes() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("unread bytes are accounted");

    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), async {
        while client.buffered_stream_bytes() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dropping the stream releases accounted bytes");

    client.force_close();
    server.session.force_close();
}

// M10 回归：超过 data channel 容量的 pre-SYNACK 数据 + FIN 部分投递时，
// FIN 必须随剩余数据一起保留，消费者读完全部数据后读到 EOF。
#[tokio::test(flavor = "current_thread")]
async fn pre_synack_overflow_data_and_fin_are_delivered_before_eof() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    let sid = stream.stream_id;

    // 模拟 SYNACK 到达前积压的状态：数据量超过 channel 容量，末尾带 FIN。
    let frame_count = STREAM_CHANNEL_CAPACITY + 8;
    for idx in 0..frame_count {
        assert!(client
            .store_pending_data(
                sid,
                crate::session::BufferedPayload::new(
                    vec![idx as u8; 64],
                    &client.buffered_stream_bytes
                )
            )
            .await);
    }
    client.store_pending_fin(sid).await;

    client.flush_client_pending_stream(sid).await;

    for idx in 0..frame_count {
        let data = tokio::time::timeout(Duration::from_secs(1), stream.read())
            .await
            .expect("client read returns before timeout")
            .expect("data is delivered before eof");
        assert_eq!(data, vec![idx as u8; 64]);
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read())
            .await
            .expect("eof is delivered before timeout"),
        None
    );
    assert_eq!(client.buffered_stream_bytes(), 0);

    client.force_close();
    server.session.force_close();
}

// M11 回归：两条流在同一会话上并发首开时，SETTINGS 由写循环随首个
// control 请求前置，后提交的 SYN 不会被对端以 "settings not received"
// 拒绝，两条流都必须 SYNACK 成功。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_opens_on_fresh_session_both_succeed() {
    let (client, server) = session_pair().await;

    let client_a = client.clone();
    let open_a = tokio::spawn(async move {
        let mut stream = client_a.open_stream().await.expect("stream A opens");
        stream
            .write_early(b"a.example:443")
            .await
            .expect("stream A writes target");
        stream
    });
    let client_b = client.clone();
    let open_b = tokio::spawn(async move {
        let mut stream = client_b.open_stream().await.expect("stream B opens");
        stream
            .write_early(b"b.example:443")
            .await
            .expect("stream B writes target");
        stream
    });
    let mut stream_a = open_a.await.expect("stream A task joins");
    let mut stream_b = open_b.await.expect("stream B task joins");

    let mut targets = Vec::new();
    for _ in 0..2 {
        let (_sid, mut server_stream) =
            tokio::time::timeout(Duration::from_secs(2), server.accept_stream())
                .await
                .expect("server accepts stream before timeout")
                .expect("server accepts stream");
        let target = tokio::time::timeout(Duration::from_secs(2), server_stream.read())
            .await
            .expect("server reads target before timeout")
            .expect("target payload arrives");
        server_stream
            .send_synack()
            .await
            .expect("server sends synack");
        targets.push(target);
    }
    targets.sort();
    assert_eq!(
        targets,
        vec![b"a.example:443".to_vec(), b"b.example:443".to_vec()]
    );

    tokio::time::timeout(Duration::from_secs(2), stream_a.wait_open())
        .await
        .expect("stream A wait_open returns before timeout")
        .expect("stream A opens");
    tokio::time::timeout(Duration::from_secs(2), stream_b.wait_open())
        .await
        .expect("stream B wait_open returns before timeout")
        .expect("stream B opens");
    assert!(client.pending_client_settings.lock().await.is_none());

    client.force_close();
    server.session.force_close();
}

// W3 稳态 H2 骨架共用的裸服务端搭建：client 跑完整 Session（读循环注入
// 骨架帧），server 端用 into_split 裸收发，便于逐帧解码统计 padding。
// 返回 (client, stream, server_read, server_write, buf, read_buf)：流已
// SYNACK 打开，client 的 SETTINGS/SYN 突发已被消费。
#[allow(clippy::type_complexity)]
async fn raw_server_session_with_open_stream(
    client_config: SessionConfig,
    target: &'static [u8],
) -> (
    Arc<Session>,
    crate::Stream,
    super::SplitReadHalf,
    super::SplitWriteHalf,
    bytes::BytesMut,
    Vec<u8>,
) {
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    let client = Arc::new(Session::new(client_tunnel, client_config, None));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let (mut server_read, mut server_write) = server_tunnel.into_split();

    let mut stream = client.open_stream().await.expect("stream opens");
    stream.write_early(target).await.expect("client writes target");

    let mut buf = bytes::BytesMut::with_capacity(65536);
    let mut read_buf = vec![0u8; 16384];
    let mut sid = None;
    tokio::time::timeout(Duration::from_secs(2), async {
        while sid.is_none() {
            let n = server_read.read(&mut read_buf).await.expect("server reads");
            assert!(n > 0, "tunnel closed before client SYN");
            buf.extend_from_slice(&read_buf[..n]);
            while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
                if frame.cmd == crate::frame::CMD_SYN {
                    sid = Some(frame.stream_id);
                }
            }
        }
    })
    .await
    .expect("client SYN arrives before timeout");
    let sid = sid.unwrap();

    let synack = crate::frame::Frame::new(crate::frame::CMD_SYNACK, sid, vec![])
        .encode()
        .expect("synack encodes");
    let state = server_write.control_state();
    let size = server_write.next_control_size(state, FlowDirection::S2C);
    server_write
        .prepare_control_record(&synack, size)
        .expect("server prepares synack");
    server_write.flush().await.expect("server flushes synack");
    stream.wait_open().await.expect("stream opens");

    (client, stream, server_read, server_write, buf, read_buf)
}

// W3(a)：bulk 接收端按分发字节数回注 WINDOW_UPDATE 尺寸的 flag=1 padding；
// 在 bulk 发送方（裸 server 端）统计到的 reply 帧数量必须达到阈值/块数
// 推算出的预期量级，且流数据完好。
#[tokio::test]
async fn bulk_transfer_triggers_window_update_padding_on_sender_side() {
    use super::H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    const THRESHOLD: usize = 8 * 1024;
    const CHUNK: usize = 8 * 1024;
    const CHUNKS: usize = 32;
    const TOTAL: usize = THRESHOLD * CHUNKS;
    H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.store(THRESHOLD, Ordering::Relaxed);

    let (client, mut stream, mut server_read, mut server_write, mut buf, mut read_buf) =
        raw_server_session_with_open_stream(test_session_config(true), b"wu-bulk.example:443")
            .await;
    let sid = stream.stream_id;

    let pattern = |i: usize| -> u8 { ((i * 31 + 7) % 251) as u8 };
    let send_task = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < TOTAL {
            let mut chunk = vec![0u8; CHUNK];
            for (j, b) in chunk.iter_mut().enumerate() {
                *b = pattern(sent + j);
            }
            let mut frame_bytes = Vec::new();
            crate::frame::Frame::encode_psh_into(&mut frame_bytes, sid, &chunk)
                .expect("psh encodes");
            let wire = SnowyStream::data_record_wire_len(frame_bytes.len());
            server_write
                .prepare_data_record(&frame_bytes, wire)
                .expect("server prepares bulk record");
            server_write.flush().await.expect("server flushes bulk");
            sent += CHUNK;
        }
    });

    let reader = tokio::spawn(async move {
        let mut received = 0usize;
        let mut ok = true;
        while received < TOTAL {
            let Some(data) = stream.read().await else {
                ok = false;
                break;
            };
            for (j, &b) in data.iter().enumerate() {
                if b != pattern(received + j) {
                    ok = false;
                    break;
                }
            }
            received += data.len();
            if !ok {
                break;
            }
        }
        (received, ok)
    });

    // 每收到 CHUNK(=THRESHOLD) 字节，client 读循环恰好越过一次阈值，
    // 预期恰好 CHUNKS 条 flag=1 padding；留少量余量防计时边界。
    let mut replies = 0usize;
    let collect = async {
        while replies < CHUNKS {
            let n = server_read.read(&mut read_buf).await.expect("server reads");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&read_buf[..n]);
            while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
                if frame.cmd == crate::frame::CMD_PADDING && frame.payload.first() == Some(&1) {
                    replies += 1;
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), collect).await;

    let (received, ok) = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .expect("bulk reader joins before timeout")
        .expect("bulk reader completes");
    send_task.await.expect("bulk sender joins");

    assert!(ok, "bulk payload corrupted under h2 skeleton injection");
    assert_eq!(received, TOTAL, "received byte count must equal sent");
    assert!(
        replies >= CHUNKS * 3 / 4,
        "expected ~{} window-update padding frames on the bulk sender side, got {}",
        CHUNKS,
        replies
    );

    H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.store(0, Ordering::Relaxed);
    client.force_close();
}

// W3(c)：post_script_off=true 时阈值覆写也不得引出任何注入帧。
#[tokio::test]
async fn post_script_off_disables_h2_skeleton_injection() {
    use super::H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    const THRESHOLD: usize = 8 * 1024;
    const CHUNK: usize = 8 * 1024;
    const CHUNKS: usize = 32;
    const TOTAL: usize = THRESHOLD * CHUNKS;
    H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.store(THRESHOLD, Ordering::Relaxed);

    let mut client_config = test_session_config(true);
    client_config.post_script_off = true;
    let (client, mut stream, mut server_read, mut server_write, mut buf, mut read_buf) =
        raw_server_session_with_open_stream(client_config, b"wu-gated.example:443").await;
    let sid = stream.stream_id;

    let send_task = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < TOTAL {
            let chunk = vec![0x5Au8; CHUNK];
            let mut frame_bytes = Vec::new();
            crate::frame::Frame::encode_psh_into(&mut frame_bytes, sid, &chunk)
                .expect("psh encodes");
            let wire = SnowyStream::data_record_wire_len(frame_bytes.len());
            server_write
                .prepare_data_record(&frame_bytes, wire)
                .expect("server prepares bulk record");
            server_write.flush().await.expect("server flushes bulk");
            sent += CHUNK;
        }
    });

    let reader = tokio::spawn(async move {
        let mut received = 0usize;
        while received < TOTAL {
            let Some(data) = stream.read().await else {
                break;
            };
            received += data.len();
        }
        received
    });

    // 从建流后即开始统计任何 CMD_PADDING；bulk 收完后再空闲 500ms 收尾。
    let counter = tokio::spawn(async move {
        let mut padding_frames = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_millis(500), server_read.read(&mut read_buf))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&read_buf[..n]);
                    while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
                        if frame.cmd == crate::frame::CMD_PADDING {
                            padding_frames += 1;
                        }
                    }
                }
                Ok(Err(e)) => panic!("server read error: {}", e),
                Err(_) => break,
            }
        }
        padding_frames
    });

    let received = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .expect("bulk reader joins before timeout")
        .expect("bulk reader completes");
    send_task.await.expect("bulk sender joins");
    let padding_frames = tokio::time::timeout(Duration::from_secs(5), counter)
        .await
        .expect("padding counter joins before timeout")
        .expect("padding counter completes");

    assert_eq!(received, TOTAL, "bulk transfer must complete with gating on");
    assert_eq!(
        padding_frames, 0,
        "post_script_off must disable all h2 skeleton padding injection"
    );

    H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.store(0, Ordering::Relaxed);
    client.force_close();
}

// 一条 PING 请求的判定：flag=0 且**帧长反解出的线速尺寸恰为 PING_WIRE**。
// 不能只看 flag——合成 H2 交换的请求同样是 flag=0，只是尺寸落在 HEADERS 档
// （274–824）。判定式与 `handle_frame` 里复原请求尺寸的那一行同源。
fn is_ping_request(frame: &crate::frame::Frame) -> bool {
    frame.cmd == crate::frame::CMD_PADDING
        && frame.payload.first() == Some(&0)
        && crate::frame::FRAME_HEADER_SIZE
            + frame.payload.len()
            + crate::frame::CONTROL_RECORD_MIN_OVERHEAD
            == super::PADDING_REQUEST_WIRE
}

// 在 `window` 时间内数出对端发来的 PING 请求条数（读到 EOF 或超时即返回）。
async fn count_ping_requests(
    read_half: &mut super::SplitReadHalf,
    buf: &mut bytes::BytesMut,
    window: Duration,
) -> usize {
    use tokio::io::AsyncReadExt;
    let mut read_buf = vec![0u8; 16384];
    let mut pings = 0usize;
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return pings;
        }
        match tokio::time::timeout(left, read_half.read(&mut read_buf)).await {
            Err(_) => return pings,
            Ok(Ok(0)) | Ok(Err(_)) => return pings,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&read_buf[..n]);
                while let Some(frame) = crate::frame::Frame::decode(buf) {
                    if is_ping_request(&frame) {
                        pings += 1;
                    }
                }
            }
        }
    }
}

// 从对端注入一条 flag=1 的 padding 记录（收方静默吸收，不换应答）：用来
// 制造「对端到达」事件而不引出任何回写。
async fn inject_absorbed_record(write_half: &mut super::SplitWriteHalf) {
    use kanotls_tunnel::control_size::WINDOW_UPDATE_WIRE;
    use tokio::io::AsyncWriteExt;
    let packet = crate::frame::encode_padding_reply_sized(WINDOW_UPDATE_WIRE);
    write_half
        .prepare_control_record(&packet, WINDOW_UPDATE_WIRE)
        .expect("absorbed record prepares");
    write_half.flush().await.expect("absorbed record flushes");
}

// W3(b) 回归：PING 必须是**空闲触发 + 仅客户端发起 + 常量阈值**，并且在连接
// 仍处于论文 `Wo = 25` 观测窗口内时被抑制。
//
// 三段分别对应任务 2b 的三处修正：
//  (a) 窗口内抑制——arrivals < Wo 时无论空闲多久都不发。窗口之外的 PING 完全
//      不被采样，所以窗口内抑制是零代价的：一对 `(+41, −41)` 若紧跟在此前
//      下行 burst 的尾段之后，在包序列上就是 `(−L4, L1, −L1)`（Distinc 2.879）。
//  (b) 有活动不探活——arrivals ≥ Wo 但对端持续说话（间隔 < 阈值）时不发。
//      此前是固定周期定时器，会在正在传输大流量的连接上插 PING。
//  (c) 空闲即探活——对端安静超过阈值后必发一条 **PING 尺寸**的 flag=0 请求。
#[tokio::test]
async fn h2_ping_is_idle_triggered_and_suppressed_inside_the_observation_window() {
    use super::H2_PING_IDLE_THRESHOLD_OVERRIDE_MS;
    use std::sync::atomic::Ordering;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    const THRESHOLD_MS: u64 = 60;
    H2_PING_IDLE_THRESHOLD_OVERRIDE_MS.store(THRESHOLD_MS, Ordering::Relaxed);
    let threshold = Duration::from_millis(THRESHOLD_MS);

    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let (mut server_read, mut server_write) = server_tunnel.into_split();
    let mut buf = bytes::BytesMut::with_capacity(65536);

    // (a) 窗口内：只喂几个到达事件，然后彻底安静 4 个阈值周期。
    for _ in 0..3 {
        inject_absorbed_record(&mut server_write).await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
        client.inbound.arrivals() < super::PAPER_OBSERVATION_WINDOW_PACKETS,
        "前置条件：此时必须仍在观测窗口内"
    );
    let pings = count_ping_requests(&mut server_read, &mut buf, threshold * 3).await;
    assert_eq!(
        pings, 0,
        "连接仍在论文的 Wo=25 观测窗口内时不得发 PING"
    );

    // 把连接推出观测窗口：一次一条记录，每条对应读循环的一次 read()。
    // TCP 可能合并，故以 arrivals 计数为准循环补喂。
    let push_out = async {
        while client.inbound.arrivals() < super::PAPER_OBSERVATION_WINDOW_PACKETS {
            inject_absorbed_record(&mut server_write).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), push_out)
        .await
        .expect("connection leaves the observation window before timeout");

    // (b) 窗口之外但**有活动**：每 threshold/4 喂一条，持续 4 个阈值周期。
    let busy_until = tokio::time::Instant::now() + threshold * 3;
    let mut busy_pings = 0usize;
    while tokio::time::Instant::now() < busy_until {
        inject_absorbed_record(&mut server_write).await;
        busy_pings += count_ping_requests(&mut server_read, &mut buf, threshold / 4).await;
    }
    assert_eq!(
        busy_pings, 0,
        "对端持续说话（间隔 < 阈值）的连接上不得插 PING"
    );

    // (c) 窗口之外且**空闲**：安静超过阈值后必有 PING。
    let pings = count_ping_requests(&mut server_read, &mut buf, threshold * 4).await;
    assert!(
        pings >= 1,
        "空闲超过阈值后必须发出至少一条 PING 尺寸的 flag=0 请求"
    );

    H2_PING_IDLE_THRESHOLD_OVERRIDE_MS.store(0, Ordering::Relaxed);
    client.force_close();
}

// W3(b) 回归：**服务端方向从不主动发 PING**——真实 nginx 只回 PING-ACK。
// 此前两端共用同一个周期定时器，服务端也会自发探活。
#[tokio::test]
async fn server_never_initiates_h2_ping() {
    use super::H2_PING_IDLE_THRESHOLD_OVERRIDE_MS;
    use std::sync::atomic::Ordering;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    const THRESHOLD_MS: u64 = 40;
    H2_PING_IDLE_THRESHOLD_OVERRIDE_MS.store(THRESHOLD_MS, Ordering::Relaxed);
    let threshold = Duration::from_millis(THRESHOLD_MS);

    let (server_tunnel, client_tunnel) = snowy_stream_pair().await;
    let server = Arc::new(Session::new(server_tunnel, test_session_config(false), None));
    let server_read_loop = server.clone();
    tokio::spawn(async move {
        let _ = server_read_loop.run_read_loop().await;
    });
    let (mut client_read, mut client_write) = client_tunnel.into_split();
    let mut buf = bytes::BytesMut::with_capacity(65536);

    // 推出观测窗口，确保「不发 PING」不是被窗口抑制掩盖的。
    let push_out = async {
        while server.inbound.arrivals() < super::PAPER_OBSERVATION_WINDOW_PACKETS {
            inject_absorbed_record(&mut client_write).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), push_out)
        .await
        .expect("connection leaves the observation window before timeout");

    let pings = count_ping_requests(&mut client_read, &mut buf, threshold * 5).await;
    assert_eq!(pings, 0, "服务端方向不得主动发起 H2 PING");

    H2_PING_IDLE_THRESHOLD_OVERRIDE_MS.store(0, Ordering::Relaxed);
    server.force_close();
}

// M12 回归：read_closed=true 且三个 channel 全关的句柄必须能被 prune
// （长连接+大量短流场景下 streams 映射不再泄漏）；此类句柄在
// mark_stream_read_closed_locked 时已扣减过容量计数，prune 不得重复扣减。
#[test]
fn prune_removes_read_closed_orphan_without_double_decrement() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counter = AtomicUsize::new(0);
    let mut streams = std::collections::HashMap::new();

    let (data_tx, data_rx) = tokio::sync::mpsc::channel(1);
    let (fin_tx, fin_rx) = tokio::sync::mpsc::channel(1);
    let (synack_tx, synack_rx) = tokio::sync::oneshot::channel();
    drop(data_rx);
    drop(fin_rx);
    drop(synack_rx);
    streams.insert(
        1u32,
        super::StreamHandle {
            data_tx,
            fin_tx,
            synack_tx: Some(synack_tx),
            read_closed: true,
            pending_notify: Arc::new(tokio::sync::Notify::new()),
        },
    );

    super::Session::prune_orphaned_streams_locked(&mut streams, &counter);
    assert!(
        streams.is_empty(),
        "read_closed 且 channel 全关的句柄必须被 prune"
    );
    assert_eq!(
        counter.load(Ordering::Relaxed),
        0,
        "read_closed 句柄 prune 不得重复扣减容量计数"
    );
}

// M12 回归：read_closed=false 的 orphan 仍被 prune 且容量计数恰好减 1。
#[test]
fn prune_removes_open_orphan_and_decrements_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counter = AtomicUsize::new(1);
    let mut streams = std::collections::HashMap::new();

    let (data_tx, data_rx) = tokio::sync::mpsc::channel(1);
    let (fin_tx, fin_rx) = tokio::sync::mpsc::channel(1);
    drop(data_rx);
    drop(fin_rx);
    streams.insert(
        7u32,
        super::StreamHandle {
            data_tx,
            fin_tx,
            synack_tx: None,
            read_closed: false,
            pending_notify: Arc::new(tokio::sync::Notify::new()),
        },
    );

    super::Session::prune_orphaned_streams_locked(&mut streams, &counter);
    assert!(streams.is_empty());
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

// M12 回归：channel 仍有存活者的句柄（无论 read_closed 与否）不得被 prune。
#[test]
fn prune_keeps_handles_with_live_channels() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counter = AtomicUsize::new(2);
    let mut streams = std::collections::HashMap::new();

    let (data_tx, _data_rx) = tokio::sync::mpsc::channel(1);
    let (fin_tx, fin_rx) = tokio::sync::mpsc::channel(1);
    drop(fin_rx);
    streams.insert(
        1u32,
        super::StreamHandle {
            data_tx,
            fin_tx,
            synack_tx: None,
            read_closed: true,
            pending_notify: Arc::new(tokio::sync::Notify::new()),
        },
    );

    let (data_tx2, _data_rx2) = tokio::sync::mpsc::channel(1);
    let (fin_tx2, _fin_rx2) = tokio::sync::mpsc::channel(1);
    let (synack_tx2, _synack_rx2) = tokio::sync::oneshot::channel();
    streams.insert(
        2u32,
        super::StreamHandle {
            data_tx: data_tx2,
            fin_tx: fin_tx2,
            synack_tx: Some(synack_tx2),
            read_closed: false,
            pending_notify: Arc::new(tokio::sync::Notify::new()),
        },
    );

    super::Session::prune_orphaned_streams_locked(&mut streams, &counter);
    assert_eq!(streams.len(), 2);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
}

// 裸服务端配对：client 端包装成 SnowyStream，server 端保留裸 TcpStream
// 与 server 端传输态，用于逐字节抓取线上 record 并离线解密比对。
async fn client_stream_with_raw_server() -> (SnowyStream, TcpStream, kanotls_tunnel::NoiseTransport) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener binds");
    let addr = listener.local_addr().expect("listener has address");
    let client_task = tokio::spawn(async move {
        TcpStream::connect(addr)
            .await
            .expect("client connects to listener")
    });
    let (server_tcp, _) = listener.accept().await.expect("listener accepts client");
    let client_tcp = client_task.await.expect("client connect task completes");
    let (client_noise, server_noise) = build_transport_pair();
    (
        SnowyStream::new(client_tcp, client_noise),
        server_tcp,
        server_noise,
    )
}

// 离线解密抓取的线上 record 流：返回 (record wire 尺寸序列, 拼接载荷)。
fn decrypt_wire_records(
    wire: &[u8],
    noise: &mut kanotls_tunnel::NoiseTransport,
) -> (Vec<usize>, Vec<u8>) {
    let mut sizes = Vec::new();
    let mut plaintext = Vec::new();
    let mut block = vec![0u8; kanotls_tunnel::common::BLOCK_PLAINTEXT_SIZE];
    let mut off = 0usize;
    while off < wire.len() {
        assert_eq!(wire[off], 0x17, "record type must be application data");
        let ct_len = u16::from_be_bytes([wire[off + 3], wire[off + 4]]) as usize;
        let pt_len = noise
            .read_message(&wire[off + 5..off + 5 + ct_len], &mut block)
            .expect("record decrypts");
        // 块结构：2 字节长度前缀 + 载荷 + padding + 0x17 inner content type。
        let data_len = u16::from_be_bytes([block[0], block[1]]) as usize;
        assert!(data_len + 3 <= pt_len);
        assert_eq!(block[pt_len - 1], 0x17);
        plaintext.extend_from_slice(&block[2..2 + data_len]);
        sizes.push(5 + ct_len);
        off += 5 + ct_len;
    }
    (sizes, plaintext)
}

// P3 回归：`store_pending_open_data` 的限额语义在改成 O(1) 记账后完全不变
// ——字节上限是全局的、每流帧上限独立、未登记的流不建条目、拒绝的载荷不留
// 残余、全部丢弃后两本账都归零。
#[tokio::test]
async fn store_pending_open_data_limit_semantics_are_preserved() {
    // 不启动读循环：读循环会在结束时 clear() pending_open_streams。
    let (client_tunnel, _server_tunnel) = snowy_stream_pair().await;
    let session = Session::new(client_tunnel, test_session_config(false), None);

    // 未登记的流：返回 false（表示「未处理，走常规派发」），且不建条目。
    assert!(!session.store_pending_open_data(7, Bytes::from(vec![0u8; 4])).await);
    assert!(!session.pending_open_streams.lock().await.contains(7));
    assert_eq!(session.buffered_stream_bytes(), 0);

    session.pending_open_streams.lock().await.insert_new(7);

    // 每流帧上限：越限后仍返回 true（帧已被吞掉），但不得入队。
    for _ in 0..super::MAX_PENDING_STREAM_FRAMES {
        assert!(session.store_pending_open_data(7, Bytes::from(vec![0u8; 1])).await);
    }
    assert!(session.store_pending_open_data(7, Bytes::from(vec![0u8; 1])).await);
    {
        let pending = session.pending_open_streams.lock().await;
        assert_eq!(pending.stream_frames(7), super::MAX_PENDING_STREAM_FRAMES);
        assert_eq!(pending.total_bytes(), super::MAX_PENDING_STREAM_FRAMES);
    }
    assert_eq!(
        session.buffered_stream_bytes(),
        super::MAX_PENDING_STREAM_FRAMES
    );

    // 字节上限是全局的：另一条流吃满余额后，任何新帧都必须被拒。
    session.pending_open_streams.lock().await.insert_new(8);
    let remaining = super::MAX_PENDING_STREAM_BYTES - super::MAX_PENDING_STREAM_FRAMES;
    assert!(session.store_pending_open_data(8, Bytes::from(vec![0u8; remaining])).await);
    {
        let pending = session.pending_open_streams.lock().await;
        assert_eq!(pending.total_bytes(), super::MAX_PENDING_STREAM_BYTES);
        assert_eq!(pending.stream_frames(8), 1);
    }
    assert!(session.store_pending_open_data(8, Bytes::from(vec![0u8; 1])).await);
    assert_eq!(session.pending_open_streams.lock().await.stream_frames(8), 1);

    // 全部丢弃后两本账归零。
    session.pending_open_streams.lock().await.clear();
    assert_eq!(session.pending_open_streams.lock().await.total_bytes(), 0);
    assert_eq!(session.buffered_stream_bytes(), 0);
}

// 增量解密：消费 `wire` 中所有完整 record，返回 (wire 尺寸, 块载荷) 列表，
// 未完整的尾部留在 `wire` 里等下次读取补齐。record 必须按序恰好解密一次
// （nonce 单调），故游标状态由调用方通过 `wire` 的截断维护。
fn drain_wire_records(
    wire: &mut Vec<u8>,
    noise: &mut kanotls_tunnel::NoiseTransport,
) -> Vec<(usize, Vec<u8>)> {
    let mut out = Vec::new();
    let mut block = vec![0u8; kanotls_tunnel::common::BLOCK_PLAINTEXT_SIZE];
    let mut off = 0usize;
    while off + 5 <= wire.len() {
        assert_eq!(wire[off], 0x17, "record type must be application data");
        let ct_len = u16::from_be_bytes([wire[off + 3], wire[off + 4]]) as usize;
        if off + 5 + ct_len > wire.len() {
            break;
        }
        let pt_len = noise
            .read_message(&wire[off + 5..off + 5 + ct_len], &mut block)
            .expect("record decrypts");
        let data_len = u16::from_be_bytes([block[0], block[1]]) as usize;
        assert!(data_len + 3 <= pt_len);
        assert_eq!(block[pt_len - 1], 0x17);
        out.push((5 + ct_len, block[2..2 + data_len].to_vec()));
        off += 5 + ct_len;
    }
    wire.drain(..off);
    out
}

// 合并 flush 之后，`drive_shaper` 与 control 写路径都不再自带冲刷：末批由
// 写循环的 `flush_or_merge` 与紧随其后的内容合并（见 `FlushBatch`）。下面两个
// 包装为**单元测试**恢复旧口径——「一轮排空 = 字节全部出网」「补发暂存
// control 写 = 立即出网」——于是既有断言的语义原封不动，被测的仍是记录的
// 尺寸/条数/顺序，而不是分段边界。分段边界本身由
// `queued_control_and_data_share_one_flush` /
// `queued_control_writes_share_one_flush_without_changing_records` 断言。
#[allow(clippy::too_many_arguments)]
async fn drive_shaper_flushed(
    pending: &mut Vec<u8>,
    shaper: &mut crate::shaper::TrafficShaper,
    write_half: &mut super::SplitWriteHalf,
    control_rx: &mut tokio::sync::mpsc::Receiver<super::WriteRequest>,
    pending_client_settings: &Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
    direction: kanotls_tunnel::FlowDirection,
    inbound: &super::InboundSignal,
    pinned_sids: std::collections::HashSet<u32>,
) -> std::io::Result<(Vec<u8>, Vec<super::WriteRequest>)> {
    let mut batch = super::FlushBatch::default();
    let out = super::SessionWriter::drive_shaper(
        pending,
        shaper,
        write_half,
        control_rx,
        pending_client_settings,
        direction,
        inbound,
        pinned_sids,
        &mut batch,
    )
    .await?;
    batch.flush(write_half).await?;
    Ok(out)
}

async fn control_requests_flushed(
    requests: Vec<super::WriteRequest>,
    write_half: &mut super::SplitWriteHalf,
    direction: kanotls_tunnel::FlowDirection,
) -> Result<(), String> {
    let mut batch = super::FlushBatch::default();
    super::SessionWriter::prepare_deferred_control_requests(
        requests,
        write_half,
        direction,
        &mut batch,
    )?;
    batch
        .flush(write_half)
        .await
        .map_err(|e| e.to_string())
}

// 用给定传输态手工封一条 0x17 控制记录（块结构见 §3.9）：
// [len_prefix(2) | payload | 零填充 | 0x17] → AEAD → 5 字节 TLS 头。
fn seal_control_record(
    noise: &mut kanotls_tunnel::NoiseTransport,
    payload: &[u8],
    target_wire_len: usize,
) -> Vec<u8> {
    let pt_len = target_wire_len
        .saturating_sub(5 + 16)
        .max(payload.len() + 3);
    let mut block = vec![0u8; pt_len];
    block[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    block[2..2 + payload.len()].copy_from_slice(payload);
    block[pt_len - 1] = 0x17;
    let mut ciphertext = vec![0u8; pt_len + 16];
    let ct_len = noise
        .write_message(&block, &mut ciphertext)
        .expect("control record encrypts");
    let mut record = Vec::with_capacity(5 + ct_len);
    record.extend_from_slice(&[0x17, 0x03, 0x03]);
    record.extend_from_slice(&(ct_len as u16).to_be_bytes());
    record.extend_from_slice(&ciphertext[..ct_len]);
    record
}

// C1 回归：CMD_PADDING 记录的线速尺寸必须精确等于编码时用的目标尺寸。
// 反解 junk 后经 prepare_control_record 得到的 buffered_write_len 增量 ==
// target，对 Handshake / Transport 两个连接态都成立（旧实现里目标被
// `max(payload + 前缀 + inner)` 吃掉，尺寸由 payload 反向决定）。
#[tokio::test]
async fn padding_records_hit_their_target_wire_size_exactly() {
    use kanotls_tunnel::ConnectionState;

    let (client, _server) = snowy_stream_pair().await;
    let (_r, mut w) = client.into_split();
    let mut saw_handshake = false;
    let mut saw_transport = false;

    for _ in 0..64 {
        for target in [
            crate::frame::MIN_PADDING_RECORD_WIRE_LEN,
            super::PADDING_WINDOW_UPDATE_WIRE,
            super::PADDING_REQUEST_WIRE,
            46,
            54,
            300,
        ] {
            for m in [0u8, 1, 2] {
                let (state, delta) = {
                    let state = w.control_state();
                    let before = w.buffered_write_len();
                    let packet = crate::frame::encode_padding_request_sized(m, target);
                    w.prepare_control_record(&packet, target)
                        .expect("request record prepares");
                    (state, w.buffered_write_len() - before)
                };
                assert_eq!(delta, target, "请求记录尺寸必须精确命中目标");
                match state {
                    ConnectionState::Handshake => saw_handshake = true,
                    ConnectionState::Transport => saw_transport = true,
                }
            }
            let delta = {
                let before = w.buffered_write_len();
                let packet = crate::frame::encode_padding_reply_sized(target);
                w.prepare_control_record(&packet, target)
                    .expect("reply record prepares");
                w.buffered_write_len() - before
            };
            assert_eq!(delta, target, "应答记录尺寸必须精确命中目标");
        }
    }
    assert!(saw_handshake && saw_transport, "两个连接态都必须覆盖");
}

// C1 回归：采样池的最小档不得低于 CMD_PADDING 记录的结构下限（33）——这是
// 「目标 < 33 无需额外钳制」这一论证的前提，也是零 junk 编码 + 采样侧定
// 尺寸能精确命中的前提。
#[tokio::test]
async fn sampled_control_sizes_never_undercut_padding_floor() {
    use kanotls_tunnel::{ConnectionState, FlowDirection};

    let (client, _server) = snowy_stream_pair().await;
    let (_r, mut w) = client.into_split();
    for state in [ConnectionState::Handshake, ConnectionState::Transport] {
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            for _ in 0..2000 {
                let size = w.next_control_size(state, direction);
                assert!(
                    size >= crate::frame::MIN_PADDING_RECORD_WIRE_LEN,
                    "sampled control size {} below the padding record floor",
                    size
                );
            }
        }
    }
}

// C1 + C2 回归（线上视角）：一条 CMD_PADDING 请求换来的 m 条应答必须是 m
// 条**独立记录**，尺寸落在 H2 角色常量上（首条 PING-ACK，其余
// WINDOW_UPDATE），且绝不出现旧实现的 81/97/129/138/252 常量簇。
#[tokio::test]
async fn padding_replies_are_independent_records_with_h2_role_sizes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    // 旧实现的尺寸簇：请求 81/97/129（m=1/2/4），应答合并成单条 81/138/252。
    const LEGACY_SIZES: [usize; 5] = [81, 97, 129, 138, 252];

    for m in [1u8, 2] {
        let (client_tunnel, mut raw_server, mut server_noise) =
            client_stream_with_raw_server().await;
        // 关闭稳态 H2 骨架：并行测试会临时覆写全局 PING/WU 阈值，关掉后本
        // 测试观察到的记录只可能来自 padding 应答路径。
        let mut config = test_session_config(true);
        config.post_script_off = true;
        let client = Arc::new(Session::new(client_tunnel, config, None));
        let read_loop = client.clone();
        tokio::spawn(async move {
            let _ = read_loop.run_read_loop().await;
        });

        let request = crate::frame::encode_padding_request_sized(m, super::PADDING_REQUEST_WIRE);
        let record =
            seal_control_record(&mut server_noise, &request, super::PADDING_REQUEST_WIRE);
        assert_eq!(
            record.len(),
            super::PADDING_REQUEST_WIRE,
            "注入的请求记录本身也必须精确命中 PING 尺寸"
        );
        raw_server
            .write_all(&record)
            .await
            .expect("raw server injects padding request");

        // 客户端的首个 control 写请求会前置 SETTINGS，故先到的记录里有一条
        // 承载 CMD_SETTINGS；应答记录随后逐条到达。
        let mut wire = Vec::new();
        let mut read_buf = vec![0u8; 16384];
        let mut reply_sizes = Vec::new();
        let collect = async {
            while reply_sizes.len() < m as usize {
                let n = raw_server
                    .read(&mut read_buf)
                    .await
                    .expect("raw server reads");
                assert!(n > 0, "tunnel closed before replies arrived");
                wire.extend_from_slice(&read_buf[..n]);
                for (size, payload) in drain_wire_records(&mut wire, &mut server_noise) {
                    // 应答记录的判定：整条记录的块载荷恰好是一条完整的
                    // CMD_PADDING flag=1 帧——即「独占一条记录」。其余记录
                    // （SETTINGS 那条可能被按数据口径切分）跳过。
                    let mut buf = bytes::BytesMut::from(payload.as_slice());
                    let Some(frame) = crate::frame::Frame::decode(&mut buf) else {
                        continue;
                    };
                    if !buf.is_empty()
                        || frame.cmd != crate::frame::CMD_PADDING
                        || frame.payload.first() != Some(&1)
                    {
                        continue;
                    }
                    assert!(
                        !LEGACY_SIZES.contains(&size),
                        "应答记录尺寸 {} 是旧的 payload 反向决定的常量",
                        size
                    );
                    reply_sizes.push(size);
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(3), collect)
            .await
            .expect("replies arrive before timeout");

        // 角色尺寸：PING 尺寸的请求 ⇒ 首条应答是 PING-ACK，其余是接收方的
        // WINDOW_UPDATE。
        let expected: Vec<usize> = (0..m as usize)
            .map(|i| {
                super::padding_reply_wire_len(
                    super::PADDING_REQUEST_WIRE,
                    i,
                    kanotls_tunnel::FlowDirection::C2S,
                )
            })
            .collect();
        assert_eq!(reply_sizes, expected, "m={} 的应答尺寸角色不符", m);

        client.force_close();
    }
}

// 采样池的离散支撑集（§3.2）+ HEADERS 分布区间。C22 的断言用它判定「每条
// control 记录的线速尺寸都落在允许的支撑集内」。
const CONTROL_DISCRETE_POOL: [usize; 9] = [33, 37, 41, 46, 51, 54, 64, 69, 82];

fn control_record_size_is_allowed(size: usize) -> bool {
    use kanotls_tunnel::common::MIN_DATA_WIRE_LEN;
    use kanotls_tunnel::control_size::{L1_MAX_WIRE_LEN, MIN_DATA_RECORD_PAYLOAD};
    // 离散 H2 帧尺寸；HEADERS 截断正态（C2S 274–824 / S2C 124–424）；按 H2
    // 数据记录分布切分的段（下界 = L1 上界 + 1，上界 = 一个 MTU 分段）；
    // 满载数据记录。
    debug_assert_eq!(MIN_DATA_RECORD_PAYLOAD + MIN_DATA_WIRE_LEN, L1_MAX_WIRE_LEN + 1);
    CONTROL_DISCRETE_POOL.contains(&size)
        || (124..=824).contains(&size)
        || (L1_MAX_WIRE_LEN + 1..=1400 + MIN_DATA_WIRE_LEN).contains(&size)
        || size == SnowyStream::max_data_record_wire_len()
}

// C22 回归：control 通道上的载荷长度绝不允许 1:1 映射到记录线速尺寸。
// `write_gather_open` 把 [SETTINGS][SYN][PSH(target)][PSH(首块)] 合并成一个
// control packet，旧实现下每条流的首记录尺寸恒为「内层首包尺寸 + 24」。
#[tokio::test]
async fn control_records_never_map_payload_length_to_wire_size() {
    use super::{FlushBehavior, WriteRequest};
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    // 10：小载荷；23：SETTINGS 自身；517/1884：Chrome / 带 ML-KEM 的 Firefox
    // 内层 ClientHello；8000/20000：跨过满载数据记录门槛前后。
    for payload_len in [10usize, 23, 517, 1884, 8000, 20000] {
        let mut first_sizes = std::collections::HashSet::new();
        for _ in 0..8 {
            let (client, mut raw_server, mut server_noise) = client_stream_with_raw_server().await;
            let (_r, mut w) = client.into_split();

            // 复刻 gather-open 的 packet：SETTINGS + SYN + PSH，coalesce 成一个包。
            let frames = vec![
                crate::frame::Frame::cmd_settings().encode().unwrap(),
                crate::frame::Frame::syn(5).encode().unwrap(),
                crate::frame::Frame::psh(5, vec![0xC3u8; payload_len])
                    .encode()
                    .unwrap(),
            ];
            let packets = coalesce_encoded_frames(frames, crate::frame::MAX_PAYLOAD_LEN);
            assert_eq!(packets.len(), 1, "gather-open 合并为单个 packet");
            let packet = packets[0].clone();

            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(async move {
                control_requests_flushed(
                    vec![WriteRequest {
                        packets,
                        response_tx,
                        flush: FlushBehavior::Immediate,
                    }],
                    &mut w,
                    FlowDirection::C2S,
                )
                .await
                .expect("control write ok");
            });

            // 读到明文覆盖整个 packet 即可停：末条记录的零填充在块长度前缀
            // 之外，不进入重组后的字节流。
            let mut wire = Vec::new();
            let mut read_buf = vec![0u8; 32768];
            let mut sizes = Vec::new();
            let mut plaintext = Vec::new();
            let collect = async {
                while plaintext.len() < packet.len() {
                    let n = raw_server.read(&mut read_buf).await.expect("peer reads");
                    assert!(n > 0, "tunnel closed early");
                    wire.extend_from_slice(&read_buf[..n]);
                    for (size, payload) in drain_wire_records(&mut wire, &mut server_noise) {
                        sizes.push(size);
                        plaintext.extend_from_slice(&payload);
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), collect)
                .await
                .expect("control records arrive before timeout");
            writer.await.expect("writer joins");
            assert!(matches!(response_rx.await, Ok(Ok(()))));

            // 切分后对端能完整、按序重组：字节流与原 packet 逐字节相同，故
            // SETTINGS 必然先于 SYN、SYN 先于 PSH。
            assert_eq!(plaintext, packet, "切分不得改变重组后的字节流");
            let mut buf = bytes::BytesMut::from(plaintext.as_slice());
            let mut cmds = Vec::new();
            while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
                cmds.push(frame.cmd);
            }
            assert!(buf.is_empty(), "重组后必须恰好是完整帧序列");
            assert_eq!(
                cmds,
                vec![
                    crate::frame::CMD_SETTINGS,
                    crate::frame::CMD_SYN,
                    crate::frame::CMD_PSH
                ],
                "SETTINGS 必须仍严格先于 SYN"
            );

            for size in &sizes {
                assert!(
                    control_record_size_is_allowed(*size),
                    "control record wire size {} 落在采样池支撑集之外（payload_len={}）",
                    size,
                    payload_len
                );
            }
            first_sizes.insert(sizes[0]);
        }

        if payload_len + 21 >= SnowyStream::data_record_capacity() {
            // 大载荷首段锚定满载数据记录：这本身与载荷长度无关。
            assert_eq!(
                first_sizes,
                std::iter::once(SnowyStream::max_data_record_wire_len()).collect(),
                "大载荷首记录必须锚定满载数据记录"
            );
        } else {
            assert!(
                first_sizes.len() > 1,
                "payload_len={} 的首记录尺寸跨连接必须变化（无 1:1 映射），实测 {:?}",
                payload_len,
                first_sizes
            );
        }
    }
}

// C22 回归：SYNACK 拒绝原因的串长度（17/19/21/28/31 字节）不得通过记录尺寸
// 泄漏——持有合法 PSK 的探测者据此可以区分服务端内部状态。
#[tokio::test]
async fn synack_rejection_reason_length_does_not_leak_via_record_size() {
    use tokio::io::AsyncReadExt;

    const REASONS: [&str; 4] = [
        "server overloaded",
        "duplicate stream id",
        "settings not received",
        "max streams per session reached",
    ];

    // 关键不变量：上帧的载荷长度对所有 reason **恒等**。载荷长度一旦恒等，
    // 记录尺寸的分布就不可能依赖 reason —— 这正是补白要达到的效果。此处不去
    // 断言「首记录尺寸集合相交」：那条统计断言依赖 tunnel 侧开场序列的内部
    // 细节（h2_opening_size 的容量恰好能否装下本帧），会随对侧改动而抖动。
    for reason in REASONS {
        for _ in 0..4 {
            let (client_tunnel, mut raw_server, mut server_noise) =
                client_stream_with_raw_server().await;
            // is_client=false ⇒ 不前置 SETTINGS，方向为 S2C；不启读循环。
            let session = Session::new(client_tunnel, test_session_config(false), None);
            session
                .send_synack_rejection(9, reason)
                .await
                .expect("rejection sent");

            let padded = 7 + Session::SYNACK_REJECTION_PAYLOAD_LEN;
            let mut wire = Vec::new();
            let mut read_buf = vec![0u8; 4096];
            let mut record_sizes = Vec::new();
            let mut plaintext = Vec::new();
            let collect = async {
                while plaintext.len() < padded {
                    let n = raw_server.read(&mut read_buf).await.expect("peer reads");
                    assert!(n > 0, "tunnel closed early");
                    wire.extend_from_slice(&read_buf[..n]);
                    for (size, payload) in drain_wire_records(&mut wire, &mut server_noise) {
                        record_sizes.push(size);
                        plaintext.extend_from_slice(&payload);
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), collect)
                .await
                .expect("synack record arrives before timeout");

            let mut cursor = bytes::BytesMut::from(plaintext.as_slice());
            let frame = crate::frame::Frame::decode(&mut cursor).expect("synack decodes");
            assert_eq!(frame.cmd, crate::frame::CMD_SYNACK);
            assert_eq!(
                frame.payload.len(),
                Session::SYNACK_REJECTION_PAYLOAD_LEN,
                "拒绝原因必须定长上帧，长度不得随 reason 变化"
            );
            assert_eq!(
                String::from_utf8_lossy(&frame.payload).trim_end(),
                reason,
                "补白必须可 trim 回原文"
            );

            for size in &record_sizes {
                assert!(
                    control_record_size_is_allowed(*size),
                    "synack record wire size {} 落在支撑集之外",
                    size
                );
                assert_ne!(
                    *size,
                    7 + reason.len() + crate::frame::CONTROL_RECORD_MIN_OVERHEAD,
                    "记录尺寸不得等于「原始 reason 载荷 + 24」"
                );
            }
        }
    }
}

// C6 回归：非 sticky（脚本）路径的批量 flush 必须与逐条 flush 产生完全一致的
// record 尺寸/条数/顺序/载荷。
#[tokio::test]
async fn scripted_batched_flush_matches_per_record_byte_stream() {
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // `L:1` 经 `randomize_script` 的缩放后仍是 1，再被 `script_policy` 的 L1
    // 硬下界抬到 `MIN_DATA_RECORD_PAYLOAD` —— 两级都是确定的，故每条记录恰好
    // 承载 `CHUNK` 字节、线速恒为 `record_wire`，两条路径可逐项比对。
    const RECORDS: usize = 64;
    const CHUNK: usize = kanotls_tunnel::control_size::MIN_DATA_RECORD_PAYLOAD;
    let record_wire = SnowyStream::data_record_wire_len(CHUNK);
    let payload: Vec<u8> = (0..RECORDS * CHUNK)
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();
    let expected_wire_bytes = RECORDS * record_wire;
    let script = vec!["stop=64".to_string(), "0=L:1,D:0,F:0".to_string()];

    // 参考路径（旧行为）：逐条 prepare + flush。
    let (reference_wire, mut reference_noise) = {
        let (client, mut raw_server, server_noise) = client_stream_with_raw_server().await;
        let (_r, mut w) = client.into_split();
        let payload = payload.clone();
        let writer = tokio::spawn(async move {
            for chunk in payload.chunks(CHUNK) {
                w.prepare_data_record(chunk, record_wire)
                    .expect("reference prepares record");
                w.flush().await.expect("reference flushes record");
            }
        });
        let mut buf = vec![0u8; expected_wire_bytes];
        tokio::time::timeout(Duration::from_secs(5), raw_server.read_exact(&mut buf))
            .await
            .expect("reference bytes arrive before timeout")
            .expect("reference read ok");
        writer.await.expect("reference writer joins");
        (buf, server_noise)
    };

    // 新路径：drive_shaper 批量 flush（8 条一批）。
    let (batched_wire, mut batched_noise) = {
        let (client, mut raw_server, server_noise) = client_stream_with_raw_server().await;
        let (_r, mut w) = client.into_split();
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&script), false);
        shaper.skip_first_flight();
        let mut pending = payload.clone();
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
        drop(control_tx);
        let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
        let inbound = Arc::new(super::InboundSignal::default());
        let writer = tokio::spawn(async move {
            let (fake, deferred) = drive_shaper_flushed(
                &mut pending,
                &mut shaper,
                &mut w,
                &mut control_rx,
                &pending_client_settings,
                FlowDirection::C2S,
                &inbound,
                std::collections::HashSet::new(),
            )
            .await
            .expect("drive_shaper ok");
            assert!(fake.is_empty(), "F:0 规则不产生 fake 请求");
            assert!(deferred.is_empty());
            assert!(pending.is_empty());
        });
        let mut buf = vec![0u8; expected_wire_bytes];
        tokio::time::timeout(Duration::from_secs(5), raw_server.read_exact(&mut buf))
            .await
            .expect("batched bytes arrive before timeout")
            .expect("batched read ok");
        writer.await.expect("batched writer joins");
        (buf, server_noise)
    };

    let mut reference_wire = reference_wire;
    let mut batched_wire = batched_wire;
    let reference = drain_wire_records(&mut reference_wire, &mut reference_noise);
    let batched = drain_wire_records(&mut batched_wire, &mut batched_noise);

    let sizes: Vec<usize> = batched.iter().map(|(size, _)| *size).collect();
    assert_eq!(sizes, vec![record_wire; RECORDS]);
    assert_eq!(sizes, reference.iter().map(|(s, _)| *s).collect::<Vec<_>>());
    let plaintext: Vec<u8> = batched.iter().flat_map(|(_, p)| p.clone()).collect();
    assert_eq!(plaintext, payload);
    assert_eq!(
        plaintext,
        reference.iter().flat_map(|(_, p)| p.clone()).collect::<Vec<u8>>()
    );
}

// C6 回归：零间隔的连续记录合并为一次写出（真实端点的行为），而 delay > 0
// 的记录必须在 sleep **之前**就已离开 write_buffer——否则待发字节会攒到
// sleep 之后一起出网，延迟根本作用不到线上，IAT 模型失效。
#[tokio::test]
async fn zero_delay_records_coalesce_and_delayed_record_flushes_before_sleep() {
    // 单规则脚本：`L:1` 经 `randomize_script` 的缩放后仍是 1，再被
    // `script_policy` 的 L1 硬下界抬到 `MIN_DATA_RECORD_PAYLOAD`——两级都是
    // 确定的，规则轮转对单规则又是恒等，故记录尺寸/条数完全确定。
    const CHUNK: usize = kanotls_tunnel::control_size::MIN_DATA_RECORD_PAYLOAD;
    let record_wire = SnowyStream::data_record_wire_len(CHUNK);

    async fn drive(
        script: Vec<String>,
        pending_bytes: usize,
    ) -> (usize, std::time::Duration, std::time::Duration) {
            use crate::shaper::TrafficShaper;
        use kanotls_tunnel::FlowDirection;
        use tokio::io::AsyncReadExt;

        let (client, mut raw_server, _server_noise) = client_stream_with_raw_server().await;
        let (_r, mut w) = client.into_split();
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&script), false);
        // 跳过首发让出方向的那一条记录：本测试断言的是常态 flush 边界。
        shaper.skip_first_flight();
        let mut pending = vec![0xA1u8; pending_bytes];
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
        drop(control_tx);
        let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
        let inbound = Arc::new(super::InboundSignal::default());

        let started = std::time::Instant::now();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            let n = raw_server.read(&mut buf).await.expect("raw server reads");
            (n, started.elapsed())
        });

        drive_shaper_flushed(
            &mut pending,
            &mut shaper,
            &mut w,
            &mut control_rx,
            &pending_client_settings,
            FlowDirection::C2S,
            &inbound,
            std::collections::HashSet::new(),
        )
        .await
        .expect("drive_shaper ok");
        let drive_elapsed = started.elapsed();
        let (first_read, first_read_at) = reader.await.expect("reader joins");
        (first_read, first_read_at, drive_elapsed)
    }

    // (a) 零延迟：8 条记录（批量上限）必须合并成一次写出。
    let (first_read, _, _) = drive(
        vec!["stop=64".to_string(), "0=L:1,D:0,F:0".to_string()],
        super::STICKY_BULK_FLUSH_MAX_RECORDS * CHUNK,
    )
    .await;
    assert_eq!(
        first_read,
        super::STICKY_BULK_FLUSH_MAX_RECORDS * record_wire,
        "零间隔的连续记录必须合并为一次写出"
    );

    // (b) delay > 0：记录必须在 sleep 之前就离开 write_buffer，故首条记录
    // 到达对端的时刻远早于整段 drain 结束（drain 要等两次 ~200ms 采样）。
    let (first_read, first_read_at, drive_elapsed) =
        drive(vec!["stop=64".to_string(), "0=L:1,D:200,F:0".to_string()], 2 * CHUNK).await;
    assert_eq!(first_read, record_wire, "带延迟的记录逐条 flush");
    assert!(
        first_read_at * 2 < drive_elapsed,
        "delay 记录必须先 flush 再 sleep：first_read_at={:?} drive_elapsed={:?}",
        first_read_at,
        drive_elapsed
    );
}

// C22 回归（端到端）：外层握手后的第一个上行 burst 必须 < 300 字节。
//
// burst = 方向相同的连续包尺寸累加，只能被方向改变打断（时间间隔不算）。
// 旧路径下 gather-open 把 [SETTINGS][SYN][PSH(target)][PSH(内层 CH)] 作为一个
// control packet 发出，首记录线速尺寸 = 内层首包 + 24（Chrome 541、带 ML-KEM
// 的 Firefox ~1908），第一个上行 burst 直接落在被标记的一侧。
#[tokio::test]
async fn first_upstream_burst_stays_under_300_bytes() {
    use tokio::io::AsyncReadExt;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    // 带 ML-KEM 的 Firefox 量级内层 ClientHello。
    let inner_hello = vec![0x16u8; 1884];
    let target: &[u8] = b"burst.example:443";

    let (client_tunnel, mut raw_server, mut server_noise) = client_stream_with_raw_server().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let read_loop = client.clone();
    tokio::spawn(async move {
        let _ = read_loop.run_read_loop().await;
    });

    let mut stream = client.open_stream().await.expect("stream opens");
    let sid = stream.stream_id;
    stream.defer_target(target);
    let hello = inner_hello.clone();
    let writer = tokio::spawn(async move {
        let _ = stream.write(&hello).await;
        stream
    });

    // 对端（裸 server）不发任何东西 ⇒ 方向从未改变 ⇒ 这段时间内读到的全部
    // 字节就是第一个上行 burst。窗口 120ms 远小于让出方向的 300ms 上限，
    // 因此窗口内客户端必定仍挂在 quiet gap 上。
    // 以「读到 120ms 静默」界定 burst 边界（120ms 远小于让出方向的 300ms
    // 上限），首次读取给足 2s 以免负载高的机器把首条记录也算成空 burst。
    let mut wire = Vec::new();
    let mut buf = vec![0u8; 32768];
    let mut window = Duration::from_secs(2);
    loop {
        match tokio::time::timeout(window, raw_server.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                wire.extend_from_slice(&buf[..n]);
                window = Duration::from_millis(120);
            }
            Ok(Err(e)) => panic!("raw server read error: {}", e),
        }
    }
    let burst = wire.len();
    assert!(
        burst < 300,
        "第一个上行 burst 为 {} 字节，必须 < 300",
        burst
    );
    assert!(burst > 0, "首条记录必须已经上链");

    // 余下的字节在让出方向之后继续发出，且重组后与原帧序列逐字节相同。
    let mut expected = crate::frame::Frame::cmd_settings().encode().unwrap();
    expected.extend_from_slice(&crate::frame::Frame::syn(sid).encode().unwrap());
    expected.extend_from_slice(&crate::frame::Frame::psh(sid, target.to_vec()).encode().unwrap());
    expected.extend_from_slice(
        &crate::frame::Frame::psh(sid, inner_hello.clone())
            .encode()
            .unwrap(),
    );

    let mut plaintext = Vec::new();
    let mut sizes = Vec::new();
    let collect = async {
        while plaintext.len() < expected.len() {
            let n = raw_server.read(&mut buf).await.expect("raw server reads");
            assert!(n > 0, "tunnel closed before the backlog drained");
            wire.extend_from_slice(&buf[..n]);
            for (size, payload) in drain_wire_records(&mut wire, &mut server_noise) {
                sizes.push(size);
                plaintext.extend_from_slice(&payload);
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), collect)
        .await
        .expect("backlog drains before timeout");

    // padding 请求（PING）不进数据帧流，先把它从重组结果里剔掉再比对。
    let mut decoded = Vec::new();
    let mut cursor = bytes::BytesMut::from(plaintext.as_slice());
    while let Some(frame) = crate::frame::Frame::decode(&mut cursor) {
        if frame.cmd != crate::frame::CMD_PADDING {
            decoded.extend_from_slice(&frame.encode().unwrap());
        }
    }
    assert_eq!(decoded, expected, "让出方向后余下字节必须完整按序送达");

    // 任何一条记录都不得等于「内层首包 + 24」。
    let leaked = crate::frame::Frame::psh(sid, inner_hello).encode().unwrap().len()
        + crate::frame::CONTROL_RECORD_MIN_OVERHEAD;
    assert!(
        !sizes.contains(&leaked),
        "记录尺寸 {} 把内层首包长度 1:1 送上线了：{:?}",
        leaked,
        sizes
    );

    let stream = writer.await.expect("writer joins");
    drop(stream);
    client.force_close();
}

// W4 回归：sticky bulk 路径的批量 flush 与逐条 flush 必须产生完全一致的
// record 尺寸/顺序/载荷序列（仅 syscall 合并；不同连接的密文本身不可比，
// 故离线解密后比对）。
#[tokio::test]
async fn sticky_bulk_batched_flush_matches_per_record_byte_stream() {
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let cap = SnowyStream::data_record_capacity();
    let tail = 1234usize;
    // 9 条满载 record > STICKY_BULK_FLUSH_MAX_RECORDS(8)：触发一次批量
    // 上限 flush，再触发排空时的收尾 flush。
    let full_records = 9usize;
    let total = cap * full_records + tail;
    let payload: Vec<u8> = (0..total).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let expected_wire_bytes = full_records * SnowyStream::max_data_record_wire_len()
        + SnowyStream::data_record_wire_len(tail);

    // 参考路径（旧行为）：逐条 prepare + flush。
    let (reference_wire, mut reference_noise) = {
        let (client, mut raw_server, server_noise) = client_stream_with_raw_server().await;
        let (_r, mut w) = client.into_split();
        let payload = payload.clone();
        let writer = tokio::spawn(async move {
            let mut off = 0usize;
            while off < payload.len() {
                let take = (payload.len() - off).min(cap);
                let wire = if take == cap {
                    SnowyStream::max_data_record_wire_len()
                } else {
                    SnowyStream::data_record_wire_len(take)
                };
                w.prepare_data_record(&payload[off..off + take], wire)
                    .expect("reference prepares record");
                w.flush().await.expect("reference flushes record");
                off += take;
            }
        });
        let mut buf = vec![0u8; expected_wire_bytes];
        tokio::time::timeout(Duration::from_secs(5), raw_server.read_exact(&mut buf))
            .await
            .expect("reference bytes arrive before timeout")
            .expect("reference read ok");
        writer.await.expect("reference writer joins");
        (buf, server_noise)
    };

    // 新路径：drive_shaper sticky 批量 flush。
    let (batched_wire, mut batched_noise) = {
        let (client, mut raw_server, server_noise) = client_stream_with_raw_server().await;
        let (_r, mut w) = client.into_split();
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        // 跳过首发让出方向的那一条记录：本测试比对的是 sticky bulk 稳态。
        shaper.skip_first_flight();
        let mut pending = payload.clone();
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
        drop(control_tx);
        let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
        let inbound = Arc::new(super::InboundSignal::default());
        let writer = tokio::spawn(async move {
            let (fake, deferred) = drive_shaper_flushed(
                &mut pending,
                &mut shaper,
                &mut w,
                &mut control_rx,
                &pending_client_settings,
                FlowDirection::C2S,
                &inbound,
                std::collections::HashSet::new(),
            )
            .await
            .expect("drive_shaper ok");
            assert!(fake.is_empty(), "sticky 路径不产生 fake 帧");
            assert!(deferred.is_empty());
            assert!(pending.is_empty());
        });
        let mut buf = vec![0u8; expected_wire_bytes];
        tokio::time::timeout(Duration::from_secs(5), raw_server.read_exact(&mut buf))
            .await
            .expect("batched bytes arrive before timeout")
            .expect("batched read ok");
        writer.await.expect("batched writer joins");
        (buf, server_noise)
    };

    let (reference_sizes, reference_plain) =
        decrypt_wire_records(&reference_wire, &mut reference_noise);
    let (batched_sizes, batched_plain) = decrypt_wire_records(&batched_wire, &mut batched_noise);

    // record 尺寸/顺序完全一致：full_records 条满载 + 1 条精确尺寸尾 record。
    let mut expected_sizes = vec![SnowyStream::max_data_record_wire_len(); full_records];
    expected_sizes.push(SnowyStream::data_record_wire_len(tail));
    assert_eq!(batched_sizes, expected_sizes);
    assert_eq!(batched_sizes, reference_sizes);
    // 拼接载荷完全一致且等于原始数据。
    assert_eq!(reference_plain, payload);
    assert_eq!(batched_plain, payload);
}

// W4 回归：prepare_data_record 在 write_buffer 中自然累积，flush 前不出网；
// 累积语义是批量 flush 正确性的基础。
#[tokio::test]
async fn prepare_data_record_accumulates_until_flush() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut server) = snowy_stream_pair().await;
    let (_r, mut w) = client.into_split();
    let payload = vec![0x5Au8; 1000];
    let wire = SnowyStream::data_record_wire_len(payload.len());

    let after_first = {
        w.prepare_data_record(&payload, wire).expect("prepare first");
        w.buffered_write_len()
    };
    assert_eq!(after_first, wire);
    let after_second = {
        w.prepare_data_record(&payload, wire)
            .expect("prepare second");
        w.buffered_write_len()
    };
    assert_eq!(after_second, 2 * wire, "prepare 自然累积，flush 前不出网");

    w.flush().await.expect("flush");
    assert_eq!(w.buffered_write_len(), 0);

    let mut buf = vec![0u8; 2000];
    tokio::time::timeout(Duration::from_secs(2), server.read_exact(&mut buf))
        .await
        .expect("server reads both records")
        .expect("server read ok");
    assert_eq!(buf, vec![0x5Au8; 2000]);
}

// W5 回归：脚本 delay 窗口内到达的 SYN 在帧边界处立即 prepare+flush（真实
// H2 端点本就优先控制帧），不等 delay 期满；data record 的尺寸/数量不变。
#[tokio::test]
async fn delay_window_passes_through_syn_before_delay_expires() {
    use super::{FlushBehavior, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = client.into_split();
    let (mut sr, _sw) = server.into_split();

    // 单规则脚本：policy target 大于整条 pending——唯一 record 恰好落在
    // 帧边界（policy 切分不越过帧尾），其后的 delay 窗口允许控制帧插队。
    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some(&["stop=64".to_string(), "0=L:1500,D:200,F:0".to_string()][..]),
        false,
    );
    // 跳过首发让出方向的记录：本测试断言的是 delay 窗口行为。
    shaper.skip_first_flight();

    let psh = crate::frame::Frame::psh(7, vec![0xAAu8; 1000])
        .encode()
        .expect("psh encodes");
    let syn = crate::frame::Frame::syn(0x2A).encode().expect("syn encodes");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
    let inbound = Arc::new(super::InboundSignal::default());

    let expected_len = psh.len() + syn.len();
    let reader = tokio::spawn(async move {
        let mut all = Vec::new();
        let mut buf = vec![0u8; 16384];
        while all.len() < expected_len {
            let n = tokio::time::timeout(Duration::from_secs(10), sr.read(&mut buf))
                .await
                .expect("server reads before timeout")
                .expect("server read ok");
            assert!(n > 0, "tunnel closed early");
            all.extend_from_slice(&buf[..n]);
        }
        all
    });

    // SYN 在 drive 开始前排入 control 通道：delay 窗口内即被消费。
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control_tx
        .send(WriteRequest {
            packets: vec![syn.clone()],
            response_tx,
            flush: FlushBehavior::Immediate,
        })
        .await
        .expect("syn queued");

    let mut pending = psh.clone();
    let (fake, deferred) = drive_shaper_flushed(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
        &inbound,
        std::collections::HashSet::new(),
    )
    .await
    .expect("drive_shaper ok");

    assert!(fake.is_empty());
    // SYN 未被暂存——它已在 delay 窗口内（drive_shaper 返回前）上链，
    // 否则窗口外没有任何路径能把它的字节写出去。
    assert!(deferred.is_empty(), "SYN 必须在窗口内插队，不得暂存");
    assert!(matches!(response_rx.await, Ok(Ok(()))));

    let received = reader.await.expect("reader joins");
    // 线上序列：完整的 PSH 帧在前，SYN 帧紧随其后落在帧边界上；data
    // record 的数量/尺寸不变（pending 仍是单 record 排空）。
    let mut expected = psh.clone();
    expected.extend_from_slice(&syn);
    assert_eq!(received, expected);
}

// W5 回归：delay 窗口未落在帧边界时，SYN 不得插队（会插进 PSH 帧载荷
// 中间破坏对端帧重组）——暂存后由主循环按到达顺序补发，responder 在
// 其字节真正 flush 后才应答。
#[tokio::test]
async fn delay_window_defers_syn_off_frame_boundary() {
    use super::{FlushBehavior, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = client.into_split();
    let (mut sr, _sw) = server.into_split();

    // policy target ~300 字节：1007 字节 PSH 帧被切成多条 record，前几个
    // delay 窗口都落在帧载荷中间（非边界），SYN 不得插队。
    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some(&["stop=64".to_string(), "0=L:300,D:100,F:0".to_string()][..]),
        false,
    );
    // 跳过首发让出方向的记录：本测试断言的是 delay 窗口行为。
    shaper.skip_first_flight();

    let psh = crate::frame::Frame::psh(7, vec![0xAAu8; 1000])
        .encode()
        .expect("psh encodes");
    let syn = crate::frame::Frame::syn(0x2A).encode().expect("syn encodes");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
    let inbound = Arc::new(super::InboundSignal::default());

    let expected_len = psh.len() + syn.len();
    let reader = tokio::spawn(async move {
        let mut all = Vec::new();
        let mut buf = vec![0u8; 16384];
        while all.len() < expected_len {
            let n = tokio::time::timeout(Duration::from_secs(10), sr.read(&mut buf))
                .await
                .expect("server reads before timeout")
                .expect("server read ok");
            assert!(n > 0, "tunnel closed early");
            all.extend_from_slice(&buf[..n]);
        }
        all
    });

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control_tx
        .send(WriteRequest {
            packets: vec![syn.clone()],
            response_tx,
            flush: FlushBehavior::Immediate,
        })
        .await
        .expect("syn queued");

    let mut pending = psh.clone();
    let (fake, deferred) = drive_shaper_flushed(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
        &inbound,
        std::collections::HashSet::new(),
    )
    .await
    .expect("drive_shaper ok");

    assert!(fake.is_empty());
    assert_eq!(
        deferred.len(),
        1,
        "非帧边界窗口内的 SYN 必须暂存，不得插队"
    );

    let response_rx = response_rx;
    tokio::pin!(response_rx);
    assert!(poll!(&mut response_rx).is_pending());

    // 主循环补发：drive_shaper 返回后按到达顺序处理暂存写。
    control_requests_flushed(deferred, &mut cw, FlowDirection::C2S)
        .await
        .expect("deferred flush ok");
    assert!(matches!(response_rx.await, Ok(Ok(()))));

    let received = reader.await.expect("reader joins");
    let mut expected = psh.clone();
    expected.extend_from_slice(&syn);
    assert_eq!(received, expected);
}

// W5 回归：CMD_PADDING（H2 骨架/假响应）在 delay 窗口内不得发出——暂存
// 后由主循环按到达顺序补发，responder 在其字节真正 flush 后才应答。
#[tokio::test]
async fn delay_window_defers_padding_until_after_drain() {
    use super::{FlushBehavior, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = client.into_split();
    let (mut sr, _sw) = server.into_split();

    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some(&["stop=64".to_string(), "0=L:300,D:200,F:0".to_string()][..]),
        false,
    );
    // 跳过首发让出方向的记录：本测试断言的是 delay 窗口行为。
    shaper.skip_first_flight();

    let data = vec![0xAAu8; 1000];
    let padding = crate::frame::encode_padding_request_sized(2, super::PADDING_REQUEST_WIRE);
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
    let inbound = Arc::new(super::InboundSignal::default());

    let expected_len = data.len() + padding.len();
    let reader = tokio::spawn(async move {
        let mut all = Vec::new();
        let mut buf = vec![0u8; 16384];
        while all.len() < expected_len {
            let n = tokio::time::timeout(Duration::from_secs(10), sr.read(&mut buf))
                .await
                .expect("server reads before timeout")
                .expect("server read ok");
            assert!(n > 0, "tunnel closed early");
            all.extend_from_slice(&buf[..n]);
        }
        all
    });

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control_tx
        .send(WriteRequest {
            packets: vec![padding.clone()],
            response_tx,
            flush: FlushBehavior::Immediate,
        })
        .await
        .expect("padding queued");

    let mut pending = data.clone();
    let (fake, deferred) = drive_shaper_flushed(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
        &inbound,
        std::collections::HashSet::new(),
    )
    .await
    .expect("drive_shaper ok");

    assert!(fake.is_empty());
    assert_eq!(deferred.len(), 1, "CMD_PADDING 必须暂存，窗口内不得发出");

    // 暂存写的 responder 在其字节真正 flush 前不得应答。
    let response_rx = response_rx;
    tokio::pin!(response_rx);
    assert!(poll!(&mut response_rx).is_pending());

    // 主循环补发：drive_shaper 返回后按到达顺序处理暂存写。
    control_requests_flushed(deferred, &mut cw, FlowDirection::C2S)
        .await
        .expect("deferred flush ok");
    assert!(matches!(response_rx.await, Ok(Ok(()))));

    let received = reader.await.expect("reader joins");
    assert_eq!(received.len(), expected_len);
    assert_eq!(
        &received[..data.len()],
        data.as_slice(),
        "全部 data record 在前，窗口内未夹带 padding"
    );
    assert_eq!(
        &received[data.len()..],
        padding.as_slice(),
        "padding 在 drain 完成后补发"
    );
}

// FIFO 回归：窗口 1（非帧边界）内 R1 被暂存后，窗口 2（帧边界）内到达的
// R2 不得越过 R1 插队——否则 R2 的 SYN 可能先于被暂存的 SETTINGS+SYN
// 到达对端，而服务端会丢弃先于 SETTINGS 的 SYN。本 drain 内一旦存在
// 暂存写，控制写必须保持严格 FIFO。
#[tokio::test]
async fn delay_window_blocks_pass_through_once_deferred() {
    use super::{FlushBehavior, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = client.into_split();
    let (mut sr, _sw) = server.into_split();

    // 单规则脚本：target ∈ [595,840]（随机化缩放后），两条 PSH 帧
    // （各 507 字节，边界 507/1014）被切成两条 record——record1 消费
    // ∈ [571,816]（非边界），record2 吞掉剩余（边界）。
    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some(&["stop=64".to_string(), "0=L:700,D:200,F:0".to_string()][..]),
        false,
    );
    // 跳过首发让出方向的记录：本测试断言的是 delay 窗口行为。
    shaper.skip_first_flight();

    let psh_a = crate::frame::Frame::psh(7, vec![0xAAu8; 500])
        .encode()
        .expect("psh a encodes");
    let psh_b = crate::frame::Frame::psh(8, vec![0xBBu8; 500])
        .encode()
        .expect("psh b encodes");
    let mut psh = psh_a.clone();
    psh.extend_from_slice(&psh_b);
    let syn_a = crate::frame::Frame::syn(0x2A).encode().expect("syn a encodes");
    let syn_b = crate::frame::Frame::syn(0x2B).encode().expect("syn b encodes");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
    let inbound = Arc::new(super::InboundSignal::default());

    let expected_len = psh.len() + syn_a.len() + syn_b.len();
    // 确定性同步（不依赖墙钟）：record2 在 W1 结束 flush 后 reader 才能
    // 收满 psh.len() 字节——此刻正是边界窗口 W2 的起点，R2 此时发出
    // 必落在 W2 内。
    let psh_len = psh.len();
    let control_tx2 = control_tx.clone();
    let syn_b2 = syn_b.clone();
    let reader = tokio::spawn(async move {
        let mut all = Vec::new();
        let mut buf = vec![0u8; 16384];
        let mut r2_sent = false;
        while all.len() < expected_len {
            let n = tokio::time::timeout(Duration::from_secs(10), sr.read(&mut buf))
                .await
                .expect("server reads before timeout")
                .expect("server read ok");
            assert!(n > 0, "tunnel closed early");
            all.extend_from_slice(&buf[..n]);
            if !r2_sent && all.len() >= psh_len {
                r2_sent = true;
                let (response_tx_b, _response_rx_b) = tokio::sync::oneshot::channel();
                control_tx2
                    .send(WriteRequest {
                        packets: vec![syn_b2.clone()],
                        response_tx: response_tx_b,
                        flush: FlushBehavior::Immediate,
                    })
                    .await
                    .expect("syn b queued");
            }
        }
        all
    });

    // R1 在 drive 开始前排入：窗口 1（非边界）消费并暂存。
    let (response_tx_a, response_rx_a) = tokio::sync::oneshot::channel();
    control_tx
        .send(WriteRequest {
            packets: vec![syn_a.clone()],
            response_tx: response_tx_a,
            flush: FlushBehavior::Immediate,
        })
        .await
        .expect("syn a queued");

    let mut pending = psh.clone();
    let (_fake, deferred) = drive_shaper_flushed(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
        &inbound,
        std::collections::HashSet::new(),
    )
    .await
    .expect("drive_shaper ok");

    assert_eq!(
        deferred.len(),
        2,
        "一旦存在暂存写，后续控制写在本 drain 内不得插队"
    );
    assert_eq!(
        deferred[0].packets,
        vec![syn_a.clone()],
        "暂存顺序必须先 R1 后 R2"
    );
    assert_eq!(deferred[1].packets, vec![syn_b.clone()]);

    let response_rx_a = response_rx_a;
    tokio::pin!(response_rx_a);
    assert!(poll!(&mut response_rx_a).is_pending());

    control_requests_flushed(deferred, &mut cw, FlowDirection::C2S)
        .await
        .expect("deferred flush ok");
    assert!(matches!(response_rx_a.await, Ok(Ok(()))));

    let received = reader.await.expect("reader joins");
    let mut expected = psh.clone();
    expected.extend_from_slice(&syn_a);
    expected.extend_from_slice(&syn_b);
    assert_eq!(received, expected);
}

// ============ 论文特征回归台（USENIX Sec'24, Xue et al.） ============
//
// 观测口径与论文 §6.2 一致：
// * 每个整数 = 一个 **TCP 载荷**字节数（不是 TLS record 尺寸），符号 = 方向；
// * 观测窗口 `Wo = 25` 个承载数据的包，且外层 TLS 握手已被剥掉——本台从
//   Noise 转入传输态之后开始抓，正对应那个窗口；
// * burst = 方向相同的连续包尺寸累加（论文另有 IAT ≥ 3×RTT 也断开 burst 的
//   条件，本台不建模：不建模只会让 burst 更长/更少，是保守方向）。
//
// 抓包方式：client 与 server 之间插一个中继任务，每次 `read()` 记一个 flush
// 组，再按 MSS 展开成分段序列。一个 flush 组 = 写端一次 `write_all`，内核对它
// 按 MSS 切分——这正是审查者看到的分段结构，且不需要解密。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    C2S,
    S2C,
}

#[derive(Clone, Debug)]
struct WireEvent {
    dir: Dir,
    /// 该 flush 组的原始字节。TLS record 头（`17 03 03 LL LL`）在线上是明文，
    /// 因此不解密也能切出 record 边界——审查者的能力也就到这一步。
    bytes: Vec<u8>,
}

impl WireEvent {
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

type Tap = Arc<std::sync::Mutex<Vec<WireEvent>>>;

// 中继：client_tcp <-> mid <-> server_tcp，逐次 read 记录一个 flush 组。
async fn tapped_tunnel_pair() -> (SnowyStream, SnowyStream, Tap) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a1 = l1.local_addr().unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a2 = l2.local_addr().unwrap();

    let client_task = tokio::spawn(async move { TcpStream::connect(a1).await.unwrap() });
    let (mid_client, _) = l1.accept().await.unwrap();
    let client_tcp = client_task.await.unwrap();

    let mid_task = tokio::spawn(async move { TcpStream::connect(a2).await.unwrap() });
    let (server_tcp, _) = l2.accept().await.unwrap();
    let mid_server = mid_task.await.unwrap();

    for s in [&client_tcp, &mid_client, &mid_server, &server_tcp] {
        s.set_nodelay(true).unwrap();
    }

    let tap: Tap = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (mut cr, mut cw) = mid_client.into_split();
    let (mut sr, mut sw) = mid_server.into_split();
    let t1 = tap.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            t1.lock().unwrap().push(WireEvent { dir: Dir::C2S, bytes: buf[..n].to_vec() });
            if sw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let t2 = tap.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            t2.lock().unwrap().push(WireEvent { dir: Dir::S2C, bytes: buf[..n].to_vec() });
            if cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    let (client_noise, server_noise) = build_transport_pair();
    (
        SnowyStream::new(client_tcp, client_noise),
        SnowyStream::new(server_tcp, server_noise),
        tap,
    )
}

const MSS: usize = 1460;

// flush 组 → TCP 分段序列（带符号：+ 为 C2S）。
fn to_packets(events: &[WireEvent]) -> Vec<(Dir, usize)> {
    let mut out = Vec::new();
    for ev in events {
        let mut left = ev.len();
        while left > MSS {
            out.push((ev.dir, MSS));
            left -= MSS;
        }
        if left > 0 {
            out.push((ev.dir, left));
        }
    }
    out
}

// 论文的 |L| = 4 离散化，带方向符号。
fn l_class(dir: Dir, size: usize) -> i32 {
    let c = match size {
        0..=160 => 1,
        161..=600 => 2,
        601..=1210 => 3,
        _ => 4,
    };
    if dir == Dir::C2S {
        c
    } else {
        -c
    }
}

fn bursts(packets: &[(Dir, usize)]) -> Vec<(Dir, usize)> {
    let mut out: Vec<(Dir, usize)> = Vec::new();
    for &(dir, size) in packets {
        match out.last_mut() {
            Some(last) if last.0 == dir => last.1 += size,
            _ => out.push((dir, size)),
        }
    }
    out
}


// 一个方向上的 TLS record 线速尺寸序列，只按明文 record 头切分（不解密）。
fn record_sizes(events: &[WireEvent], dir: Dir) -> Vec<usize> {
    let mut wire = Vec::new();
    for ev in events.iter().filter(|e| e.dir == dir) {
        wire.extend_from_slice(&ev.bytes);
    }
    let mut sizes = Vec::new();
    let mut off = 0usize;
    while off + 5 <= wire.len() {
        assert_eq!(wire[off], 0x17, "record type must be application data");
        let len = u16::from_be_bytes([wire[off + 3], wire[off + 4]]) as usize;
        if off + 5 + len > wire.len() {
            break;
        }
        sizes.push(5 + len);
        off += 5 + len;
    }
    sizes
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    inner: usize,
    downstream: usize,
    /// 源站延迟：SYNACK 之后、响应体之前的等待。真实部署里这一段至少是一个
    /// 到源站的 RTT（外加 DNS + connect），零延迟只在源站与代理同机时出现。
    origin_latency_ms: u64,
}

struct Capture {
    packets: Vec<(Dir, usize)>,
    bursts: Vec<(Dir, usize)>,
    upstream_records: Vec<usize>,
}

// 跑一条完整的双向连接：客户端首个 flight（内层 ClientHello 量级）→ 服务端
// 响应（SYNACK + 响应体）→ 客户端第二个 flight（内层 Finished 量级）。
async fn capture_scenario(scenario: Scenario) -> Capture {
    let (client_tunnel, server_tunnel, tap) = tapped_tunnel_pair().await;
    // 客户端侧再抓一份记录边界：从裸 TCP 上按 TLS record 头切分即可，
    // 不需要解密（record 头在线上是明文）。
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let server = ServerSessionHandler::new(server_tunnel, test_session_config(false));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let server_read_loop = server.session.clone();
    tokio::spawn(async move {
        let _ = server_read_loop.run_read_loop().await;
    });

    let downstream = scenario.downstream;
    let origin_latency_ms = scenario.origin_latency_ms;
    let acceptor = tokio::spawn(async move {
        let (_sid, mut st) = server.accept_stream().await.expect("server accepts stream");
        let _target = st.read().await;
        st.send_synack().await.expect("server sends synack");
        let mut got = 0usize;
        while got < 8 {
            match st.read().await {
                Some(d) => got += d.len(),
                None => break,
            }
        }
        if origin_latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(origin_latency_ms)).await;
        }
        st.write(&vec![0x17u8; downstream])
            .await
            .expect("server writes response");
        tokio::time::sleep(Duration::from_millis(180)).await;
        st
    });

    let mut stream = client.open_stream().await.expect("stream opens");
    stream.defer_target(b"paper.example:443");
    stream
        .write(&vec![0x16u8; scenario.inner])
        .await
        .expect("client writes inner client hello");
    tokio::time::sleep(Duration::from_millis(80)).await;
    // 第二个上行 flight：内层 Finished + GET 量级。
    stream
        .write(&[0x17u8; 80])
        .await
        .expect("client writes second flight");
    tokio::time::sleep(Duration::from_millis(220)).await;

    let events = tap.lock().expect("tap lock").clone();
    let packets = to_packets(&events);
    let bursts = bursts(&packets);
    let upstream_records = record_sizes(&events, Dir::C2S);

    drop(stream);
    let _ = acceptor.await;
    client.force_close();

    Capture {
        packets,
        bursts,
        upstream_records,
    }
}

/// 论文 Table 2 判别力前 5 的 3-gram（`Distinc.` = 两类出现概率之比）。
const PAPER_TOP_GRAMS: [((i32, i32, i32), &str, f64); 5] = [
    ((2, -4, 1), "C-Hello -> S-Hello+EX -> C-EX+CCS", 7.226),
    ((-4, -4, -4), "S-Hello 连续分段", 5.886),
    ((-4, 1, -1), "S-Hello -> C-EX+CCS -> S-CCS+FIN", 2.879),
    ((-4, -4, -3), "S-Hello -> cont. -> S-EX", 2.780),
    ((2, -4, -4), "C-Hello -> S-Hello -> cont.", 2.416),
];

/// 「嵌套握手往返」型 3-gram：这两个是 KanoTLS **必须**且**能够**避免的。
///
/// 它们共同的结构是「本端中/小包 → 单个（或很短的）大对端包 → 小的本端包」，
/// 也就是一次内层握手的往返；正常 HTTPS 的应用数据里客户端在收到响应之后
/// 要么结束、要么发下一个请求（L2），不会紧跟一个 L1 小包。
///
/// 另外三个（`(−L4,−L4,−L4)` / `(−L4,−L4,−L3)` / `(L2,−L4,−L4)`）是**正常
/// HTTPS 响应分段的形态**：论文那张表是「TLS vs 非 TLS」的判别力，而本项目的
/// 参照物是「外层握手剥掉之后的正常 HTTPS 应用数据」（论文 §7.1.2：*"for TLS
/// flows, we remove packets forming the (cover) TLS handshakes prior to feature
/// extraction"*，FPR 就是在这批流量上量的）。一个 4 KB 以上的 HTTPS 响应必然
/// 产生连续的满 MSS 下行分段与一个收尾的残段，硬压掉它们等于让下行**永远
/// 没有满 MSS 分段**——那比原来的问题更反常。因此这里只对可避免的两个断言，
/// 另外三个由 `paper_segmentation_grams_only_come_from_real_response_bursts`
/// 记录它们只在真实响应分段处出现。
const AVOIDABLE_HANDSHAKE_GRAMS: [(i32, i32, i32); 2] = [(2, -4, 1), (-4, 1, -1)];

/// 场景里的源站延迟：SYNACK 之后到响应体之间的等待。
///
/// 真实部署里这一段至少是「DNS + 到源站的 TCP 握手 + 源站的处理时间」，本地
/// 环回上的零延迟只在源站与代理同机时才出现。取 15ms 是保守值（同城 CDN 量级）。
///
/// 为什么这个参数会影响 3-gram：服务端的开场 flight 只有 121/139 字节
/// （`−L1`），但源站零延迟时它会和 SYNACK、响应体的前几条记录在内核里合并成
/// **一个** ≥1211 字节的分段（`−L4`），于是「客户端首个 flight（L2）→ 合并后的
/// 下行分段（−L4）→ 客户端的 SETTINGS-ACK（L1）」正好凑成 `(L2, −L4, L1)`。
/// 实测：源站延迟 15ms 时 200 条连接 0 次命中；零延迟时 200 条连接 2 次命中
/// （均为上述结构）。完全可避免的 `(−L4, L1, −L1)` 在两种情形下都是 0 次
/// ——那一个的成因是「一问一答的小控制帧对」，已随注入 PING 的删除消失。
const ORIGIN_LATENCY_MS: u64 = 15;

fn grams(packets: &[(Dir, usize)]) -> Vec<(i32, i32, i32)> {
    let classes: Vec<i32> = packets
        .iter()
        .take(25)
        .map(|&(d, s)| l_class(d, s))
        .collect();
    classes.windows(3).map(|w| (w[0], w[1], w[2])).collect()
}

// 验收 1 + 2（核心）：一次完整的「客户端首个 flight → 服务端响应 → 客户端第二个
// flight」序列上
//   (a) 第一个 burst 必须是**上行**、< 300 字节，且各内层长度的取值区间互相
//       重叠（否则仍泄漏内层长度）、跨连接变化（否则是新常量）；
//   (b) 论文里两个「嵌套握手往返」型 3-gram 一个都不许出现。
#[tokio::test]
async fn paper_features_stay_clear_of_nested_handshake_grams() {
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;
    const ROUNDS: usize = 3;
    let scenarios = [
        Scenario { inner: 64, downstream: 4096, origin_latency_ms: ORIGIN_LATENCY_MS },
        Scenario { inner: 517, downstream: 4096, origin_latency_ms: ORIGIN_LATENCY_MS },
        Scenario { inner: 1884, downstream: 4096, origin_latency_ms: ORIGIN_LATENCY_MS },
        Scenario { inner: 20000, downstream: 4096, origin_latency_ms: ORIGIN_LATENCY_MS },
        // bulk 下行：`(−L4,−L4,−L4)` 在这里必然出现，正如真实 HTTPS 下载。
        Scenario { inner: 517, downstream: 400_000, origin_latency_ms: ORIGIN_LATENCY_MS },
    ];

    // 每个场景是一条独立连接（各自的 TcpListener + 中继任务），互不干扰，
    // 因此全部并发跑：15 次抓取的墙钟从 ~7s 压到 ~0.5s。
    let mut tasks = Vec::new();
    for _ in 0..ROUNDS {
        for scenario in scenarios {
            tasks.push(tokio::spawn(
                async move { (scenario, capture_scenario(scenario).await) },
            ));
        }
    }

    let mut bursts_by_inner: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for task in tasks {
        let (scenario, capture) = task.await.expect("capture task joins");
        {
            let (dir, first_burst) = *capture
                .bursts
                .first()
                .expect("connection must produce at least one burst");
            assert_eq!(
                dir,
                Dir::C2S,
                "外层握手后的第一个 burst 必须是上行（论文 Figure 8 量的就是它）"
            );
            assert!(
                first_burst < 300,
                "inner={} 的第一个上行 burst 为 {} 字节，必须 < 300",
                scenario.inner,
                first_burst
            );
            bursts_by_inner
                .entry(scenario.inner)
                .or_default()
                .push(first_burst);

            for gram in grams(&capture.packets) {
                assert!(
                    !AVOIDABLE_HANDSHAKE_GRAMS.contains(&gram),
                    "inner={} down={} 出现了嵌套握手 3-gram {:?}；包序列 {:?}",
                    scenario.inner,
                    scenario.downstream,
                    gram,
                    capture
                        .packets
                        .iter()
                        .take(25)
                        .map(|&(d, s)| if d == Dir::C2S { s as i64 } else { -(s as i64) })
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    // 各内层长度的取值必须落在**同一个**声明窗口里——这正是「burst 尺寸不
    // 泄漏内层长度」的充分条件，且不依赖样本量（区间两两重叠的直接检验在每种
    // 内层长度只有几个样本时会因抽样噪声误报）。窗口本身与内层长度无关这一点
    // 由 shaper 层的 `first_flight_size_distribution_is_independent_of_backlog`
    // 用 40 组样本逐个积压量断言。
    const WINDOW: std::ops::RangeInclusive<usize> = 176..=272;
    for (&inner, values) in &bursts_by_inner {
        for &v in values {
            assert!(
                WINDOW.contains(&v),
                "inner={} 的第一个上行 burst {} 越出公共窗口 {:?}",
                inner,
                v,
                WINDOW
            );
        }
    }
    let distinct: std::collections::HashSet<usize> =
        bursts_by_inner.values().flatten().copied().collect();
    assert!(
        distinct.len() > 1,
        "第一个上行 burst 必须跨连接变化，不能是常量：{:?}",
        distinct
    );
}

// C24 回归（record 级）：连接的第一条上行 TLS record 必须是一条**数据**记录，
// 不能是 41 字节的 PING。
//
// 此前为了「让出方向」而在首条数据记录之前同批注入一条 CMD_PADDING 请求
// （线速恰为 H2 PING 尺寸），于是上行记录序列恒为 `[41, N]`。真实 H2 连接在
// 握手后的第一帧是 HEADERS：PING 是 30–150s 量级的保活帧，把它放在论文
// `Wo = 25` 窗口的第 0 条记录上，等于用一个新特征换掉旧特征。
#[tokio::test]
async fn first_upstream_record_is_a_data_record_not_a_ping() {
    use kanotls_tunnel::control_size::{PING_WIRE, WINDOW_UPDATE_WIRE};
    const SETTINGS_ACK_WIRE: usize = kanotls_tunnel::control_size::SETTINGS_ACK_WIRE;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    let mut tasks = Vec::new();
    for inner in [64usize, 517, 1884, 20000] {
        tasks.push(tokio::spawn(async move {
            (
                inner,
                capture_scenario(Scenario {
                    inner,
                    downstream: 4096,
                    origin_latency_ms: ORIGIN_LATENCY_MS,
                })
                .await,
            )
        }));
    }
    let mut seen = std::collections::HashSet::new();
    for task in tasks {
        let (inner, capture) = task.await.expect("capture task joins");
        let first = *capture
            .upstream_records
            .first()
            .expect("client must have written at least one record");
        assert_ne!(first, PING_WIRE, "inner={inner} 的首条上行记录是 PING（41）");
        assert_ne!(
            first, WINDOW_UPDATE_WIRE,
            "inner={inner} 的首条上行记录是 WINDOW_UPDATE（37）"
        );
        assert_ne!(
            first, SETTINGS_ACK_WIRE,
            "inner={inner} 的首条上行记录是 SETTINGS-ACK（33）"
        );
        assert!(
            (176..=272).contains(&first),
            "inner={} 的首条上行记录 {} 不在 first-flight 数据记录窗口 [176, 272] 内",
            inner,
            first
        );
        seen.insert(first);
    }
    assert!(seen.len() > 1, "首条上行记录尺寸必须跨连接变化");
}

// 反向验收（防「过度整形」）：论文那 5 个 3-gram 里剩下的三个是**正常 HTTPS
// 响应分段**的形态，KanoTLS 必须**照样产生**它们。
//
// 一个下行永远不出现满 MSS 分段的 TLS 连接本身就是异常的：真实 nginx 把
// 4 KB 以上的响应写成一条大 record，内核按 MSS 切成 `1460, 1460, …, 残段`。
// 此前 `markov_policy` 让数据记录复用控制帧的离散池（33–54 字节），实测一条
// 4 KB 下行被切成十几条 sub-MSS 记录、下行**从不**出现满 MSS 分段——那是比
// 原问题更强的判别特征。本断言把这个方向也钉住。
#[tokio::test]
async fn bulk_downstream_still_produces_full_mss_runs_like_real_https() {
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;
    let capture = capture_scenario(Scenario { inner: 517, downstream: 400_000, origin_latency_ms: ORIGIN_LATENCY_MS }).await;
    let grams = grams(&capture.packets);
    let segmented = *PAPER_TOP_GRAMS
        .iter()
        .find(|(g, _, _)| *g == (-4, -4, -4))
        .map(|(g, _, _)| g)
        .expect("table contains the segmented-response gram");
    assert!(
        grams.contains(&segmented),
        "bulk 下行必须像真实 HTTPS 一样产生连续满 MSS 分段；实测 3-gram {:?}",
        grams
    );
    // 同时那两个「嵌套握手往返」型 3-gram 仍不许出现。
    for gram in &grams {
        assert!(
            !AVOIDABLE_HANDSHAKE_GRAMS.contains(gram),
            "bulk 场景出现了嵌套握手 3-gram {:?}",
            gram
        );
    }
}

// 裸客户端 + 真实服务端 Session：用于观察服务端主动发出的记录。
async fn raw_client_with_server_session() -> (Arc<Session>, TcpStream, kanotls_tunnel::NoiseTransport) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener binds");
    let addr = listener.local_addr().expect("listener has address");
    let client_task = tokio::spawn(async move {
        TcpStream::connect(addr)
            .await
            .expect("client connects to listener")
    });
    let (server_tcp, _) = listener.accept().await.expect("listener accepts client");
    let client_tcp = client_task.await.expect("client connect task completes");
    let (client_noise, server_noise) = build_transport_pair();
    let server = Arc::new(Session::new(
        SnowyStream::new(server_tcp, server_noise),
        test_session_config(false),
        None,
    ));
    let read_loop = server.clone();
    tokio::spawn(async move {
        let _ = read_loop.run_read_loop().await;
    });
    (server, client_tcp, client_noise)
}

// C24 回归（缺口 1 + 遗留 1）：服务端收到客户端 CMD_SETTINGS 后必须立刻发出
// nginx/h2o 那条开场 flight —— `SETTINGS → WINDOW_UPDATE → SETTINGS-ACK`，
// 尺寸恰为 `control_size::h2_opening_size(S2C, 0..3)`，且顺序固定、不含 PING
// 尺寸。这把 `h2_opening_size` 从一张尺寸表变成了真正的发送时序：
//   * 服务端一侧此前根本不发这条 flight（它只在有 SYNACK/padding 要发时说话）；
//   * 客户端一侧的 `h2_opening_size(C2S, 0) = SETTINGS-ACK` 此前永远被跳过。
// 它同时是客户端首个 flight 之后那次**方向改变**的来源（取代注入的 PING），
// 且不经 DNS/connect，一个 RTT 内必到。
#[tokio::test]
async fn server_emits_the_nginx_h2_opening_flight_on_client_settings() {
    use kanotls_tunnel::control_size::{h2_opening_size, PING_WIRE};
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    let expected: Vec<usize> = (0..)
        .map_while(|i| h2_opening_size(FlowDirection::S2C, i))
        .collect();
    assert_eq!(expected.len(), 3, "S2C 开场序列必须是 3 条");
    // 三条记录一次 flush ⇒ 线上是**一个**分段，因此总长必须装进一个 MSS。
    assert!(
        expected.iter().sum::<usize>() < 1460,
        "开场 flight 总长 {} 超过一个 MSS，无法像 nginx 那样一次写出",
        expected.iter().sum::<usize>()
    );

    let (server, mut raw_client, mut client_noise) = raw_client_with_server_session().await;

    let settings = crate::frame::Frame::cmd_settings()
        .encode()
        .expect("settings encodes");
    let record = seal_control_record(&mut client_noise, &settings, 47);
    raw_client
        .write_all(&record)
        .await
        .expect("raw client sends settings");

    let mut wire = Vec::new();
    let mut buf = vec![0u8; 16384];
    let mut sizes = Vec::new();
    let collect = async {
        while sizes.len() < expected.len() {
            let n = raw_client.read(&mut buf).await.expect("raw client reads");
            assert!(n > 0, "tunnel closed before the opening flight arrived");
            wire.extend_from_slice(&buf[..n]);
            sizes.clear();
            let mut off = 0usize;
            while off + 5 <= wire.len() {
                let len = u16::from_be_bytes([wire[off + 3], wire[off + 4]]) as usize;
                if off + 5 + len > wire.len() {
                    break;
                }
                sizes.push(5 + len);
                off += 5 + len;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(3), collect)
        .await
        .expect("opening flight arrives before timeout");

    assert_eq!(
        &sizes[..expected.len()],
        &expected[..],
        "服务端开场 flight 的尺寸/顺序必须等于 h2_opening_size(S2C, ·)"
    );
    for size in &sizes[..expected.len()] {
        assert_ne!(*size, PING_WIRE, "开场 flight 不得出现 PING 尺寸");
    }
    server.force_close();
}

// C24 回归：SETTINGS 尺寸的 CMD_PADDING 请求必须换来恰好一条 33 字节的
// SETTINGS-ACK —— 这就是 `h2_opening_size(C2S, 0)`，客户端一侧开场序列的
// 全部内容。角色表见 `padding_reply_wire_len`。
#[tokio::test]
async fn client_answers_a_settings_sized_request_with_a_settings_ack() {
    use kanotls_tunnel::control_size::{h2_opening_size, SETTINGS_ACK_WIRE};
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    assert_eq!(
        h2_opening_size(FlowDirection::C2S, 0),
        Some(SETTINGS_ACK_WIRE)
    );
    let settings_wire = h2_opening_size(FlowDirection::S2C, 0).expect("server settings size");

    let (client_tunnel, mut raw_server, mut server_noise) = client_stream_with_raw_server().await;
    let mut config = test_session_config(true);
    // 关掉 H2 骨架与合成交换：本测试只观察 SETTINGS/SETTINGS-ACK 这一对。
    config.post_script_off = true;
    let client = Arc::new(Session::new(client_tunnel, config, None));
    let read_loop = client.clone();
    tokio::spawn(async move {
        let _ = read_loop.run_read_loop().await;
    });

    let request = crate::frame::encode_padding_request_sized(1, settings_wire);
    let record = seal_control_record(&mut server_noise, &request, settings_wire);
    assert_eq!(record.len(), settings_wire);
    raw_server
        .write_all(&record)
        .await
        .expect("raw server sends its SETTINGS");

    let mut wire = Vec::new();
    let mut buf = vec![0u8; 16384];
    let mut ack = None;
    let collect = async {
        while ack.is_none() {
            let n = raw_server.read(&mut buf).await.expect("raw server reads");
            assert!(n > 0, "tunnel closed before the settings ack arrived");
            wire.extend_from_slice(&buf[..n]);
            for (size, payload) in drain_wire_records(&mut wire, &mut server_noise) {
                let mut cursor = bytes::BytesMut::from(payload.as_slice());
                while let Some(frame) = crate::frame::Frame::decode(&mut cursor) {
                    if frame.cmd == crate::frame::CMD_PADDING
                        && frame.payload.first() == Some(&1)
                    {
                        ack = Some(size);
                    }
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(3), collect)
        .await
        .expect("settings ack arrives before timeout");
    assert_eq!(
        ack,
        Some(SETTINGS_ACK_WIRE),
        "SETTINGS 尺寸的请求必须换来一条 SETTINGS-ACK（33），不是 PING-ACK（41）"
    );
    client.force_close();
}

// 验收 4：合成共存流必须**贯穿连接生命周期**——一段完全没有真实数据的时间里
// 仍要有符合 H2 成因的记录发出。
//
// 成因是「浏览器在同一条 H2 连接上继续发请求」：上行一条 HEADERS 尺寸的记录，
// 下行换来一条响应尺寸的记录。断言同时钉住尺寸角色：请求必须**越过论文的
// `L1` 上界**（不是 PING 尺寸），否则「小的本端包 → 小的对端包」紧跟在下行
// burst 之后就等于 `(−L4, L1, −L1)`（Distinc 2.879）。
#[tokio::test]
async fn synthetic_h2_exchange_persists_without_real_application_data() {
    use super::H2_EXCHANGE_INTERVAL_OVERRIDE_MS;
    use kanotls_tunnel::control_size::L1_MAX_WIRE_LEN;
    use std::sync::atomic::Ordering;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    H2_EXCHANGE_INTERVAL_OVERRIDE_MS.store(20, Ordering::Relaxed);

    let (client_tunnel, server_tunnel, tap) = tapped_tunnel_pair().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let server = ServerSessionHandler::new(server_tunnel, test_session_config(false));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let server_read_loop = server.session.clone();
    tokio::spawn(async move {
        let _ = server_read_loop.run_read_loop().await;
    });

    // 开一条流并让它保持打开，之后**不再写任何真实数据**。
    let acceptor = tokio::spawn(async move {
        let (_sid, st) = server.accept_stream().await.expect("server accepts");
        st.send_synack().await.expect("server sends synack");
        st
    });
    let mut stream = client.open_stream().await.expect("stream opens");
    stream.defer_target(b"idlestream.example:443");
    stream.write(b"hello").await.expect("client writes target");
    let server_stream = tokio::time::timeout(Duration::from_secs(3), acceptor)
        .await
        .expect("server accepts before timeout")
        .expect("acceptor joins");
    stream.wait_open().await.expect("stream opens after synack");

    let quiet_start = tap.lock().expect("tap lock").len();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let events = tap.lock().expect("tap lock")[quiet_start..].to_vec();

    let up = record_sizes(&events, Dir::C2S);
    let down = record_sizes(&events, Dir::S2C);
    // 静默期内允许出现真实 H2 控制帧尺寸（SETTINGS-ACK / WINDOW_UPDATE /
    // PING）——它们是既有骨架的成因；除此之外的记录必须全部是合成交换的
    // 请求/应答，且必须**越过 L1 上界**。
    const H2_CONTROL_WIRE: [usize; 3] = [
        kanotls_tunnel::control_size::SETTINGS_ACK_WIRE,
        kanotls_tunnel::control_size::WINDOW_UPDATE_WIRE,
        kanotls_tunnel::control_size::PING_WIRE,
    ];
    let classify = |sizes: &[usize], label: &str| -> Vec<usize> {
        let mut exchange = Vec::new();
        for &size in sizes {
            if size > L1_MAX_WIRE_LEN {
                exchange.push(size);
            } else {
                assert!(
                    H2_CONTROL_WIRE.contains(&size),
                    "{}方向的 {} 字节记录既不是合成交换也不是真实 H2 控制帧尺寸",
                    label,
                    size
                );
            }
        }
        exchange
    };
    let up_exchange = classify(&up, "上行");
    let down_exchange = classify(&down, "下行");
    assert!(
        up_exchange.len() >= 3 && down_exchange.len() >= 3,
        "静默期内合成交换必须持续发出记录：上行 {:?} 下行 {:?}",
        up,
        down
    );
    assert!(
        up_exchange
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 1,
        "合成请求尺寸必须变化，不能是常量：{:?}",
        up_exchange
    );

    H2_EXCHANGE_INTERVAL_OVERRIDE_MS.store(0, Ordering::Relaxed);
    drop(server_stream);
    drop(stream);
    client.force_close();
}

// C24 回归（角色表）：`padding_reply_wire_len` 的三档角色必须精确对应真实 H2。
// SETTINGS / PING 两档是**确定值**（真实 H2 里 SETTINGS-ACK 恒 9 字节帧、
// PING-ACK 恒回显 8 字节载荷，逐连接抖动本身就是判别特征）；HEADERS 量级的
// 请求换来的是响应体，尺寸必须**变化**。
#[test]
fn padding_reply_roles_match_real_h2_frame_semantics() {
    use kanotls_tunnel::control_size::{h2_opening_size, SETTINGS_ACK_WIRE, WINDOW_UPDATE_WIRE};
    use kanotls_tunnel::FlowDirection;

    let settings_wire = h2_opening_size(FlowDirection::S2C, 0).expect("server settings size");
    for direction in [FlowDirection::C2S, FlowDirection::S2C] {
        // SETTINGS → 恰好一条 SETTINGS-ACK，跨调用恒定。
        for _ in 0..64 {
            assert_eq!(
                super::padding_reply_wire_len(settings_wire, 0, direction),
                SETTINGS_ACK_WIRE
            );
        }
        // PING → PING-ACK，跨调用恒定。
        for _ in 0..64 {
            assert_eq!(
                super::padding_reply_wire_len(super::PADDING_REQUEST_WIRE, 0, direction),
                super::PADDING_ACK_WIRE
            );
        }
        // 第二条应答一律是接收方本来就要发的 WINDOW_UPDATE。
        for request in [settings_wire, super::PADDING_REQUEST_WIRE, 600] {
            assert_eq!(
                super::padding_reply_wire_len(request, 1, direction),
                WINDOW_UPDATE_WIRE
            );
        }
        // HEADERS 量级的请求（合成交换）→ 响应量级、且尺寸必须变化。
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let size = super::padding_reply_wire_len(600, 0, direction);
            assert!(size > kanotls_tunnel::control_size::L1_MAX_WIRE_LEN);
            seen.insert(size);
        }
        assert!(seen.len() > 20, "合成交换的应答尺寸必须是分布而不是常量");
    }
}

// C24：源站零延迟（源站与代理同机）这一极端情形下的下限保证。
//
// 这时服务端的开场 flight 会与 SYNACK、响应体合并成一个大分段，`(L2, −L4, L1)`
// 有约 1% 的连接会出现一次（成因见 `ORIGIN_LATENCY_MS`）；但**纯控制帧一问一答**
// 型的 `(−L4, L1, −L1)`（Distinc 2.879）必须始终为 0——它的唯一成因是「小的本端
// 控制帧换来小的对端控制帧」，而连接开场处那对注入的 PING/PING-ACK 已被删除，
// 剩下的 WINDOW_UPDATE 是 flag=1（不换应答），合成交换是 HEADERS/响应量级。
// 同时首个上行 burst 的 < 300 保证与源站延迟无关。
#[tokio::test]
async fn zero_latency_origin_still_avoids_the_control_pair_gram() {
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;
    let mut tasks = Vec::new();
    for inner in [64usize, 517, 1884, 20000] {
        tasks.push(tokio::spawn(async move {
            capture_scenario(Scenario {
                inner,
                downstream: 4096,
                origin_latency_ms: 0,
            })
            .await
        }));
    }
    for task in tasks {
        let capture = task.await.expect("capture task joins");
        let (dir, first_burst) = *capture.bursts.first().expect("at least one burst");
        assert_eq!(dir, Dir::C2S);
        assert!(first_burst < 300, "第一个上行 burst {} 必须 < 300", first_burst);
        for gram in grams(&capture.packets) {
            assert_ne!(
                gram,
                (-4, 1, -1),
                "出现了纯控制帧一问一答的 3-gram (−L4, L1, −L1)；包序列 {:?}",
                capture
                    .packets
                    .iter()
                    .take(25)
                    .map(|&(d, s)| if d == Dir::C2S { s as i64 } else { -(s as i64) })
                    .collect::<Vec<_>>()
            );
        }
    }
}

// ============ 合并 flush 边界（任务 1）============
//
// socket 开了 TCP_NODELAY ⇒ 一次 `write()` 内的字节尽量落进同一个 TCP 段，
// **flush 边界就是分段边界，就是分类器观测的单位**。此前每条小控制记录各自
// flush 一次，于是一条 33 字节的 SETTINGS-ACK 独占一个 33 字节的段，哪怕同
// 一时刻队列里还压着后续内容；真实 NSS/BoringSSL 把 nghttp2 已排队的全部
// 内容一次写出。论文只在连接的前 `Wo = 25` 个承载数据的包上采样一次，包数
// 正是那个窗口能覆盖多少内容的分母，因此这条改动直接作用在唯一被采样的窗口上。
//
// 下面两个测试都依赖 `#[tokio::test]` 的**当前线程**运行时：写循环任务只有在
// 测试任务让出时才被调度，而 `submit_write_packets` 在通道有余量时不产生真正
// 的挂起点，因此连续两次提交确实是「同一时刻排队」。

// 按明文 TLS record 头把一段线上字节切成 (尺寸) 序列，不解密。
fn split_record_sizes(wire: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut off = 0usize;
    while off + 5 <= wire.len() {
        assert_eq!(wire[off], 0x17, "record type must be application data");
        let len = u16::from_be_bytes([wire[off + 3], wire[off + 4]]) as usize;
        if off + 5 + len > wire.len() {
            break;
        }
        sizes.push(5 + len);
        off += 5 + len;
    }
    assert_eq!(off, wire.len(), "flush 组必须由完整 record 构成");
    sizes
}

// 任务 1 验收：同一时刻排队的「控制记录 + 数据记录」必须进入**同一次
// flush**，即对端的同一个 `read()` 组（= 同一个 TCP 段）。
//
// 用服务端方向：客户端首个 control 写会前置 `CMD_SETTINGS`，那会多出一条
// 记录，掩盖「记录条数不变」这一半的断言；服务端没有该前置，期望的记录序列
// 因此是精确的两条。
#[tokio::test]
async fn queued_control_and_data_share_one_flush() {
    use super::{FlushBehavior, TrafficClass};
    use kanotls_tunnel::control_size::SETTINGS_ACK_WIRE;
    use tokio::io::AsyncReadExt;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    let (server_tunnel, mut raw_peer, mut peer_noise) = client_stream_with_raw_server().await;
    // post_script_off 关掉 H2 骨架；单规则零延迟脚本让数据记录的条数与
    // 「本条之后不施加间隔」两点都确定——`D:` 非零的规则本来就要求那条记录
    // 独占一次 flush（间隔必须真的作用到线上），那是另一条语义，不在此断言。
    let mut config = test_session_config(false);
    config.post_script_off = true;
    config.traffic_script = Some(vec!["stop=64".to_string(), "0=L:200,D:0,F:0".to_string()]);
    let session = Arc::new(Session::new(server_tunnel, config, None));

    let reply = crate::frame::encode_padding_reply_sized(SETTINGS_ACK_WIRE);
    let psh = crate::frame::Frame::psh(9, vec![0xD1u8; 60])
        .encode()
        .expect("psh encodes");

    // 两条请求在同一时刻入队：中间没有任何真正的挂起点，写循环还没被调度。
    let mut control_write = session
        .writer
        .submit_write_packets(vec![reply.clone()], FlushBehavior::Auto, TrafficClass::Control)
        .await
        .expect("control queued");
    let mut bulk_write = session
        .writer
        .submit_write_packets(
            vec![psh.clone()],
            FlushBehavior::Immediate,
            TrafficClass::Bulk,
        )
        .await
        .expect("bulk queued");

    let mut read_buf = vec![0u8; 32768];
    let n = tokio::time::timeout(Duration::from_secs(3), raw_peer.read(&mut read_buf))
        .await
        .expect("first flush group arrives before timeout")
        .expect("peer reads");
    let group = &read_buf[..n];

    let sizes = split_record_sizes(group);
    assert_eq!(
        sizes.len(),
        2,
        "控制记录与数据记录必须在同一个 flush 组里；实测尺寸序列 {:?}",
        sizes
    );
    // 顺序：写循环先排空 bulk 积压（数据记录），再写 control 记录——与
    // 合并前完全一致，只是不再各自占一个分段。
    assert_eq!(
        sizes[1], SETTINGS_ACK_WIRE,
        "控制记录必须原样是 SETTINGS-ACK 尺寸（33），尺寸不因合并而改变"
    );
    assert!(
        sizes[0] > kanotls_tunnel::control_size::L1_MAX_WIRE_LEN,
        "数据记录尺寸不变（仍由 shaper 决定，越过 L1 上界）：{}",
        sizes[0]
    );

    // 载荷/顺序也必须原样：解密后是 [PSH 帧][CMD_PADDING flag=1 帧]。
    let (decrypted_sizes, plaintext) = decrypt_wire_records(group, &mut peer_noise);
    assert_eq!(decrypted_sizes, sizes);
    let mut expected = psh.clone();
    expected.extend_from_slice(&reply);
    assert_eq!(plaintext, expected, "合并只改分段边界，字节序不变");

    // responder 语义不变：字节真正 flush 之后才应答 Ok。
    tokio::time::timeout(Duration::from_secs(3), bulk_write.wait())
        .await
        .expect("bulk responder answers")
        .expect("bulk write ok");
    tokio::time::timeout(Duration::from_secs(3), control_write.wait())
        .await
        .expect("control responder answers")
        .expect("control write ok");

    session.force_close();
}

// 任务 1 验收：同一时刻排队的多条 control 写合并进**同一次 flush**，且记录的
// 尺寸、条数、顺序（FIFO）完全不变——只有分段边界变了。
//
// 第二段同时钉住「合并不引入延迟」：单独一条 control 写在通道空时立即冲刷。
#[tokio::test]
async fn queued_control_writes_share_one_flush_without_changing_records() {
    use super::{FlushBehavior, TrafficClass};
    use tokio::io::AsyncReadExt;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    // 自定尺寸的 CMD_PADDING：线速尺寸完全确定，期望序列可解析地写死。
    const TARGETS: [usize; 5] = [33, 37, 41, 46, 54];

    let (server_tunnel, mut raw_peer, mut peer_noise) = client_stream_with_raw_server().await;
    let mut config = test_session_config(false);
    config.post_script_off = true;
    let session = Arc::new(Session::new(server_tunnel, config, None));

    let packets: Vec<Vec<u8>> = TARGETS
        .iter()
        .map(|&t| crate::frame::encode_padding_reply_sized(t))
        .collect();
    let mut writes = Vec::new();
    for packet in &packets {
        writes.push(
            session
                .writer
                .submit_write_packets(
                    vec![packet.clone()],
                    FlushBehavior::Immediate,
                    TrafficClass::Control,
                )
                .await
                .expect("control queued"),
        );
    }

    let mut read_buf = vec![0u8; 32768];
    let n = tokio::time::timeout(Duration::from_secs(3), raw_peer.read(&mut read_buf))
        .await
        .expect("first flush group arrives before timeout")
        .expect("peer reads");
    let group = &read_buf[..n];

    let (sizes, plaintext) = decrypt_wire_records(group, &mut peer_noise);
    assert_eq!(
        sizes,
        TARGETS.to_vec(),
        "5 条同刻排队的 control 写必须在同一个 flush 组内，且尺寸/条数/顺序不变"
    );
    let expected: Vec<u8> = packets.iter().flatten().copied().collect();
    assert_eq!(plaintext, expected, "FIFO 字节序不变");

    for mut write in writes {
        tokio::time::timeout(Duration::from_secs(3), write.wait())
            .await
            .expect("responder answers after the merged flush")
            .expect("control write ok");
    }

    // 通道空时单独一条 control 写立即冲刷：合并不得给孤立写请求加延迟。
    let lone = crate::frame::encode_padding_reply_sized(64);
    let mut lone_write = session
        .writer
        .submit_write_packets(
            vec![lone.clone()],
            FlushBehavior::Immediate,
            TrafficClass::Control,
        )
        .await
        .expect("lone control queued");
    let n = tokio::time::timeout(Duration::from_millis(500), raw_peer.read(&mut read_buf))
        .await
        .expect("lone control write is flushed immediately")
        .expect("peer reads");
    let (sizes, _) = decrypt_wire_records(&read_buf[..n], &mut peer_noise);
    assert_eq!(sizes, vec![64]);
    tokio::time::timeout(Duration::from_millis(500), lone_write.wait())
        .await
        .expect("lone responder answers")
        .expect("lone write ok");

    session.force_close();
}

// 任务 1：合并有**确定性**上界（不加抖动），沿用 sticky bulk 的双阈值——
// 它保证合并不会无界攒字节，也不会让 responder 无界等待。
#[test]
fn flush_batch_merge_bound_is_deterministic() {
    let mut by_records = super::FlushBatch::default();
    assert!(!by_records.is_full(0));
    by_records.note_records(super::STICKY_BULK_FLUSH_MAX_RECORDS - 1);
    assert!(!by_records.is_full(0));
    by_records.note_records(1);
    assert!(by_records.is_full(0), "记录条数达上限即必须冲刷");

    let by_bytes = super::FlushBatch::default();
    assert!(!by_bytes.is_full(super::STICKY_BULK_FLUSH_MAX_BYTES - 1));
    assert!(
        by_bytes.is_full(super::STICKY_BULK_FLUSH_MAX_BYTES),
        "缓冲字节达上限即必须冲刷"
    );
}

// ============ 优雅拆除前的 H2 GOAWAY（任务 2c）============

// 收集连接上的全部线上字节直到 EOF。
async fn read_to_eof(peer: &mut TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut wire = Vec::new();
    let mut buf = vec![0u8; 32768];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return wire,
            Ok(Ok(n)) => wire.extend_from_slice(&buf[..n]),
        }
    }
}

// 任务 2c 验收：优雅拆除时线上必须先出现一条 GOAWAY 尺寸的记录，然后才是
// close_notify。此前只有一条 24 字节的 close_notify，前面没有任何控制尺寸的
// 记录——真实 nginx/Firefox 关闭 H2 连接必发 GOAWAY，缺了它本身就是特征。
#[tokio::test]
async fn graceful_teardown_emits_an_h2_goaway_before_close_notify() {
    use kanotls_tunnel::control_size::PING_WIRE;
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    // close_notify 记录：3 字节 alert 明文 + 16 字节 tag + 5 字节 TLS 头。
    const CLOSE_NOTIFY_WIRE: usize = 5 + 3 + 16;

    let (client_tunnel, mut raw_peer, mut peer_noise) = client_stream_with_raw_server().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    // 不开读循环、不开流 ⇒ 拆除前线上一个字节都没有，序列可精确断言。
    client.force_close();

    let wire = read_to_eof(&mut raw_peer).await;
    let sizes = split_record_sizes(&wire);
    assert_eq!(
        sizes,
        vec![PING_WIRE, CLOSE_NOTIFY_WIRE],
        "拆除序列必须是 [GOAWAY(41)][close_notify(24)]"
    );

    // GOAWAY 用「不换应答」的 flag=2 形式：对端静默丢弃（`handle_frame` 只对
    // flag=0 作答），不会换来一条 ACK。
    let (_, plaintext) = decrypt_wire_records(&wire[..PING_WIRE], &mut peer_noise);
    let mut cursor = bytes::BytesMut::from(plaintext.as_slice());
    let frame = crate::frame::Frame::decode(&mut cursor).expect("goaway record carries a frame");
    assert!(cursor.is_empty(), "GOAWAY 独占一条记录");
    assert_eq!(frame.cmd, crate::frame::CMD_PADDING);
    assert_eq!(
        frame.payload.first(),
        Some(&crate::frame::PADDING_FLAG_GOAWAY),
        "flag=2 ⇒ GOAWAY，不换应答"
    );
    // 客户端从不接受入站流（流只由客户端发起），故 last_stream_id 恒为 0——
    // 与真实 H2 客户端在没有服务端推送时发出的 GOAWAY 一致。
    assert_eq!(
        crate::frame::decode_padding_goaway(&frame.payload),
        Some(0),
        "GOAWAY 必须携带 last_stream_id"
    );
}

// 任务 2 的硬性不变量：GOAWAY 载荷里多出的 4 字节 last_stream_id **不得**改变
// 线速尺寸。它写在原本的零 junk 区内，所以 41 字节（= PING_WIRE，H2 GOAWAY 与
// PING 的最小帧载荷都是 17 字节）原样成立；任何让它溢出到下一档的改动都会在
// 这里变红，而线速尺寸的变化才是唯一线上可见的东西。
#[test]
fn goaway_last_stream_id_does_not_change_the_wire_size() {
    use crate::frame::{
        decode_padding_goaway, encode_padding_goaway_sized, encode_padding_reply_sized,
        CONTROL_RECORD_MIN_OVERHEAD,
    };
    use kanotls_tunnel::control_size::PING_WIRE;

    let plain = encode_padding_reply_sized(PING_WIRE);
    for last in [0u32, 1, 255, 256, 65535, 12_345_678, u32::MAX] {
        let goaway = encode_padding_goaway_sized(last, PING_WIRE);
        assert_eq!(
            goaway.len(),
            plain.len(),
            "GOAWAY 的明文帧长必须与同尺寸的纯填充帧一致"
        );
        // prepare_control_record 精确命中目标的充要条件（见 frame.rs 的
        // sized_padding_junk_derivation_hits_target_wire_len_exactly）。
        assert_eq!(goaway.len() + CONTROL_RECORD_MIN_OVERHEAD, PING_WIRE);
        assert_eq!(decode_padding_goaway(&goaway.as_slice()[7..]), Some(last));
    }
}

// 任务 2 的向后兼容性验收（**这是引入新 flag 值的全部前提**）：`handle_frame`
// 的 CMD_PADDING 分支只对 flag=0 作答，其余 flag 值走完 match 臂直接 Ok(())。
//
// 注入的 flag 取一个**未分配**值（3）而不是 2——那正是未升级的旧对端收到
// flag=2 时所走的、逐字节相同的代码路径。断言两件事：
//  1. 会话不被拆除。新增一个 **CMD 操作码**会落进 `_ => bail!("unknown frame
//     cmd")`，旧对端立刻断开；新增一个 **flag 值**不会。
//  2. 线上不多出任何记录，且帧解码器仍然同步——随后注入的 flag=0 请求照常
//     换回应答即为证。
#[tokio::test]
async fn an_unassigned_padding_flag_is_ignored_without_tearing_down_the_session() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;

    let (client_tunnel, mut raw_server, mut server_noise) = client_stream_with_raw_server().await;
    // 关掉稳态 H2 骨架：本测试观察到的记录只可能来自 padding 应答路径。
    let mut config = test_session_config(true);
    config.post_script_off = true;
    let client = Arc::new(Session::new(client_tunnel, config, None));
    let read_loop = client.clone();
    tokio::spawn(async move {
        let _ = read_loop.run_read_loop().await;
    });

    const UNASSIGNED_FLAG: u8 = 3;
    let mut unknown = crate::frame::encode_padding_reply_sized(super::PADDING_REQUEST_WIRE);
    unknown[7] = UNASSIGNED_FLAG;
    raw_server
        .write_all(&seal_control_record(
            &mut server_noise,
            &unknown,
            super::PADDING_REQUEST_WIRE,
        ))
        .await
        .expect("raw server injects an unknown-flag padding frame");

    // 未知 flag 不得换回任何东西。
    let mut wire = Vec::new();
    let mut read_buf = vec![0u8; 16384];
    let silent = tokio::time::timeout(Duration::from_millis(300), async {
        let n = raw_server.read(&mut read_buf).await.expect("raw read");
        wire.extend_from_slice(&read_buf[..n]);
        n
    })
    .await;
    assert!(
        silent.is_err(),
        "未知 flag 不得产生任何线上记录，收到 {:?}",
        silent
    );
    assert!(client.is_alive(), "未知 flag 不得拆除会话");

    // 帧解码器仍与对端同步：一条正常的 flag=0 请求照常换回应答。
    let request = crate::frame::encode_padding_request_sized(1, super::PADDING_REQUEST_WIRE);
    raw_server
        .write_all(&seal_control_record(
            &mut server_noise,
            &request,
            super::PADDING_REQUEST_WIRE,
        ))
        .await
        .expect("raw server injects a normal padding request");

    let collect = async {
        loop {
            let n = raw_server.read(&mut read_buf).await.expect("raw read");
            assert!(n > 0, "tunnel closed before the reply arrived");
            wire.extend_from_slice(&read_buf[..n]);
            for (_, payload) in drain_wire_records(&mut wire, &mut server_noise) {
                let mut buf = bytes::BytesMut::from(payload.as_slice());
                let Some(frame) = crate::frame::Frame::decode(&mut buf) else {
                    continue;
                };
                if frame.cmd == crate::frame::CMD_PADDING
                    && frame.payload.first() == Some(&crate::frame::PADDING_FLAG_REPLY)
                {
                    return;
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(3), collect)
        .await
        .expect("a normal flag=0 request still gets a reply after the unknown flag");

    client.force_close();
}

// 任务 2 的方向语义：GOAWAY 的 `last_stream_id` 指的是「**接收方发起的**流」。
// 客户端发出的 GOAWAY 说的是服务端推送流（KanoTLS 没有，故恒为 0），与服务端
// accept 来的那些**客户端发起**的流毫无关系。服务端若照单全收，一条
// last_stream_id=0 的客户端 GOAWAY 会把它手上每一条流（id ≥ 1）都判成「对端
// 从未处理」——正好是最危险的误判方向。
#[tokio::test]
async fn a_client_goaway_never_marks_the_servers_own_streams_as_unprocessed() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"direction.example:443")
        .await
        .expect("client sends target");
    let (sid, server_stream) = tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
        .await
        .expect("server accepts stream")
        .expect("server accepts stream");
    server_stream.send_synack().await.expect("synack");

    // 客户端优雅拆除 ⇒ 发出 GOAWAY(last_stream_id = 0)。
    client.force_close();
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !server.session.peer_never_processed(sid),
        "服务端不得把自己 accept 来的流判成未处理"
    );
    assert!(!server.session.peer_never_processed(1));
    assert!(!server.session.peer_never_processed(u32::MAX));

    drop(server_stream);
    drop(stream);
    server.session.force_close();
}

// 任务 2(a) 端到端：服务端拆除时发出的 GOAWAY 必须携带它**实际处理过**的最大
// 流 id，客户端解析后据此把更高的流 id 判为「对端从未处理」。
#[tokio::test]
async fn server_goaway_reports_the_highest_processed_stream_id() {
    let (client, server) = session_pair().await;

    let mut stream = client.open_stream().await.expect("stream opens");
    stream
        .write_early(b"goaway.example:443")
        .await
        .expect("client sends target");
    let (sid, server_stream) = tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
        .await
        .expect("server accepts stream")
        .expect("server accepts stream");
    server_stream.send_synack().await.expect("synack");
    drop(server_stream);

    // 服务端优雅拆除 ⇒ 写循环退出路径发 GOAWAY(last_stream_id = sid)。
    server.session.force_close();

    tokio::time::timeout(Duration::from_secs(3), async {
        while !client.peer_never_processed(sid + 1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client parses the server GOAWAY");

    // 已被处理过的流（含 sid 自身）绝不能落进「可安全重试」集合——把一条其实
    // 已经转发给源站的请求判成可重放，比漏判严重得多。
    assert!(!client.peer_never_processed(sid));
    assert!(client.peer_never_processed(sid + 5));

    drop(stream);
    client.force_close();
}

// 任务 2(b)：被 GOAWAY 判定为未处理的流，必须以一个**可区分**的错误结束，而不是
// 与普通连接断开（`session writer closed` / EOF）混在一起。
#[tokio::test]
async fn unprocessed_streams_fail_with_a_distinguishable_retryable_error() {
    let (client, server) = session_pair().await;

    // 先开一条流并让服务端处理，把水位抬到 sid1。
    let mut opened = client.open_stream().await.expect("stream opens");
    opened
        .write_early(b"first.example:443")
        .await
        .expect("client sends target");
    let (sid1, server_stream) = tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
        .await
        .expect("server accepts stream")
        .expect("server accepts stream");
    server_stream.send_synack().await.expect("synack");
    drop(server_stream);

    // 第二条流：只在本端分配 id，SYN 还压在 DeferredUnsent 里没出网 ⇒ 服务端
    // 从来没见过它。
    let mut unsent = client.open_stream().await.expect("second stream opens");
    assert!(unsent.stream_id > sid1);

    server.session.force_close();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !unsent.peer_never_processed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client parses the server GOAWAY");

    let err = unsent
        .write(b"never reached the peer")
        .await
        .expect_err("an unprocessed stream must fail")
        .to_string();
    assert!(
        err.contains(crate::stream::PEER_NEVER_PROCESSED_ERROR),
        "错误必须可区分于泛型断开，实际: {}",
        err
    );

    // 已处理过的流不受影响：它拿到的仍是原来的泛型断开错误。
    assert!(!opened.peer_never_processed());

    drop(unsent);
    drop(opened);
    client.force_close();
}

// 任务 2c：`post_script_off`（关闭整形/骨架）时不得注入 GOAWAY——与
// `post_script_off_disables_h2_skeleton_injection` 的口径一致。
#[tokio::test]
async fn post_script_off_teardown_has_no_goaway() {
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;
    const CLOSE_NOTIFY_WIRE: usize = 5 + 3 + 16;

    let (client_tunnel, mut raw_peer, _peer_noise) = client_stream_with_raw_server().await;
    let mut config = test_session_config(true);
    config.post_script_off = true;
    let client = Arc::new(Session::new(client_tunnel, config, None));
    client.force_close();

    let wire = read_to_eof(&mut raw_peer).await;
    assert_eq!(split_record_sizes(&wire), vec![CLOSE_NOTIFY_WIRE]);
}






// 观测口径扩展：**整条连接的一生**，而不只是出生时的前 25 个包。
//
// 论文的检测器只在连接出生时判一次，但一条最多承载 256 条流的隧道，其
// 「开流 / 关流」是散布在连接一生中的重复事件；把观测窗口挪到流中段对审查者
// 只多出「按流保留有界状态」这一项成本。因此本台不设锚点，直接在全量包序列
// 上扫两个零容忍 3-gram。
//
// 场景取最常见、也是此前唯一漏检的那一种：**请求发完就等响应，收完即关**
// （HTTP GET）。`capture_scenario` 在关流前总会再写一个 80 字节的上行 flight，
// 那条 `L2` 数据记录恰好把响应末段的 `−L4` 与关流的 `L1` 隔开，于是
// `(−L4, L1, −L1)` 一直没被看见。
async fn scan_stream_lifecycles(inner: usize, downstream: usize, streams: usize) -> Vec<Vec<i64>> {
    let (client_tunnel, server_tunnel, tap) = tapped_tunnel_pair().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let server = ServerSessionHandler::new(server_tunnel, test_session_config(false));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let server_read_loop = server.session.clone();
    tokio::spawn(async move {
        let _ = server_read_loop.run_read_loop().await;
    });

    let acceptor = tokio::spawn(async move {
        loop {
            let Ok((_sid, mut st)) = server.accept_stream().await else {
                break;
            };
            tokio::spawn(async move {
                let _target = st.read().await;
                // 源站延迟：真实部署里 SYNACK 与响应体之间至少隔一个源站 RTT。
                tokio::time::sleep(Duration::from_millis(ORIGIN_LATENCY_MS)).await;
                let _ = st.send_synack().await;
                let _ = st.write(&vec![0x17u8; downstream]).await;
                // 源站关闭 ⇒ 服务端也关流（HTTP 响应完毕后的 FIN）。
                while st.read().await.is_some() {}
                let _ = st.close().await;
            });
        }
    });

    for _ in 0..streams {
        let mut stream = client.open_stream().await.expect("stream opens");
        stream.defer_target(b"paper.example:443");
        stream
            .write(&vec![0x16u8; inner])
            .await
            .expect("client writes inner client hello");
        let mut got = 0usize;
        while got < downstream {
            match stream.read().await {
                Some(d) => got += d.len(),
                None => break,
            }
        }
        let _ = stream.close().await;
        drop(stream);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    let events = tap.lock().expect("tap lock").clone();
    let packets = to_packets(&events);
    let classes: Vec<i32> = packets.iter().map(|&(d, s)| l_class(d, s)).collect();
    let mut hits = Vec::new();
    for (i, window) in classes.windows(3).enumerate() {
        let gram = (window[0], window[1], window[2]);
        if AVOIDABLE_HANDSHAKE_GRAMS.contains(&gram) {
            let lo = i.saturating_sub(2);
            let hi = (i + 5).min(packets.len());
            hits.push(
                packets[lo..hi]
                    .iter()
                    .map(|&(d, s)| if d == Dir::C2S { s as i64 } else { -(s as i64) })
                    .collect(),
            );
        }
    }
    client.force_close();
    acceptor.abort();
    hits
}

/// 关流不得复现 `(−L4, L1, −L1)`（论文 Table 2 判别力第 3，Distinc 2.879）。
///
/// 此前 SYN / FIN 的记录尺寸取自控制帧离散池 `{33, 37, 41, 46, 54}`
/// ——全部落在 `L1`。于是每次关流都在响应体末段之后放出一对
/// 「本端 L1 → 对端 L1」：实测一条连接跑 24 次流生命周期，`(−L4, L1, −L1)`
/// 出现 5–6 次，命中与否只取决于响应末段是否 ≥1211 字节。
///
/// 现在这三种帧按数据记录分布定尺寸（论证见
/// `packet_carries_stream_lifecycle_frame`），实测同口径 0 次。
#[tokio::test]
async fn stream_lifecycles_never_reproduce_the_control_pair_gram() {
    let _wire_lock = WIRE_OBSERVATION_LOCK.lock().await;
    // downstream 取 4096：响应末段落在 `L4` 的概率最高，也正是此前必中的档。
    // 两条连接并发跑，覆盖 Chrome / 带 ML-KEM 的 Firefox 两种内层首包尺寸。
    let tasks: Vec<_> = [517usize, 1884]
        .into_iter()
        .map(|inner| tokio::spawn(async move { (inner, scan_stream_lifecycles(inner, 4096, 8).await) }))
        .collect();
    for task in tasks {
        let (inner, hits) = task.await.expect("scan joins");
        assert!(
            hits.is_empty(),
            "inner={} 的流生命周期复现了嵌套握手 3-gram；命中处上下文 {:?}",
            inner,
            hits
        );
    }
}

/// 结构性不变量（记录级，与上面的端到端台互补）：承载 SYN / FIN 的控制
/// 记录，线速尺寸恒 > `L1_MAX_WIRE_LEN`，且分布与常规数据记录**同一个**
/// 采样器——不给它们专属窄窗口。
///
/// 一条连接最多承载 256 条流，开/关各一次即 512 次重复事件；任何专属于流
/// 生命周期的窄尺寸窗口都可以跨流聚合出来，而可聚合的弱特征等于强特征。
#[tokio::test]
async fn stream_lifecycle_control_records_never_land_in_the_l1_class() {
    use super::{FlushBehavior, WriteRequest};
    use kanotls_tunnel::control_size::L1_MAX_WIRE_LEN;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let mut seen = std::collections::HashSet::new();
    for frame in [crate::frame::Frame::syn(7), crate::frame::Frame::fin(7)] {
        for _ in 0..12 {
            let (client_tunnel, mut raw_server, mut server_noise) =
                client_stream_with_raw_server().await;
            let (_r, mut w) = client_tunnel.into_split();
            // 先把连接推过 Handshake 态：开场 flight 的确定尺寸必须保留，
            // 生命周期改尺寸只在 Transport 态生效。
            let warmup: Vec<WriteRequest> = (0..8)
                .map(|_| {
                    let (response_tx, _rx) = tokio::sync::oneshot::channel();
                    WriteRequest {
                        packets: vec![super::encode_padding_reply_sized(
                            kanotls_tunnel::control_size::WINDOW_UPDATE_WIRE,
                        )],
                        response_tx,
                        flush: FlushBehavior::Immediate,
                    }
                })
                .collect();
            control_requests_flushed(warmup, &mut w, FlowDirection::C2S)
                .await
                .expect("warmup ok");

            let (response_tx, _rx) = tokio::sync::oneshot::channel();
            control_requests_flushed(
                vec![WriteRequest {
                    packets: vec![frame.encode().expect("frame encodes")],
                    response_tx,
                    flush: FlushBehavior::Immediate,
                }],
                &mut w,
                FlowDirection::C2S,
            )
            .await
            .expect("lifecycle write ok");

            let mut wire = Vec::new();
            let mut read_buf = vec![0u8; 8192];
            let mut sizes = Vec::new();
            let collect = async {
                while sizes.len() < 9 {
                    let n = raw_server.read(&mut read_buf).await.expect("peer reads");
                    assert!(n > 0, "tunnel closed early");
                    wire.extend_from_slice(&read_buf[..n]);
                    for (size, _payload) in drain_wire_records(&mut wire, &mut server_noise) {
                        sizes.push(size);
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), collect)
                .await
                .expect("records arrive before timeout");

            let lifecycle_size = *sizes.last().expect("at least one record");
            assert!(
                lifecycle_size > L1_MAX_WIRE_LEN,
                "cmd=0x{:02x} 的控制记录 {} 落在论文的 L1 类",
                frame.cmd,
                lifecycle_size
            );
            assert!(
                control_record_size_is_allowed(lifecycle_size),
                "cmd=0x{:02x} 的控制记录 {} 越出允许的支撑集",
                frame.cmd,
                lifecycle_size
            );
            seen.insert(lifecycle_size);
        }
    }
    assert!(
        seen.len() > 3,
        "生命周期记录必须与常规数据记录同分布，不能是窄窗口：{:?}",
        seen
    );
}

/// 开流宽限期是全局覆写点，两条用例要的值相反（一条要小、一条要大），
/// 必须串行。
static DEFERRED_OPEN_GRACE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 功能回归：**服务端先说话**的协议（SSH / SMTP / IMAP / MySQL…）下，本端
/// 永远不写第一个字节，目标地址仍必须在有界时间内抵达对端。
///
/// 此前 `defer_target` 把目标地址挂在「首次写入」上，而 `relay_tcp_client`
/// 是 `select!` 双向轮询：本端不写 ⇒ 目标永不出网 ⇒ 服务端要么不知道这条流
/// 存在（第 1 条流，SYN 也压在 `DeferredUnsent` 里），要么 accept 之后卡在
/// `read()` 上等目标。两边互等到 SOCKS 客户端超时。实测**两条路径都挂**。
///
/// 两条流都要覆盖：第 1 条走 `DeferredUnsent`（SYN + 目标一起攒着），
/// 第 2 条走 `Submitted`（SYN 已单发，只差目标）。
#[tokio::test]
async fn deferred_open_reaches_peer_without_a_local_first_write() {
    let _grace_lock = DEFERRED_OPEN_GRACE_LOCK.lock().await;
    const BANNER: &[u8] = b"220 mail.example ESMTP ready\r\n";

    let (client, server) = session_pair().await;
    let acceptor = tokio::spawn(async move {
        let mut targets = Vec::new();
        for _ in 0..2 {
            let (_sid, mut st) = server.accept_stream().await.expect("server accepts stream");
            // 服务端先说话：读到目标后立刻发 banner，本端一个字节都没写过。
            let target = st.read().await.expect("target must arrive");
            st.send_synack().await.expect("server sends synack");
            st.write(BANNER).await.expect("server writes banner");
            targets.push(target);
            std::mem::forget(st);
        }
        targets
    });

    for i in 0..2u32 {
        let mut stream = client.open_stream().await.expect("stream opens");
        stream.defer_target(b"smtp.example:25");
        // 只读，从不写。
        let banner = tokio::time::timeout(Duration::from_secs(2), stream.read())
            .await
            .unwrap_or_else(|_| {
                panic!("第 {} 条流：本端不写时开流必须在有界时间内出网，不得挂死", i + 1)
            });
        assert_eq!(
            banner.as_deref(),
            Some(BANNER),
            "第 {} 条流必须收到服务端 banner",
            i + 1
        );
        std::mem::forget(stream);
    }

    let targets = tokio::time::timeout(Duration::from_secs(2), acceptor)
        .await
        .expect("acceptor 必须在有界时间内收到两条流的目标")
        .expect("acceptor joins");
    assert_eq!(targets.len(), 2);
    for (i, target) in targets.iter().enumerate() {
        assert_eq!(
            &target[..],
            b"smtp.example:25",
            "第 {} 条流的目标地址不完整",
            i + 1
        );
    }
    client.force_close();
}

/// 反向回归（防「修 bug 修坏优化」）：**客户端先说话**时 gather 不得退化。
///
/// 判据取在**记录内容**上，不掐时间也不看帧序——帧序在两种实现下完全相同
/// （`[SETTINGS][SYN][PSH(target)][PSH(首块)]`，区别只在是否同一次提交），
/// 只断言「全都送到了」是抓不住退化的。
///
/// 真正的判据：**连接第一条数据记录的明文里必须已经含有首块的字节**。
/// gather 成立时 `pending` 是 `[SETTINGS][SYN][PSH(target)][PSH(首块)]` 一整块
/// （55 字节头部 + 1884 字节首块），首条记录按 `FIRST_RECORD_PAYLOAD_*` 切走
/// 152–248 字节 ⇒ 明文长度恒 > 55，尾部是首块的填充字节；若退化成「先单发
/// 目标、首块另走一次写」，`pending` 只有 55 字节 ⇒ 首条记录明文恰为 55。
///
/// 这条合并是「每条流的开场只占一条 shaper 定尺寸的记录」的前提：拆开的话
/// 目标先走一条记录、首块再走数据记录，内层首包尺寸重新暴露在「第一条记录
/// = 内层首包 + 24」上（§3.1/§3.3 声称已消除的那条映射）。
///
/// 本用例按 `relay_tcp_client` 的形状驱动：先 `select!` 轮询 `stream.read()`
/// （这会武装宽限计时器），2ms 后本地才产出首块。宽限期覆写成 30 秒，于是
/// 宽限路径不可能参与，能送出目标的只剩 gather 路径。
#[tokio::test]
async fn client_first_write_still_gathers_target_and_first_chunk() {
    use crate::stream::DEFERRED_OPEN_GRACE_OVERRIDE_MS;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;

    let _grace_lock = DEFERRED_OPEN_GRACE_LOCK.lock().await;
    DEFERRED_OPEN_GRACE_OVERRIDE_MS.store(30_000, Ordering::Relaxed);

    const TARGET: &[u8] = b"gather.example:443";
    // 内层 ClientHello 量级（带 ML-KEM 的 Firefox）。
    const FIRST_CHUNK: usize = 1884;
    // SETTINGS(23) + SYN(7) + PSH 帧头(7) + 目标(18)。
    const OPEN_PREFIX_LEN: usize = 23 + 7 + 7 + TARGET.len();

    let (client_tunnel, mut raw_peer, mut peer_noise) = client_stream_with_raw_server().await;
    // 不启读循环：对端是裸 socket，不会应答。首条记录的 `quiet_gap` 于是等满
    // `PEER_TURN_MAX_WAIT` 才继续——但它是在**冲刷之后**才等的，第一条记录
    // 早已出网，正是本用例要看的那条。
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));

    let driver = tokio::spawn(async move {
        let mut stream = client.open_stream().await.expect("stream opens");
        stream.defer_target(TARGET);
        // relay_tcp_client 的形状：隧道侧 read 与本地侧 read 并行轮询。
        let mut local_ready = false;
        tokio::select! {
            _ = stream.read() => {}
            _ = tokio::time::sleep(Duration::from_millis(2)) => { local_ready = true; }
        }
        assert!(local_ready, "对端无数据，本地侧必须先就绪");
        stream
            .write(&vec![0x16u8; FIRST_CHUNK])
            .await
            .expect("client writes inner client hello");
        std::mem::forget(stream);
        client
    });

    let mut wire = Vec::new();
    let mut read_buf = vec![0u8; 16384];
    let mut records = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while records.is_empty() {
            let n = raw_peer.read(&mut read_buf).await.expect("peer reads");
            assert!(n > 0, "tunnel closed before the first record");
            wire.extend_from_slice(&read_buf[..n]);
            records.extend(drain_wire_records(&mut wire, &mut peer_noise));
        }
    })
    .await
    .expect("首条记录必须在有界时间内到达");

    // 先复位覆写点再断言：断言失败时不得把 30 秒的宽限期漏给后续用例。
    DEFERRED_OPEN_GRACE_OVERRIDE_MS.store(0, Ordering::Relaxed);

    let (_wire_len, plaintext) = &records[0];
    assert!(
        plaintext.len() > OPEN_PREFIX_LEN,
        "gather 退化：首条记录明文只有 {} 字节（= SETTINGS+SYN+PSH(target) 的 {} 字节），\
         首块没有与目标同批提交",
        plaintext.len(),
        OPEN_PREFIX_LEN
    );
    // 紧随其后的是首块自己的 PSH 帧头（cmd=PSH、sid、len=1884），再往后全是
    // 首块的填充字节 —— 这就是「目标与首块在同一次提交里」的直接证据。
    let data_frame = &plaintext[OPEN_PREFIX_LEN..];
    assert_eq!(data_frame[0], crate::frame::CMD_PSH, "首块必须紧跟目标帧");
    assert_eq!(
        u16::from_be_bytes([data_frame[5], data_frame[6]]) as usize,
        FIRST_CHUNK,
        "首块 PSH 帧头必须声明整块长度"
    );
    let filler = &data_frame[crate::frame::FRAME_HEADER_SIZE..];
    assert!(!filler.is_empty(), "首条记录必须已经带上首块的字节");
    assert!(
        filler.iter().all(|&b| b == 0x16),
        "首条记录的尾部必须是首块的字节"
    );

    let client = driver.await.expect("driver joins");
    client.force_close();
}

/// 线上不变量：**开流前就被本地拆除**的 deferred 流，一个字节都不得上网。
///
/// `relay_tcp_client` 在本地 EOF 后先 `close_write()`、再继续轮询
/// `remote.read()` 直到隧道侧也 EOF——也就是说宽限计时器所在的 `read()` 在
/// 拆除**之后**仍会被调用。若它此时还把 SYN 发出去，对端就会为一条已经没有
/// 本地端的流建一个 `pending_open_streams` 条目，挂到会话结束。
///
/// 口径说明（不要高估这条用例）：当前实现里 `close_write` 的
/// `unregister_stream` 会丢掉 `data_tx`，`read()` 的 `data_rx.recv()` 于是
/// 立即返回 `None`，计时器来不及到期——因此本用例**抓不到**
/// `open_is_unsent` 少写 `!closed / !write_closed` 这一种改动（实测：去掉
/// 那两个判据本用例仍通过）。它钉住的是**可观测的线上结果**，而不是某一处
/// 判据；`open_is_unsent` 里的显式判据是纵深防御，用来切断对另一个模块清理
/// 顺序的隐式依赖。
#[tokio::test]
async fn grace_timer_does_not_open_a_locally_torn_down_stream() {
    use crate::stream::DEFERRED_OPEN_GRACE_OVERRIDE_MS;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;

    let _grace_lock = DEFERRED_OPEN_GRACE_LOCK.lock().await;
    // 极短宽限期：若逻辑有漏，SYN 会立刻出网，用例必然抓到。
    DEFERRED_OPEN_GRACE_OVERRIDE_MS.store(5, Ordering::Relaxed);

    let (client_tunnel, mut raw_peer, mut peer_noise) = client_stream_with_raw_server().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));

    let mut stream = client.open_stream().await.expect("stream opens");
    stream.defer_target(b"torndown.example:443");
    // 本地 EOF ⇒ 关写侧；随后中继仍会继续读隧道侧。
    stream.close_write().await.expect("close_write");
    let read_after_close = tokio::time::timeout(Duration::from_millis(120), stream.read()).await;

    DEFERRED_OPEN_GRACE_OVERRIDE_MS.store(0, Ordering::Relaxed);
    assert!(
        matches!(read_after_close, Ok(None)),
        "已拆除的流读侧应给 EOF，实测 {:?}",
        read_after_close.is_ok()
    );

    // 对端一个字节都不该收到：这条流从未在线上存在过。
    let mut wire = Vec::new();
    let mut read_buf = vec![0u8; 8192];
    let quiet = tokio::time::timeout(Duration::from_millis(150), async {
        loop {
            let n = raw_peer.read(&mut read_buf).await.expect("peer reads");
            if n == 0 {
                break;
            }
            wire.extend_from_slice(&read_buf[..n]);
        }
    })
    .await;
    let frames: Vec<u8> = drain_wire_records(&mut wire, &mut peer_noise)
        .into_iter()
        .flat_map(|(_size, payload)| payload)
        .collect();
    let mut buf = bytes::BytesMut::from(frames.as_slice());
    while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
        assert_ne!(
            frame.cmd,
            crate::frame::CMD_SYN,
            "宽限计时器为一条已本地拆除的流发出了 SYN"
        );
    }
    let _ = quiet;
    client.force_close();
}

/// 读粒度回归：一次隧道读取绝不能超过 `TUNNEL_READ_CHUNK`。
///
/// `InboundSignal::arrivals()` 计的是「成功 read 的次数」，而它同时是喂给
/// `TrafficShaper` 的窗口进度下界（`begin_drain`）、PING 抑制的判据
/// （`>= PAPER_OBSERVATION_WINDOW_PACKETS`）与让出方向的等待条件
/// （`wait_for_peer_turn`）。读循环改成用 `read_buf` 直接读进 `BytesMut`
/// 之后，若漏掉 `limit`，单次读取会按缓冲的全部剩余容量一路吃到 64 KiB，
/// arrivals 掉到四分之一——**线上的记录尺寸与延迟分布随之改变**。
///
/// 本测试在 socket 里一次压进远超单次上限的数据，断言每次读取都不越界。
#[tokio::test]
async fn tunnel_reads_never_exceed_the_shaping_granularity() {
    use tokio::io::AsyncWriteExt;

    let (client, server) = snowy_stream_pair().await;
    let (mut client_read, _client_write) = client.into_split();
    let (_server_read, mut server_write) = server.into_split();

    const RECORDS: usize = 8;
    let cap = SnowyStream::data_record_capacity();
    let payload = vec![0x5Au8; cap];
    for _ in 0..RECORDS {
        server_write
            .prepare_data_record(&payload, SnowyStream::max_data_record_wire_len())
            .expect("server prepares full record");
    }
    server_write.flush().await.expect("server flushes");

    let total = RECORDS * cap;
    let mut buf = bytes::BytesMut::with_capacity(super::TUNNEL_REASSEMBLY_CAPACITY);
    let mut got = 0usize;
    let mut reads = 0usize;
    while got < total {
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            super::read_tunnel_chunk(&mut client_read, &mut buf),
        )
        .await
        .expect("read completes in time")
        .expect("read ok");
        assert!(n > 0, "spurious EOF at {} bytes", got);
        assert!(
            n <= super::TUNNEL_READ_CHUNK,
            "单次隧道读取 {} 字节，超过整形粒度 {}",
            n,
            super::TUNNEL_READ_CHUNK
        );
        got += n;
        reads += 1;
    }
    assert_eq!(got, total);
    assert_eq!(buf.len(), total, "字节必须直接落在重组缓冲里");
    assert!(
        reads >= RECORDS,
        "{} 条满载记录只用了 {} 次读取，粒度被放大了",
        RECORDS,
        reads
    );
}

// ---------------------------------------------------------------------------
// 吞吐基准（默认 `#[ignore]`，不参与 `cargo test --workspace` 的计数）
//
// 跑法：
//   cargo test --release -p kanotls-session -- --ignored --nocapture bench_
//
// 必须用多线程 runtime：读半与写半在 current_thread 上天然串行，
// `SplitInner` 那把 std::Mutex 的争用在单线程 runtime 下**恒为零**，
// 测不出任何东西。
// ---------------------------------------------------------------------------

/// 进程累计 CPU 时间（user + sys），单位秒。用于度量接收路径的 CPU 开销。
fn process_cpu_secs() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("procfs readable");
    // comm 字段可能含空格，从最后一个 ')' 之后开始切分。
    let tail = &stat[stat.rfind(')').expect("stat has comm") + 2..];
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // tail[0] = state(3rd field) ⇒ utime 是第 14 个字段 = tail[11]，stime = tail[12]
    let utime: u64 = fields[11].parse().expect("utime");
    let stime: u64 = fields[12].parse().expect("stime");
    let hz = 100.0; // Linux USER_HZ
    (utime + stime) as f64 / hz
}

async fn bench_open_stream(
    client: &Arc<Session>,
    server: &ServerSessionHandler,
    target: &'static [u8],
) -> (crate::Stream, crate::server::ServerStream) {
    let mut client_stream = client.open_stream().await.expect("client stream opens");
    client_stream
        .write_early(target)
        .await
        .expect("client sends target");
    let (_sid, mut server_stream) =
        tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
            .await
            .expect("server accepts stream")
            .expect("server accepts stream");
    // 与载荷类型无关的比较：基线（`Vec<u8>`）与当前（`Bytes`）都能编译，
    // 故同一段基准代码可以原样放进两棵树里做 A/B。
    assert_eq!(server_stream.read().await.as_deref(), Some(target));
    server_stream
        .send_synack()
        .await
        .expect("server sends synack");
    client_stream.wait_open().await.expect("stream opens");
    (client_stream, server_stream)
}

const BENCH_TOTAL: usize = 400 * 1024 * 1024;
const BENCH_CHUNK: usize = 256 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf benchmark"]
async fn bench_unidirectional_throughput() {
    let (client, server) = session_pair().await;
    let (mut up_client, mut up_server) = bench_open_stream(&client, &server, b"bench.up:443").await;

    let reader = tokio::spawn(async move {
        let mut received = 0usize;
        while let Some(data) = up_server.read().await {
            received += data.len();
            if received >= BENCH_TOTAL {
                break;
            }
        }
        received
    });

    let cpu0 = process_cpu_secs();
    let t0 = std::time::Instant::now();
    let writer = tokio::spawn(async move {
        let buf = vec![0x5au8; BENCH_CHUNK];
        let mut sent = 0usize;
        while sent < BENCH_TOTAL {
            let n = BENCH_CHUNK.min(BENCH_TOTAL - sent);
            up_client.write(&buf[..n]).await.expect("client writes");
            sent += n;
        }
        sent
    });
    let sent = tokio::time::timeout(Duration::from_secs(120), writer)
        .await
        .expect("writer finishes")
        .expect("writer joins");
    let received = tokio::time::timeout(Duration::from_secs(120), reader)
        .await
        .expect("reader finishes")
        .expect("reader joins");
    let elapsed = t0.elapsed();
    let cpu = process_cpu_secs() - cpu0;
    assert_eq!(sent, BENCH_TOTAL);
    assert_eq!(received, BENCH_TOTAL);
    let mib = BENCH_TOTAL as f64 / (1024.0 * 1024.0);
    println!(
        "BENCH unidirectional: {:.1} MiB in {:.3}s = {:.1} MiB/s | cpu {:.3}s ({:.2} cpu-s per 100MiB)",
        mib,
        elapsed.as_secs_f64(),
        mib / elapsed.as_secs_f64(),
        cpu,
        cpu / (mib / 100.0),
    );
    client.force_close();
    server.session.force_close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf benchmark"]
async fn bench_bidirectional_throughput() {
    let (client, server) = session_pair().await;
    let (mut up_client, mut up_server) = bench_open_stream(&client, &server, b"bench.up:443").await;
    let (mut down_client, down_server) =
        bench_open_stream(&client, &server, b"bench.down:443").await;

    let up_reader = tokio::spawn(async move {
        let mut received = 0usize;
        while let Some(data) = up_server.read().await {
            received += data.len();
            if received >= BENCH_TOTAL {
                break;
            }
        }
        received
    });
    let down_reader = tokio::spawn(async move {
        let mut received = 0usize;
        while let Some(data) = down_client.read().await {
            received += data.len();
            if received >= BENCH_TOTAL {
                break;
            }
        }
        received
    });

    let cpu0 = process_cpu_secs();
    let t0 = std::time::Instant::now();
    let up_writer = tokio::spawn(async move {
        let buf = vec![0x5au8; BENCH_CHUNK];
        let mut sent = 0usize;
        while sent < BENCH_TOTAL {
            let n = BENCH_CHUNK.min(BENCH_TOTAL - sent);
            up_client.write(&buf[..n]).await.expect("client writes");
            sent += n;
        }
        sent
    });
    let down_writer = tokio::spawn(async move {
        let buf = vec![0xa5u8; BENCH_CHUNK];
        let mut sent = 0usize;
        while sent < BENCH_TOTAL {
            let n = BENCH_CHUNK.min(BENCH_TOTAL - sent);
            down_server.write(&buf[..n]).await.expect("server writes");
            sent += n;
        }
        sent
    });

    let up_sent = tokio::time::timeout(Duration::from_secs(180), up_writer)
        .await
        .expect("up writer finishes")
        .expect("up writer joins");
    let down_sent = tokio::time::timeout(Duration::from_secs(180), down_writer)
        .await
        .expect("down writer finishes")
        .expect("down writer joins");
    let up_received = tokio::time::timeout(Duration::from_secs(180), up_reader)
        .await
        .expect("up reader finishes")
        .expect("up reader joins");
    let down_received = tokio::time::timeout(Duration::from_secs(180), down_reader)
        .await
        .expect("down reader finishes")
        .expect("down reader joins");
    let elapsed = t0.elapsed();
    let cpu = process_cpu_secs() - cpu0;
    assert_eq!(up_sent, BENCH_TOTAL);
    assert_eq!(down_sent, BENCH_TOTAL);
    assert_eq!(up_received, BENCH_TOTAL);
    assert_eq!(down_received, BENCH_TOTAL);
    let mib = 2.0 * BENCH_TOTAL as f64 / (1024.0 * 1024.0);
    println!(
        "BENCH bidirectional: {:.1} MiB aggregate in {:.3}s = {:.1} MiB/s | cpu {:.3}s ({:.2} cpu-s per 100MiB)",
        mib,
        elapsed.as_secs_f64(),
        mib / elapsed.as_secs_f64(),
        cpu,
        cpu / (mib / 100.0),
    );
    client.force_close();
    server.session.force_close();
}
