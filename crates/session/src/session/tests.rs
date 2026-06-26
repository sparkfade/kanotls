use super::{
    coalesce_encoded_frames, ActivityTracker, Session, SessionConfig, STREAM_CHANNEL_CAPACITY,
};
use crate::server::ServerSessionHandler;
use futures::poll;
use kanotls_tunnel::common::{derive_psk, NOISE_PARAMS};
use kanotls_tunnel::SnowyStream;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn coalesce_encoded_frames_packs_adjacent_small_frames() {
    let frames = vec![vec![1u8; 7], vec![2u8; 7], vec![3u8; 7]];
    let out = coalesce_encoded_frames(&frames, 32);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].len(), 21);
}

#[test]
fn coalesce_encoded_frames_respects_packet_limit() {
    let frames = vec![vec![1u8; 20], vec![2u8; 20], vec![3u8; 8]];
    let out = coalesce_encoded_frames(&frames, 32);

    assert_eq!(out.len(), 2);
    assert_eq!(out[0].len(), 20);
    assert_eq!(out[1].len(), 28);
}

#[tokio::test]
async fn activity_tracker_wakes_waiters_after_write_activity() {
    let tracker = ActivityTracker::new();
    tracker.record_write_activity();

    tokio::time::timeout(Duration::from_millis(10), tracker.notify.notified())
        .await
        .expect("activity notification should be delivered");
}

fn test_session_config(is_client: bool) -> SessionConfig {
    SessionConfig {
        is_client,
        max_streams_per_session: 32,
        idle_timeout_secs: 30,
    }
}

fn build_transport_pair() -> (snow::TransportState, snow::TransportState) {
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
        initiator
            .into_transport_mode()
            .expect("initiator enters transport mode"),
        responder
            .into_transport_mode()
            .expect("responder enters transport mode"),
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
        Some(b"example.com:443".to_vec())
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
    assert_eq!(client.active_stream_count().await, 0);
    assert!(client.pending_data.lock().await.is_empty());
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
        Some(b"retry.example:443".to_vec())
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
        Some(b"retry.example:443".to_vec())
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

    assert_eq!(stream.read().await, Some(b"last".to_vec()));
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

    assert!(!client.pending_data.lock().await.contains_key(&sid));
    assert!(!client.pending_fin.lock().await.contains(&sid));
    assert_eq!(client.active_stream_count().await, 0);

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
        Some(b"example.com:443".to_vec())
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
    };
    let server_config = SessionConfig {
        is_client: false,
        max_streams_per_session: 32,
        idle_timeout_secs: 1,
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
    };
    let server_config = SessionConfig {
        is_client: false,
        max_streams_per_session: 32,
        idle_timeout_secs: 1,
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
    assert_eq!(server.session.active_stream_count().await, 0);
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
        Some(b"example.com:443".to_vec())
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

    assert_eq!(stream.read().await, Some(b"response".to_vec()));
    assert_eq!(stream.read().await, None);

    client.force_close();
    server.session.force_close();
}
