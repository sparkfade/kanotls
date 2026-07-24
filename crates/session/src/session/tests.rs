use super::{coalesce_encoded_frames, Session, SessionConfig, STREAM_CHANNEL_CAPACITY};
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

fn test_session_config(is_client: bool) -> SessionConfig {
    SessionConfig {
        is_client,
        max_streams_per_session: 32,
        idle_timeout_secs: 30,
        traffic_script: None,
        post_script_off: false,
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
        Some(b"bulk.example:443".to_vec())
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
        assert_eq!(server_stream.read().await, Some(target.to_vec()));
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
        Some(b"probe.example:443".to_vec())
    );
    probe_server_stream
        .send_synack()
        .await
        .expect("probe synack");
    probe.wait_open().await.expect("probe opens");
    probe.write(b"ping").await.expect("probe writes ping");
    assert_eq!(probe_server_stream.read().await, Some(b"ping".to_vec()));
    probe_server_stream
        .write(b"pong")
        .await
        .expect("probe writes pong");
    assert_eq!(probe.read().await, Some(b"pong".to_vec()));

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
        Some(b"pad-test.example:443".to_vec())
    );
    server_stream
        .send_synack()
        .await
        .expect("server sends SYNACK");
    stream.wait_open().await.expect("stream opens");

    // Fire a CMD_PADDING request from server → client with m=3.
    // The client queues its reply frames as one merged control write.
    let mut encoded = Vec::new();
    crate::frame::encode_padding_request_into(&mut encoded, 3);
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
    assert_eq!(received, Some(payload.to_vec()));

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
    let mut encoded = Vec::new();
    crate::frame::encode_padding_reply_into(&mut encoded, 64);
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
    assert_eq!(server_stream.read().await, Some(b"healthy".to_vec()));

    client.force_close();
    server.session.force_close();
}

// CMD_PADDING 请求里的 m 必须被钳制到 16：从裸 tunnel 端注入 m=255 的请求，
// 逐帧解码对端回包，统计 reply（flag==1）数量必须恰好为 16。
#[tokio::test]
async fn cmd_padding_request_with_large_m_is_capped_at_16_replies() {
    use super::split_snowy;
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

    let (mut server_read, mut server_write) = split_snowy(server_tunnel);

    // Hand-inject a padding request with m=255 from the raw server end.
    let mut request = Vec::new();
    crate::frame::encode_padding_request_into(&mut request, 255);
    server_write
        .with_stream(|stream| {
            let state = stream.control_state();
            let size = stream.next_control_size(state, FlowDirection::S2C);
            stream.prepare_control_record(&request, size)
        })
        .expect("server prepares padding request record");
    server_write.flush().await.expect("server flushes request");

    // The client must answer with at most 16 CMD_PADDING replies, merged
    // into control records. Decode frames from the raw stream and count.
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
            if replies >= 16 {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), collect).await;
    assert_eq!(replies, 16, "m=255 must be clamped to 16 replies");

    // No further padding frames may be in flight beyond the clamp.
    if let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(200), server_read.read(&mut read_buf)).await
    {
        buf.extend_from_slice(&read_buf[..n]);
        while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
            assert_ne!(
                frame.cmd,
                crate::frame::CMD_PADDING,
                "unexpected extra padding frame beyond the 16-reply clamp"
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
        Some(b"auto-ack.example:443".to_vec())
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
        elapsed < Duration::from_millis(25),
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
// 骨架帧），server 端用 split_snowy 裸收发，便于逐帧解码统计 padding。
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
    use super::split_snowy;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    let client = Arc::new(Session::new(client_tunnel, client_config, None));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let (mut server_read, mut server_write) = split_snowy(server_tunnel);

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
    server_write
        .with_stream(|stream| {
            let state = stream.control_state();
            let size = stream.next_control_size(state, FlowDirection::S2C);
            stream.prepare_control_record(&synack, size)
        })
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
            server_write
                .with_stream(|stream| {
                    let wire = SnowyStream::data_record_wire_len(frame_bytes.len());
                    stream.prepare_data_record(&frame_bytes, wire)
                })
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
            server_write
                .with_stream(|stream| {
                    let wire = SnowyStream::data_record_wire_len(frame_bytes.len());
                    stream.prepare_data_record(&frame_bytes, wire)
                })
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

// W3(b)：会话活跃期按采样间隔发出 flag=0 m=1 的 PING 尺寸 padding 请求。
#[tokio::test]
async fn h2_ping_padding_is_emitted_on_the_sampled_interval() {
    use super::{split_snowy, H2_PING_INTERVAL_OVERRIDE_MS};
    use bytes::BytesMut;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;

    H2_PING_INTERVAL_OVERRIDE_MS.store(50, Ordering::Relaxed);

    let (client_tunnel, server_tunnel) = snowy_stream_pair().await;
    let client = Arc::new(Session::new(client_tunnel, test_session_config(true), None));
    let client_read_loop = client.clone();
    tokio::spawn(async move {
        let _ = client_read_loop.run_read_loop().await;
    });
    let (mut server_read, _server_write) = split_snowy(server_tunnel);

    let mut buf = BytesMut::with_capacity(65536);
    let mut read_buf = vec![0u8; 16384];
    let mut pings = 0usize;
    let collect = async {
        while pings == 0 {
            let n = server_read.read(&mut read_buf).await.expect("server reads");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&read_buf[..n]);
            while let Some(frame) = crate::frame::Frame::decode(&mut buf) {
                if frame.cmd == crate::frame::CMD_PADDING && frame.payload.first() == Some(&0) {
                    pings += 1;
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(2), collect)
        .await
        .expect("h2 ping padding request arrives before timeout");
    assert!(pings >= 1, "expected at least one h2 ping padding request");

    H2_PING_INTERVAL_OVERRIDE_MS.store(0, Ordering::Relaxed);
    client.force_close();
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
async fn client_stream_with_raw_server() -> (SnowyStream, TcpStream, snow::TransportState) {
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
    noise: &mut snow::TransportState,
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

// W4 回归：sticky bulk 路径的批量 flush 与逐条 flush 必须产生完全一致的
// record 尺寸/顺序/载荷序列（仅 syscall 合并；不同连接的密文本身不可比，
// 故离线解密后比对）。
#[tokio::test]
async fn sticky_bulk_batched_flush_matches_per_record_byte_stream() {
    use super::{split_snowy, SessionWriter};
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
        let (_r, mut w) = split_snowy(client);
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
                w.with_stream(|s| s.prepare_data_record(&payload[off..off + take], wire))
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
        let (_r, mut w) = split_snowy(client);
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        let mut pending = payload.clone();
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
        drop(control_tx);
        let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));
        let writer = tokio::spawn(async move {
            let (fake, deferred) = SessionWriter::drive_shaper(
                &mut pending,
                &mut shaper,
                &mut w,
                &mut control_rx,
                &pending_client_settings,
                FlowDirection::C2S,
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
    use super::split_snowy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut server) = snowy_stream_pair().await;
    let (_r, mut w) = split_snowy(client);
    let payload = vec![0x5Au8; 1000];
    let wire = SnowyStream::data_record_wire_len(payload.len());

    let after_first = w.with_stream(|s| {
        s.prepare_data_record(&payload, wire)
            .expect("prepare first");
        s.buffered_write_len()
    });
    assert_eq!(after_first, wire);
    let after_second = w.with_stream(|s| {
        s.prepare_data_record(&payload, wire)
            .expect("prepare second");
        s.buffered_write_len()
    });
    assert_eq!(after_second, 2 * wire, "prepare 自然累积，flush 前不出网");

    w.flush().await.expect("flush");
    assert_eq!(w.with_stream(|s| s.buffered_write_len()), 0);

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
    use super::{split_snowy, FlushBehavior, SessionWriter, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = split_snowy(client);
    let (mut sr, _sw) = split_snowy(server);

    // 单规则脚本：policy target 大于整条 pending——唯一 record 恰好落在
    // 帧边界（policy 切分不越过帧尾），其后的 delay 窗口允许控制帧插队。
    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some("Length: 1500, Delay: 200, FakeResponse: 0"),
        false,
    );

    let psh = crate::frame::Frame::psh(7, vec![0xAAu8; 1000])
        .encode()
        .expect("psh encodes");
    let syn = crate::frame::Frame::syn(0x2A).encode().expect("syn encodes");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));

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
    let (fake, deferred) = SessionWriter::drive_shaper(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
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
    use super::{split_snowy, FlushBehavior, SessionWriter, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = split_snowy(client);
    let (mut sr, _sw) = split_snowy(server);

    // policy target ~300 字节：1007 字节 PSH 帧被切成多条 record，前几个
    // delay 窗口都落在帧载荷中间（非边界），SYN 不得插队。
    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some("Length: 300, Delay: 100, FakeResponse: 0"),
        false,
    );

    let psh = crate::frame::Frame::psh(7, vec![0xAAu8; 1000])
        .encode()
        .expect("psh encodes");
    let syn = crate::frame::Frame::syn(0x2A).encode().expect("syn encodes");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));

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
    let (fake, deferred) = SessionWriter::drive_shaper(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
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
    SessionWriter::write_deferred_control_requests(deferred, &mut cw, FlowDirection::C2S)
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
    use super::{split_snowy, FlushBehavior, SessionWriter, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = split_snowy(client);
    let (mut sr, _sw) = split_snowy(server);

    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some("Length: 300, Delay: 200, FakeResponse: 0"),
        false,
    );

    let data = vec![0xAAu8; 1000];
    let mut padding = Vec::new();
    crate::frame::encode_padding_request_into(&mut padding, 2);
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(8);
    let pending_client_settings = Arc::new(tokio::sync::Mutex::new(None));

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
    let (fake, deferred) = SessionWriter::drive_shaper(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
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
    SessionWriter::write_deferred_control_requests(deferred, &mut cw, FlowDirection::C2S)
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
    use super::{split_snowy, FlushBehavior, SessionWriter, WriteRequest};
    use crate::shaper::TrafficShaper;
    use kanotls_tunnel::FlowDirection;
    use tokio::io::AsyncReadExt;

    let (client, server) = snowy_stream_pair().await;
    let (_cr, mut cw) = split_snowy(client);
    let (mut sr, _sw) = split_snowy(server);

    // 单规则脚本：target ∈ [595,840]（随机化缩放后），两条 PSH 帧
    // （各 507 字节，边界 507/1014）被切成两条 record——record1 消费
    // ∈ [571,816]（非边界），record2 吞掉剩余（边界）。
    let mut shaper = TrafficShaper::new(
        FlowDirection::C2S,
        Some("Length: 700, Delay: 200, FakeResponse: 0"),
        false,
    );

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
    let (_fake, deferred) = SessionWriter::drive_shaper(
        &mut pending,
        &mut shaper,
        &mut cw,
        &mut control_rx,
        &pending_client_settings,
        FlowDirection::C2S,
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

    SessionWriter::write_deferred_control_requests(deferred, &mut cw, FlowDirection::C2S)
        .await
        .expect("deferred flush ok");
    assert!(matches!(response_rx_a.await, Ok(Ok(()))));

    let received = reader.await.expect("reader joins");
    let mut expected = psh.clone();
    expected.extend_from_slice(&syn_a);
    expected.extend_from_slice(&syn_b);
    assert_eq!(received, expected);
}
