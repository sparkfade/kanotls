use crate::frame::{
    coalesce_encoded_frames, Frame, CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_SYNACK,
    MAX_PAYLOAD_LEN,
};
use crate::stream::{Stream, StreamInit, StreamOpenState, StreamParts};
use bytes::BytesMut;
use kanotls_tunnel::{FlowDirection, SnowyStream};
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, RwLock};
use tracing::{debug, error, trace, warn};

struct SplitInner {
    stream: StdMutex<SnowyStream>,
}

struct SplitReadHalf {
    inner: Arc<SplitInner>,
}

struct SplitWriteHalf {
    inner: Arc<SplitInner>,
}

fn split_snowy(stream: SnowyStream) -> (SplitReadHalf, SplitWriteHalf) {
    let inner = Arc::new(SplitInner {
        stream: StdMutex::new(stream),
    });
    (
        SplitReadHalf {
            inner: inner.clone(),
        },
        SplitWriteHalf { inner },
    )
}

impl AsyncRead for SplitReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut guard = self.inner.stream.lock().unwrap();
        let stream = unsafe { Pin::new_unchecked(&mut *guard) };
        stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for SplitWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut guard = self.inner.stream.lock().unwrap();
        let stream = unsafe { Pin::new_unchecked(&mut *guard) };
        stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = self.inner.stream.lock().unwrap();
        let stream = unsafe { Pin::new_unchecked(&mut *guard) };
        stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = self.inner.stream.lock().unwrap();
        let stream = unsafe { Pin::new_unchecked(&mut *guard) };
        stream.poll_shutdown(cx)
    }
}

impl SplitWriteHalf {
    fn with_stream<R>(&self, f: impl FnOnce(&mut SnowyStream) -> R) -> R {
        let mut guard = self.inner.stream.lock().unwrap();
        f(&mut guard)
    }
}

pub(crate) type SharedTunnelWriter = Arc<SessionWriter>;

const MAX_PENDING_STREAM_FRAMES: usize = 1024;
const MAX_PENDING_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_STREAMS: usize = 1024;
const STREAM_CHANNEL_CAPACITY: usize = 32;
const MAX_SESSION_REASSEMBLY_BYTES: usize = 1024 * 1024;
const WRITE_CHANNEL_CAPACITY: usize = 64;
const MAX_STREAM_OVERFLOW_BYTES: usize = 2 * 1024 * 1024;
const MAX_PENDING_FLUSH_SIZE: usize = 256 * 1024;

const LAZY_FLUSH_MS: u64 = 5;

pub struct Session {
    read_half: Mutex<Option<SplitReadHalf>>,
    pub(crate) writer: SharedTunnelWriter,
    pub(crate) streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pub(crate) next_stream_id: AtomicU32,
    pub(crate) is_client: bool,
    pub(crate) max_streams_per_session: usize,
    idle_timeout_with_jitter_secs: u64,
    pub(crate) shutdown: Arc<Notify>,
    alive: AtomicBool,
    close_requested: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
    pending_inbound_streams: AtomicUsize,
    pending_open_streams: Arc<Mutex<HashMap<u32, PendingOpenStream>>>,
    pub(crate) pending_data: Arc<Mutex<HashMap<u32, Vec<Vec<u8>>>>>,
    pending_fin: Arc<Mutex<HashSet<u32>>>,
    closing_streams: Arc<Mutex<HashSet<u32>>>,
    on_new_stream: Option<Arc<dyn Fn(u32) -> bool + Send + Sync>>,
    pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
    pub(crate) buffered_stream_bytes: Arc<AtomicUsize>,
    activity: Arc<ActivityTracker>,
}

#[derive(Debug, Default)]
struct PendingOpenStream {
    buffered_data: Vec<Vec<u8>>,
    buffered_fin: bool,
    reservation_released: bool,
}

#[derive(Debug)]
pub(crate) struct StreamHandle {
    pub data_tx: mpsc::Sender<Vec<u8>>,
    pub fin_tx: mpsc::Sender<()>,
    pub synack_tx: Option<oneshot::Sender<Vec<u8>>>,
    pub read_closed: bool,
    pub pending_notify: Arc<Notify>,
}

enum PshDispatch {
    Deliver(mpsc::Sender<Vec<u8>>, Arc<Notify>),
    SynackPending,
    Closing,
    NotFound,
}

pub(crate) enum PendingAcceptFlushResult {
    Open,
    PeerClosed,
    PeerHalfClosed,
    ClosedLocally,
}

struct PendingStreamHandleGuard {
    stream_id: u32,
    streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pending_data: Arc<Mutex<HashMap<u32, Vec<Vec<u8>>>>>,
    pending_fin: Arc<Mutex<HashSet<u32>>>,
    closing_streams: Arc<Mutex<HashSet<u32>>>,
    cleanup: Option<SubmittedOpenCleanup>,
    armed: bool,
}

struct SubmittedOpenCleanup {
    writer: SharedTunnelWriter,
}

pub struct SessionConfig {
    pub is_client: bool,
    pub max_streams_per_session: usize,
    pub idle_timeout_secs: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushBehavior {
    Auto,
    Immediate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrafficClass {
    Bulk,
    Control,
}

pub(crate) struct SessionWriter {
    control_tx: mpsc::Sender<WriteRequest>,
    bulk_tx: mpsc::Sender<WriteRequest>,
    close_requested: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
}

struct WriteRequest {
    packets: Vec<Vec<u8>>,
    response_tx: oneshot::Sender<Result<(), String>>,
    flush: FlushBehavior,
}

pub(crate) struct PendingWrite {
    response_rx: Option<oneshot::Receiver<Result<(), String>>>,
}

struct ActivityTracker {
    started_at: Instant,
    last_activity_ms: AtomicU64,
    notify: Notify,
}

impl Session {
    pub fn new(
        tunnel: SnowyStream,
        config: SessionConfig,
        on_new_stream: Option<Arc<dyn Fn(u32) -> bool + Send + Sync>>,
    ) -> Self {
        let pending_client_settings = if config.is_client {
            Some(
                Frame::cmd_settings()
                    .encode()
                    .expect("settings frame encodes"),
            )
        } else {
            None
        };
        let (read_half, write_half) = split_snowy(tunnel);
        let close_requested = Arc::new(AtomicBool::new(false));
        let close_notify = Arc::new(Notify::new());
        let activity = Arc::new(ActivityTracker::new());
        let writer = Arc::new(SessionWriter::new(
            write_half,
            close_requested.clone(),
            close_notify.clone(),
            activity.clone(),
            config.is_client,
        ));
        let idle_timeout_with_jitter_secs = {
            let base = config.idle_timeout_secs.max(1);
            let jitter_max = (base / 10).max(1);
            use rand::Rng;
            let mut rng = rand::thread_rng();
            base + rng.gen_range(0..=jitter_max)
        };

        Self {
            read_half: Mutex::new(Some(read_half)),
            writer: writer.clone(),
            streams: Arc::new(RwLock::new(HashMap::new())),
            next_stream_id: AtomicU32::new(if config.is_client { 1 } else { 0 }),
            is_client: config.is_client,
            max_streams_per_session: config.max_streams_per_session,
            idle_timeout_with_jitter_secs,
            shutdown: Arc::new(Notify::new()),
            alive: AtomicBool::new(true),
            close_requested,
            close_notify,
            pending_inbound_streams: AtomicUsize::new(0),
            pending_open_streams: Arc::new(Mutex::new(HashMap::new())),
            pending_data: Arc::new(Mutex::new(HashMap::new())),
            pending_fin: Arc::new(Mutex::new(HashSet::new())),
            closing_streams: Arc::new(Mutex::new(HashSet::new())),
            on_new_stream,
            pending_client_settings: Arc::new(Mutex::new(pending_client_settings)),
            buffered_stream_bytes: Arc::new(AtomicUsize::new(0)),
            activity,
        }
    }

    pub fn next_stream_id(&self) -> anyhow::Result<u32> {
        loop {
            let sid = self.next_stream_id.load(Ordering::Relaxed);
            if sid == 0 || sid == u32::MAX {
                self.alive.store(false, Ordering::Relaxed);
                self.shutdown.notify_waiters();
                anyhow::bail!("stream id exhausted");
            }
            if self
                .next_stream_id
                .compare_exchange_weak(sid, sid + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(sid);
            }
        }
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn is_closing(&self) -> bool {
        self.close_requested.load(Ordering::Relaxed)
    }

    pub fn force_close(&self) {
        if !self.close_requested.swap(true, Ordering::Relaxed) {
            self.alive.store(false, Ordering::Relaxed);
            self.writer.close();
            self.close_notify.notify_waiters();
            self.shutdown.notify_waiters();
        }
    }

    pub fn idle_timeout_with_jitter_secs(&self) -> u64 {
        self.idle_timeout_with_jitter_secs
    }

    pub fn buffered_stream_bytes(&self) -> usize {
        self.buffered_stream_bytes.load(Ordering::Relaxed)
    }

    pub(crate) async fn active_stream_count(&self) -> usize {
        let mut streams = self.streams.write().await;
        Self::prune_orphaned_streams_locked(&mut streams);
        streams.len()
    }

    async fn is_idle_timeout_eligible(&self) -> bool {
        {
            let mut streams = self.streams.write().await;
            Self::prune_orphaned_streams_locked(&mut streams);
            if count_capacity_streams_locked(&streams) > 0 {
                return false;
            }
        }

        if self.pending_inbound_streams.load(Ordering::Relaxed) > 0 {
            return false;
        }

        self.pending_open_streams.lock().await.is_empty()
    }

    pub(crate) async fn clear_pending_client_stream_state(&self, sid: u32) {
        self.pending_data.lock().await.remove(&sid);
        self.pending_fin.lock().await.remove(&sid);
    }

    pub(crate) async fn remove_stream_state(&self, sid: u32) {
        self.streams.write().await.remove(&sid);
        self.clear_pending_client_stream_state(sid).await;
    }

    pub(crate) async fn finish_closing_stream(&self, sid: u32) {
        self.remember_closing_stream(sid).await;
        self.remove_stream_state(sid).await;
    }

    async fn remember_closing_stream(&self, sid: u32) {
        let mut closing = self.closing_streams.lock().await;
        if !closing.contains(&sid) && closing.len() >= MAX_PENDING_STREAMS {
            if let Some(evicted_sid) = closing.iter().next().copied() {
                closing.remove(&evicted_sid);
                warn!(
                    evicted_stream_id = evicted_sid,
                    stream_id = sid,
                    "evicting closing stream tombstone: limit exceeded"
                );
            }
        }
        closing.insert(sid);
    }

    async fn clear_closing_stream(&self, sid: u32) -> bool {
        self.closing_streams.lock().await.remove(&sid)
    }

    pub async fn open_stream(&self) -> Result<Stream, anyhow::Error> {
        if !self.is_alive() || self.is_closing() {
            anyhow::bail!("session is closed");
        }
        let sid = self.next_stream_id()?;
        let syn = Frame::syn(sid).encode()?;
        let has_deferred_open =
            self.is_client && self.pending_client_settings.lock().await.is_some();
        let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let (fin_tx, fin_rx) = mpsc::channel(1);
        let (synack_tx, synack_rx) = oneshot::channel();
        let pending_notify = Arc::new(Notify::new());

        let handle = StreamHandle {
            data_tx,
            fin_tx,
            synack_tx: Some(synack_tx),
            read_closed: false,
            pending_notify: pending_notify.clone(),
        };
        let mut handle_guard = PendingStreamHandleGuard {
            stream_id: sid,
            streams: self.streams.clone(),
            pending_data: self.pending_data.clone(),
            pending_fin: self.pending_fin.clone(),
            closing_streams: self.closing_streams.clone(),
            cleanup: None,
            armed: true,
        };
        let mut pending_write = None;

        {
            let mut streams = self.streams.write().await;
            Self::prune_orphaned_streams_locked(&mut streams);
            if count_capacity_streams_locked(&streams) >= self.max_streams_per_session {
                anyhow::bail!("max streams per session reached");
            }
            streams.insert(sid, handle);
        }

        if !has_deferred_open {
            let packets = vec![syn.clone()];
            let submitted = match self
                .writer
                .submit_write_packets(packets, FlushBehavior::Immediate, TrafficClass::Control)
                .await
            {
                Ok(pending_write) => pending_write,
                Err(e) => {
                    self.streams.write().await.remove(&sid);
                    self.clear_pending_client_stream_state(sid).await;
                    self.writer.close();
                    return Err(e);
                }
            };
            handle_guard.arm_submitted_open(SubmittedOpenCleanup {
                writer: self.writer.clone(),
            });
            pending_write = Some(submitted);
        }

        handle_guard.disarm();

        Ok(Stream::new(StreamInit {
            stream_id: sid,
            parts: StreamParts {
                data_rx,
                fin_rx,
                synack_rx,
            },
            writer: self.writer.clone(),
            streams: self.streams.clone(),
            pending_client_settings: self.pending_client_settings.clone(),
            pending_data: self.pending_data.clone(),
            pending_fin: self.pending_fin.clone(),
            closing_streams: self.closing_streams.clone(),
            pending_notify,
            open_state: if has_deferred_open {
                StreamOpenState::DeferredUnsent(vec![syn])
            } else {
                StreamOpenState::Submitted {
                    pending_write,
                    early_data_submitted: false,
                }
            },
            buffered_stream_bytes: self.buffered_stream_bytes.clone(),
        }))
    }

    pub(crate) async fn write_frame(
        &self,
        frame: &Frame,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        let data = frame.encode()?;
        self.write_encoded_payload(&data, FlushBehavior::Immediate, traffic_class)
            .await
    }

    pub async fn write_data(&self, sid: u32, data: &[u8]) -> Result<(), anyhow::Error> {
        if data.is_empty() {
            let frame = Frame::psh(sid, Vec::new());
            return self.write_frame(&frame, TrafficClass::Bulk).await;
        }

        let mut encoded = Vec::new();
        for chunk in data.chunks(MAX_PAYLOAD_LEN) {
            let frame = Frame::psh(sid, chunk.to_vec());
            encoded.push(frame.encode()?);
        }
        self.write_many_encoded_payloads(&encoded, FlushBehavior::Auto, TrafficClass::Bulk)
            .await?;
        Ok(())
    }

    pub(crate) async fn shutdown_stream(&self, sid: u32) -> Result<(), anyhow::Error> {
        let frame = Frame::fin(sid);
        self.write_frame(&frame, TrafficClass::Control).await
    }

    pub async fn close_stream(&self, sid: u32) -> Result<(), anyhow::Error> {
        self.finish_closing_stream(sid).await;
        self.shutdown_stream(sid).await
    }

    async fn write_encoded_payload(
        &self,
        data: &[u8],
        flush: FlushBehavior,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        self.write_many_encoded_payloads(&[data.to_vec()], flush, traffic_class)
            .await
    }

    async fn write_many_encoded_payloads(
        &self,
        frames: &[Vec<u8>],
        flush: FlushBehavior,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        let packets = coalesce_encoded_frames(frames, MAX_PAYLOAD_LEN);
        self.writer
            .write_packets(packets, flush, traffic_class)
            .await
    }

    pub async fn run_read_loop(&self) -> Result<(), anyhow::Error> {
        let mut read_half = self
            .read_half
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("session read loop already running"))?;
        let mut buf = BytesMut::with_capacity(16384);
        let mut read_buf = vec![0u8; 16384];

        let mut settings_received = self.is_client;

        let idle_duration = Duration::from_secs(self.idle_timeout_with_jitter_secs);
        let idle_timeout = tokio::time::sleep(idle_duration);
        tokio::pin!(idle_timeout);

        loop {
            if self.close_requested.load(Ordering::Relaxed) {
                debug!("session close requested, ending read loop");
                break;
            }

            let read_result = tokio::select! {
                _ = self.close_notify.notified() => {
                    debug!("session close requested during read loop");
                    break;
                }
                _ = &mut idle_timeout => {
                    if self.is_idle_timeout_eligible().await {
                        debug!("session idle for {}s, tearing down", self.idle_timeout_with_jitter_secs);
                        break;
                    }
                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    continue;
                }
                result = read_half.read(&mut read_buf) => result,
            };

            idle_timeout
                .as_mut()
                .reset(tokio::time::Instant::now() + idle_duration);

            let n = match read_result {
                Ok(0) => {
                    debug!("tunnel eof, ending read loop");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!("tunnel read error: {}", e);
                    break;
                }
            };

            self.activity.record_read_activity();
            buf.extend_from_slice(&read_buf[..n]);
            if buf.len() > MAX_SESSION_REASSEMBLY_BYTES {
                warn!(
                    "closing session: frame reassembly buffer exceeded {} bytes",
                    MAX_SESSION_REASSEMBLY_BYTES
                );
                break;
            }

            while let Some(frame) = Frame::decode(&mut buf) {
                if let Err(e) = self.handle_frame(frame, &mut settings_received).await {
                    warn!("frame handler error: {}", e);
                }
            }
        }

        self.force_close();
        self.streams.write().await.clear();
        self.pending_open_streams.lock().await.clear();
        self.pending_data.lock().await.clear();
        self.pending_fin.lock().await.clear();
        self.closing_streams.lock().await.clear();
        self.shutdown.notify_waiters();
        Ok(())
    }

    async fn send_synack_rejection(
        &self,
        stream_id: u32,
        reason: &'static str,
    ) -> Result<(), anyhow::Error> {
        let frame = Frame::new(CMD_SYNACK, stream_id, reason.as_bytes().to_vec());
        self.write_frame(&frame, TrafficClass::Control).await
    }

    async fn handle_frame(
        &self,
        frame: Frame,
        settings_received: &mut bool,
    ) -> Result<(), anyhow::Error> {
        match frame.cmd {
            CMD_PSH => {
                if self.is_pending_open_stream(frame.stream_id).await
                    && self
                        .store_pending_open_data(frame.stream_id, frame.payload.clone())
                        .await
                {
                    return Ok(());
                }
                let payload_len = frame.payload.len();
                let dispatch = {
                    self.streams
                        .read()
                        .await
                        .get(&frame.stream_id)
                        .map(|handle| {
                            if self.is_client && handle.synack_tx.is_some() {
                                PshDispatch::SynackPending
                            } else if handle.read_closed {
                                PshDispatch::Closing
                            } else {
                                PshDispatch::Deliver(
                                    handle.data_tx.clone(),
                                    handle.pending_notify.clone(),
                                )
                            }
                        })
                        .unwrap_or(PshDispatch::NotFound)
                };
                match dispatch {
                    PshDispatch::SynackPending => {
                        self.store_pending_data(frame.stream_id, frame.payload)
                            .await;
                    }
                    PshDispatch::Closing => {
                        trace!(
                            stream_id = frame.stream_id,
                            "ignoring late stream data after local close"
                        );
                    }
                    PshDispatch::Deliver(data_tx, notify) => {
                        // 若 pending_data 中已有该流数据，新帧必须直接追加到
                        // pending_data 末尾，而不是 try_send 到主 Channel，
                        // 否则会插队到 pending_data 中更早到达的数据之前，导致乱序。
                        // 读循环是单线程顺序执行，消费者只能从 pending_data 中取走
                        // 数据，不会在此检查与发送之间增加条目，故无 TOCTOU 风险。
                        let has_pending = self
                            .pending_data
                            .try_lock()
                            .map(|guard| guard.contains_key(&frame.stream_id))
                            .unwrap_or(true);

                        if !has_pending {
                            match data_tx.try_send(frame.payload) {
                                Ok(()) => {
                                    self.buffered_stream_bytes
                                        .fetch_add(payload_len, Ordering::Relaxed);
                                }
                                Err(mpsc::error::TrySendError::Full(payload)) => {
                                    if self.store_pending_data(frame.stream_id, payload).await {
                                        notify.notify_one();
                                    } else {
                                        warn!(
                                            stream_id = frame.stream_id,
                                            "closing stream: pending overflow limit exceeded"
                                        );
                                        let _ = self.close_stream(frame.stream_id).await;
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    trace!(
                                        stream_id = frame.stream_id,
                                        "dropping stream data after receiver closed"
                                    );
                                }
                            }
                        } else {
                            if self
                                .store_pending_data(frame.stream_id, frame.payload)
                                .await
                            {
                                notify.notify_one();
                            } else {
                                warn!(
                                    stream_id = frame.stream_id,
                                    "closing stream: pending overflow limit exceeded"
                                );
                                let _ = self.close_stream(frame.stream_id).await;
                            }
                        }
                    }
                    PshDispatch::NotFound => {
                        if self.is_closing_stream(frame.stream_id) {
                            trace!(
                                stream_id = frame.stream_id,
                                "ignoring late stream data for closing stream"
                            );
                        } else {
                            warn!(
                                stream_id = frame.stream_id,
                                "dropping stream data for unopened stream"
                            );
                        }
                    }
                }
            }
            CMD_SYN => {
                if !*settings_received {
                    tracing::warn!("CMD_SYN received before CMD_SETTINGS, dropping");
                    self.send_synack_rejection(frame.stream_id, "settings not received")
                        .await?;
                    return Ok(());
                }
                if self.streams.read().await.contains_key(&frame.stream_id)
                    || self.is_pending_open_stream(frame.stream_id).await
                {
                    tracing::warn!(stream_id = frame.stream_id, "dropping duplicate CMD_SYN");
                    self.send_synack_rejection(frame.stream_id, "duplicate stream id")
                        .await?;
                    return Ok(());
                }
                if !self.try_reserve_inbound_stream().await {
                    tracing::warn!(
                        stream_id = frame.stream_id,
                        "dropping CMD_SYN: max streams per session reached"
                    );
                    self.send_synack_rejection(frame.stream_id, "max streams per session reached")
                        .await?;
                    return Ok(());
                }
                self.pending_open_streams
                    .lock()
                    .await
                    .insert(frame.stream_id, PendingOpenStream::default());
                if let Some(ref cb) = self.on_new_stream {
                    if !cb(frame.stream_id) {
                        self.pending_open_streams
                            .lock()
                            .await
                            .remove(&frame.stream_id);
                        self.release_inbound_stream_reservation();
                        self.send_synack_rejection(frame.stream_id, "server overloaded")
                            .await?;
                    }
                } else {
                    self.pending_open_streams
                        .lock()
                        .await
                        .remove(&frame.stream_id);
                    self.release_inbound_stream_reservation();
                    self.send_synack_rejection(frame.stream_id, "inbound streams not accepted")
                        .await?;
                }
            }
            CMD_FIN => {
                if self.is_client {
                    let synack_tx = {
                        self.streams
                            .write()
                            .await
                            .get_mut(&frame.stream_id)
                            .and_then(|handle| handle.synack_tx.take())
                    };
                    if let Some(tx) = synack_tx {
                        let _ = tx.send(b"stream closed before SYNACK".to_vec());
                        self.store_pending_fin(frame.stream_id).await;
                        return Ok(());
                    }
                }
                if self.store_pending_open_fin(frame.stream_id).await {
                    return Ok(());
                }
                if self.clear_closing_stream(frame.stream_id).await {
                    trace!(
                        stream_id = frame.stream_id,
                        "ignoring peer FIN after local close"
                    );
                    return Ok(());
                }
                let fin_tx = {
                    self.streams
                        .write()
                        .await
                        .get_mut(&frame.stream_id)
                        .map(|handle| {
                            handle.read_closed = true;
                            handle.fin_tx.clone()
                        })
                };
                if let Some(fin_tx) = fin_tx {
                    let _ = fin_tx.try_send(());
                    if self.streams.read().await.contains_key(&frame.stream_id) {
                        self.clear_closing_stream(frame.stream_id).await;
                    }
                } else {
                    warn!(
                        stream_id = frame.stream_id,
                        "dropping FIN for unopened stream"
                    );
                }
            }
            0x00 => {
                trace!(
                    "ignoring unknown cmd=0x00 frame ({} bytes)",
                    frame.payload.len()
                );
            }
            CMD_SYNACK => {
                let synack_tx = {
                    self.streams
                        .write()
                        .await
                        .get_mut(&frame.stream_id)
                        .and_then(|handle| handle.synack_tx.take())
                };
                if let Some(tx) = synack_tx {
                    let payload = frame.payload;
                    let has_pending = self
                        .pending_data
                        .lock()
                        .await
                        .contains_key(&frame.stream_id)
                        || self.pending_fin.lock().await.contains(&frame.stream_id);
                    if tx.send(payload).is_err() {
                        self.streams.write().await.remove(&frame.stream_id);
                        self.pending_data.lock().await.remove(&frame.stream_id);
                        self.pending_fin.lock().await.remove(&frame.stream_id);
                        return Ok(());
                    }
                    if has_pending {
                        self.flush_client_pending_stream(frame.stream_id).await;
                    }
                }
            }
            CMD_SETTINGS => {
                *settings_received = true;
                trace!(
                    "client settings: {}",
                    String::from_utf8_lossy(&frame.payload)
                );
            }
            _ => {
                warn!("unknown frame cmd: {}", frame.cmd);
            }
        }
        Ok(())
    }

    async fn store_pending_data(&self, sid: u32, payload: Vec<u8>) -> bool {
        let mut pending = self.pending_data.lock().await;
        let total_bytes: usize = pending.values().flatten().map(Vec::len).sum();
        if total_bytes.saturating_add(payload.len()) > MAX_PENDING_STREAM_BYTES {
            warn!("dropping pending stream data: pending byte limit exceeded");
            return false;
        }

        if !pending.contains_key(&sid) && pending.len() >= MAX_PENDING_STREAMS {
            warn!(
                stream_id = sid,
                "dropping pending stream data: pending stream limit exceeded"
            );
            return false;
        }

        let queue = pending.entry(sid).or_default();
        let stream_bytes: usize = queue.iter().map(Vec::len).sum();
        if stream_bytes.saturating_add(payload.len()) > MAX_STREAM_OVERFLOW_BYTES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: per-stream overflow byte limit exceeded"
            );
            return false;
        }
        if queue.len() >= MAX_PENDING_STREAM_FRAMES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: per-stream frame limit exceeded"
            );
            return false;
        }
        queue.push(payload);
        true
    }

    async fn store_pending_fin(&self, sid: u32) {
        let mut pending_fin = self.pending_fin.lock().await;
        if pending_fin.len() >= MAX_PENDING_STREAMS && !pending_fin.contains(&sid) {
            warn!(
                stream_id = sid,
                "dropping pending fin: pending stream limit exceeded"
            );
            return;
        }
        pending_fin.insert(sid);
    }

    async fn store_pending_open_data(&self, sid: u32, payload: Vec<u8>) -> bool {
        let mut pending = self.pending_open_streams.lock().await;
        let total_bytes: usize = pending
            .values()
            .flat_map(|stream| stream.buffered_data.iter())
            .map(Vec::len)
            .sum();
        let Some(stream) = pending.get_mut(&sid) else {
            return false;
        };

        if total_bytes.saturating_add(payload.len()) > MAX_PENDING_STREAM_BYTES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: pending byte limit exceeded"
            );
            return true;
        }

        if stream.buffered_data.len() >= MAX_PENDING_STREAM_FRAMES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: per-stream frame limit exceeded"
            );
            return true;
        }

        stream.buffered_data.push(payload);
        true
    }

    async fn store_pending_open_fin(&self, sid: u32) -> bool {
        let mut pending = self.pending_open_streams.lock().await;
        let Some(stream) = pending.get_mut(&sid) else {
            return false;
        };
        stream.buffered_fin = true;
        if !stream.reservation_released {
            stream.reservation_released = true;
            drop(pending);
            self.release_inbound_stream_reservation();
        }
        true
    }

    pub(crate) async fn release_pending_open_reservation(&self, sid: u32) -> bool {
        let mut pending = self.pending_open_streams.lock().await;
        let Some(stream) = pending.get_mut(&sid) else {
            return false;
        };
        if stream.reservation_released {
            return false;
        }
        stream.reservation_released = true;
        true
    }

    async fn try_reserve_inbound_stream(&self) -> bool {
        let streams = self.streams.read().await;
        let active = count_capacity_streams_locked(&streams);
        loop {
            let pending = self.pending_inbound_streams.load(Ordering::Relaxed);
            if active.saturating_add(pending) >= self.max_streams_per_session {
                return false;
            }
            if self
                .pending_inbound_streams
                .compare_exchange_weak(pending, pending + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub(crate) fn release_inbound_stream_reservation(&self) {
        let _ = self.pending_inbound_streams.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |pending| pending.checked_sub(1),
        );
    }

    pub(crate) async fn begin_accept_pending_stream(&self, sid: u32) -> Result<(), anyhow::Error> {
        let pending = self.pending_open_streams.lock().await;
        if pending.contains_key(&sid) {
            Ok(())
        } else {
            anyhow::bail!("pending stream {} disappeared before accept", sid)
        }
    }

    async fn is_pending_open_stream(&self, sid: u32) -> bool {
        self.pending_open_streams.lock().await.contains_key(&sid)
    }

    fn is_closing_stream(&self, sid: u32) -> bool {
        self.closing_streams
            .try_lock()
            .map(|guard| guard.contains(&sid))
            .unwrap_or(false)
    }

    pub(crate) async fn flush_pending_accept_stream(
        &self,
        sid: u32,
        data_tx: mpsc::Sender<Vec<u8>>,
        fin_tx: mpsc::Sender<()>,
    ) -> PendingAcceptFlushResult {
        let mut delivered_data = false;
        loop {
            let (pending_data, pending_fin) = {
                let mut pending = self.pending_open_streams.lock().await;
                let Some(stream) = pending.get_mut(&sid) else {
                    return PendingAcceptFlushResult::Open;
                };
                if stream.buffered_data.is_empty() && !stream.buffered_fin {
                    pending.remove(&sid);
                    return PendingAcceptFlushResult::Open;
                }
                let pending_data = std::mem::take(&mut stream.buffered_data);
                let pending_fin = stream.buffered_fin;
                stream.buffered_fin = false;
                (pending_data, pending_fin)
            };

            for payload in pending_data {
                let payload_len = payload.len();
                if data_tx.try_send(payload).is_err() {
                    warn!(
                        stream_id = sid,
                        "closing stream: receiver queue full while flushing pending accept data"
                    );
                    let _ = self.close_stream(sid).await;
                    self.pending_open_streams.lock().await.remove(&sid);
                    return PendingAcceptFlushResult::ClosedLocally;
                }
                delivered_data = true;
                self.buffered_stream_bytes
                    .fetch_add(payload_len, Ordering::Relaxed);
            }

            if pending_fin {
                let _ = fin_tx.try_send(());
                if delivered_data {
                    if let Some(handle) = self.streams.write().await.get_mut(&sid) {
                        handle.read_closed = true;
                    }
                    self.pending_open_streams.lock().await.remove(&sid);
                    return PendingAcceptFlushResult::PeerHalfClosed;
                }
                self.streams.write().await.remove(&sid);
                self.pending_open_streams.lock().await.remove(&sid);
                return PendingAcceptFlushResult::PeerClosed;
            }
        }
    }

    async fn flush_client_pending_stream(&self, sid: u32) {
        let (pending_data, pending_fin, data_tx, fin_tx, notify) = {
            let mut streams = self.streams.write().await;
            let Some(handle) = streams.get_mut(&sid) else {
                return;
            };

            let data_tx = handle.data_tx.clone();
            let fin_tx = handle.fin_tx.clone();
            let notify = handle.pending_notify.clone();
            let pending_data = self
                .pending_data
                .lock()
                .await
                .remove(&sid)
                .unwrap_or_default();
            let pending_fin = self.pending_fin.lock().await.remove(&sid);
            (pending_data, pending_fin, data_tx, fin_tx, notify)
        };

        let mut all_delivered = true;
        let mut remaining: Vec<Vec<u8>> = Vec::new();

        for payload in pending_data {
            if all_delivered {
                let payload_len = payload.len();
                match data_tx.try_send(payload) {
                    Ok(()) => {
                        self.buffered_stream_bytes
                            .fetch_add(payload_len, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Full(payload)) => {
                        remaining.push(payload);
                        all_delivered = false;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!(
                            stream_id = sid,
                            "closing stream: receiver closed while flushing pre-SYNACK data"
                        );
                        let _ = self.close_stream(sid).await;
                        return;
                    }
                }
            } else {
                remaining.push(payload);
            }
        }

        if !remaining.is_empty() {
            let mut pending = self.pending_data.lock().await;
            let queue = pending.entry(sid).or_default();
            for item in remaining {
                queue.push(item);
            }
            drop(pending);
            notify.notify_one();
        }

        if all_delivered && pending_fin {
            let _ = fin_tx.try_send(());
            self.streams.write().await.remove(&sid);
            self.clear_closing_stream(sid).await;
        }
    }
}

impl SessionWriter {
    fn new(
        write_half: SplitWriteHalf,
        close_requested: Arc<AtomicBool>,
        close_notify: Arc<Notify>,
        activity: Arc<ActivityTracker>,
        is_client: bool,
    ) -> Self {
        let direction = if is_client {
            FlowDirection::C2S
        } else {
            FlowDirection::S2C
        };
        let (control_tx, control_rx) = mpsc::channel(WRITE_CHANNEL_CAPACITY);
        let (bulk_tx, bulk_rx) = mpsc::channel(WRITE_CHANNEL_CAPACITY);
        let run_close_requested = close_requested.clone();
        let run_close_notify = close_notify.clone();
        let run_activity = activity.clone();
        tokio::spawn(async move {
            Self::run(
                write_half,
                control_rx,
                bulk_rx,
                run_close_requested,
                run_close_notify,
                run_activity,
                direction,
            )
            .await;
        });
        Self {
            control_tx,
            bulk_tx,
            close_requested,
            close_notify,
        }
    }

    pub(crate) fn close(&self) {
        self.close_requested.store(true, Ordering::Relaxed);
        self.close_notify.notify_waiters();
    }

    pub(crate) async fn write_packets(
        &self,
        packets: Vec<Vec<u8>>,
        flush: FlushBehavior,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        self.submit_write_packets(packets, flush, traffic_class)
            .await?
            .wait()
            .await
    }

    pub(crate) async fn submit_write_packets(
        &self,
        packets: Vec<Vec<u8>>,
        flush: FlushBehavior,
        traffic_class: TrafficClass,
    ) -> Result<PendingWrite, anyhow::Error> {
        if self.close_requested.load(Ordering::Relaxed) {
            anyhow::bail!("session writer closed");
        }
        let (response_tx, response_rx) = oneshot::channel();
        let tx = match traffic_class {
            TrafficClass::Control => &self.control_tx,
            TrafficClass::Bulk => &self.bulk_tx,
        };
        tx.send(WriteRequest {
            packets,
            response_tx,
            flush,
        })
        .await
        .map_err(|_| anyhow::anyhow!("session writer closed"))?;

        Ok(PendingWrite {
            response_rx: Some(response_rx),
        })
    }

    pub(crate) fn try_write_packets(
        &self,
        packets: Vec<Vec<u8>>,
        flush: FlushBehavior,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        if self.close_requested.load(Ordering::Relaxed) {
            anyhow::bail!("session writer closed");
        }

        let (response_tx, _response_rx) = oneshot::channel();
        let tx = match traffic_class {
            TrafficClass::Control => &self.control_tx,
            TrafficClass::Bulk => &self.bulk_tx,
        };
        tx.try_send(WriteRequest {
            packets,
            response_tx,
            flush,
        })
        .map_err(|err| anyhow::anyhow!("failed to queue session write: {}", err))
    }

    async fn run(
        mut write_half: SplitWriteHalf,
        mut control_rx: mpsc::Receiver<WriteRequest>,
        mut bulk_rx: mpsc::Receiver<WriteRequest>,
        close_requested: Arc<AtomicBool>,
        close_notify: Arc<Notify>,
        activity: Arc<ActivityTracker>,
        direction: FlowDirection,
    ) {
        let mut pending: Vec<u8> = Vec::with_capacity(65536);
        let mut responders: Vec<oneshot::Sender<Result<(), String>>> = Vec::new();

        loop {
            if close_requested.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                biased;

                _ = close_notify.notified() => {
                    break;
                }
                maybe_control = control_rx.recv() => {
                    let Some(request) = maybe_control else { break; };

                    if close_requested.load(Ordering::Relaxed) {
                        let msg = "session writer closed".to_string();
                        for responder in responders {
                            let _ = responder.send(Err(msg.clone()));
                        }
                        let _ = request.response_tx.send(Err(msg));
                        break;
                    }

                    if !pending.is_empty() {
                        match Self::emit_pending(&mut pending, &mut write_half, &activity).await {
                            Ok(()) => {
                                for responder in responders.drain(..) {
                                    let _ = responder.send(Ok(()));
                                }
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                for responder in responders.drain(..) {
                                    let _ = responder.send(Err(msg.clone()));
                                }
                                let _ = request.response_tx.send(Err(msg));
                                break;
                            }
                        }
                    }

                    let prepare_result: Result<(), String> =
                        write_half.with_stream(|stream| {
                            let state = stream.control_state();
                            for packet in &request.packets {
                                let size = stream.next_control_size(state, direction);
                                debug!(
                                    "control write: frame_cmd=0x{:02x} wire_size={}",
                                    packet.first().unwrap_or(&0),
                                    size
                                );
                                if let Err(e) = stream.prepare_control_record(packet, size) {
                                    return Err(e.to_string());
                                }
                            }
                            Ok(())
                        });

                    match prepare_result {
                        Err(msg) => {
                            let _ = request.response_tx.send(Err(msg.clone()));
                            break;
                        }
                        Ok(()) => {
                            if let Err(e) = write_half.flush().await {
                                let msg = e.to_string();
                                let _ = request.response_tx.send(Err(msg.clone()));
                                break;
                            }
                            activity.record_write_activity();
                            let _ = request.response_tx.send(Ok(()));
                        }
                    }
                }
                maybe_bulk = bulk_rx.recv() => {
                    let Some(request) = maybe_bulk else { break; };

                    if close_requested.load(Ordering::Relaxed) {
                        let msg = "session writer closed".to_string();
                        for responder in responders {
                            let _ = responder.send(Err(msg.clone()));
                        }
                        let _ = request.response_tx.send(Err(msg));
                        break;
                    }

                    for packet in &request.packets {
                        pending.extend_from_slice(packet);
                    }
                    responders.push(request.response_tx);

                    if request.flush == FlushBehavior::Immediate
                        || pending.len() >= MAX_PENDING_FLUSH_SIZE
                    {
                        match Self::emit_pending(&mut pending, &mut write_half, &activity).await {
                            Ok(()) => {
                                for responder in responders.drain(..) {
                                    let _ = responder.send(Ok(()));
                                }
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                for responder in responders.drain(..) {
                                    let _ = responder.send(Err(msg.clone()));
                                }
                                break;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(LAZY_FLUSH_MS)), if !pending.is_empty() => {
                    if let Err(e) = Self::emit_pending(&mut pending, &mut write_half, &activity).await {
                        let msg = e.to_string();
                        for responder in responders.drain(..) {
                            let _ = responder.send(Err(msg.clone()));
                        }
                        break;
                    }
                    for responder in responders.drain(..) {
                        let _ = responder.send(Ok(()));
                    }
                }
            }
        }

        if !pending.is_empty() {
            let _ = Self::emit_pending(&mut pending, &mut write_half, &activity).await;
        }
        let _ = write_half.shutdown().await;
    }

    async fn emit_pending(
        pending: &mut Vec<u8>,
        write_half: &mut SplitWriteHalf,
        activity: &ActivityTracker,
    ) -> std::io::Result<()> {
        if !pending.is_empty() {
            write_half.write_all(pending).await?;
            pending.clear();
        }
        write_half.flush().await?;
        activity.record_write_activity();
        Ok(())
    }
}

impl ActivityTracker {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn record_read_activity(&self) {
        self.last_activity_ms
            .store(self.elapsed_ms(), Ordering::Relaxed);
    }

    fn record_write_activity(&self) {
        self.record_read_activity();
        self.notify.notify_one();
    }

    fn elapsed_ms(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }
}

impl PendingWrite {
    pub(crate) async fn wait(&mut self) -> Result<(), anyhow::Error> {
        let response = {
            let Some(response_rx) = self.response_rx.as_mut() else {
                return Ok(());
            };
            response_rx
                .await
                .map_err(|_| anyhow::anyhow!("session writer response dropped"))?
        };
        self.response_rx = None;
        response.map_err(|msg| anyhow::anyhow!(msg))
    }
}

impl PendingStreamHandleGuard {
    fn arm_submitted_open(&mut self, cleanup: SubmittedOpenCleanup) {
        self.cleanup = Some(cleanup);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingStreamHandleGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let stream_id = self.stream_id;
        let pending_data = self.pending_data.clone();
        let pending_fin = self.pending_fin.clone();
        let closing_streams = self.closing_streams.clone();
        if let Ok(mut guard) = self.streams.try_write() {
            guard.remove(&stream_id);
        }

        if let Ok(mut pending) = pending_data.try_lock() {
            pending.remove(&stream_id);
        }
        if let Ok(mut pending) = pending_fin.try_lock() {
            pending.remove(&stream_id);
        }

        let streams = self.streams.clone();
        let cleanup = self.cleanup.take();
        if let Some(cleanup) = cleanup.as_ref() {
            remember_closing_stream_sync(stream_id, &closing_streams);
            let _ = crate::stream::try_send_fin_frame(stream_id, &cleanup.writer);
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                streams.write().await.remove(&stream_id);
                pending_data.lock().await.remove(&stream_id);
                pending_fin.lock().await.remove(&stream_id);
            });
        }
    }
}

impl Session {
    fn prune_orphaned_streams_locked(streams: &mut HashMap<u32, StreamHandle>) {
        streams.retain(|_, handle| !stream_handle_is_orphaned(handle));
    }
}

fn stream_handle_is_orphaned(handle: &StreamHandle) -> bool {
    if handle.read_closed {
        return false;
    }
    handle.data_tx.is_closed()
        && handle.fin_tx.is_closed()
        && handle
            .synack_tx
            .as_ref()
            .map(|tx| tx.is_closed())
            .unwrap_or(true)
}

fn count_capacity_streams_locked(streams: &HashMap<u32, StreamHandle>) -> usize {
    streams
        .values()
        .filter(|handle| !handle.read_closed)
        .count()
}

pub(crate) fn remember_closing_stream_sync(
    stream_id: u32,
    closing_streams: &Arc<Mutex<HashSet<u32>>>,
) {
    if let Ok(mut closing) = closing_streams.try_lock() {
        if !closing.contains(&stream_id) && closing.len() >= MAX_PENDING_STREAMS {
            if let Some(evicted_sid) = closing.iter().next().copied() {
                closing.remove(&evicted_sid);
            }
        }
        closing.insert(stream_id);
        return;
    }

    let closing_streams = closing_streams.clone();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut closing = closing_streams.lock().await;
            if !closing.contains(&stream_id) && closing.len() >= MAX_PENDING_STREAMS {
                if let Some(evicted_sid) = closing.iter().next().copied() {
                    closing.remove(&evicted_sid);
                }
            }
            closing.insert(stream_id);
        });
    }
}

#[cfg(test)]
mod tests;
