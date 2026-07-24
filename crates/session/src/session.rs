use crate::frame::{
    coalesce_encoded_frames, encode_padding_reply_into, encode_padding_request_into,
    encode_psh_frames, Frame, CMD_FIN, CMD_PADDING, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_SYNACK,
    FRAME_HEADER_SIZE, MAX_PAYLOAD_LEN,
};
use crate::shaper::{ShapePolicy, TrafficShaper};
use crate::stream::{Stream, StreamInit, StreamOpenState, StreamParts};
use bytes::BytesMut;
use kanotls_tunnel::{FlowDirection, SnowyStream};
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;
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

/// 入账缓冲载荷：创建即计入 buffered_stream_bytes，被消费者取走
/// （into_vec）或被丢弃（Drop）时恰好扣减一次，杜绝手工记账漏减。
#[derive(Debug)]
pub(crate) struct BufferedPayload {
    data: Vec<u8>,
    counter: Arc<AtomicUsize>,
    accounted: bool,
}

impl BufferedPayload {
    pub(crate) fn new(data: Vec<u8>, counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(data.len(), Ordering::Relaxed);
        Self {
            data,
            counter: counter.clone(),
            accounted: true,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// 数据离开缓冲交付应用层：按口径扣减后返回原始字节。
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        self.release();
        std::mem::take(&mut self.data)
    }

    fn release(&mut self) {
        if self.accounted {
            self.accounted = false;
            subtract_buffered_stream_bytes(&self.counter, self.data.len());
        }
    }
}

impl Drop for BufferedPayload {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Default)]
pub(crate) struct PendingData {
    queues: HashMap<u32, VecDeque<BufferedPayload>>,
}

impl PendingData {
    pub fn contains(&self, sid: u32) -> bool {
        self.queues.contains_key(&sid)
    }

    pub fn remove(&mut self, sid: u32) -> Option<VecDeque<BufferedPayload>> {
        self.queues.remove(&sid)
    }

    pub fn clear(&mut self) {
        self.queues.clear();
    }

    pub fn len(&self) -> usize {
        self.queues.len()
    }

    pub fn entry(&mut self, sid: u32) -> &mut VecDeque<BufferedPayload> {
        self.queues.entry(sid).or_default()
    }

    pub fn get_mut(&mut self, sid: u32) -> Option<&mut VecDeque<BufferedPayload>> {
        self.queues.get_mut(&sid)
    }

    pub fn total_bytes(&self) -> usize {
        self.queues
            .values()
            .flat_map(|q| q.iter())
            .map(BufferedPayload::len)
            .sum()
    }
}

pub(crate) type SharedTunnelWriter = Arc<SessionWriter>;

/// 顺序扫描编码缓冲中的帧头，逐帧回调 (cmd, stream_id, frame_len)；缓冲
/// 可能是多帧合并（control 写）或任意帧拼接（bulk 积压），尾部不足一帧
/// 时停止。
fn walk_frame_headers(mut buf: &[u8], mut f: impl FnMut(u8, u32, usize)) {
    while buf.len() >= FRAME_HEADER_SIZE {
        let data_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
        let frame_len = FRAME_HEADER_SIZE + data_len;
        if buf.len() < frame_len {
            break;
        }
        f(
            buf[0],
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            frame_len,
        );
        buf = &buf[frame_len..];
    }
}

/// delay 窗口插队判定：请求内全部为真实协议控制帧（SYN/FIN/SETTINGS/
/// SYNACK）且不触及被钉住的流（在途 control 请求、pending 积压中的
/// 数据、已暂存写）才允许立即上链；CMD_PADDING（H2 骨架/假响应）与
/// 其他帧一律不得插队，窗口内的尺寸/时序模型保持原样。
fn control_write_can_pass_through(request: &WriteRequest, pinned_sids: &HashSet<u32>) -> bool {
    let mut saw_frame = false;
    let mut pass = true;
    for packet in &request.packets {
        walk_frame_headers(packet, |cmd, sid, _len| {
            saw_frame = true;
            if !matches!(cmd, CMD_SYN | CMD_FIN | CMD_SETTINGS | CMD_SYNACK)
                || pinned_sids.contains(&sid)
            {
                pass = false;
            }
        });
    }
    saw_frame && pass
}

const MAX_PENDING_STREAM_FRAMES: usize = 1024;
const MAX_PENDING_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_STREAMS: usize = 1024;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const MAX_SESSION_REASSEMBLY_BYTES: usize = 1024 * 1024;
const WRITE_CHANNEL_CAPACITY: usize = 64;
const MAX_STREAM_OVERFLOW_BYTES: usize = 2 * 1024 * 1024;

/// sticky bulk 批量 flush 双上限（先到先 flush）：连续 prepare 最多 K 条
/// record 且 write_buffer 累计不超过 ~128KB 后统一冲刷一次。仅合并内部
/// syscall，record 尺寸/顺序与逐条 flush 完全一致。
const STICKY_BULK_FLUSH_MAX_RECORDS: usize = 8;
const STICKY_BULK_FLUSH_MAX_BYTES: usize = 128 * 1024;

/// 稳态 H2 行为骨架（post-script steady state）：真实 HTTP/2 接收端按消费
/// 字节数回发 WINDOW_UPDATE，并偶发 PING/PING-ACK 对。内容加密不可见，
/// 只需复刻尺寸/时序语义。两者都以 CMD_PADDING 帧实现：flag=1 被对端
/// 静默吸收（等价 WINDOW_UPDATE 的“无回复”语义），flag=0 m=1 会换来
/// 一条 reply（等价 PING/PING-ACK 对）。
const H2_WINDOW_UPDATE_MIN_BYTES: usize = 1024 * 1024;
const H2_WINDOW_UPDATE_MAX_BYTES: usize = 4 * 1024 * 1024;
const H2_PING_MIN_INTERVAL_SECS: u64 = 60;
const H2_PING_MAX_INTERVAL_SECS: u64 = 150;

/// 测试覆写点：0 表示使用上面的生产常量。
pub(crate) static H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES: AtomicUsize =
    AtomicUsize::new(0);
pub(crate) static H2_PING_INTERVAL_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

/// H2 骨架关闭时的定时器“禁用”姿态：分支被 select guard 屏蔽，deadline
/// 只需足够遥远。
const H2_TIMER_DISABLED: Duration = Duration::from_secs(3600);

/// `prepare_control_record` 的最小 wire 开销：block 长度前缀 + TLS record
/// 头 + AEAD tag + inner content type。junk_len 按此反解，使整条控制记录
/// 的 wire 尺寸命中目标 H2 帧尺寸（采样尺寸更大时由 shaper 采样兜底）。
const CONTROL_RECORD_MIN_OVERHEAD: usize = kanotls_tunnel::common::BLOCK_LEN_PREFIX_SIZE
    + kanotls_tunnel::common::TLS_RECORD_HEADER_LEN
    + kanotls_tunnel::common::AEAD_TAG_LEN
    + kanotls_tunnel::common::INNER_CONTENT_TYPE_LEN;

fn sample_h2_window_update_threshold() -> usize {
    let override_bytes = H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.load(Ordering::Relaxed);
    if override_bytes > 0 {
        return override_bytes;
    }
    use rand::Rng;
    rand::thread_rng().gen_range(H2_WINDOW_UPDATE_MIN_BYTES..=H2_WINDOW_UPDATE_MAX_BYTES)
}

fn sample_h2_ping_interval() -> Duration {
    let override_ms = H2_PING_INTERVAL_OVERRIDE_MS.load(Ordering::Relaxed);
    if override_ms > 0 {
        return Duration::from_millis(override_ms);
    }
    use rand::Rng;
    let secs = rand::thread_rng().gen_range(H2_PING_MIN_INTERVAL_SECS..=H2_PING_MAX_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// 构造一条 wire 尺寸 ≈ target_wire_len 的 CMD_PADDING 帧：junk_len 按
/// CONTROL_RECORD_MIN_OVERHEAD 反解，packet 长度对齐目标 H2 帧总长。
fn encode_h2_wire_sized_padding(flag: u8, m: u8, target_wire_len: usize) -> Vec<u8> {
    let junk_len = target_wire_len
        .saturating_sub(CONTROL_RECORD_MIN_OVERHEAD)
        .saturating_sub(crate::frame::FRAME_HEADER_SIZE + 2);
    let mut payload = vec![0u8; 2 + junk_len];
    payload[0] = flag;
    payload[1] = m;
    kanotls_tunnel::fill_from_pool(&mut payload[2..]);
    Frame::new(CMD_PADDING, 0, payload)
        .encode()
        .expect("h2 skeleton padding frame encodes")
}

pub struct Session {
    read_half: Mutex<Option<SplitReadHalf>>,
    pub(crate) writer: SharedTunnelWriter,
    pub(crate) streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pub(crate) capacity_stream_count: Arc<AtomicUsize>,
    pub(crate) next_stream_id: AtomicU32,
    pub(crate) is_client: bool,
    pub(crate) max_streams_per_session: usize,
    pub(crate) post_script_off: bool,
    idle_timeout_with_jitter_secs: u64,
    pub(crate) shutdown: Arc<Notify>,
    alive: AtomicBool,
    close_requested: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
    pending_inbound_streams: AtomicUsize,
    pending_open_streams: Arc<Mutex<HashMap<u32, PendingOpenStream>>>,
    pub(crate) pending_data: Arc<Mutex<PendingData>>,
    pending_fin: Arc<Mutex<HashSet<u32>>>,
    closing_streams: Arc<Mutex<HashSet<u32>>>,
    on_new_stream: Option<Arc<dyn Fn(u32) -> bool + Send + Sync>>,
    pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
    pub(crate) buffered_stream_bytes: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct PendingOpenStream {
    buffered_data: Vec<BufferedPayload>,
    buffered_fin: bool,
    reservation_released: bool,
}

#[derive(Debug)]
pub(crate) struct StreamHandle {
    pub data_tx: mpsc::Sender<BufferedPayload>,
    pub fin_tx: mpsc::Sender<()>,
    pub synack_tx: Option<oneshot::Sender<Vec<u8>>>,
    pub read_closed: bool,
    pub pending_notify: Arc<Notify>,
}

enum PshDispatch {
    Deliver(mpsc::Sender<BufferedPayload>, Arc<Notify>),
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
    capacity_stream_count: Arc<AtomicUsize>,
    pending_data: Arc<Mutex<PendingData>>,
    pending_fin: Arc<Mutex<HashSet<u32>>>,
    closing_streams: Arc<Mutex<HashSet<u32>>>,
    cleanup: Option<SubmittedOpenCleanup>,
    armed: bool,
}

struct SubmittedOpenCleanup {
    writer: SharedTunnelWriter,
}

#[derive(Clone)]
pub struct SessionConfig {
    pub is_client: bool,
    pub max_streams_per_session: usize,
    pub idle_timeout_secs: u64,
    pub traffic_script: Option<String>,
    pub post_script_off: bool,
}

impl SessionConfig {
    pub fn with_limits(
        is_client: bool,
        max_streams_per_session: usize,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            is_client,
            max_streams_per_session,
            idle_timeout_secs,
            traffic_script: None,
            post_script_off: false,
        }
    }

    pub fn with_script(
        is_client: bool,
        max_streams_per_session: usize,
        idle_timeout_secs: u64,
        traffic_script: Option<String>,
        post_script_off: bool,
    ) -> Self {
        Self {
            is_client,
            max_streams_per_session,
            idle_timeout_secs,
            traffic_script,
            post_script_off,
        }
    }
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

impl Session {
    pub fn new(
        tunnel: SnowyStream,
        config: SessionConfig,
        on_new_stream: Option<Arc<dyn Fn(u32) -> bool + Send + Sync>>,
    ) -> Self {
        let pending_client_settings = Arc::new(Mutex::new(if config.is_client {
            Some(
                Frame::cmd_settings()
                    .encode()
                    .expect("settings frame encodes"),
            )
        } else {
            None
        }));
        let close_requested = Arc::new(AtomicBool::new(false));
        let close_notify = Arc::new(Notify::new());
        let (read_half, write_half) = split_snowy(tunnel);
        let writer = Arc::new(SessionWriter::new(
            write_half,
            close_requested.clone(),
            close_notify.clone(),
            config.is_client,
            config.traffic_script.as_deref(),
            config.post_script_off,
            pending_client_settings.clone(),
        ));
        // 空闲拆除仅服务端生效（见 run_read_loop）：客户端无需抖动采样。
        let idle_timeout_with_jitter_secs = {
            let base = config.idle_timeout_secs.max(1);
            if config.is_client {
                base
            } else {
                let jitter_max = (base / 10).max(1);
                use rand::Rng;
                let mut rng = rand::thread_rng();
                base + rng.gen_range(0..=jitter_max)
            }
        };

        Self {
            read_half: Mutex::new(Some(read_half)),
            writer: writer.clone(),
            streams: Arc::new(RwLock::new(HashMap::new())),
            capacity_stream_count: Arc::new(AtomicUsize::new(0)),
            next_stream_id: AtomicU32::new(if config.is_client { 1 } else { 0 }),
            is_client: config.is_client,
            max_streams_per_session: config.max_streams_per_session,
            post_script_off: config.post_script_off,
            idle_timeout_with_jitter_secs,
            shutdown: Arc::new(Notify::new()),
            alive: AtomicBool::new(true),
            close_requested,
            close_notify,
            pending_inbound_streams: AtomicUsize::new(0),
            pending_open_streams: Arc::new(Mutex::new(HashMap::new())),
            pending_data: Arc::new(Mutex::new(PendingData::default())),
            pending_fin: Arc::new(Mutex::new(HashSet::new())),
            closing_streams: Arc::new(Mutex::new(HashSet::new())),
            on_new_stream,
            pending_client_settings,
            buffered_stream_bytes: Arc::new(AtomicUsize::new(0)),
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

    pub fn buffered_stream_bytes(&self) -> usize {        self.buffered_stream_bytes.load(Ordering::Relaxed)
    }

    /// 池选择/补涓热路径使用的无锁计数：与 streams 映射中 read_closed=false
    /// 的条目数保持一致（注册 +1，read_closed 置位或移除 -1）。
    pub fn active_stream_count(&self) -> usize {
        self.capacity_stream_count.load(Ordering::Relaxed)
    }

    async fn is_idle_timeout_eligible(&self) -> bool {
        {
            let mut streams = self.streams.write().await;
            Self::prune_orphaned_streams_locked(&mut streams, &self.capacity_stream_count);
            if self.active_stream_count() > 0 {
                return false;
            }
        }

        if self.pending_inbound_streams.load(Ordering::Relaxed) > 0 {
            return false;
        }

        self.pending_open_streams.lock().await.is_empty()
    }

    pub(crate) async fn clear_pending_client_stream_state(&self, sid: u32) {
        // 移除的入账载荷随队列丢弃自动回账。
        self.pending_data.lock().await.remove(sid);
        self.pending_fin.lock().await.remove(&sid);
    }

    pub(crate) async fn remove_stream_state(&self, sid: u32) {
        unregister_stream_locked(
            &mut *self.streams.write().await,
            &self.capacity_stream_count,
            sid,
        );
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
            capacity_stream_count: self.capacity_stream_count.clone(),
            pending_data: self.pending_data.clone(),
            pending_fin: self.pending_fin.clone(),
            closing_streams: self.closing_streams.clone(),
            cleanup: None,
            armed: true,
        };
        let mut pending_write = None;

        {
            let mut streams = self.streams.write().await;
            Self::prune_orphaned_streams_locked(&mut streams, &self.capacity_stream_count);
            if self.active_stream_count() >= self.max_streams_per_session {
                anyhow::bail!("max streams per session reached");
            }
            register_stream_locked(
                &mut streams,
                &self.capacity_stream_count,
                sid,
                handle,
            );
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
                    unregister_stream_locked(
                        &mut *self.streams.write().await,
                        &self.capacity_stream_count,
                        sid,
                    );
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
            capacity_stream_count: self.capacity_stream_count.clone(),
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
        }))
    }

    pub(crate) async fn write_frame(
        &self,
        frame: &Frame,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        let data = frame.encode()?;
        self.write_encoded_payload(data, FlushBehavior::Immediate, traffic_class)
            .await
    }

    pub async fn write_data(&self, sid: u32, data: &[u8]) -> Result<(), anyhow::Error> {
        if data.is_empty() {
            let frame = Frame::psh(sid, Vec::new());
            return self.write_frame(&frame, TrafficClass::Bulk).await;
        }

        let encoded = encode_psh_frames(sid, data)?;
        self.write_many_encoded_payloads(encoded, FlushBehavior::Auto, TrafficClass::Bulk)
            .await?;
        Ok(())
    }

    pub(crate) async fn shutdown_stream(&self, sid: u32) -> Result<(), anyhow::Error> {
        let frame = Frame::fin(sid);
        // FIN 走 Control（保序论证见 send_fin_frame）。
        self.write_frame(&frame, TrafficClass::Control).await
    }

    pub async fn close_stream(&self, sid: u32) -> Result<(), anyhow::Error> {
        self.finish_closing_stream(sid).await;
        self.shutdown_stream(sid).await
    }

    async fn write_encoded_payload(
        &self,
        data: Vec<u8>,
        flush: FlushBehavior,
        traffic_class: TrafficClass,
    ) -> Result<(), anyhow::Error> {
        self.write_many_encoded_payloads(vec![data], flush, traffic_class)
            .await
    }

    async fn write_many_encoded_payloads(
        &self,
        frames: Vec<Vec<u8>>,
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
        let mut buf = BytesMut::with_capacity(65536);
        let mut read_buf = vec![0u8; 16384];

        let mut settings_received = self.is_client;

        // 空闲拆除仅服务端生效：池化客户端的空闲连接由连接池的 idle drain
        // 统一管理（drain 后 force_close 本 session），session 层不再重复
        // 维护一套永远更晚触发的空闲定时器。
        let idle_teardown_enabled = !self.is_client;
        let idle_duration = Duration::from_secs(self.idle_timeout_with_jitter_secs);
        let idle_timeout = tokio::time::sleep(idle_duration);
        tokio::pin!(idle_timeout);

        // 稳态 H2 骨架状态：post_script_off 时整体关闭（定时器取禁用姿态，
        // 分支被 guard 屏蔽）。
        let h2_skeleton_enabled = !self.post_script_off;
        let mut bytes_since_window_update = 0usize;
        let mut window_update_threshold = sample_h2_window_update_threshold();
        let h2_ping_timer = tokio::time::sleep(if h2_skeleton_enabled {
            sample_h2_ping_interval()
        } else {
            H2_TIMER_DISABLED
        });
        tokio::pin!(h2_ping_timer);

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
                _ = &mut idle_timeout, if idle_teardown_enabled => {
                    if self.is_idle_timeout_eligible().await {
                        debug!("session idle for {}s, tearing down", self.idle_timeout_with_jitter_secs);
                        break;
                    }
                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    continue;
                }
                _ = &mut h2_ping_timer, if h2_skeleton_enabled => {
                    // 偶发 PING 对：flag=0 m=1 请求（wire ≈ H2 PING），对端
                    // 回一条 padding reply，构成 PING/PING-ACK 时序。
                    let packet = encode_h2_wire_sized_padding(
                        0,
                        1,
                        kanotls_tunnel::control_size::PING_WIRE,
                    );
                    if let Err(e) = self
                        .writer
                        .submit_write_packets(
                            vec![packet],
                            FlushBehavior::Auto,
                            TrafficClass::Control,
                        )
                        .await
                    {
                        warn!("failed to queue h2 ping padding: {}", e);
                    }
                    h2_ping_timer
                        .as_mut()
                        .reset(tokio::time::Instant::now() + sample_h2_ping_interval());
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

            buf.extend_from_slice(&read_buf[..n]);
            if buf.len() > MAX_SESSION_REASSEMBLY_BYTES {
                warn!(
                    "closing session: frame reassembly buffer exceeded {} bytes",
                    MAX_SESSION_REASSEMBLY_BYTES
                );
                break;
            }

            let mut protocol_error = false;
            while let Some(frame) = Frame::decode(&mut buf) {
                // WINDOW_UPDATE 节奏：每分发约 1–4MB 数据（阈值每连接随机、
                // 越过后重采样）即向对端注入一条 flag=1 padding（wire ≈ H2
                // WINDOW_UPDATE），方向天然是收 bulk 的一方发 WU。
                if h2_skeleton_enabled && frame.cmd == CMD_PSH {
                    bytes_since_window_update += frame.payload.len();
                    while bytes_since_window_update >= window_update_threshold {
                        bytes_since_window_update -= window_update_threshold;
                        window_update_threshold = sample_h2_window_update_threshold();
                        let packet = encode_h2_wire_sized_padding(
                            1,
                            0,
                            kanotls_tunnel::control_size::WINDOW_UPDATE_WIRE,
                        );
                        if let Err(e) = self
                            .writer
                            .submit_write_packets(
                                vec![packet],
                                FlushBehavior::Auto,
                                TrafficClass::Control,
                            )
                            .await
                        {
                            warn!("failed to queue h2 window update padding: {}", e);
                            break;
                        }
                    }
                }
                if let Err(e) = self.handle_frame(frame, &mut settings_received).await {
                    warn!("frame handler error: {}", e);
                    protocol_error = true;
                    break;
                }
            }
            if protocol_error {
                break;
            }
        }

        self.force_close();
        self.streams.write().await.clear();
        self.capacity_stream_count.store(0, Ordering::Relaxed);
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
                        self.store_pending_data(
                            frame.stream_id,
                            BufferedPayload::new(frame.payload, &self.buffered_stream_bytes),
                        )
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
                            .map(|guard| guard.contains(frame.stream_id))
                            .unwrap_or(true);

                        let payload =
                            BufferedPayload::new(frame.payload, &self.buffered_stream_bytes);
                        if !has_pending {
                            match data_tx.try_send(payload) {
                                Ok(()) => {}
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
                            mark_stream_read_closed_locked(
                                handle,
                                &self.capacity_stream_count,
                            );
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
                    let has_pending = self.pending_data.lock().await.contains(frame.stream_id)
                        || self.pending_fin.lock().await.contains(&frame.stream_id);
                    if tx.send(payload).is_err() {
                        self.remove_stream_state(frame.stream_id).await;
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
            CMD_PADDING => {
                let flag = frame.payload.first().copied().unwrap_or(0);
                if flag == 0 {
                    let m = frame.payload.get(1).copied().unwrap_or(1).clamp(1, 16);
                    let total_junk = frame.payload.len().saturating_sub(2).max(32);
                    // 全部 reply 连续写进一个 buffer，作为单个 control
                    // WriteRequest fire-and-forget 提交：只等入队成功，
                    // 不等 socket 冲刷，读循环不被 reply 拖住。
                    let mut replies = Vec::new();
                    for i in 0..m as usize {
                        let step = i.saturating_mul(41) % 192;
                        let junk_len = total_junk.min(48 + step);
                        encode_padding_reply_into(&mut replies, junk_len);
                    }
                    if let Err(e) = self
                        .writer
                        .submit_write_packets(
                            vec![replies],
                            FlushBehavior::Auto,
                            TrafficClass::Control,
                        )
                        .await
                    {
                        warn!("failed to queue CMD_PADDING replies: {}", e);
                    }
                }
            }
            _ => {
                anyhow::bail!("unknown frame cmd: {}", frame.cmd);
            }
        }
        Ok(())
    }

    /// payload 入账发生在 BufferedPayload::new；此处只做限量检查与入队，
    /// 拒绝时 payload 随作用域丢弃自动回账。
    async fn store_pending_data(&self, sid: u32, payload: BufferedPayload) -> bool {
        let mut pending = self.pending_data.lock().await;
        let total_bytes: usize = pending.total_bytes();
        if total_bytes.saturating_add(payload.len()) > MAX_PENDING_STREAM_BYTES {
            warn!("dropping pending stream data: pending byte limit exceeded");
            return false;
        }

        if !pending.contains(sid) && pending.len() >= MAX_PENDING_STREAMS {
            warn!(
                stream_id = sid,
                "dropping pending stream data: pending stream limit exceeded"
            );
            return false;
        }

        let queue = pending.entry(sid);
        let stream_bytes: usize = queue.iter().map(BufferedPayload::len).sum();
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
        queue.push_back(payload);
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
            .map(BufferedPayload::len)
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

        // pre-accept 缓冲同样由 BufferedPayload 入账；
        // flush_pending_accept_stream 投递时只是转移所有权。
        stream.buffered_data.push(BufferedPayload::new(
            payload,
            &self.buffered_stream_bytes,
        ));
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
        let active = self.active_stream_count();
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
        data_tx: mpsc::Sender<BufferedPayload>,
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

            // buffered_data 在 store_pending_open_data 时已入账，投递进
            // data channel 只是转移所有权；投递失败被丢弃时由 Drop 自动回账。
            let mut payloads = pending_data.into_iter();
            while let Some(payload) = payloads.next() {
                if data_tx.try_send(payload).is_err() {
                    warn!(
                        stream_id = sid,
                        "closing stream: receiver queue full while flushing pending accept data"
                    );
                    drop(payloads);
                    let _ = self.close_stream(sid).await;
                    self.pending_open_streams.lock().await.remove(&sid);
                    return PendingAcceptFlushResult::ClosedLocally;
                }
                delivered_data = true;
            }

            if pending_fin {
                let _ = fin_tx.try_send(());
                if delivered_data {
                    if let Some(handle) = self.streams.write().await.get_mut(&sid) {
                        mark_stream_read_closed_locked(handle, &self.capacity_stream_count);
                    }
                    self.pending_open_streams.lock().await.remove(&sid);
                    return PendingAcceptFlushResult::PeerHalfClosed;
                }
                unregister_stream_locked(
                    &mut *self.streams.write().await,
                    &self.capacity_stream_count,
                    sid,
                );
                self.pending_open_streams.lock().await.remove(&sid);
                return PendingAcceptFlushResult::PeerClosed;
            }
        }
    }

    async fn flush_client_pending_stream(&self, sid: u32) {
        let (mut pending_data, pending_fin, data_tx, fin_tx, notify) = {
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
                .remove(sid)
                .unwrap_or_default();
            let pending_fin = self.pending_fin.lock().await.remove(&sid);
            (pending_data, pending_fin, data_tx, fin_tx, notify)
        };

        let mut all_delivered = true;
        let mut remaining: Vec<BufferedPayload> = Vec::new();

        // pending_data 在入队时已入账，投递进 data channel 只是转移；
        // 投递失败被丢弃的条目由 Drop 自动回账。
        while let Some(payload) = pending_data.pop_front() {
            if all_delivered {
                match data_tx.try_send(payload) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(payload)) => {
                        remaining.push(payload);
                        all_delivered = false;
                    }
                    Err(mpsc::error::TrySendError::Closed(payload)) => {
                        warn!(
                            stream_id = sid,
                            "closing stream: receiver closed while flushing pre-SYNACK data"
                        );
                        drop(payload);
                        drop(remaining);
                        drop(pending_data);
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
            let queue = pending.entry(sid);
            for item in remaining {
                queue.push_back(item);
            }
            drop(pending);
            notify.notify_one();
        }

        if pending_fin {
            if all_delivered {
                let _ = fin_tx.try_send(());
                unregister_stream_locked(
                    &mut *self.streams.write().await,
                    &self.capacity_stream_count,
                    sid,
                );
                self.clear_closing_stream(sid).await;
            } else {
                // 数据未全部投递时 FIN 不能丢：重新挂回 pending_fin，由消费者
                // 排空 pending_data 后在 read 路径补投为 EOF。
                self.pending_fin.lock().await.insert(sid);
                notify.notify_one();
            }
        }
    }
}

impl SessionWriter {
    fn new(
        write_half: SplitWriteHalf,
        close_requested: Arc<AtomicBool>,
        close_notify: Arc<Notify>,
        is_client: bool,
        traffic_script: Option<&str>,
        post_script_off: bool,
        pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
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
        let run_direction = direction;
        let script_owned = traffic_script.map(|s| s.to_string());
        tokio::spawn(async move {
            Self::run(
                write_half,
                control_rx,
                bulk_rx,
                run_close_requested,
                run_close_notify,
                run_direction,
                script_owned,
                post_script_off,
                pending_client_settings,
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

    #[allow(clippy::too_many_arguments)]
    async fn run(
        mut write_half: SplitWriteHalf,
        mut control_rx: mpsc::Receiver<WriteRequest>,
        mut bulk_rx: mpsc::Receiver<WriteRequest>,
        close_requested: Arc<AtomicBool>,
        close_notify: Arc<Notify>,
        direction: FlowDirection,
        traffic_script: Option<String>,
        post_script_off: bool,
        pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
    ) {
        let mut pending: Vec<u8> = Vec::with_capacity(65536);
        // 仅 Immediate 写请求进入此队列：其字节随下一次 drive_shaper 全部
        // 排空后统一应答。Auto 写请求入队即应答（背压由有界 bulk channel
        // 的 send().await 提供），不进此队列。
        let mut responders: Vec<oneshot::Sender<Result<(), String>>> = Vec::new();
        let mut shaper = TrafficShaper::new(direction, traffic_script.as_deref(), post_script_off);

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
                        for responder in responders.drain(..) {
                            let _ = responder.send(Err(msg.clone()));
                        }
                        let _ = request.response_tx.send(Err(msg));
                        break;
                    }

                    // 客户端的 SETTINGS 必须随首个 control 写请求上链。
                    // 写循环串行处理 control 请求，在此前置可保证并发
                    // deferred open 的 SYN 无法越过 SETTINGS 先到达对端。
                    let mut request = request;
                    if let Some(settings) = pending_client_settings.lock().await.take() {
                        request.packets.insert(0, settings);
                    }

                    // Auto 应答解耦后，写端不等冲刷即可把后续 control 帧
                    // 送入通道；control 写（如 FIN）不得越过仍滞留在 bulk
                    // channel 中的数据。先把 bulk 队列中已到达的请求全部
                    // 并入 pending，由下面的 drive_shaper 统一冲刷。
                    while let Ok(bulk_request) = bulk_rx.try_recv() {
                        Self::queue_bulk_request(&mut pending, &mut responders, bulk_request);
                    }

                    let mut deferred_control = Vec::new();
                    if !pending.is_empty() {
                        // 钉住当前 control 请求触及的流：delay 窗口内同流
                        // 控制帧不得越过本请求插队（保序论证见 drive_shaper）。
                        let mut pinned_sids = HashSet::new();
                        for packet in &request.packets {
                            walk_frame_headers(packet, |_cmd, sid, _len| {
                                pinned_sids.insert(sid);
                            });
                        }
                        match Self::drain_pending_and_respond(
                            &mut pending,
                            &mut shaper,
                            &mut write_half,
                            &mut responders,
                            &mut control_rx,
                            &pending_client_settings,
                            direction,
                            pinned_sids,
                        )
                        .await
                        {
                            Ok(deferred) => deferred_control = deferred,
                            Err(msg) => {
                                let _ = request.response_tx.send(Err(msg));
                                break;
                            }
                        }
                    }

                    if Self::write_control_request_now(request, &mut write_half, direction)
                        .await
                        .is_err()
                    {
                        break;
                    }

                    // 窗口内暂存的 control 写按到达顺序补发（排在本请求
                    // 之后，与旧版“下一事件循环回合再处理”的相对顺序一致）。
                    if Self::write_deferred_control_requests(
                        deferred_control,
                        &mut write_half,
                        direction,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                maybe_bulk = bulk_rx.recv() => {
                    let Some(request) = maybe_bulk else { break; };

                    if close_requested.load(Ordering::Relaxed) {
                        let msg = "session writer closed".to_string();
                        for responder in responders.drain(..) {
                            let _ = responder.send(Err(msg.clone()));
                        }
                        let _ = request.response_tx.send(Err(msg));
                        break;
                    }

                    // 合批只在同一事件循环回合内发生：收首包后排空队列中
                    // 已到达的写请求，随即整批交给 shaper 冲刷。相比旧的
                    // 5ms 懒冲刷定时器，小帧不再承担固定延迟；高负载下写
                    // 请求在 drive_shaper await 期间自然积压，合批效果不变。
                    Self::queue_bulk_request(&mut pending, &mut responders, request);
                    while let Ok(request) = bulk_rx.try_recv() {
                        Self::queue_bulk_request(&mut pending, &mut responders, request);
                    }

                    if !pending.is_empty() {
                        match Self::drain_pending_and_respond(
                            &mut pending,
                            &mut shaper,
                            &mut write_half,
                            &mut responders,
                            &mut control_rx,
                            &pending_client_settings,
                            direction,
                            HashSet::new(),
                        )
                        .await
                        {
                            Ok(deferred) => {
                                // 窗口内暂存的 control 写按到达顺序补发。
                                if Self::write_deferred_control_requests(
                                    deferred,
                                    &mut write_half,
                                    direction,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        if !pending.is_empty() {
            // 收尾排空不再消费 control 通道（主循环已退出）：喂入一条已
            // 关闭的通道，delay 窗口行为与旧版一致（安静等到期满）。
            let (dead_tx, mut dead_rx) = mpsc::channel(1);
            drop(dead_tx);
            let _ = Self::drive_shaper(
                &mut pending,
                &mut shaper,
                &mut write_half,
                &mut dead_rx,
                &pending_client_settings,
                direction,
                HashSet::new(),
            )
            .await;
            for responder in responders.drain(..) {
                let _ = responder.send(Ok(()));
            }
        }
        let _ = write_half.shutdown().await;
    }

    /// 两个写循环分支共用的“排空 + 收尾”序列：drive_shaper 排空 pending，
    /// 发出 fake 帧，并应答全部 Immediate 等待者。delay 窗口内被暂存的
    /// control 写随 Ok 一并返回，由调用方按分支语义补发（control 分支
    /// 排在本请求之后，bulk 分支立即补发）；其 responder 在字节真正
    /// flush 后才应答。失败时已入队的 responder 以同一错误应答，错误
    /// 消息返回给调用方做分支专属处理。
    #[allow(clippy::too_many_arguments)]
    async fn drain_pending_and_respond(
        pending: &mut Vec<u8>,
        shaper: &mut TrafficShaper,
        write_half: &mut SplitWriteHalf,
        responders: &mut Vec<oneshot::Sender<Result<(), String>>>,
        control_rx: &mut mpsc::Receiver<WriteRequest>,
        pending_client_settings: &Arc<Mutex<Option<Vec<u8>>>>,
        direction: FlowDirection,
        pinned_sids: HashSet<u32>,
    ) -> Result<Vec<WriteRequest>, String> {
        match Self::drive_shaper(
            pending,
            shaper,
            write_half,
            control_rx,
            pending_client_settings,
            direction,
            pinned_sids,
        )
        .await
        {
            Ok((fake_frames, deferred)) => {
                let _ = Self::emit_fake_frames(write_half, direction, &fake_frames).await;
                for responder in responders.drain(..) {
                    let _ = responder.send(Ok(()));
                }
                Ok(deferred)
            }
            Err(e) => {
                let msg = e.to_string();
                for responder in responders.drain(..) {
                    let _ = responder.send(Err(msg.clone()));
                }
                Err(msg)
            }
        }
    }

    /// Append a bulk write request to the plaintext backlog. Auto writes are
    /// acked at enqueue — backpressure comes from the bounded bulk channel's
    /// send().await, so writers never wait on the shaper's flush cadence;
    /// Immediate writes queue their responder until the next drain.
    fn queue_bulk_request(
        pending: &mut Vec<u8>,
        responders: &mut Vec<oneshot::Sender<Result<(), String>>>,
        request: WriteRequest,
    ) {
        for packet in &request.packets {
            pending.extend_from_slice(packet);
        }
        if request.flush == FlushBehavior::Auto {
            let _ = request.response_tx.send(Ok(()));
        } else {
            responders.push(request.response_tx);
        }
    }

    /// Drain the plaintext backlog into individually-sized 0x17 records, each
    /// with an on-wire length dictated by the `TrafficShaper`. Unlike the old
    /// `write_all(pending)` dump, plaintext length never maps to wire size:
    /// oversized backlogs are sliced, sub-target backlogs are emitted at their
    /// shaper-chosen size.
    ///
    /// The first policy of a drain is sticky: when it allows a full block
    /// (bulk fast path), the entire backlog is carved into capacity-sized
    /// records — the tail at its exact wire length — with zero delay, no fake
    /// frames, and no per-record policy consultation. sticky 路径按
    /// STICKY_BULK_FLUSH_MAX_RECORDS / STICKY_BULK_FLUSH_MAX_BYTES 双上限
    /// 批量 flush：多次 prepare 在 write_buffer 中自然累积后统一冲刷，
    /// record 尺寸/顺序与逐条 flush 完全一致，仅减少 syscall 次数。非
    /// sticky（脚本/Markov/逐条策略）路径保持逐条 flush 不变。批量有界，
    /// write_buffer 不会无界增长。
    ///
    /// 脚本/Markov 策略的 delay 窗口内监听 control 通道：真实协议控制帧
    /// （SYN/FIN/SETTINGS/SYNACK，且不触及 pinned_sids 与 pending 数据流）
    /// 立即 prepare+flush 插队上链——真实 H2 端点本就优先控制帧；其余
    /// control 写（CMD_PADDING 骨架/假响应等）暂存返回，由主循环按到达
    /// 顺序补发。data record 的尺寸、数量、delay 时长分布严格不变。
    ///
    /// Returns (fake_frames, deferred_control_writes)：fake 帧由调用方走
    /// control 路径发出；暂存的 control 写按到达顺序补发，其 responder
    /// 必须在字节真正 flush 后才应答 Ok。
    #[allow(clippy::too_many_arguments)]
    async fn drive_shaper(
        pending: &mut Vec<u8>,
        shaper: &mut TrafficShaper,
        write_half: &mut SplitWriteHalf,
        control_rx: &mut mpsc::Receiver<WriteRequest>,
        pending_client_settings: &Arc<Mutex<Option<Vec<u8>>>>,
        direction: FlowDirection,
        mut pinned_sids: HashSet<u32>,
    ) -> std::io::Result<(Vec<Vec<u8>>, Vec<WriteRequest>)> {
        let mut fake_frames = Vec::new();
        let mut deferred_control = Vec::new();
        let mut consumed = 0usize;

        // 钉住 pending 积压中的数据流：同流控制帧（如 FIN）不得越过仍在
        // 积压中的数据插队，否则对端会因 FIN 先至而丢弃其后的数据。
        // 同时记录全部帧边界偏移：wire 协议没有 record 边界标记，对端把
        // 各 record 的块载荷拼接后重组帧，插队 control 帧只能落在完整帧
        // 边界上（旧实现靠“先排空 pending 再写 control”隐式保证）。
        let mut frame_boundaries = HashSet::new();
        let mut frame_offset = 0usize;
        walk_frame_headers(pending, |cmd, sid, frame_len| {
            if cmd == CMD_PSH {
                pinned_sids.insert(sid);
            }
            frame_offset += frame_len;
            frame_boundaries.insert(frame_offset);
        });

        let mut first_policy = if pending.is_empty() {
            None
        } else {
            Some(shaper.next_data_policy(pending.len()))
        };
        let sticky_full_block = first_policy
            .as_ref()
            .is_some_and(|policy| policy.allow_full_block);

        // sticky 批量 flush 记账：自上次 flush 以来累积的 record 条数。
        let mut batched_records = 0usize;

        loop {
            if consumed >= pending.len() {
                break;
            }
            let remaining = pending.len() - consumed;
            let policy = match first_policy.take() {
                Some(policy) => policy,
                None if sticky_full_block => {
                    let take = remaining.min(SnowyStream::data_record_capacity());
                    ShapePolicy {
                        target_wire_len: if take == SnowyStream::data_record_capacity() {
                            SnowyStream::max_data_record_wire_len()
                        } else {
                            SnowyStream::data_record_wire_len(take)
                        },
                        delay: Duration::ZERO,
                        fake: None,
                        allow_full_block: true,
                    }
                }
                None => shaper.next_data_policy(remaining),
            };
            let overhead = kanotls_tunnel::common::MIN_DATA_WIRE_LEN;
            let payload_cap = policy
                .target_wire_len
                .saturating_sub(overhead)
                .min(SnowyStream::data_record_capacity());
            let take = payload_cap.min(remaining);

            {
                let slice = &pending[consumed..consumed + take];
                write_half.with_stream(|stream| {
                    stream.prepare_data_record(slice, policy.target_wire_len)
                })?;
            }

            consumed += take;
            shaper.advance();

            if sticky_full_block {
                batched_records += 1;
                let buffered = write_half.with_stream(|stream| stream.buffered_write_len());
                if batched_records >= STICKY_BULK_FLUSH_MAX_RECORDS
                    || buffered >= STICKY_BULK_FLUSH_MAX_BYTES
                {
                    write_half.flush().await?;
                    batched_records = 0;
                }
            } else {
                write_half.flush().await?;
            }

            if let Some(fake) = &policy.fake {
                let mut encoded = Vec::new();
                encode_padding_request_into(&mut encoded, fake.responses);
                fake_frames.push(encoded);
            }

            if policy.delay > Duration::ZERO {
                Self::wait_shaping_delay(
                    policy.delay,
                    frame_boundaries.contains(&consumed),
                    write_half,
                    control_rx,
                    pending_client_settings,
                    direction,
                    &mut pinned_sids,
                    &mut deferred_control,
                )
                .await?;
            }
        }

        if sticky_full_block && batched_records > 0 {
            write_half.flush().await?;
        }

        pending.clear();
        Ok((fake_frames, deferred_control))
    }

    /// 整形 delay 窗口：挂起 data record 节奏期间同时监听 control 通道。
    /// 窗口内到达的真实协议控制帧立即上链，其余 control 写暂存；deadline
    /// 不变（等待至 delay 期满），data record 间隔分布严格不变。
    /// at_frame_boundary：当前 drain 偏移是否恰好落在完整帧边界——只有
    /// 边界处才允许插队，否则 control 帧会插进某个 PSH 帧的载荷中间，
    /// 破坏对端帧重组。
    #[allow(clippy::too_many_arguments)]
    async fn wait_shaping_delay(
        delay: Duration,
        at_frame_boundary: bool,
        write_half: &mut SplitWriteHalf,
        control_rx: &mut mpsc::Receiver<WriteRequest>,
        pending_client_settings: &Arc<Mutex<Option<Vec<u8>>>>,
        direction: FlowDirection,
        pinned_sids: &mut HashSet<u32>,
        deferred: &mut Vec<WriteRequest>,
    ) -> std::io::Result<()> {
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                maybe_control = control_rx.recv() => {
                    let Some(mut request) = maybe_control else {
                        // control 通道已关闭：安静等到窗口期满。
                        sleep.await;
                        break;
                    };
                    // 与主 control 分支同一口径：客户端首个 control 写请求
                    // 携带 SETTINGS，并发 deferred open 的 SYN 无法越过
                    // SETTINGS 先到达对端。
                    if let Some(settings) = pending_client_settings.lock().await.take() {
                        request.packets.insert(0, settings);
                    }
                    // 已有暂存写时禁止后续插队：控制写在本 drain 内保持严格
                    // FIFO。否则后到的 SYN 可能越过被暂存的 SETTINGS+SYN 先
                    // 到达对端，而服务端会丢弃先于 SETTINGS 的 SYN。
                    if deferred.is_empty()
                        && at_frame_boundary
                        && control_write_can_pass_through(&request, pinned_sids)
                    {
                        Self::write_control_request_now(request, write_half, direction)
                            .await
                            .map_err(std::io::Error::other)?;
                    } else {
                        // 暂存请求触及的流一并钉住：后续窗口内同流控制帧
                        // 不得越过暂存写插队（保持到达顺序）。
                        for packet in &request.packets {
                            walk_frame_headers(packet, |_cmd, sid, _len| {
                                pinned_sids.insert(sid);
                            });
                        }
                        deferred.push(request);
                    }
                }
            }
        }
        Ok(())
    }

    /// 单条 control 写请求的 prepare + flush + 应答：主 control 分支、
    /// delay 窗口插队、窗口暂存补发共用同一口径。responder 在字节真正
    /// flush 完成后才收到 Ok；失败时先应答 Err 再把错误交调用方终止
    /// 写循环。
    async fn write_control_request_now(
        request: WriteRequest,
        write_half: &mut SplitWriteHalf,
        direction: FlowDirection,
    ) -> Result<(), String> {
        let state = write_half.with_stream(|stream| stream.control_state());
        for packet in &request.packets {
            let result = write_half.with_stream(|stream| {
                let size = stream.next_control_size(state, direction);
                trace!(
                    "control write: frame_cmd=0x{:02x} wire_size={}",
                    packet.first().unwrap_or(&0),
                    size
                );
                stream.prepare_control_record(packet, size)
            });
            if let Err(e) = result {
                let msg = e.to_string();
                let _ = request.response_tx.send(Err(msg.clone()));
                return Err(msg);
            }
        }
        match write_half.flush().await {
            Ok(()) => {
                let _ = request.response_tx.send(Ok(()));
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                let _ = request.response_tx.send(Err(msg.clone()));
                Err(msg)
            }
        }
    }

    /// 窗口暂存 control 写的补发：按到达顺序逐条 prepare+flush，任一
    /// 失败即终止（失败请求的 responder 已在 write_control_request_now
    /// 内应答 Err）。
    async fn write_deferred_control_requests(
        deferred: Vec<WriteRequest>,
        write_half: &mut SplitWriteHalf,
        direction: FlowDirection,
    ) -> Result<(), String> {
        for request in deferred {
            Self::write_control_request_now(request, write_half, direction).await?;
        }
        Ok(())
    }

    /// Emit fake-response control frames generated by the shaper.
    async fn emit_fake_frames(
        write_half: &mut SplitWriteHalf,
        direction: FlowDirection,
        frames: &[Vec<u8>],
    ) -> std::io::Result<()> {
        if frames.is_empty() {
            return Ok(());
        }
        write_half.with_stream(|stream| {
            let state = stream.control_state();
            for packet in frames {
                let size = stream.next_control_size(state, direction);
                stream.prepare_control_record(packet, size)?;
            }
            std::io::Result::Ok(())
        })?;
        write_half.flush().await
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
        // 三处状态先尝试同步移除；全部成功则无需再 spawn 异步重复移除。
        let streams_done = self
            .streams
            .try_write()
            .map(|mut guard| {
                unregister_stream_locked(&mut guard, &self.capacity_stream_count, stream_id);
            })
            .is_ok();
        let pending_data_done = self
            .pending_data
            .try_lock()
            .map(|mut pending| {
                pending.remove(stream_id);
            })
            .is_ok();
        let pending_fin_done = self
            .pending_fin
            .try_lock()
            .map(|mut pending| {
                pending.remove(&stream_id);
            })
            .is_ok();

        let cleanup = self.cleanup.take();
        if let Some(cleanup) = cleanup.as_ref() {
            remember_closing_stream_sync(stream_id, &self.closing_streams);
            let _ = crate::stream::try_send_fin_frame(stream_id, &cleanup.writer);
        }

        if streams_done && pending_data_done && pending_fin_done {
            return;
        }
        let streams = self.streams.clone();
        let capacity_stream_count = self.capacity_stream_count.clone();
        let pending_data = self.pending_data.clone();
        let pending_fin = self.pending_fin.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                unregister_stream_locked(
                    &mut *streams.write().await,
                    &capacity_stream_count,
                    stream_id,
                );
                pending_data.lock().await.remove(stream_id);
                pending_fin.lock().await.remove(&stream_id);
            });
        }
    }
}

impl Session {
    fn prune_orphaned_streams_locked(
        streams: &mut HashMap<u32, StreamHandle>,
        capacity_stream_count: &AtomicUsize,
    ) {
        streams.retain(|_, handle| {
            let orphaned = stream_handle_is_orphaned(handle);
            // 计数口径：read_closed 句柄在置位时已扣减过容量计数，
            // prune 时不得重复扣减；仅 read_closed=false 的 orphan 入账。
            if orphaned && !handle.read_closed {
                capacity_stream_count.fetch_sub(1, Ordering::Relaxed);
            }
            !orphaned
        });
    }
}

/// orphan 判定：三个 channel 全部关闭（消费者已走，句柄不再可达）。
/// read_closed 句柄同样适用——已 read_closed 且 channel 全关的句柄
/// 残留于 streams 映射会在长连接+大量短流场景下缓慢泄漏。
fn stream_handle_is_orphaned(handle: &StreamHandle) -> bool {
    handle.data_tx.is_closed()
        && handle.fin_tx.is_closed()
        && handle
            .synack_tx
            .as_ref()
            .map(|tx| tx.is_closed())
            .unwrap_or(true)
}

/// 向 streams 映射注册新流：映射与 capacity_stream_count 保持同增同减。
pub(crate) fn register_stream_locked(
    streams: &mut HashMap<u32, StreamHandle>,
    capacity_stream_count: &AtomicUsize,
    sid: u32,
    handle: StreamHandle,
) {
    streams.insert(sid, handle);
    capacity_stream_count.fetch_add(1, Ordering::Relaxed);
}

/// 从 streams 映射移除流：仅当条目仍计入容量（read_closed=false）时扣减，
/// 与 read_closed 置位处的扣减互斥，保证每条流恰好扣一次。
pub(crate) fn unregister_stream_locked(
    streams: &mut HashMap<u32, StreamHandle>,
    capacity_stream_count: &AtomicUsize,
    sid: u32,
) {
    if let Some(handle) = streams.remove(&sid) {
        if !handle.read_closed {
            capacity_stream_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// 置位 read_closed 并按口径扣减容量计数（幂等：已置位时不再重复扣）。
pub(crate) fn mark_stream_read_closed_locked(
    handle: &mut StreamHandle,
    capacity_stream_count: &AtomicUsize,
) {
    if !handle.read_closed {
        handle.read_closed = true;
        capacity_stream_count.fetch_sub(1, Ordering::Relaxed);
    }
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

/// buffered_stream_bytes 的统一减法口径：任何扣减都不允许下溢回绕。
pub(crate) fn subtract_buffered_stream_bytes(counter: &AtomicUsize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(bytes))
    });
}

#[cfg(test)]
mod tests;
