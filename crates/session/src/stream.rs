use crate::frame::{coalesce_encoded_frames, encode_psh_frames, Frame, MAX_PAYLOAD_LEN};
use crate::session::{
    mark_stream_read_closed_locked, peer_never_processed, remember_closing_stream_sync,
    unregister_stream_locked, BufferedPayload, FlushBehavior, PendingData, PendingWrite,
    SharedTunnelWriter, StreamHandle, TrafficClass, WindowState,
};
use anyhow::Error;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::{mpsc, oneshot, Notify, RwLock};

const SYNACK_TIMEOUT_SECS: u64 = 10;

/// 对端 GOAWAY 判定「这条流从未被处理」时，本流对外报出的错误前缀。
///
/// **为什么需要一个可区分的错误**：连接池把 `streams_per_connection_target`
/// 提到 256（= `max_streams_per_session`）之后，一条隧道连接的死亡最多牵连
/// 256 条流，而 KanoTLS 没有流迁移。真实 H2 的爆炸半径一样大，但浏览器在
/// **HTTP 层**对幂等请求做重试；SOCKS 代理没有这一层，应用只看到 socket 被
/// 关闭。此前无论「对端已经把请求转给源站后才断」还是「对端连 SYN 都没读到」，
/// 上层拿到的都是同一个泛型错误（`session writer closed` / EOF），于是**没有
/// 任何一条流可以被安全地重试**——重试一条可能已经执行过的非幂等请求比不重试
/// 更糟。
///
/// 拿到 GOAWAY 的 `last_stream_id` 之后这两种情形第一次可分：`stream_id`
/// 高于它 ⇒ 对端的读循环根本没走到这条流的 CMD_SYN ⇒ 重试无副作用。
///
/// 前缀是给跨 crate 调用方（`kanotls/**`）的稳定标识；不想匹配字符串的调用方
/// 用 [`Stream::peer_never_processed`]。
pub const PEER_NEVER_PROCESSED_ERROR: &str = "stream was never processed by the peer";

/// 「开流未发出」的宽限期：本端迟迟不写第一个字节时，`read()` 等到此刻就
/// 把 open（SYN + 目标地址）单独发出去。
///
/// **修的是什么**：`defer_target` 把目标地址挂在「首次写入」上，而
/// `relay_tcp_client` 对本地连接与隧道流是双向轮询——**服务端先说话**的协议
/// （SSH / SMTP / IMAP / MySQL…）里本端根本不会先写，于是目标地址永远到不了
/// 对端：服务端要么完全不知道这条流存在（首条流，SYN 也还压在
/// `DeferredUnsent` 里），要么 accept 之后卡在 `read()` 上等目标。两边互等，
/// 直到 SOCKS 客户端自己超时。实测两条路径都挂（见
/// `deferred_open_reaches_peer_without_a_local_first_write`）。
///
/// **为什么不能「读侧一被调用就冲刷」**：客户端先说话的协议里读侧同样会立刻
/// 被调用，于是 gather 优化（`[SETTINGS][SYN][PSH(target)][PSH(首块)]` 合并成
/// 一次提交）会被无条件摧毁——而那条合并正是「每条流的开场只占一条 shaper
/// 定尺寸的记录」的前提。宽限期让两者共存：客户端先说话时本端在毫秒级内就
/// 写了，计时器永远不触发；服务端先说话时它是唯一的出路。
///
/// **驱动点**：未拆半的 `Stream` 由 `Stream::read` 内联驱动（计时器在
/// `select!` 反复取消重建时不归零，靠 `open_flush_deadline` 字段记住截止
/// 时刻）；`into_split` 拆半后读半拿不到写半的开流状态，改由中继上行任务
/// 用 `StreamWriteHalf::open_grace_deadline` 武装一次性计时器，到期调
/// `flush_unsent_open_if_pending`——截止时刻从「首次读挂起」变为「拆半」，
/// 两者在真实中继里只差毫秒级。
///
/// **取值**：40ms。下界要显著大于本地应用产出首字节的时延（环回/局域网上是
/// 亚毫秒到几毫秒），否则会误伤 gather；上界要显著小于服务端先说话的协议
/// 本来就要付的「代理 RTT + 源站 connect + banner」，40ms 在这两者之间有充足
/// 余量。命中宽限期与否不改变端到端时延的量级——两条路径都是「open 发出后
/// 才轮到源站」，宽限期只决定 open 什么时候发出。
///
/// **为什么是定值而不是抖动值**：与 `PEER_TURN_MAX_WAIT` /
/// `H2_EXCHANGE_MAX_INTERVAL_SECS` 同一口径——这是一个**截止期**，不是 IAT
/// 模型。它可观测的形态是「目标记录之后、下一条上行记录在 X 之后」，而那个
/// X 由源站 banner 的往返决定，不由本常量决定；本常量只决定目标记录相对
/// 「开流」这一**对端无法观测的时刻**的偏移。对第 2..N 条流，线上确实存在
/// 「SYN 记录 → 40ms → 目标记录」这一对，但两条记录都已按数据记录分布定
/// 尺寸（见 `packet_carries_stream_lifecycle_frame`），观测者无从判定它们
/// 属于同一条流；而在真实 H2 上「HEADERS → 数十毫秒 → 请求体」本就是常态。
const DEFERRED_OPEN_GRACE: std::time::Duration = std::time::Duration::from_millis(40);

/// 宽限计时器的「禁用」姿态：分支被 select guard 屏蔽，deadline 只需足够
/// 遥远（与 `session.rs` 的 `H2_TIMER_DISABLED` 同一手法）。
const DEFERRED_OPEN_GRACE_DISABLED: std::time::Duration = std::time::Duration::from_secs(3600);

/// 测试覆写点：0 表示使用上面的生产常量。
pub(crate) static DEFERRED_OPEN_GRACE_OVERRIDE_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn deferred_open_grace() -> std::time::Duration {
    let override_ms = DEFERRED_OPEN_GRACE_OVERRIDE_MS.load(std::sync::atomic::Ordering::Relaxed);
    if override_ms > 0 {
        return std::time::Duration::from_millis(override_ms);
    }
    DEFERRED_OPEN_GRACE
}

// Distinguish a deferred open that can still be retried from one whose bytes
// are already committed to the session writer.
pub(crate) enum StreamOpenState {
    DeferredUnsent(Vec<Vec<u8>>),
    Submitted {
        pending_write: Option<PendingWrite>,
        early_data_submitted: bool,
    },
}

pub(crate) struct StreamParts {
    pub data_rx: mpsc::Receiver<BufferedPayload>,
    pub fin_rx: mpsc::Receiver<()>,
    pub synack_rx: oneshot::Receiver<Vec<u8>>,
}

pub(crate) struct StreamInit {
    pub stream_id: u32,
    pub parts: StreamParts,
    pub writer: SharedTunnelWriter,
    pub streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pub capacity_stream_count: Arc<AtomicUsize>,
    pub pending_data: Arc<Mutex<PendingData>>,
    pub pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    pub closing_streams: Arc<Mutex<std::collections::HashSet<u32>>>,
    pub pending_notify: Arc<Notify>,
    /// 本流发送方向剩余信贷（与句柄中的同一 Arc，见 StreamHandle::send_credit）。
    pub send_credit: Arc<AtomicI64>,
    /// 会话级流控状态（连接级窗口 + 回补记账）。
    pub windows: Arc<WindowState>,
    pub peer_goaway_last_stream_id: Arc<AtomicU64>,
    pub open_state: StreamOpenState,
}

/// 写半 drop 时留下的状态快照：拆除协调器据此选择安全网路径，字段与
/// 拆分前 `Stream::drop` 当场读取的那几个一一对应。
struct WriteEndState {
    /// 等价拆分前的 `has_deferred_open() || open_failed.is_some()`。
    open_never_sent_or_failed: bool,
    write_closed: bool,
    pending_open_write: Option<PendingWrite>,
    wait_for_pending_open: bool,
}

/// 整条流的拆除协调器：读/写两半各持一份，`close*` 与安全网拆除的所有
/// 路径都收敛到这里，保证「FIN + 注销 + 清 pending」对整条流恰好执行
/// 一次——无论流以整体（`Stream` 字段成对 drop）还是拆半（两个中继
/// 任务各自 drop）的形式终结。
pub(crate) struct StreamTeardown {
    stream_id: u32,
    streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    capacity_stream_count: Arc<AtomicUsize>,
    pending_data: Arc<Mutex<PendingData>>,
    pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    closing_streams: Arc<Mutex<std::collections::HashSet<u32>>>,
    writer: SharedTunnelWriter,
    /// 仍存活的半句柄数（恒从 2 起步：未拆半的 `Stream` 也只是同时持有
    /// 两半）。归零时由最后放手的一方执行安全网拆除。
    halves_alive: AtomicU8,
    /// `close()`（或 `close_write` 的轻拆除分支）已完成：安全网短路。
    fully_closed: AtomicBool,
    write_end: std::sync::Mutex<Option<WriteEndState>>,
}

impl StreamTeardown {
    /// 注销 + 清 pending（`close` 系列路径的公共收尾；各辅助函数幂等）。
    async fn cleanup_registration(&self) {
        unregister_stream_locked(
            &mut *self.streams.write().await,
            &self.capacity_stream_count,
            self.stream_id,
        );
        // 移除的入账载荷随队列丢弃自动回账。
        self.pending_data.lock().await.remove(self.stream_id);
        self.pending_fin.lock().await.remove(&self.stream_id);
    }

    /// 「开流未发出/已失败」的轻拆除：对端根本不知道这条流，不发 FIN、
    /// 不记 closing（等价拆分前 `close_write`/`Drop` 的该分支）。
    async fn light_teardown(&self) {
        self.fully_closed.store(true, Ordering::Relaxed);
        self.cleanup_registration().await;
    }

    /// 半句柄计数归零时的安全网拆除（等价拆分前 `Stream::drop` 的职责）。
    fn half_dropped(&self) {
        if self.halves_alive.fetch_sub(1, Ordering::Relaxed) != 1 {
            return;
        }
        if self.fully_closed.load(Ordering::Relaxed) {
            return;
        }
        let end = self.write_end.lock().unwrap().take();
        let (light, write_closed, pending_open_write, wait_for_pending_open) = match end {
            Some(s) => (
                s.open_never_sent_or_failed,
                s.write_closed,
                s.pending_open_write,
                s.wait_for_pending_open,
            ),
            // 写半先走时必有快照；读半最后走而没有快照只可能发生在写半
            // 被 mem::forget 之类的非常规路径，按「未关写侧」兜底即可。
            None => (false, false, None, false),
        };

        if light {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let streams = self.streams.clone();
                let capacity_stream_count = self.capacity_stream_count.clone();
                let pending_data = self.pending_data.clone();
                let pending_fin = self.pending_fin.clone();
                let stream_id = self.stream_id;
                handle.spawn(async move {
                    unregister_stream_locked(
                        &mut *streams.write().await,
                        &capacity_stream_count,
                        stream_id,
                    );
                    pending_data.lock().await.remove(stream_id);
                    pending_fin.lock().await.remove(&stream_id);
                });
            } else {
                if let Ok(mut streams) = self.streams.try_write() {
                    unregister_stream_locked(&mut streams, &self.capacity_stream_count, self.stream_id);
                }
                if let Ok(mut pending_data) = self.pending_data.try_lock() {
                    pending_data.remove(self.stream_id);
                }
                if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
                    pending_fin.remove(&self.stream_id);
                }
            }
            return;
        }

        let stream_id = self.stream_id;
        remember_closing_stream_sync(stream_id, &self.closing_streams);
        let fin_queued =
            !write_closed && !wait_for_pending_open && try_send_fin_frame(stream_id, &self.writer).is_ok();
        if let Ok(mut streams) = self.streams.try_write() {
            if let Some(handle) = streams.get_mut(&stream_id) {
                mark_stream_read_closed_locked(handle, &self.capacity_stream_count);
            }
        }
        if let Ok(mut pending_data) = self.pending_data.try_lock() {
            pending_data.remove(stream_id);
        }
        if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
            pending_fin.remove(&stream_id);
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let streams = self.streams.clone();
            let capacity_stream_count = self.capacity_stream_count.clone();
            let pending_data = self.pending_data.clone();
            let pending_fin = self.pending_fin.clone();
            let writer = self.writer.clone();
            handle.spawn(async move {
                if let Some(mut pending_write) = pending_open_write {
                    if wait_for_pending_open {
                        let _ = pending_write.wait().await;
                    }
                }
                if !write_closed && !fin_queued {
                    let _ = send_fin_frame(stream_id, writer).await;
                }
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

/// 隧道流的读半（`into_split` 产物）：交付对端数据 + 每流消费回补。
///
/// 与写半完全解耦：写方向在流控门（`acquire_credit`）挂起等
/// WINDOW_UPDATE 时，读方向的交付与回补照常进行。拆分前的单任务
/// 全双工中继里，`write().await` 的挂起会同时冻住读方向，反向回补
/// 随之中断，双向饱和时两端互等形成无定时器的死锁环。
pub struct StreamReadHalf {
    pub stream_id: u32,
    data_rx: mpsc::Receiver<BufferedPayload>,
    fin_rx: mpsc::Receiver<()>,
    pending_data: Arc<Mutex<PendingData>>,
    pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    pending_notify: Arc<Notify>,
    /// 本流**接收**方向已消费、尚未回补的字节（单消费者：本端中继独占，
    /// fetch_add/fetch_sub 安全）。
    consumed_since_wu: AtomicU64,
    windows: Arc<WindowState>,
    peer_goaway_last_stream_id: Arc<AtomicU64>,
    read_closed: bool,
    teardown: Arc<StreamTeardown>,
}

impl StreamReadHalf {
    pub async fn read(&mut self) -> Option<Bytes> {
        loop {
            if let Ok(payload) = self.data_rx.try_recv() {
                return Some(payload.into_bytes());
            }
            // 先注册再检查：pending 数据到达用 `notify_waiters`（不留
            // permit），若先检查后注册，间隙到达的通知会被丢掉。
            // 克隆 Arc 是为了让 Notified 不借用 self。
            let pending_notify = self.pending_notify.clone();
            let pending_notified = pending_notify.notified();
            tokio::pin!(pending_notified);
            let _ = pending_notified.as_mut().enable();
            if let Some(data) = self.try_drain_pending_data() {
                return Some(data);
            }
            if self.read_closed {
                return None;
            }

            tokio::select! {
                payload = self.data_rx.recv() => {
                    return payload.map(BufferedPayload::into_bytes);
                }
                _ = pending_notified => {
                    continue;
                }
                _ = self.fin_rx.recv() => {
                    // 先置 read_closed 再回路排空：channel/pending_data 中的
                    // 残留数据仍会在返回 None 之前被投递（见循环开头两步）。
                    // fin 令牌只此一枚——若消费令牌后因恰好又有数据而直接返回，
                    // 却不置位，一旦后续出现乱序/丢帧，read 将永远挂在 select。
                    self.read_closed = true;
                    continue;
                }
            }
        }
    }

    /// 接收侧每流回补入账：中继在字节真正交付本地应用后调用（H2 语义，
    /// 见 `WindowState::note_consumed`）。
    pub fn note_consumed(&self, len: usize) {
        self.windows
            .note_consumed(self.stream_id, &self.consumed_since_wu, len);
    }

    /// 对端的 GOAWAY 是否宣告本流从未被处理（见 `Stream::peer_never_processed`）。
    pub fn peer_never_processed(&self) -> bool {
        peer_never_processed(&self.peer_goaway_last_stream_id, self.stream_id)
    }

    fn try_drain_pending_data(&mut self) -> Option<Bytes> {
        let mut pending = self.pending_data.try_lock().ok()?;
        let Some(payload) = pending.pop_front(self.stream_id) else {
            // pending_data 已排空：若 pre-SYNACK 的 FIN 曾因部分投递被退回
            // 重挂（flush_client_pending_stream），此刻即应补投为 EOF。
            drop(pending);
            self.take_queued_pending_fin();
            return None;
        };
        // pop_front 排空时会移除条目，因此 contains 即「是否仍有积压」。
        let drained = !pending.contains(self.stream_id);
        drop(pending);
        if drained {
            self.take_queued_pending_fin();
        }
        Some(payload.into_bytes())
    }

    fn take_queued_pending_fin(&mut self) {
        if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
            if pending_fin.remove(&self.stream_id) {
                self.read_closed = true;
            }
        }
    }
}

impl Drop for StreamReadHalf {
    fn drop(&mut self) {
        // 读半先死：立刻在句柄上标记 read_closed，让迟到的数据走 Closing
        // 路径而不是占着缓冲（幂等；等价拆分前 Drop 里的对应一步）。
        if let Ok(mut streams) = self.teardown.streams.try_write() {
            if let Some(handle) = streams.get_mut(&self.stream_id) {
                mark_stream_read_closed_locked(handle, &self.teardown.capacity_stream_count);
            }
        }
        self.teardown.half_dropped();
    }
}

/// 隧道流的写半（`into_split` 产物）：开流（SYN/目标地址/宽限期冲刷）、
/// 数据写入（流控门）、半关与全关。
pub struct StreamWriteHalf {
    pub stream_id: u32,
    synack_rx: Option<oneshot::Receiver<Vec<u8>>>,
    writer: SharedTunnelWriter,
    pending_notify: Arc<Notify>,
    /// 本流发送方向剩余信贷（H2 每流窗口；与句柄共享，见
    /// `WindowState::acquire_credit`）。
    send_credit: Arc<AtomicI64>,
    /// 会话级流控状态：连接级窗口、fc 协商与回补记账。
    windows: Arc<WindowState>,
    /// 对端 GOAWAY 的 `last_stream_id`（见 `Session::peer_never_processed`）：
    /// 本流 id 高于它 ⇒ 对端从未处理过这条流。
    peer_goaway_last_stream_id: Arc<AtomicU64>,
    open_state: StreamOpenState,
    deferred_target: Option<Vec<u8>>,
    write_closed: bool,
    closed: bool,
    open_failed: Option<String>,
    teardown: Arc<StreamTeardown>,
}

impl StreamWriteHalf {
    pub fn defer_target(&mut self, target: &[u8]) {
        self.deferred_target = Some(target.to_vec());
    }

    /// 开流宽限期的截止时刻：开流仍未出网时返回 `Some`（从拆半起算，
    /// 论证见 `DEFERRED_OPEN_GRACE`），否则 `None`。供拆半中继的上行
    /// 任务武装一次性计时器。
    pub fn open_grace_deadline(&self) -> Option<tokio::time::Instant> {
        if self.open_is_unsent() {
            Some(tokio::time::Instant::now() + deferred_open_grace())
        } else {
            None
        }
    }

    /// 宽限期到期：开流仍未出网才把开场（不带数据）发出去；已出网则
    /// 空操作。等价拆分前 `Stream::read` 里的宽限分支。
    pub async fn flush_unsent_open_if_pending(&mut self) -> Result<(), anyhow::Error> {
        if !self.open_is_unsent() {
            return Ok(());
        }
        self.flush_unsent_open().await
    }

    pub async fn write_early(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        if let Some(err) = self.goaway_retry_error() {
            return Err(err);
        }
        if let Some(msg) = &self.open_failed {
            anyhow::bail!(msg.clone());
        }
        // 先检关闭再扣信贷：反向顺序会为注定失败的写白扣一份窗口。
        if self.write_closed || self.closed {
            anyhow::bail!("stream write side is closed");
        }
        // 发送侧流控门（H2 语义，见 WindowState::acquire_credit）：窗口不足
        // 即挂起等对端 WINDOW_UPDATE，接收缓冲被窗口界定，此前的
        // 「超限丢数据 + 杀流」结构性不可达。对未声明 fc 的对端整体旁路。
        self.windows
            .acquire_credit(&self.send_credit, &self.pending_notify, data.len())
            .await;
        if self.has_deferred_open() {
            return self.write_pending_open_with_data(data).await;
        }

        self.finish_pending_open_submission().await?;
        // 此前 `early_data_already_submitted()` 时直接 `return Ok(())`，把本次
        // 载荷静默丢弃；开场数据已经随 SYN 出网只说明「早前的那一份」发了，
        // 这一次的字节仍必须按普通数据帧写出去。
        self.write_data_frame_with_flush(data, FlushBehavior::Immediate)
            .await
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        // GOAWAY 的判定先于 open_failed：TCP CONNECT 中继（`relay_tcp_client`）
        // 从不 `wait_open()`，本流的失败第一次浮到应用层就是在这里。
        if let Some(err) = self.goaway_retry_error() {
            return Err(err);
        }
        if let Some(msg) = &self.open_failed {
            anyhow::bail!(msg.clone());
        }
        // 先检关闭再扣信贷：反向顺序会为注定失败的写白扣一份窗口。
        if self.write_closed || self.closed {
            anyhow::bail!("stream write side is closed");
        }

        // 流控门在各终态路径内部各扣恰好一次（write_gather_open 连目标
        // 地址一起扣，write_early / 普通路径只扣数据）——此处不再统一
        // 预扣：此前预扣 + write_early 内再扣会让开场首写被双倍扣费，
        // 每条流的首块数据永久漏掉一份窗口信贷。
        if let Some(target) = self.deferred_target.take() {
            return self.write_gather_open(&target, data).await;
        }

        if self.has_deferred_open() {
            return self.write_early(data).await;
        }

        self.windows
            .acquire_credit(&self.send_credit, &self.pending_notify, data.len())
            .await;
        self.finish_pending_open_submission().await?;
        self.write_data_frame(data).await
    }

    /// 对端的 GOAWAY 是否宣告本流从未被处理 ⇒ 重放这条流无副作用。
    ///
    /// 没收到 GOAWAY（本端主动关、TCP 被打断、对端是未升级的旧版本）时恒为
    /// `false`：这个判据只做加法，不改变任何既有失败路径的语义。
    ///
    /// 判据的可信度等同于对端本身：`last_stream_id` 由已通过 Noise PSK 认证的
    /// 对端给出，一个作恶的对端可以谎报 0 把本端全部流标成「可重试」。这在本轮
    /// 只影响错误文案；**任何**真正的自动重放逻辑都必须自己评估这一点。
    pub fn peer_never_processed(&self) -> bool {
        peer_never_processed(&self.peer_goaway_last_stream_id, self.stream_id)
    }

    /// 本流被 GOAWAY 判定为未处理时的可区分错误。
    ///
    /// 优先级高于 `open_failed`：后者多半已经被写路径填成泛型的
    /// `session writer closed`，而 GOAWAY 携带的是严格更强的信息。
    fn goaway_retry_error(&self) -> Option<anyhow::Error> {
        if !self.peer_never_processed() {
            return None;
        }
        Some(anyhow::anyhow!(
            "{} (stream {}); safe to retry",
            PEER_NEVER_PROCESSED_ERROR,
            self.stream_id
        ))
    }

    async fn wait_synack(&mut self) -> Result<(), anyhow::Error> {
        if let Some(err) = self.goaway_retry_error() {
            return Err(err);
        }
        if let Some(msg) = &self.open_failed {
            anyhow::bail!(msg.clone());
        }
        self.flush_pending_open_frames().await?;
        self.wait_synack_once().await
    }

    pub async fn wait_open(&mut self) -> Result<(), anyhow::Error> {
        self.wait_synack().await
    }

    async fn write_data_frame(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.write_data_frame_with_flush(data, FlushBehavior::Auto)
            .await
    }

    async fn write_data_frame_with_flush(
        &mut self,
        data: &[u8],
        flush: FlushBehavior,
    ) -> Result<(), anyhow::Error> {
        if self.write_closed || self.closed {
            anyhow::bail!("stream write side is closed");
        }
        if data.is_empty() {
            self.write_frame(Frame::psh(self.stream_id, Vec::new()))
                .await?;
            return Ok(());
        }

        let packets = encode_psh_frames(self.stream_id, data)?;
        self.writer
            .write_packets(packets, flush, TrafficClass::Bulk)
            .await
    }

    async fn write_pending_open_with_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        let Some(mut frames) = self.deferred_open_frames() else {
            return self
                .write_data_frame_with_flush(data, FlushBehavior::Immediate)
                .await;
        };
        if data.is_empty() {
            frames.push(Frame::psh(self.stream_id, Vec::new()).encode()?);
        } else {
            frames.extend(encode_psh_frames(self.stream_id, data)?);
        }
        let packets = self.coalesce_and_pad(frames)?;

        // SETTINGS/SYN and the target payload must reach the peer before we
        // wait on SYNACK; otherwise the bytes can remain buffered inside the
        // tunnel writer and the stream appears to hang or time out.
        let pending_write = match self
            .writer
            .submit_write_packets(packets, FlushBehavior::Immediate, TrafficClass::Control)
            .await
        {
            Ok(pending_write) => pending_write,
            Err(err) => {
                self.writer.close();
                self.open_failed = Some(err.to_string());
                return Err(err);
            }
        };

        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: true,
        };

        self.finish_pending_open_submission().await
    }

    async fn write_gather_open(&mut self, target: &[u8], data: &[u8]) -> Result<(), anyhow::Error> {
        // 流控门：目标地址与数据在同一批 PSH 帧里出网，接收侧按帧载荷
        // 「收到即回补」，故这里把两者一起扣，计账口径与接收侧对称。
        self.windows
            .acquire_credit(
                &self.send_credit,
                &self.pending_notify,
                target.len() + data.len(),
            )
            .await;
        let Some(mut frames) = self.deferred_open_frames() else {
            self.finish_pending_open_submission().await?;
            let mut combined_frames = encode_psh_frames(self.stream_id, target)?;
            if !data.is_empty() {
                combined_frames.extend(encode_psh_frames(self.stream_id, data)?);
            }
            let packets = self.coalesce_and_pad(combined_frames)?;
            return self
                .writer
                .write_packets(packets, FlushBehavior::Immediate, TrafficClass::Bulk)
                .await;
        };

        frames.extend(encode_psh_frames(self.stream_id, target)?);
        if !data.is_empty() {
            frames.extend(encode_psh_frames(self.stream_id, data)?);
        }
        let packets = self.coalesce_and_pad(frames)?;

        let pending_write = self
            .submit_packets_or_fail(packets, TrafficClass::Control)
            .await?;

        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: true,
        };

        self.finish_pending_open_submission().await
    }

    async fn flush_pending_open_frames(&mut self) -> Result<(), anyhow::Error> {
        let Some(frames) = self.deferred_open_frames() else {
            return self.finish_pending_open_submission().await;
        };
        let packets = self.coalesce_and_pad(frames)?;

        let pending_write = self
            .submit_packets_or_fail(packets, TrafficClass::Control)
            .await?;

        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: false,
        };

        self.finish_pending_open_submission().await
    }

    async fn finish_pending_open_submission(&mut self) -> Result<(), anyhow::Error> {
        let pending_write = match &mut self.open_state {
            StreamOpenState::DeferredUnsent(_) => return Ok(()),
            StreamOpenState::Submitted { pending_write, .. } => pending_write.as_mut(),
        };

        let Some(pending_write) = pending_write else {
            return Ok(());
        };

        if let Err(err) = pending_write.wait().await {
            self.writer.close();
            self.open_failed = Some(err.to_string());
            return Err(err);
        }

        Ok(())
    }

    fn coalesce_and_pad(&self, frames: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, anyhow::Error> {
        Ok(coalesce_encoded_frames(frames, MAX_PAYLOAD_LEN))
    }

    async fn submit_packets_or_fail(
        &mut self,
        packets: Vec<Vec<u8>>,
        traffic_class: TrafficClass,
    ) -> Result<PendingWrite, anyhow::Error> {
        match self
            .writer
            .submit_write_packets(packets, FlushBehavior::Immediate, traffic_class)
            .await
        {
            Ok(pw) => Ok(pw),
            Err(err) => {
                self.writer.close();
                self.open_failed = Some(err.to_string());
                Err(err)
            }
        }
    }

    fn mark_open_failed(&mut self, err: Error, close_writer: bool) -> anyhow::Error {
        if close_writer {
            self.writer.close();
        }
        let msg = err.to_string();
        self.open_failed = Some(msg.clone());
        anyhow::anyhow!(msg)
    }

    async fn write_frame(&self, frame: Frame) -> Result<(), anyhow::Error> {
        let payload = frame.encode()?;
        self.writer
            .write_packets(vec![payload], FlushBehavior::Immediate, TrafficClass::Bulk)
            .await
    }

    pub async fn close_write(&mut self) -> Result<(), anyhow::Error> {
        if self.closed || self.write_closed {
            return Ok(());
        }

        if self.has_deferred_open() || self.open_failed.is_some() {
            self.deferred_target = None;
            self.write_closed = true;
            self.closed = true;
            self.teardown.light_teardown().await;
            return Ok(());
        }

        self.deferred_target = None;

        self.finish_pending_open_submission().await?;

        let result = send_fin_frame(self.stream_id, self.writer.clone()).await;

        if result.is_ok() {
            self.write_closed = true;
        }
        result
    }

    pub async fn close(&mut self) -> Result<(), anyhow::Error> {
        if self.closed {
            self.teardown.cleanup_registration().await;
            return Ok(());
        }

        let result = if self.write_closed {
            Ok(())
        } else {
            self.close_write().await
        };
        remember_closing_stream_sync(self.stream_id, &self.teardown.closing_streams);
        self.teardown.cleanup_registration().await;
        self.closed = true;
        self.teardown.fully_closed.store(true, Ordering::Relaxed);
        result
    }

    /// 这条流的「开场」是否还有字节没出网：目标地址仍挂在 `deferred_target`
    /// 上，或 SYN 仍压在 `DeferredUnsent` 里。
    ///
    /// 两种情形都要覆盖：第 1 条流两者皆是（SYN 与目标一起攒着），第 2..N 条
    /// 流只有后者（`open_stream` 已经把 SYN 单发出去了，服务端 accept 之后
    /// 卡在等目标）。
    ///
    /// 已失败或已关闭的流一律不武装。这是**纵深防御**，不是当前唯一的保护：
    /// `relay_tcp_client` 在本地 EOF 后会 `close_write()` 然后继续轮询
    /// 读侧，而 `close_write` 对仍处 `DeferredUnsent` 的流是纯本地拆除
    /// （不发 FIN——对端根本不知道这条流），其中的注销会丢掉 `data_tx`，
    /// 于是读侧 `data_rx.recv()` 立即返回 `None`，计时器根本来不及到期。
    ///
    /// 之所以仍然显式挡一道：这条「来不及到期」依赖的是**另一个模块**的清理
    /// 顺序（注销恰好丢掉发送端），一旦那边改成延迟清理，宽限计时器就会为
    /// 一条已经没有本地端的流在对端凭空建流——对端把它挂在
    /// `pending_open_streams` 里直到会话结束，既漏资源又多一条线上记录。
    /// 判据放在本函数里，这个隐式依赖就不再是正确性的一部分。
    fn open_is_unsent(&self) -> bool {
        self.open_failed.is_none()
            && !self.closed
            && !self.write_closed
            && (self.deferred_target.is_some() || self.has_deferred_open())
    }

    /// 宽限期到期：把开场**不带数据**发出去，此后该流退回普通写路径。
    ///
    /// 复用 `write_gather_open` / `flush_pending_open_frames` 这两条既有路径，
    /// 不新增线上形态：前者以空 data 调用时产出的正是
    /// `[SYN][PSH(target)]`（第 1 条流）或 `[PSH(target)]`（第 2..N 条流），
    /// 与「本端恰好只写了目标地址」完全同形。
    async fn flush_unsent_open(&mut self) -> Result<(), anyhow::Error> {
        match self.deferred_target.take() {
            Some(target) => self.write_gather_open(&target, &[]).await,
            None => self.flush_pending_open_frames().await,
        }
    }

    fn deferred_open_frames(&self) -> Option<Vec<Vec<u8>>> {
        match &self.open_state {
            StreamOpenState::DeferredUnsent(frames) => Some(frames.clone()),
            StreamOpenState::Submitted { .. } => None,
        }
    }

    fn has_deferred_open(&self) -> bool {
        matches!(self.open_state, StreamOpenState::DeferredUnsent(_))
    }

    fn take_pending_open_write_for_drop(&mut self) -> Option<PendingWrite> {
        match &mut self.open_state {
            StreamOpenState::DeferredUnsent(_) => None,
            StreamOpenState::Submitted { pending_write, .. } => pending_write.take(),
        }
    }

    fn drop_waits_for_pending_open_flush(&self) -> bool {
        matches!(
            self.open_state,
            StreamOpenState::Submitted {
                early_data_submitted: true,
                ..
            }
        )
    }

    async fn wait_synack_once(&mut self) -> Result<(), anyhow::Error> {
        let Some(rx) = self.synack_rx.as_mut() else {
            return Ok(());
        };

        let payload =
            match tokio::time::timeout(std::time::Duration::from_secs(SYNACK_TIMEOUT_SECS), rx)
                .await
            {
                Ok(Ok(payload)) => payload,
                Ok(Err(_)) => {
                    self.synack_rx = None;
                    remember_closing_stream_sync(self.stream_id, &self.teardown.closing_streams);
                    self.teardown.cleanup_registration().await;
                    // 「对端没读到这条 SYN」正是被 GOAWAY 判定为未处理的流所走
                    // 的路径（水位在 CMD_SYN 一进 handle_frame 就抬起，所以任何
                    // 收到过 SYNACK 的流必然 ≤ 水位）。读循环先处理完 GOAWAY 帧
                    // 才清空 streams 映射、丢掉这里的 synack 发送端，所以此刻
                    // 判据必已就绪。
                    let err = self
                        .goaway_retry_error()
                        .unwrap_or_else(|| anyhow::anyhow!("stream closed before SYNACK"));
                    return Err(self.mark_open_failed(err, false));
                }
                Err(_) => {
                    self.synack_rx = None;
                    remember_closing_stream_sync(self.stream_id, &self.teardown.closing_streams);
                    let _ = send_fin_frame(self.stream_id, self.writer.clone()).await;
                    self.teardown.cleanup_registration().await;
                    return Err(self
                        .mark_open_failed(anyhow::anyhow!("timed out waiting for SYNACK"), false));
                }
            };

        self.synack_rx = None;
        if !payload.is_empty() {
            // 拒绝原因在线上是定长载荷（见 Session::SYNACK_REJECTION_PAYLOAD_LEN），
            // 右侧补白在此剥掉后才是原始文本。
            let msg = format!(
                "stream open rejected: {}",
                String::from_utf8_lossy(&payload).trim_end()
            );
            self.open_failed = Some(msg.clone());
            remember_closing_stream_sync(self.stream_id, &self.teardown.closing_streams);
            self.teardown.cleanup_registration().await;
            anyhow::bail!(msg);
        }

        Ok(())
    }
}

impl Drop for StreamWriteHalf {
    fn drop(&mut self) {
        let state = WriteEndState {
            open_never_sent_or_failed: self.has_deferred_open() || self.open_failed.is_some(),
            write_closed: self.write_closed,
            pending_open_write: self.take_pending_open_write_for_drop(),
            wait_for_pending_open: self.drop_waits_for_pending_open_flush(),
        };
        *self.teardown.write_end.lock().unwrap() = Some(state);
        self.teardown.half_dropped();
    }
}

pub struct Stream {
    pub stream_id: u32,
    read_half: StreamReadHalf,
    write_half: StreamWriteHalf,
    /// 开流宽限期的截止时刻，在 `read()` 首次真正挂起时惰性起算（见
    /// `DEFERRED_OPEN_GRACE`）。存在 `Stream` 上而不是 `read()` 的局部变量里，
    /// 是因为 `relay_tcp_client` 的 `select!` 会反复取消并重建 `read()` 的
    /// future——放在局部变量里每次取消都会把计时器归零，计时器永远走不到期。
    open_flush_deadline: Option<tokio::time::Instant>,
}

impl Stream {
    pub(crate) fn new(init: StreamInit) -> Self {
        let teardown = Arc::new(StreamTeardown {
            stream_id: init.stream_id,
            streams: init.streams,
            capacity_stream_count: init.capacity_stream_count,
            pending_data: init.pending_data,
            pending_fin: init.pending_fin,
            closing_streams: init.closing_streams,
            writer: init.writer.clone(),
            halves_alive: AtomicU8::new(2),
            fully_closed: AtomicBool::new(false),
            write_end: std::sync::Mutex::new(None),
        });
        Self {
            stream_id: init.stream_id,
            read_half: StreamReadHalf {
                stream_id: init.stream_id,
                data_rx: init.parts.data_rx,
                fin_rx: init.parts.fin_rx,
                pending_data: teardown.pending_data.clone(),
                pending_fin: teardown.pending_fin.clone(),
                pending_notify: init.pending_notify.clone(),
                consumed_since_wu: AtomicU64::new(0),
                windows: init.windows.clone(),
                peer_goaway_last_stream_id: init.peer_goaway_last_stream_id.clone(),
                read_closed: false,
                teardown: teardown.clone(),
            },
            write_half: StreamWriteHalf {
                stream_id: init.stream_id,
                synack_rx: Some(init.parts.synack_rx),
                writer: init.writer,
                pending_notify: init.pending_notify,
                send_credit: init.send_credit,
                windows: init.windows,
                peer_goaway_last_stream_id: init.peer_goaway_last_stream_id,
                open_state: init.open_state,
                deferred_target: None,
                write_closed: false,
                closed: false,
                open_failed: None,
                teardown,
            },
            open_flush_deadline: None,
        }
    }

    /// 拆成读/写两半，供两个独立的中继任务分别持有：写方向在流控门
    /// 挂起时读方向的交付与回补不再被冻结（拆分前单任务 `select!` 里
    /// `write().await` 的挂起会连带冻住 `read()`，双向饱和时两端互等
    /// 形成死锁环）。拆除语义不变：两半都消亡后由 `StreamTeardown`
    /// 执行与拆分前 `Drop` 等价的安全网清理，恰好一次。
    pub fn into_split(self) -> (StreamReadHalf, StreamWriteHalf) {
        (self.read_half, self.write_half)
    }

    pub async fn read(&mut self) -> Option<Bytes> {
        loop {
            if let Ok(payload) = self.read_half.data_rx.try_recv() {
                return Some(payload.into_bytes());
            }
            // 先注册再检查：pending 数据到达用 `notify_waiters`（不留
            // permit），若先检查后注册，间隙到达的通知会被丢掉。
            // 克隆 Arc 是为了让 Notified 不借用 self。
            let pending_notify = self.read_half.pending_notify.clone();
            let pending_notified = pending_notify.notified();
            tokio::pin!(pending_notified);
            let _ = pending_notified.as_mut().enable();
            if let Some(data) = self.read_half.try_drain_pending_data() {
                return Some(data);
            }
            if self.read_half.read_closed {
                return None;
            }

            // 开流尚未出网时武装宽限计时器（论证见 `DEFERRED_OPEN_GRACE`）。
            // 截止时刻只算一次：`get_or_insert_with` 保证 `select!` 反复取消
            // 重建本 future 时计时器不被归零。
            let grace_deadline = if self.write_half.open_is_unsent() {
                Some(
                    *self
                        .open_flush_deadline
                        .get_or_insert_with(|| tokio::time::Instant::now() + deferred_open_grace()),
                )
            } else {
                None
            };
            let grace_armed = grace_deadline.is_some();
            let grace = tokio::time::sleep_until(
                grace_deadline
                    .unwrap_or_else(|| tokio::time::Instant::now() + DEFERRED_OPEN_GRACE_DISABLED),
            );
            tokio::pin!(grace);

            // 宽限期到期后才冲刷：`select!` 的臂里拿不到 `&mut self`
            // （data_rx/fin_rx 的借用仍在作用域内），故那一臂空着，出了
            // select 再动手；其余各臂一律 return/continue，因此能落到下面
            // 那行的只有宽限期分支。
            tokio::select! {
                payload = self.read_half.data_rx.recv() => {
                    return payload.map(BufferedPayload::into_bytes);
                }
                _ = pending_notified => {
                    continue;
                }
                _ = self.read_half.fin_rx.recv() => {
                    // 先置 read_closed 再回路排空：channel/pending_data 中的
                    // 残留数据仍会在返回 None 之前被投递（见循环开头两步）。
                    // fin 令牌只此一枚——若消费令牌后因恰好又有数据而直接返回，
                    // 却不置位，一旦后续出现乱序/丢帧，read 将永远挂在 select。
                    self.read_half.read_closed = true;
                    continue;
                }
                _ = &mut grace, if grace_armed => {}
            }

            if self.write_half.flush_unsent_open().await.is_err() {
                // 开流失败 ⇒ 这条流已死，读侧给 EOF；`open_failed` 已置位，
                // 后续 `write()` 会带着原始错误返回。
                return None;
            }
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.write_half.write(data).await
    }

    pub async fn write_early(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.write_half.write_early(data).await
    }

    pub async fn wait_synack(&mut self) -> Result<(), anyhow::Error> {
        self.write_half.wait_synack().await
    }

    pub async fn wait_open(&mut self) -> Result<(), anyhow::Error> {
        self.write_half.wait_open().await
    }

    pub fn defer_target(&mut self, target: &[u8]) {
        self.write_half.defer_target(target)
    }

    /// 接收侧每流回补入账：中继在字节真正交付本地应用后调用（H2 语义，
    /// 见 `WindowState::note_consumed`）。
    pub fn note_consumed(&self, len: usize) {
        self.read_half.note_consumed(len)
    }

    /// 对端的 GOAWAY 是否宣告本流从未被处理 ⇒ 重放这条流无副作用
    /// （完整论证见 `StreamWriteHalf::peer_never_processed`）。
    pub fn peer_never_processed(&self) -> bool {
        self.write_half.peer_never_processed()
    }

    pub async fn close_write(&mut self) -> Result<(), anyhow::Error> {
        self.write_half.close_write().await
    }

    pub async fn close(&mut self) -> Result<(), anyhow::Error> {
        self.write_half.close().await
    }
}

pub(crate) async fn send_fin_frame(
    stream_id: u32,
    writer: SharedTunnelWriter,
) -> Result<(), anyhow::Error> {
    let payload = Frame::fin(stream_id).encode()?;
    // FIN 必须留在 control 通道：与后续 SYN/SYNACK 等 control 帧保持 FIFO；
    // 而写循环的 control 分支会先把 bulk channel 中已到达的请求并入
    // pending 统一冲刷，因此 FIN 也不会越过此前写入的 bulk 数据。
    writer
        .write_packets(
            vec![payload],
            FlushBehavior::Immediate,
            TrafficClass::Control,
        )
        .await
}

pub(crate) fn try_send_fin_frame(
    stream_id: u32,
    writer: &SharedTunnelWriter,
) -> Result<(), anyhow::Error> {
    let payload = Frame::fin(stream_id).encode()?;
    // 同 send_fin_frame：Control 保序；try_send 失败由调用方回退到异步发送。
    writer.try_write_packets(
        vec![payload],
        FlushBehavior::Immediate,
        TrafficClass::Control,
    )
}
