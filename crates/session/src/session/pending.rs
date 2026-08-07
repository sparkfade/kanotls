//! 缓冲记账：交付/丢弃即扣账的载荷包装，以及两本「限额账」。
//!
//! 两本账互不干扰：
//! * `BufferedPayload` 的 RAII 维护全局 `buffered_stream_bytes`（内存压力
//!   口径，供连接池评分与限额判断）；
//! * `PendingData` / `PendingOpenStreams` 维护各自的运行计数，使限额检查
//!   全部 O(1)——此前 `total_bytes()` 是全量求和，恰好在背压发生时被逐帧
//!   调用，构成 O(n²) 放大路径。

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 入账缓冲载荷：创建即计入 buffered_stream_bytes，被消费者取走
/// （into_vec）或被丢弃（Drop）时恰好扣减一次，杜绝手工记账漏减。
#[derive(Debug)]
pub(crate) struct BufferedPayload {
    data: Bytes,
    counter: Arc<AtomicUsize>,
    accounted: bool,
}

impl BufferedPayload {
    pub(crate) fn new(data: impl Into<Bytes>, counter: &Arc<AtomicUsize>) -> Self {
        let data = data.into();
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
    ///
    /// 返回 `Bytes` 而不是 `Vec<u8>`：载荷自 `Frame::decode` 起就是重组缓冲
    /// 的一段引用计数切片，一路移交到这里都没有发生过拷贝，交付时再 `to_vec`
    /// 等于把省下的拷贝重新付掉。中继侧只需要 `&[u8]`（`write_all(&d)`），
    /// `Bytes` 直接 deref 即可。
    pub(crate) fn into_bytes(mut self) -> Bytes {
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
struct StreamQueue {
    items: VecDeque<BufferedPayload>,
    bytes: usize,
}

/// 每流的待投递积压。
///
/// 总字节与每流字节都以运行计数维护，入队/出队时同增同减。此前
/// `total_bytes()` 是对所有队列所有载荷的全量求和，而它在
/// `store_pending_data` 中每存一帧就要调一次——限额是 1024 流 × 1024 帧，
/// 于是最坏情况下每帧扫描百万级条目。触发条件恰是它要防的那一个：消费者
/// 卡住、channel 满、帧开始落到 pending。O(1) 记账消除这条放大路径。
#[derive(Default)]
pub(crate) struct PendingData {
    queues: HashMap<u32, StreamQueue>,
    total_bytes: usize,
}

impl PendingData {
    pub fn contains(&self, sid: u32) -> bool {
        self.queues.contains_key(&sid)
    }

    pub fn remove(&mut self, sid: u32) -> Option<VecDeque<BufferedPayload>> {
        let queue = self.queues.remove(&sid)?;
        self.total_bytes -= queue.bytes;
        Some(queue.items)
    }

    pub fn clear(&mut self) {
        self.queues.clear();
        self.total_bytes = 0;
    }

    /// 有积压的流数量（空队列不会残留：拒绝入队时不创建条目，排空时移除）。
    pub fn len(&self) -> usize {
        self.queues.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn stream_bytes(&self, sid: u32) -> usize {
        self.queues.get(&sid).map(|q| q.bytes).unwrap_or(0)
    }

    pub fn stream_frames(&self, sid: u32) -> usize {
        self.queues.get(&sid).map(|q| q.items.len()).unwrap_or(0)
    }

    pub fn push_back(&mut self, sid: u32, payload: BufferedPayload) {
        let len = payload.len();
        let queue = self.queues.entry(sid).or_default();
        queue.items.push_back(payload);
        queue.bytes += len;
        self.total_bytes += len;
    }

    /// 取走队首载荷；队列排空时一并移除条目，使 `contains`/`len` 的口径
    /// 始终等于「有积压的流」。
    pub fn pop_front(&mut self, sid: u32) -> Option<BufferedPayload> {
        let queue = self.queues.get_mut(&sid)?;
        let payload = queue.items.pop_front()?;
        queue.bytes -= payload.len();
        self.total_bytes -= payload.len();
        if queue.items.is_empty() {
            self.queues.remove(&sid);
        }
        Some(payload)
    }
}

#[derive(Debug, Default)]
struct PendingOpenStream {
    buffered_data: Vec<BufferedPayload>,
    /// buffered_data 的运行字节数，与 `PendingOpenStreams::total_bytes` 同增
    /// 同减，使整条流的丢弃/取走都是 O(1) 扣减。
    bytes: usize,
    buffered_fin: bool,
    reservation_released: bool,
}

/// 服务端 pre-accept 缓冲：CMD_SYN 已到、应用层尚未 accept 期间落下的
/// PSH/FIN。
///
/// 总字节以运行计数维护，入队 + / 取走・丢弃 −，四个限额检查全部 O(1)。
/// 此前 `store_pending_open_data` 每存一帧都要
/// `values().flat_map(buffered_data).map(len).sum()` 一遍：上限是
/// max_streams_per_session（默认 256）× MAX_PENDING_STREAM_FRAMES（1024）
/// = 26 万条目，而触发条件恰是它要防的那一个——消费者不 accept、帧开始落
/// 到 pending，于是背压一发生就是 O(n²) 放大。这正是 `PendingData` 上方那段
/// 注释已经修掉的反模式，服务端 pre-accept 这条路径漏了。
///
/// 载荷本身仍由 `BufferedPayload` 的 RAII 记账维护 buffered_stream_bytes 那
/// 本账；这里维护的是 pending_open 自己的限额账，两本互不干扰。
#[derive(Default)]
pub(crate) struct PendingOpenStreams {
    streams: HashMap<u32, PendingOpenStream>,
    total_bytes: usize,
}

impl PendingOpenStreams {
    pub(crate) fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub(crate) fn contains(&self, sid: u32) -> bool {
        self.streams.contains_key(&sid)
    }

    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn stream_frames(&self, sid: u32) -> usize {
        self.streams
            .get(&sid)
            .map(|stream| stream.buffered_data.len())
            .unwrap_or(0)
    }

    /// 登记一个新的 pre-accept 条目（重复 SYN 由调用方在此之前拒绝；万一
    /// 覆盖，旧条目的字节先扣账，计数不会漂移）。
    pub(crate) fn insert_new(&mut self, sid: u32) {
        self.remove(sid);
        self.streams.insert(sid, PendingOpenStream::default());
    }

    /// 丢弃条目：未投递载荷由 `BufferedPayload::drop` 回 buffered_stream_bytes
    /// 的账，此处扣的是限额账。
    pub(crate) fn remove(&mut self, sid: u32) {
        if let Some(stream) = self.streams.remove(&sid) {
            self.total_bytes -= stream.bytes;
        }
    }

    pub(crate) fn clear(&mut self) {
        self.streams.clear();
        self.total_bytes = 0;
    }

    /// 入队一帧；条目不存在时返回 false（载荷随作用域丢弃自动回账）。
    pub(crate) fn push_data(&mut self, sid: u32, payload: BufferedPayload) -> bool {
        let len = payload.len();
        match self.streams.get_mut(&sid) {
            Some(stream) => {
                stream.buffered_data.push(payload);
                stream.bytes += len;
                self.total_bytes += len;
                true
            }
            None => false,
        }
    }

    /// 取走一批待投递内容（所有权转交调用方，限额账同步扣减）并清掉 FIN
    /// 标记；None 表示条目不存在。
    pub(crate) fn take_ready(&mut self, sid: u32) -> Option<(Vec<BufferedPayload>, bool)> {
        let stream = self.streams.get_mut(&sid)?;
        let data = std::mem::take(&mut stream.buffered_data);
        let fin = stream.buffered_fin;
        let bytes = std::mem::take(&mut stream.bytes);
        stream.buffered_fin = false;
        self.total_bytes -= bytes;
        Some((data, fin))
    }

    /// 置位 buffered_fin；返回条目是否存在。
    pub(crate) fn set_buffered_fin(&mut self, sid: u32) -> bool {
        match self.streams.get_mut(&sid) {
            Some(stream) => {
                stream.buffered_fin = true;
                true
            }
            None => false,
        }
    }

    /// 入站流预留的一次性释放：Some(true) 表示本次首次释放，None 表示条目
    /// 不存在。
    pub(crate) fn release_reservation(&mut self, sid: u32) -> Option<bool> {
        let stream = self.streams.get_mut(&sid)?;
        if stream.reservation_released {
            return Some(false);
        }
        stream.reservation_released = true;
        Some(true)
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
