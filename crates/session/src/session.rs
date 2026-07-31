use crate::frame::{
    coalesce_encoded_frames, decode_padding_goaway, decode_padding_window_update,
    encode_padding_goaway_sized, encode_padding_reply_sized, encode_padding_request_sized,
    encode_padding_window_update_sized, encode_psh_frames, self_sized_padding_wire_len, Frame,
    CMD_FIN, CMD_PADDING, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CONTROL_RECORD_MIN_OVERHEAD,
    FRAME_HEADER_SIZE, MAX_PAYLOAD_LEN, MIN_GOAWAY_RECORD_WIRE_LEN, PADDING_FLAG_GOAWAY,
    PADDING_FLAG_REQUEST, PADDING_FLAG_WINDOW_UPDATE,
};
use crate::shaper::{ShapePolicy, TrafficShaper};
use crate::stream::{Stream, StreamInit, StreamOpenState, StreamParts};
use bytes::{Bytes, BytesMut};
use kanotls_tunnel::{ConnectionState, FlowDirection, SnowyStream};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, RwLock};
use tracing::{debug, error, trace, warn};

/// 隧道的读半与写半。
///
/// 此前这两个类型是同一个 `Arc<StdMutex<SnowyStream>>` 的两个句柄：读半的
/// `poll_read` 持锁跨越最多 16 KB 的解密，写半的 `prepare_*` / `poll_flush`
/// 要同一把锁做加密与 `write()` 系统调用，于是**同一条连接的加密与解密完全
/// 串行**，双向大流量时两个 task 在这把锁上乒乓。实测（双向各 400 MiB、
/// 4 个 worker 线程）12.2 万次加锁中 5.0% 争用、累计阻塞 0.39 s。
///
/// 现在两半由 `SnowyStream::into_split` 直接给出：TCP socket 由
/// `into_split` 分开，Noise 传输态改用 `StatelessTransportState` +
/// 每半自己的 nonce 计数器（论证与线上字节等价性见
/// `kanotls_tunnel::common::NoiseTransport`），那把锁整个消失。
type SplitReadHalf = kanotls_tunnel::SnowyReadHalf;
type SplitWriteHalf = kanotls_tunnel::SnowyWriteHalf;

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

pub(crate) type SharedTunnelWriter = Arc<SessionWriter>;

/// 对端到达信号：读循环每收到一批字节就递增计数并唤醒等待者。
///
/// 写循环用它实现「让出方向」——第一个上行 burst 必须在第一条整形数据记录
/// 之后就结束，而 burst 只能被**方向改变**打断（同方向连续包的尺寸累加，时间
/// 间隔不算）。因此写端必须真的挂起到对端有记录抵达，光把 fake 请求排进队列
/// 是不够的：对端的应答要一个 RTT 才回来，那期间若继续发数据，burst 就把后续
/// 记录全部累加进去了。这正是 USENIX Sec'24 那篇论文给出的对抗建议
/// （"buffer application data when the scheduler demands quiet time"）。
#[derive(Default)]
pub(crate) struct InboundSignal {
    arrivals: AtomicU64,
    notify: Notify,
}

impl InboundSignal {
    fn arrivals(&self) -> u64 {
        self.arrivals.load(Ordering::Relaxed)
    }

    fn note_arrival(&self) {
        self.arrivals.fetch_add(1, Ordering::Relaxed);
        // notify_one 在无等待者时留存一个 permit，故等待者不会丢唤醒。
        self.notify.notify_one();
    }
}

/// 「让出方向」的等待上限。路径 RTT 未知，只能给一个有界上限：对端的
/// CMD_PADDING 应答由读循环在帧处理层立即回吐（不经应用层），因此正常路径上
/// 一个 RTT 内必到；上限只在丢包或异常慢路径上兜底，避免首条记录之后卡死。
const PEER_TURN_MAX_WAIT: Duration = Duration::from_millis(300);

/// 挂起到对端有新记录抵达（方向改变发生）或上限到期。
async fn wait_for_peer_turn(inbound: &InboundSignal, since: u64) {
    let deadline = tokio::time::sleep(PEER_TURN_MAX_WAIT);
    tokio::pin!(deadline);
    loop {
        if inbound.arrivals() != since {
            return;
        }
        tokio::select! {
            _ = &mut deadline => return,
            _ = inbound.notify.notified() => {}
        }
    }
}

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

/// 本 packet 是否承载「流生命周期」控制帧（SYN / FIN）。
///
/// 这两种帧在真实 H2 里**没有对应的独立小帧**：新流由 `HEADERS` 开启、
/// 半关闭由挂在 `DATA`/`HEADERS` 上的 `END_STREAM` 标志表达，两者都是
/// `L2` 量级的记录；一个 33–54 字节的独立记录只对应 `SETTINGS-ACK` /
/// `WINDOW_UPDATE` / `PING`，而那三种在真实 H2 里出现的**位置**完全不同
/// （开场、每 6 MiB、58 秒空闲）。
///
/// 实测（本仓测试台，一条连接跑 24 次「开流 → GET → 收响应 → 关流」）：
/// 客户端的 FIN 与服务端的 FIN 各自独占一个 TCP 分段、且紧跟在响应体的
/// 末段之后，于是 `(−L4, L1, −L1)`（论文 Table 2 判别力第 3，Distinc
/// 2.879，本项目零容忍的两个 3-gram 之一）在 24 次流生命周期里出现 5–6 次
/// ——大约每 4~5 次关流命中一次。命中与否只取决于响应末段是否 ≥1211 字节，
/// 是一枚硬币，不是可依赖的保护。
///
/// 既有的回归台看不到它：`capture_scenario` 在关流之前总会再写一个 80 字节
/// 的上行 flight，那条 `L2` 数据记录恰好把 `−L4` 与 `L1` 隔开；而最常见的
/// HTTP GET 形态（请求发完就等响应、收完即关）没有这个 flight。
///
/// **`CMD_SYNACK` 刻意不在此列**，尽管它同样逐流重复。它是三者中唯一一条
/// 记录**必然落在连接出生窗口内**的：服务端的 H2 开场 flight
/// （`SETTINGS` + `WINDOW_UPDATE` + `SETTINGS-ACK` ≈ 119 字节）与首条 SYNACK
/// 由同一次 `write()` 送出，把 SYNACK 从 ~40 字节抬到数据记录量级会让这个
/// 下行分段跨过 1211 ⇒ 变成 `−L4`，而客户端此刻恰好要回一条 33 字节的
/// `SETTINGS-ACK`（真实 H2 客户端也必须回，尺寸是定死的 9 字节帧）——于是
/// 「客户端首个 flight（`L2`）→ 合并后的开场分段（`−L4`）→ SETTINGS-ACK
/// （`L1`）」精确凑成 `(L2, −L4, L1)`（Distinc 7.226）。实测：把 SYNACK 纳入
/// 本规则后 `paper_features_stay_clear_of_nested_handshake_grams` 立即命中。
///
/// 换句话说，SYNACK 的**小**在出生窗口里是保护而不是破绽；而 SYN / FIN 的
/// 危害恰恰在出生窗口**之外**——它们在连接一生中重复至多 256 次，
/// 每次都在下行 burst 之后放出一对「本端 L1 → 对端 L1」。
fn packet_carries_stream_lifecycle_frame(packet: &[u8]) -> bool {
    let mut lifecycle = false;
    walk_frame_headers(packet, |cmd, _sid, _len| {
        if matches!(cmd, CMD_SYN | CMD_FIN) {
            lifecycle = true;
        }
    });
    lifecycle
}

/// 请求内是否承载 PSH（应用数据）帧。
///
/// `Stream::write_gather_open` / `write_pending_open_with_data` 把
/// `[SETTINGS][SYN][PSH(target)][PSH(首个数据块)]` 合并成一个 packet 走
/// **Control** 类——必须同一通道才能保住「SETTINGS 先于 SYN、SYN 先于数据」
/// 的到达顺序（若把 PSH 改走 Bulk，写循环的 biased select 会先把 bulk 积压
/// 排空，数据反而越过 SYN 先到）。但 Control 路径不经 TrafficShaper，于是
/// `prepare_control_record` 的 `max(采样值, payload 下限)` 生效，首记录的线速
/// 尺寸退化为「内层首包 + 24」（Chrome 517⇒541，带 ML-KEM 的 Firefox
/// ~1884⇒~1908），把内层 ClientHello 的尺寸 1:1 送上线，同时让第一个上行
/// burst 远超 300 字节门限。
///
/// 判定为承载数据后，请求整体并入 pending 走 shaper 排空：通道不变、字节序
/// 不变，尺寸决策回到 §3.3 声称的那一条路径上。
fn request_carries_stream_data(request: &WriteRequest) -> bool {
    let mut carries = false;
    for packet in &request.packets {
        walk_frame_headers(packet, |cmd, _sid, _len| {
            if cmd == CMD_PSH {
                carries = true;
            }
        });
    }
    carries
}

const MAX_PENDING_STREAM_FRAMES: usize = 4096;
const MAX_PENDING_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_STREAMS: usize = 1024;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const MAX_SESSION_REASSEMBLY_BYTES: usize = 1024 * 1024;
const WRITE_CHANNEL_CAPACITY: usize = 64;
const MAX_STREAM_OVERFLOW_BYTES: usize = 2 * 1024 * 1024;

/// 每流发送窗口（H2 的 `SETTINGS_INITIAL_WINDOW_SIZE` 语义）：发送方在同一条
/// 流的在途字节超过此值前可自由发送，之后挂起等对端回补 WINDOW_UPDATE。
///
/// **取值与 `MAX_STREAM_OVERFLOW_BYTES` 同值（2 MiB）**：接收方为 fc 对端
/// 保留的缓冲上限 = 窗口 + 首 RTT 越界余量（见 `store_pending_data`），于是
/// 「窗口耗尽 ⇒ 发送方停发」让接收缓冲**结构性**无法触限——此前的
/// 「超限丢数据 + 杀流」对 fc 对端彻底不可达。
///
/// 2 MiB 同时覆盖典型高 BDP 路径（200 Mbps × 150 ms ≈ 3.75 MB 的在途需求由
/// 连接级 12 MiB 窗口承接，每流窗口只管单流停滞不拖死其他流）。
const STREAM_WINDOW_BYTES: usize = 2 * 1024 * 1024;

/// 测试覆写点：0 表示使用上面的生产常量。窗口只影响**本端发送**的门控与
/// 回补节奏，不改任何线上字节形态（WINDOW_UPDATE 记录本身尺寸恒定）。
pub(crate) static STREAM_WINDOW_OVERRIDE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// sticky bulk 批量 flush 双上限（先到先 flush）：连续 prepare 最多 K 条
/// record 且 write_buffer 累计不超过 ~128KB 后统一冲刷一次。仅合并内部
/// syscall，record 尺寸/顺序与逐条 flush 完全一致。
const STICKY_BULK_FLUSH_MAX_RECORDS: usize = 8;
const STICKY_BULK_FLUSH_MAX_BYTES: usize = 128 * 1024;

/// 稳态 H2 行为骨架（post-script steady state）：真实 HTTP/2 接收端按消费
/// 字节数回发 WINDOW_UPDATE，并对收到的 PING 回 PING-ACK。内容加密不可见，
/// 只需复刻尺寸/时序语义。两者都以 CMD_PADDING 帧实现：flag=1 被对端静默
/// 吸收（等价 WINDOW_UPDATE 的“无回复”语义），flag=0 m=1 会换来一条 reply
/// （等价 PING/PING-ACK 对）。客户端不做空闲探活 PING（用户明确不需要
/// 保活），flag=0 m=1 的请求只来自脚本 fake 交互与合成 H2 交换。
///
/// WINDOW_UPDATE 的触发阈值是**逐进程常量**，不逐次重采样。此前是
/// `gen_range(1MB..=4MB)` 且每越过一次就重新采样一个新阈值 ⇒ 全随机，而
/// 真实 H2 接收端的规则是确定的：窗口是实现里的编译期常量，消费字节越过
/// 窗口的某个固定比例就回补一条 WINDOW_UPDATE。取值依据（Firefox，与本
/// 项目的 TLS 指纹同源）：
/// * `ASpdySession::kInitialRwin = 12 * 1024 * 1024`（12MB）——Firefox 在
///   `SendHello` 里把连接级接收窗口从 65535 抬到这个值，源码注释原文
///   *"This is roughly the amount of data a suspended channel will have to
///   buffer before h2 flow control kicks in."*；
/// * 「已消费量达到本地窗口的一半即回补」是 H2 接收端的通行规则（nghttp2 的
///   `session_update_recv_connection_window_size`：`local_window_size / 2 <
///   consumed_size` 时提交 WINDOW_UPDATE）。
///
/// 两者相乘 = 6 MiB。用 `OnceLock` 而不是 `const`：语义是「进程内解析一次、
/// 此后恒定」，与真实实现的编译期常量同一口径，同时保留测试覆写点。
const H2_FIREFOX_SESSION_WINDOW_BYTES: usize = 12 * 1024 * 1024;
static H2_WINDOW_UPDATE_THRESHOLD: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// 论文（USENIX Sec'24, Xue et al.）的观测窗口 `Wo`：25 个承载数据的 TCP 包。
///
/// 包数用「读循环收到的对端到达次数」近似：一次 `read()` 至少对应一个 TCP
/// 段，故 arrivals ≤ 实际包数——**低估**方向，只会让窗口判定更晚，是保守的。
///
/// `TrafficShaper` 的窗口外放松（见 `shaper::POST_WINDOW_RELAX_BAND`）复用
/// 同一个常量，但用的是一个更严的下界：`flush 次数 + arrivals`。
pub(crate) const PAPER_OBSERVATION_WINDOW_PACKETS: u64 = 25;

/// 优雅拆除前那条 H2 GOAWAY 记录的线速尺寸。
///
/// 真实 H2 端点在关闭连接前先发 GOAWAY（帧类型 0x07），然后才是
/// close_notify + FIN。GOAWAY 的最小帧 = 9 字节帧头 + 4 last_stream_id +
/// 4 error_code = 17 字节载荷，与 PING 帧（9 + 8）完全相同，故线速尺寸就是
/// `PING_WIRE`（41）。此前拆除时线上只有一条 24 字节的 close_notify，前面
/// 没有任何控制尺寸的记录——nginx/Firefox 关闭 H2 连接必有 GOAWAY，缺了它
/// 本身就是一条可观测特征。
///
/// 用 `PADDING_FLAG_GOAWAY`（flag=2）的「不换应答」形式：GOAWAY 不换 ACK，
/// 且旧对端的 `handle_frame` 只对 flag=0 作答、其余 flag 静默丢弃，因此这个
/// 新 flag 值对未升级的对端**完全无害**（论证见 `PADDING_FLAG_REQUEST`）。
const H2_GOAWAY_WIRE: usize = kanotls_tunnel::control_size::PING_WIRE;

/// 41 字节的 GOAWAY 记录必须装得下 4 字节 last_stream_id，且**不改变线速
/// 尺寸**（junk 从 8 字节变成「4 字节 id + 4 字节零」）。这条编译期断言把它
/// 钉死：任何把 `H2_GOAWAY_WIRE` 调到 37 以下的改动直接编译失败，而不是在
/// 运行期悄悄退化成一条不带 id 的 GOAWAY。
const _: () = assert!(H2_GOAWAY_WIRE >= MIN_GOAWAY_RECORD_WIRE_LEN);

/// 「未收到对端 GOAWAY」的哨兵值。
///
/// 用 `AtomicU64` 承载一个 `Option<u32>`：`u32` 的全值域都是合法的
/// last_stream_id（含 0——真实 H2 里「一条都没处理」就写 0），没有可借用的
/// 带内哨兵，而 `u64::MAX` 落在 u32 值域之外，单次原子读即可无撕裂地区分
/// 「没收到」与「收到且值为 0」。
const GOAWAY_NOT_RECEIVED: u64 = u64::MAX;

/// 「对端 GOAWAY 宣告这条流从未被处理」的判据，`Session` 与 `Stream` 共用。
///
/// 没收到 GOAWAY ⇒ 恒为 false：本端主动 `force_close`、TCP 直接被打断、旧版本
/// 对端等所有情形都落在这里，行为与引入 GOAWAY 语义之前逐字节一致。
pub(crate) fn peer_never_processed(state: &AtomicU64, stream_id: u32) -> bool {
    match state.load(Ordering::Relaxed) {
        GOAWAY_NOT_RECEIVED => false,
        last => u64::from(stream_id) > last,
    }
}

/// 合成 H2 请求/响应交换（论文所称的 "synthetic co-existing flows"）。
///
/// 论文把 mux 的致命前提写得很直白：*"the effectiveness of multiplexing depends
/// on the presence of co-existing flows. In situations where there is only a
/// single flow, or where the co-existing flows are inactive, patterns will
/// remain as exposed as non-multiplexed proxies."*，并把 "generating synthetic
/// co-existing flows when they are not naturally present" 列为未来工作。
///
/// 这里的合成流量必须以**真实 H2 成因**表达，否则只是用一个新特征换旧特征。
/// 采用的成因是「浏览器在同一条 H2 连接上继续发请求」：一条 HEADERS 尺寸的
/// 上行记录换来一条响应尺寸的下行记录。因此
/// * 请求侧尺寸取 C2S HEADERS 分布（`next_control_size` 的截断正态档，
///   250–800 载荷 ⇒ 274–824 线速）——不是 PING 尺寸，避免在下行 burst 之后
///   造出 `(−L4, L1, −L1)`；
/// * 应答侧尺寸取响应方向的数据记录分布（见 `padding_reply_wire_len`）。
///
/// **开场窗口**：真实页面加载会在连接建立后的头 100ms 内连发若干请求，所以
/// 前 `H2_EXCHANGE_OPENING_*` 次交换按数十毫秒的间隔发出——这恰好落在论文的
/// `Wo = 25` 包观测窗口内，是「窗口内真的存在共存流」的唯一办法。
/// **稳态**：此后回落到浏览量级的重尾间隔（中位数 ~20s）。
///
/// 触发条件（见读循环）：仅客户端方向、`post_script_off` 关闭时不生效、且必须
/// 已经收到过对端记录（保证连接的第一个上行 burst 已经出网，合成请求不会挤进
/// 那个 burst 把它顶过 300 字节）。稳态交换额外要求至少有一条流开着——一条
/// 完全空闲的 H2 连接本来就该被 idle timeout 拆掉，硬撑着发帧反而是伪装破绽。
const H2_EXCHANGE_OPENING_MIN_COUNT: u32 = 1;
const H2_EXCHANGE_OPENING_MAX_COUNT: u32 = 3;
const H2_EXCHANGE_OPENING_MU_MS: f64 = 3.4; // 中位数 ≈ 30ms
const H2_EXCHANGE_OPENING_SIGMA: f64 = 0.7;
const H2_EXCHANGE_STEADY_MU_MS: f64 = 9.9; // 中位数 ≈ 20s
const H2_EXCHANGE_STEADY_SIGMA: f64 = 1.2;
/// 稳态交换的间隔上限：超过它就没有观测意义，而且会把 sleep 的 deadline
/// 推到不现实的远处。
const H2_EXCHANGE_MAX_INTERVAL_SECS: u64 = 300;

/// 测试覆写点：0 表示使用上面的生产常量。
pub(crate) static H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES: AtomicUsize = AtomicUsize::new(0);
pub(crate) static H2_EXCHANGE_INTERVAL_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

/// H2 骨架关闭时的定时器“禁用”姿态：分支被 select guard 屏蔽，deadline
/// 只需足够遥远。
const H2_TIMER_DISABLED: Duration = Duration::from_secs(3600);

/// 单条 CMD_PADDING 请求可换取的应答记录上限。
///
/// 真实 H2 没有「一问 m 答」这种语义：PING 换恰好一个 PING-ACK，
/// WINDOW_UPDATE 不换任何应答，SETTINGS 换恰好一个 SETTINGS-ACK。一次交互
/// 里能站得住脚的第二条应答记录只有一种角色——「接收方本来就要发的窗口
/// 更新」，故上限压到 2。此前是 16：m=4 在线上就是「一条请求 → 一簇记录」，
/// 而且（见下方 handle_frame）这一簇还被合并成单条记录，两头都不像 H2。
const MAX_PADDING_REPLIES: usize = 2;

/// CMD_PADDING 记录的角色尺寸。真实 H2 里这三种帧的尺寸都是确定值
/// （PING/PING-ACK 恒 8 字节载荷 → 17 字节帧，WINDOW_UPDATE 恒 4 字节载荷
/// → 13 字节帧，SETTINGS-ACK 恒 9 字节帧），因此这里也取确定值而不是再过一遍
/// 混合分布采样器：在真实实现恒定的维度上随机化，本身就是一个判别特征。
const PADDING_REQUEST_WIRE: usize = kanotls_tunnel::control_size::PING_WIRE;
const PADDING_ACK_WIRE: usize = kanotls_tunnel::control_size::PING_WIRE;
const PADDING_WINDOW_UPDATE_WIRE: usize = kanotls_tunnel::control_size::WINDOW_UPDATE_WIRE;
const PADDING_SETTINGS_ACK_WIRE: usize = kanotls_tunnel::control_size::SETTINGS_ACK_WIRE;

/// 一条应答记录的目标线速尺寸，按**请求记录的 H2 角色**决定。
///
/// 角色由请求自身的线速尺寸唯一确定（`CMD_PADDING` 的 junk 已按目标尺寸反解，
/// 故接收端能从帧长复原它）：
/// * SETTINGS 尺寸的请求 → 一条 `SETTINGS-ACK`（33）；
/// * HEADERS 量级（越过 `L1` 上界）的请求 → 一条**响应尺寸**的记录，即合成的
///   H2 请求/响应交换（见 `sample_h2_exchange_request_wire`）；
/// * 其余（PING 尺寸）→ 一条 `PING-ACK`（41）；
/// * 第二条应答一律是接收方本来就要发的 `WINDOW_UPDATE`（37）。
///
/// 「应答尺寸随请求尺寸变化」在这里是**保真**而不是相关性泄漏：真实 H2 的
/// PING-ACK 必须回显 PING 的 8 字节载荷、SETTINGS-ACK 恒为 9 字节帧、HEADERS
/// 请求换来的是响应体。此前被删掉的是另一种做法——`total_junk =
/// frame.payload.len() - 2`，让应答尺寸成为请求尺寸的**连续**函数，那才是一条
/// 可观测的相关性。这里是一张 3 项的离散角色表。
fn padding_reply_wire_len(
    request_wire_len: usize,
    index: usize,
    direction: FlowDirection,
) -> usize {
    if index > 0 {
        return PADDING_WINDOW_UPDATE_WIRE;
    }
    if kanotls_tunnel::control_size::is_settings_bearing_wire_size(request_wire_len) {
        return PADDING_SETTINGS_ACK_WIRE;
    }
    if request_wire_len > kanotls_tunnel::control_size::L1_MAX_WIRE_LEN {
        // 合成交换的应答：按响应侧数据记录的尺寸分布取值。
        let payload = kanotls_tunnel::control_size::next_data_record_payload(
            direction,
            &mut rand::thread_rng(),
        );
        return SnowyStream::data_record_wire_len(payload);
    }
    PADDING_ACK_WIRE
}

/// 把一个 control packet 编码成一条或多条 0x17 记录：每条的线速尺寸独立
/// 决定，载荷不足则零填充，任何一条记录的尺寸都不是载荷长度的函数。
///
/// 此前是「一个 packet 恰好一条记录」+ `prepare_control_record(packet, 采样值)`，
/// 而后者取 `max(采样值 - TLS头 - AEAD tag, payload + 长度前缀 + inner)`：载荷
/// 一旦超出采样尺寸能承载的容量，`max` 就把采样值整个吃掉，线速尺寸退化为
/// `payload.len() + CONTROL_RECORD_MIN_OVERHEAD`。后果分三档：
///
/// * `Frame::cmd_settings()` 恒为 23 字节 ⇒ 客户端首条控制记录在多数连接上恒
///   为 47 字节，而 47 不在任何采样池里——一个跨连接稳定的常量。
/// * `send_synack_rejection` 的 reason 串长度各异（17/19/21/28/31 字节）
///   ⇒ **拒绝原因通过记录尺寸泄漏**，持有合法 PSK 的探测者可据此区分服务端
///   内部状态。
/// * 最严重的是 `Stream::write_gather_open`：它把 `[SETTINGS][SYN][PSH(target)]
///   [PSH(首个数据块)]` 合并成一个 packet 走 Control 类，于是**每条流的第一条
///   记录尺寸 = 内层首包尺寸 + 24**。对经 SOCKS5 走 HTTPS 的浏览器，那就是内层
///   TLS ClientHello 的尺寸 1:1 上链（Chrome 517 ⇒ 541，带 ML-KEM 的 Firefox
///   ~1884 ⇒ ~1908），直接违反 §3.1/§3.3 声称已在 v1.1 消除的「明文长度不再
///   映射至线速长度」。
///
/// 在任意字节边界切分都是安全的：wire 协议不标记 record 边界，对端把各 record
/// 的块载荷按序拼进同一个 `BytesMut` 再 `Frame::decode`，看到的是纯字节流。
/// （这与 `drive_shaper` 里 `frame_boundaries` 的约束不同：那里限制的是**插队**
/// 的 control 帧只能落在完整帧边界上，因为插队会切断另一个帧的载荷；此处是
/// 同一个 packet 自己被切成多条记录，字节序完全不变。）
///
/// 返回本 packet 产生的记录条数：写循环用它维护合并 flush 的批量上限
/// （见 `FlushBatch`）。
fn prepare_control_packet_records(
    stream: &mut SplitWriteHalf,
    packet: &[u8],
    state: ConnectionState,
    direction: FlowDirection,
) -> std::io::Result<usize> {
    // CMD_PADDING 的 H2 角色已知（WINDOW_UPDATE / PING / PING-ACK），尺寸由
    // 编码侧的 junk 反解定死，整包恰好一条记录、精确命中角色尺寸。
    if let Some(target) = self_sized_padding_wire_len(packet) {
        trace!("control write: padding record wire_size={}", target);
        stream.prepare_control_record(packet, target)?;
        return Ok(1);
    }

    // 流生命周期帧（SYN / FIN）按**数据记录**分布定尺寸，不再走
    // 控制帧的离散池（`{33, 37, 41, 46, 54}`，全部落在论文的 `L1`）。
    //
    // 成因与判据（含 SYNACK 为何不在此列）见
    // `packet_carries_stream_lifecycle_frame`：这两种帧在真实 H2 里分别对应
    // `HEADERS` 与挂在 `DATA` 上的 `END_STREAM`，都是 `L2` 量级；
    // 而按控制池取值时，每次关流都会在响应体末段之后放出一对
    // 「本端 L1 → 对端 L1」，实测每 4~5 次关流就精确复现 `(−L4, L1, −L1)`。
    //
    // 取的是与 `TrafficShaper::markov_policy` **完全相同**的采样器
    // （`next_data_record_payload`），不是另开一个窄区间：若给它们一个专属的
    // 窄窗口，「每条流开/关各有一条 176–272 字节的记录」本身就是一条可跨流
    // 聚合的新特征——在一条最多承载 256 条流的连接上，可聚合的弱特征等于强
    // 特征。与常规数据记录同分布则无从分离。
    //
    // 不按 `ConnectionState` 设门：`from_control_count` 用的是方向无关的上界
    // `H2_OPENING_MAX_LEN = 3`（S2C 序列长度），而 C2S 的开场序列只有 1 条，
    // 于是客户端的第 1、2 条控制记录**报 Handshake 却已落到 Transport 池**。
    // 在客户端上这两条恰好就是「首条流的 FIN」与「第二条流的 SYN」——正是本
    // 规则要覆盖的对象。实测按 `state == Transport` 设门时，`(L2, −L4, L1)`
    // （Distinc 7.226）仍会从这两条漏出来。
    //
    // 开场 flight 不受影响：它由 `emit_h2_server_opening` 以**自定尺寸的
    // CMD_PADDING** 发出，在本函数开头就短路返回了，根本不经过这里；而服务端
    // 的 SYNACK 必然排在那三条之后（flight 由收到客户端 SETTINGS 触发，
    // SYNACK 要等应用层 accept + 连源站）。
    let lifecycle_sized = packet_carries_stream_lifecycle_frame(packet);

    let mut rng = rand::thread_rng();
    let mut consumed = 0usize;
    let mut records = 0usize;
    loop {
        let remaining = packet.len() - consumed;
        let control_target = if lifecycle_sized {
            SnowyStream::data_record_wire_len(
                kanotls_tunnel::control_size::next_data_record_payload(direction, &mut rng),
            )
        } else {
            stream.next_control_size(state, direction)
        };
        let control_cap = control_target.saturating_sub(CONTROL_RECORD_MIN_OVERHEAD);
        let (target, take) = if remaining <= control_cap {
            // 常态（SYN/FIN/小 SYNACK，以及采样到较大档的 SETTINGS）：整段装
            // 进一条采样尺寸的控制记录，余量零填充。
            (control_target, remaining)
        } else if remaining >= SnowyStream::data_record_capacity() {
            // 大段载荷按满载数据记录切走，与 bulk fast path 同一口径——否则
            // 65535 字节的首块会被切成上千条 33–82 字节的小记录，那既不像真实
            // H2，也把每条记录 24 字节的固定开销放大到四成。
            (
                SnowyStream::max_data_record_wire_len(),
                SnowyStream::data_record_capacity(),
            )
        } else {
            // 装不下 ⇒ 这一段是应用数据而不是空闲期控制帧
            // （`Stream::write_gather_open` 把 `[SETTINGS][SYN][PSH(target)]
            // [PSH(首块)]` 合并成一个 control packet），必须按**数据记录**口径
            // 切分：按 H2 HEADERS/DATA 帧的尺寸分布采样一个 chunk，切走
            // `min(remaining, chunk)` 并零填充至 chunk。记录尺寸只反映这次采样，
            // 与载荷长度无关。分布与 `TrafficShaper` 的 `InteractiveControl` 共用
            // 同一个定义（`control_size::next_data_record_payload`），此前是本文件
            // 私有的 200–600 均匀区间——两处对「H2 数据记录量级」各存一份定义。
            let chunk = kanotls_tunnel::control_size::next_data_record_payload(direction, &mut rng);
            (
                SnowyStream::data_record_wire_len(chunk),
                remaining.min(chunk),
            )
        };
        debug_assert!(
            take + CONTROL_RECORD_MIN_OVERHEAD <= target,
            "control payload slice must fit its target, else prepare_control_record's floor bites"
        );
        trace!(
            "control write: frame_cmd=0x{:02x} wire_size={} payload={}",
            packet.first().unwrap_or(&0),
            target,
            take
        );
        stream.prepare_control_record(&packet[consumed..consumed + take], target)?;
        consumed += take;
        records += 1;
        if consumed >= packet.len() {
            return Ok(records);
        }
    }
}

/// WINDOW_UPDATE 阈值：逐进程解析一次，此后恒定（论证见常量定义处）。
fn h2_window_update_threshold() -> usize {
    let override_bytes = H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.load(Ordering::Relaxed);
    if override_bytes > 0 {
        return override_bytes;
    }
    *H2_WINDOW_UPDATE_THRESHOLD.get_or_init(|| H2_FIREFOX_SESSION_WINDOW_BYTES / 2)
}

/// 下一次合成 H2 交换的间隔：开场窗口内是数十毫秒量级，之后是浏览量级。
fn sample_h2_exchange_interval(opening_left: u32) -> Duration {
    let override_ms = H2_EXCHANGE_INTERVAL_OVERRIDE_MS.load(Ordering::Relaxed);
    if override_ms > 0 {
        return Duration::from_millis(override_ms);
    }
    let (mu, sigma) = if opening_left > 0 {
        (H2_EXCHANGE_OPENING_MU_MS, H2_EXCHANGE_OPENING_SIGMA)
    } else {
        (H2_EXCHANGE_STEADY_MU_MS, H2_EXCHANGE_STEADY_SIGMA)
    };
    let ms = kanotls_tunnel::utils::sample_log_normal(mu, sigma).max(1.0);
    Duration::from_micros((ms * 1000.0).round() as u64)
        .min(Duration::from_secs(H2_EXCHANGE_MAX_INTERVAL_SECS))
}

/// 合成 H2 交换的请求记录尺寸：C2S HEADERS 帧量级（不是 PING 量级）。
fn sample_h2_exchange_request_wire() -> usize {
    kanotls_tunnel::control_size::next_headers_frame_wire_len(
        FlowDirection::C2S,
        &mut rand::thread_rng(),
    )
}

/// H2 流控状态：发送侧窗口（连接级 + 每流）与接收侧回补记账（消费 → WU）。
///
/// **为什么这是修复而不是新机制**：真实 H2 接收方按消费字节数回补窗口、发送
/// 方在窗口耗尽后停发，接收缓冲由窗口自身界定——此前 KanoTLS 的「缓冲超限 →
/// 丢数据 + 杀流」正是没有窗口语义的产物。现在把已有的两条 Firefox 常量
/// （连接窗口 12 MiB、半窗口回补）从「假填充」变成真信贷：
///
/// * 发送侧：`acquire_credit` 在提交前检查（连接信贷 && 每流信贷），不足则
///   挂起；WINDOW_UPDATE 帧到达（读循环帧层处理，纯记账）后放行。挂起即
///   背压：中继不再读源站，源站 TCP 窗口自然填满——与真实 H2 逐字节同构。
/// * 接收侧：`note_consumed` 由中继在字节真正交付本地/远端后调用，按
///   「消费过半窗口」的 nghttp2 规则回吐 WINDOW_UPDATE（每流 1 MiB、
///   连接 6 MiB，尺寸恒为 37 字节的 `WINDOW_UPDATE_WIRE`）。
///
/// **旧对端兼容**：本端只在收到对端 SETTINGS 携带 `fc=1` 后才启用发送侧
/// 门控（SETTINGS 本就是 H2 协商窗口语义的载体）；对未声明 fc 的对端，门控
/// 完全旁路，行为与旧版逐字节一致。回补帧（flag=3）对旧对端是静默吸收的
/// 填充，无害。
///
/// **无死锁**：门控挂起等的是**读循环**（非阻塞）收到的 WU 通知，不再依赖
/// 写端任何 await；写端只可能在 TCP 发送缓冲真满时阻塞（正确背压）。
pub(crate) struct WindowState {
    writer: SharedTunnelWriter,
    /// 对端是否在 SETTINGS 中声明了流控支持（`fc=1`）。为 false 时发送侧
    /// 门控整体旁路，保持旧行为。
    peer_flow_control: AtomicBool,
    conn_credit: AtomicI64,
    conn_wu_threshold: u64,
    /// 连接级已消费、尚未回补的字节（CAS 记账，多流并发消费安全）。
    conn_consumed_since_wu: AtomicU64,
    stream_window: i64,
    stream_wu_threshold: u64,
    /// 连接级信贷到达信号。用 `notify_one`（留 permit）而不是
    /// `notify_waiters`：信贷在「检查 → 挂起」的间隙到达时，permit 会留给
    /// 下一个挂起者，杜绝丢唤醒。
    credit_notify: Notify,
}

impl WindowState {
    pub(crate) fn new(writer: SharedTunnelWriter) -> Self {
        // 连接窗口 = 2 × 半窗口回补阈值（Firefox 12 MiB 连接窗口，/2 即
        // nghttp2 的「消费达本地窗口一半即回补」规则）。测试覆写点
        // `H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES` 沿用在阈值上，窗口
        // 随之缩放。
        let conn_wu_threshold = h2_window_update_threshold() as u64;
        let conn_window = (conn_wu_threshold as i64).saturating_mul(2);
        let stream_window = STREAM_WINDOW_OVERRIDE_BYTES
            .load(Ordering::Relaxed)
            .max(STREAM_WINDOW_BYTES) as i64;
        Self {
            writer,
            peer_flow_control: AtomicBool::new(false),
            conn_credit: AtomicI64::new(conn_window),
            conn_wu_threshold,
            conn_consumed_since_wu: AtomicU64::new(0),
            stream_window,
            stream_wu_threshold: (stream_window as u64).saturating_div(2).max(1),
            credit_notify: Notify::new(),
        }
    }

    pub(crate) fn stream_window(&self) -> i64 {
        self.stream_window
    }

    pub(crate) fn set_peer_flow_control(&self) {
        self.peer_flow_control.store(true, Ordering::Relaxed);
    }

    pub(crate) fn peer_supports_flow_control(&self) -> bool {
        self.peer_flow_control.load(Ordering::Relaxed)
    }

    /// 发送侧门控：信贷（连接级 + 每流）充足则扣减并放行，否则挂起。
    ///
    /// 对端未声明 fc 时直接放行（旧行为）。`stream_notify` 是本流的
    /// `pending_notify`：每流 WU 到达时由帧层单独唤醒，连接级 WU 唤醒
    /// `credit_notify`——两者都只做「再查一次」的提示，误唤醒无害。
    /// 会话关闭时立即放行，让后续提交在 writer 的既有失败路径上报错。
    pub(crate) async fn acquire_credit(
        &self,
        stream_credit: &AtomicI64,
        stream_notify: &Arc<Notify>,
        len: usize,
    ) {
        if !self.peer_flow_control.load(Ordering::Relaxed) {
            return;
        }
        let len = len as i64;
        loop {
            if self.writer.is_closed() {
                return;
            }
            if self.conn_credit.load(Ordering::Relaxed) >= len
                && stream_credit.load(Ordering::Relaxed) >= len
            {
                self.conn_credit.fetch_sub(len, Ordering::Relaxed);
                stream_credit.fetch_sub(len, Ordering::Relaxed);
                return;
            }
            tokio::select! {
                _ = self.credit_notify.notified() => {}
                _ = stream_notify.notified() => {}
            }
        }
    }

    fn add_conn_credit(&self, increment: u32) {
        self.conn_credit
            .fetch_add(i64::from(increment), Ordering::Relaxed);
        self.credit_notify.notify_one();
    }

    fn add_stream_credit(&self, credit: &AtomicI64, notify: &Arc<Notify>, increment: u32) {
        credit.fetch_add(i64::from(increment), Ordering::Relaxed);
        notify.notify_one();
    }

    /// 连接级消费记账：跨流并发安全（CAS），越过阈值的那一方独占回补，
    /// 杜绝两流同时把同一段消费重复计入。
    fn bump_conn_consumed(&self, len: u64) -> Option<u32> {
        let threshold = self.conn_wu_threshold;
        let mut prev = self.conn_consumed_since_wu.load(Ordering::Relaxed);
        loop {
            let total = prev.saturating_add(len);
            let next = if total >= threshold { 0 } else { total };
            match self.conn_consumed_since_wu.compare_exchange(
                prev,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return (total >= threshold).then(|| total.min(u32::MAX as u64) as u32),
                Err(actual) => prev = actual,
            }
        }
    }

    /// 接收侧回补入账：中继在字节真正交付应用层后调用。每流与连接级各自
    /// 累计，越过半窗口阈值即回吐一条真实 WINDOW_UPDATE（flag=3）。
    ///
    /// `stream_consumed_since_wu` 在流对象上（单消费者，fetch_add/fetch_sub
    /// 安全）；连接级计数器在这里（多流并发，CAS）。
    ///
    /// 回补帧走 `try_write_packets`（fire-and-forget）：控制队列满时丢弃是
    /// **保守且自愈**的——发送方少拿一次信贷只会更早停发，而接收缓冲
    /// （≥ 窗口 ≥ 阈值）仍在被中继排空，下一次越过阈值必会再发一条。
    pub(crate) fn note_consumed(&self, sid: u32, stream_consumed_since_wu: &AtomicU64, len: usize) {
        let len_u64 = len as u64;
        let stream_total = stream_consumed_since_wu.fetch_add(len_u64, Ordering::Relaxed) + len_u64;
        if stream_total >= self.stream_wu_threshold {
            stream_consumed_since_wu.fetch_sub(stream_total, Ordering::Relaxed);
            self.send_window_update(sid, stream_total.min(u32::MAX as u64) as u32);
        }
        if let Some(conn_total) = self.bump_conn_consumed(len_u64) {
            self.send_window_update(0, conn_total);
        }
    }

    fn send_window_update(&self, sid: u32, increment: u32) {
        let packet = encode_padding_window_update_sized(sid, increment, PADDING_WINDOW_UPDATE_WIRE);
        if let Err(e) =
            self.writer
                .try_write_packets(vec![packet], FlushBehavior::Auto, TrafficClass::Control)
        {
            debug!("window update dropped (control queue full): {}", e);
        }
    }
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
    idle_timeout_secs: u64,
    pub(crate) shutdown: Arc<Notify>,
    alive: AtomicBool,
    close_requested: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
    pending_inbound_streams: AtomicUsize,
    pending_open_streams: Arc<Mutex<PendingOpenStreams>>,
    pub(crate) pending_data: Arc<Mutex<PendingData>>,
    pending_fin: Arc<Mutex<HashSet<u32>>>,
    closing_streams: Arc<Mutex<HashSet<u32>>>,
    on_new_stream: Option<Arc<dyn Fn(u32) -> bool + Send + Sync>>,
    pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
    pub(crate) buffered_stream_bytes: Arc<AtomicUsize>,
    inbound: Arc<InboundSignal>,
    /// 本端已**处理**过的最大对端流 id —— 拆除时写进 GOAWAY 的
    /// `last_stream_id`。
    ///
    /// 口径刻意保守：CMD_SYN 一进 `handle_frame` 就抬水位，无论后续是接受还是
    /// 拒绝。语义是 H2 的「**可能**已被处理」，因此**高于**水位的流才是「对端
    /// 确定没碰过、可安全重试」的那批；把一条其实已经转发给源站的流误算进可
    /// 重试集合，会造成非幂等请求的重复执行，方向上比漏算严重得多。
    ///
    /// KanoTLS 中流只由客户端发起（服务端 `next_stream_id` 起始为 0，
    /// `next_stream_id()` 见 0 即 bail），所以这本账在客户端侧恒为 0——正如
    /// 真实 H2 客户端在没有服务端推送时发出的 GOAWAY 也写 0。
    peer_stream_high_water: Arc<AtomicU32>,
    /// 对端 GOAWAY 里的 last_stream_id（`GOAWAY_NOT_RECEIVED` 表示还没收到）。
    peer_goaway_last_stream_id: Arc<AtomicU64>,
    /// H2 流控状态：发送侧窗口与接收侧回补记账（见 `WindowState`）。
    pub(crate) windows: Arc<WindowState>,
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

#[derive(Debug)]
pub(crate) struct StreamHandle {
    pub data_tx: mpsc::Sender<BufferedPayload>,
    pub fin_tx: mpsc::Sender<()>,
    pub synack_tx: Option<oneshot::Sender<Vec<u8>>>,
    pub read_closed: bool,
    pub pending_notify: Arc<Notify>,
    /// 本流**发送**方向的剩余信贷（H2 每流窗口语义）。句柄存续期即窗口
    /// 存续期：注册 +1、句柄随映射移除即释放，无独立生命周期管理。
    /// 由本端写路径扣减、对端 WINDOW_UPDATE 帧入账。
    pub send_credit: Arc<AtomicI64>,
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
    pub traffic_script: Option<Vec<String>>,
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
        traffic_script: Option<Vec<String>>,
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

/// 一次 flush 边界内已 prepare 进 `write_buffer`、尚未出网的内容。
///
/// 此前每条小控制记录各自 flush 一次：`write_control_request_now` 逐请求
/// flush、`drive_shaper` 在排空末尾再 flush、`emit_fake_frames` 自己又 flush
/// 一次。socket 开了 `TCP_NODELAY`，一次 `write()` 内的字节尽量落进同一个
/// TCP 段 ⇒ **flush 边界就是分段边界，就是分类器观测的单位**。于是一条 33
/// 字节的 SETTINGS-ACK 会独占一个 33 字节的段，哪怕同一时刻队列里还压着
/// 后续内容；真实 NSS/BoringSSL 则把 nghttp2 已排队的全部内容一次
/// `write()` 出去 ⇒ 一个段。这既是 KanoTLS 包数远高于 nginx 的根因，也是
/// 零延迟源站下 `(L2, −L4, L1)` 残留的来源。而论文只在连接的前 `Wo = 25`
/// 个承载数据的包上采样一次，包数正是那个窗口能覆盖多少内容的分母。
///
/// 现在改为：control/bulk 通道当前都没有立即可取的后续内容时才 flush，否则
/// 把本批留在 `write_buffer` 里与后续内容并进同一次 `write()`。记录的尺寸、
/// 条数、顺序完全不变——只改分段边界。
///
/// **responder 语义不变**：必须在字节真正 flush 之后才应答 `Ok`
/// （`PendingWrite::wait` 的调用方依赖它），因此同一批 responder 在同一次
/// flush 之后一起应答。responder 只能在其字节**已经 prepare 进
/// write_buffer** 之后才入批——仍留在明文积压 `pending` 里的写请求，其
/// responder 由 `drain_pending_and_respond` 在整段排空之后才移交本批。
#[derive(Default)]
struct FlushBatch {
    /// 字节已进入 write_buffer、等「真正出网」才能应答的 responder。
    responders: Vec<oneshot::Sender<Result<(), String>>>,
    /// 自上次 flush 以来 prepare 的记录条数（合并上限之一）。
    records: usize,
    /// 本连接累计成功 flush 的次数。
    ///
    /// 用途：给 `TrafficShaper` 一个**可辩护的包数下界**。socket 开了
    /// `TCP_NODELAY`，一次 `flush()` = 一次 `write()` ⇒ 至少一个 TCP 段，
    /// 因此「flush 次数」恒 ≤ 本端已发出的承载数据的包数。加上
    /// `InboundSignal::arrivals()`（一次 `read()` ≥ 一个对端段，同样是下界），
    /// 两者之和是**双向总包数的下界**。
    ///
    /// 为什么不能用 shaper 自己的 `packet_seq`：它计的是**记录**条数，而合并
    /// flush 会把最多 `STICKY_BULK_FLUSH_MAX_RECORDS` 条记录塞进同一个段
    /// ⇒ `packet_seq` 会**高估**包数，据此判「窗口已过」会放松得太早。下界则
    /// 只会判得太晚——方向保守，与 PING 抑制处的口径一致。
    flushes: u64,
}

impl FlushBatch {
    fn note_records(&mut self, count: usize) {
        self.records += count;
    }

    fn push_responder(&mut self, responder: oneshot::Sender<Result<(), String>>) {
        self.responders.push(responder);
    }

    fn is_idle(&self) -> bool {
        self.records == 0 && self.responders.is_empty()
    }

    /// 合并上限（双上限，先到先 flush）：沿用 sticky bulk 的**确定性**阈值，
    /// 不加抖动——真实实现在这里也不抖动。它保证合并不会引入无界延迟，也
    /// 保证 write_buffer 不会无界增长。
    fn is_full(&self, buffered: usize) -> bool {
        self.records >= STICKY_BULK_FLUSH_MAX_RECORDS || buffered >= STICKY_BULK_FLUSH_MAX_BYTES
    }

    /// 冲刷并应答本批全部 responder。
    async fn flush(&mut self, write_half: &mut SplitWriteHalf) -> std::io::Result<()> {
        self.records = 0;
        match write_half.flush().await {
            Ok(()) => {
                self.flushes = self.flushes.saturating_add(1);
                for responder in self.responders.drain(..) {
                    let _ = responder.send(Ok(()));
                }
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                for responder in self.responders.drain(..) {
                    let _ = responder.send(Err(msg.clone()));
                }
                Err(e)
            }
        }
    }

    fn fail(&mut self, msg: &str) {
        self.records = 0;
        for responder in self.responders.drain(..) {
            let _ = responder.send(Err(msg.to_string()));
        }
    }
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
        let inbound = Arc::new(InboundSignal::default());
        // 写循环在 SessionWriter::new 里就被 spawn 出去，而 GOAWAY 由它在退出
        // 路径上发出：水位账本必须先于写循环存在，两侧共享同一个 Arc。
        let peer_stream_high_water = Arc::new(AtomicU32::new(0));
        let (read_half, write_half) = tunnel.into_split();
        let writer = Arc::new(SessionWriter::new(
            write_half,
            close_requested.clone(),
            close_notify.clone(),
            config.is_client,
            config.traffic_script.as_deref(),
            config.post_script_off,
            pending_client_settings.clone(),
            inbound.clone(),
            peer_stream_high_water.clone(),
        ));
        let windows = Arc::new(WindowState::new(writer.clone()));
        // 空闲拆除取配置值本身，**不加抖动**（论证见 `Session::idle_timeout_secs`）。
        let idle_timeout_secs = config.idle_timeout_secs.max(1);

        Self {
            read_half: Mutex::new(Some(read_half)),
            writer: writer.clone(),
            streams: Arc::new(RwLock::new(HashMap::new())),
            capacity_stream_count: Arc::new(AtomicUsize::new(0)),
            next_stream_id: AtomicU32::new(if config.is_client { 1 } else { 0 }),
            is_client: config.is_client,
            max_streams_per_session: config.max_streams_per_session,
            post_script_off: config.post_script_off,
            idle_timeout_secs,
            shutdown: Arc::new(Notify::new()),
            alive: AtomicBool::new(true),
            close_requested,
            close_notify,
            pending_inbound_streams: AtomicUsize::new(0),
            pending_open_streams: Arc::new(Mutex::new(PendingOpenStreams::default())),
            pending_data: Arc::new(Mutex::new(PendingData::default())),
            pending_fin: Arc::new(Mutex::new(HashSet::new())),
            closing_streams: Arc::new(Mutex::new(HashSet::new())),
            on_new_stream,
            pending_client_settings,
            buffered_stream_bytes: Arc::new(AtomicUsize::new(0)),
            inbound,
            peer_stream_high_water,
            peer_goaway_last_stream_id: Arc::new(AtomicU64::new(GOAWAY_NOT_RECEIVED)),
            windows,
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

    /// 服务端 session 的空闲拆除时长，**精确常量、无抖动**。
    ///
    /// 此前取 `base + U[0, base/10]`（默认 45 秒 ±10%），于是每条服务端连接的
    /// 空闲拆除时刻是一个逐连接采样的随机量。真实 nginx 的 `keepalive_timeout`
    /// 是一个编译进配置的**精确常量**：同一台服务器上所有空闲连接都在同一秒
    /// 被关掉。在一个真实实现恒定的维度上随机化，本身就是判别特征
    /// （MECHANISM §9.0 原则 2）。
    ///
    /// 这条抖动此前只是次要观测量：客户端连接池 30 秒回收先于服务端 45 秒
    /// 触发，服务端定时器多数情况下根本走不到期。上一轮把池的空闲回收提到
    /// **115 秒**（Firefox `network.http.keep-alive.timeout`）之后，**先关闭的
    /// 一方变成了服务端**，这个抖动随之升级为线上**主要的可观测拆除时序**——
    /// 一个观测者只要对同一服务端保持若干条空闲连接，就能测出「关闭时刻服从
    /// 一个宽度为 base/10 的均匀分布」，而任何真实服务器给出的都是一条直线。
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    /// 记录对端 GOAWAY 的 `last_stream_id`。
    ///
    /// **只在客户端侧记账**。H2 里 GOAWAY 的 last_stream_id 指的是「**接收方
    /// 发起的**流」——客户端发的 GOAWAY 说的是服务端推送流，与服务端 accept
    /// 来的那些客户端发起的流毫无关系。KanoTLS 里流只由客户端发起，所以客户端
    /// 发出的 GOAWAY 恒带 0；若服务端也照单全收，它会把自己手上**每一条**流
    /// （id ≥ 1）都判成「对端没处理过」，正好是最危险的误判方向。
    ///
    /// 载荷长度不足以携带 id 时（`decode_padding_goaway` 返回 `None`）保持
    /// 「未收到」状态：宁可退化成与今天完全一致的普通断开，也不能把缺省值 0
    /// 当成真值。
    fn note_peer_goaway(&self, payload: &[u8]) {
        if !self.is_client {
            return;
        }
        let Some(last_stream_id) = decode_padding_goaway(payload) else {
            return;
        };
        debug!(last_stream_id, "peer sent GOAWAY");
        // fetch_min 而不是 store：GOAWAY 在 H2 中可以发第二条以收窄范围，
        // 但绝不允许放宽（那会把已经判定为「未处理」的流又算回去）。
        // 哨兵是 u64::MAX，所以首条 GOAWAY 天然取胜。
        self.peer_goaway_last_stream_id
            .fetch_min(u64::from(last_stream_id), Ordering::Relaxed);
    }

    /// 对端 GOAWAY 是否宣告 `stream_id` 从未被处理 ⇒ 该流可安全重试。
    pub fn peer_never_processed(&self, stream_id: u32) -> bool {
        peer_never_processed(&self.peer_goaway_last_stream_id, stream_id)
    }

    pub fn buffered_stream_bytes(&self) -> usize {
        self.buffered_stream_bytes.load(Ordering::Relaxed)
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
        let send_credit = Arc::new(AtomicI64::new(self.windows.stream_window()));

        let handle = StreamHandle {
            data_tx,
            fin_tx,
            synack_tx: Some(synack_tx),
            read_closed: false,
            pending_notify: pending_notify.clone(),
            send_credit: send_credit.clone(),
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
            register_stream_locked(&mut streams, &self.capacity_stream_count, sid, handle);
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
            send_credit,
            windows: self.windows.clone(),
            peer_goaway_last_stream_id: self.peer_goaway_last_stream_id.clone(),
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
        // 发送侧流控门：连接级 + 每流信贷都覆盖本次写入才放行，否则挂起
        // 等对端 WINDOW_UPDATE（H2 语义，见 WindowState）。窗口不足即停发
        // ⇒ 接收缓冲被窗口界定，此前的「超限丢数据 + 杀流」结构性不可达。
        // 对未声明 fc 的对端，门控整体旁路（旧行为逐字节不变）。
        let credit = self
            .streams
            .read()
            .await
            .get(&sid)
            .map(|handle| (handle.send_credit.clone(), handle.pending_notify.clone()));
        if let Some((send_credit, stream_notify)) = credit {
            self.windows
                .acquire_credit(&send_credit, &stream_notify, data.len())
                .await;
        }
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

    /// 读循环内的防御性关闭：只做锁内清理 + try 发 FIN，**绝不等 flush**。
    ///
    /// `close_stream` 要等到 FIN 真正出网（`write_frame` 等 flush），写端若
    /// 卡在 TCP 发送缓冲上，读循环会连带冻结整个会话（此前的四任务死锁环）。
    /// 本路径供「接收缓冲超限」这类防御性拆除使用——对声明 fc 的对端结构性
    /// 不可达（窗口界定缓冲，见 `store_pending_data`），只可能在旧对端或
    /// 协议错误下触发。FIN 偶发丢失时，对端流由其自身的空闲拆除 / 会话拆除
    /// 回收。
    async fn close_stream_fire_and_forget(&self, sid: u32) {
        self.finish_closing_stream(sid).await;
        if let Ok(packet) = Frame::fin(sid).encode() {
            let _ = self.writer.try_write_packets(
                vec![packet],
                FlushBehavior::Immediate,
                TrafficClass::Control,
            );
        }
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
        let mut buf = BytesMut::with_capacity(TUNNEL_REASSEMBLY_CAPACITY);

        // 两侧都从「未收到对端 SETTINGS」起步：客户端凭首条服务端 SETTINGS
        // 回复 SETTINGS-ACK（真实 H2 语义，此前由服务端开场 flight 的
        // SETTINGS 尺寸填充请求触发，现在 flight 首条就是真 SETTINGS）；
        // 服务端凭客户端 SETTINGS 放行 SYN 并解析 fc 声明。
        let mut settings_received = false;

        // 空闲拆除仅服务端生效：池化客户端的空闲连接由连接池的 idle drain
        // 统一管理（drain 后 force_close 本 session），session 层不再重复
        // 维护一套永远更晚触发的空闲定时器。
        let idle_teardown_enabled = !self.is_client;
        let idle_duration = Duration::from_secs(self.idle_timeout_secs);
        let idle_timeout = tokio::time::sleep(idle_duration);
        tokio::pin!(idle_timeout);

        // 稳态 H2 骨架状态：post_script_off 时整体关闭（定时器取禁用姿态，
        // 分支被 guard 屏蔽）。消费驱动的 WINDOW_UPDATE 不再由读循环注入
        // 假填充——真实信贷帧由中继的 `note_consumed` 路径回吐（见
        // WindowState），与骨架开关无关（流控是正确性机制，不是伪装帧）。
        let h2_skeleton_enabled = !self.post_script_off;

        // 合成共存流：仅客户端方向（真实 H2 的请求由客户端发起）。
        let h2_exchange_enabled = h2_skeleton_enabled && self.is_client;
        let mut h2_exchange_opening_left = if h2_exchange_enabled {
            use rand::Rng;
            rand::thread_rng()
                .gen_range(H2_EXCHANGE_OPENING_MIN_COUNT..=H2_EXCHANGE_OPENING_MAX_COUNT)
        } else {
            0
        };
        let h2_exchange_timer = tokio::time::sleep(if h2_exchange_enabled {
            sample_h2_exchange_interval(h2_exchange_opening_left)
        } else {
            H2_TIMER_DISABLED
        });
        tokio::pin!(h2_exchange_timer);

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
                        debug!("session idle for {}s, tearing down", self.idle_timeout_secs);
                        break;
                    }
                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    continue;
                }
                _ = &mut h2_exchange_timer, if h2_exchange_enabled => {
                    // 合成 H2 请求/响应交换。发出条件（论证见
                    // H2_EXCHANGE_OPENING_MIN_COUNT）：
                    //  * 对端已经说过话——保证连接的第一个上行 burst 已出网，
                    //    合成请求不会挤进那个 burst 把它顶过 300 字节门限；
                    //  * 仍在开场窗口内，或至少有一条流开着。
                    let peer_spoke = self.inbound.arrivals() > 0;
                    let has_stream = self.capacity_stream_count.load(Ordering::Relaxed) > 0;
                    if peer_spoke && (h2_exchange_opening_left > 0 || has_stream) {
                        let wire = sample_h2_exchange_request_wire();
                        let packet = encode_padding_request_sized(1, wire);
                        if let Err(e) = self
                            .writer
                            .submit_write_packets(
                                vec![packet],
                                FlushBehavior::Auto,
                                TrafficClass::Control,
                            )
                            .await
                        {
                            warn!("failed to queue h2 synthetic exchange: {}", e);
                        }
                        h2_exchange_opening_left = h2_exchange_opening_left.saturating_sub(1);
                    }
                    h2_exchange_timer.as_mut().reset(
                        tokio::time::Instant::now()
                            + sample_h2_exchange_interval(h2_exchange_opening_left),
                    );
                    continue;
                }
                result = read_tunnel_chunk(&mut read_half, &mut buf) => result,
            };

            idle_timeout
                .as_mut()
                .reset(tokio::time::Instant::now() + idle_duration);

            match read_result {
                Ok(0) => {
                    debug!("tunnel eof, ending read loop");
                    break;
                }
                // 字节已由 `read_tunnel_chunk` 直接落进 `buf` 的尾部。
                Ok(_) => {}
                Err(e) => {
                    error!("tunnel read error: {}", e);
                    break;
                }
            }

            // 方向改变信号：写循环据此结束第一个上行 burst（见 InboundSignal）。
            self.inbound.note_arrival();

            if buf.len() > MAX_SESSION_REASSEMBLY_BYTES {
                warn!(
                    "closing session: frame reassembly buffer exceeded {} bytes",
                    MAX_SESSION_REASSEMBLY_BYTES
                );
                break;
            }

            let mut protocol_error = false;
            while let Some(frame) = Frame::decode(&mut buf) {
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

    /// 拒绝原因帧的定长载荷：全部 reason 右侧补空格到同一长度。
    ///
    /// 此前 reason 原样上帧，五种原因的长度各不相同（17/19/21/28/31 字节）。
    /// 控制记录切分后尺寸虽已落回采样池，但「载荷能否装进当前那条记录」仍取决
    /// 于长度：短原因装得下 ⇒ 一条开场尺寸的记录，长原因装不下 ⇒ 退到数据量级
    /// 的记录。于是**拒绝原因仍能通过记录尺寸/条数被区分**，持有合法 PSK 的
    /// 探测者据此可以枚举服务端内部状态（settings 未到 / 流 id 重复 / 达到流上限
    /// / 过载 / 不接受入站流）。定长后五种原因在线上完全同形。
    /// 接收侧 `Stream::wait_synack_once` 会 trim 掉补白。
    const SYNACK_REJECTION_PAYLOAD_LEN: usize = 32;

    async fn send_synack_rejection(
        &self,
        stream_id: u32,
        reason: &'static str,
    ) -> Result<(), anyhow::Error> {
        debug_assert!(reason.len() <= Self::SYNACK_REJECTION_PAYLOAD_LEN);
        let mut payload = vec![b' '; Self::SYNACK_REJECTION_PAYLOAD_LEN];
        let take = reason.len().min(Self::SYNACK_REJECTION_PAYLOAD_LEN);
        payload[..take].copy_from_slice(&reason.as_bytes()[..take]);
        let frame = Frame::new(CMD_SYNACK, stream_id, payload);
        // fire-and-forget：拒绝帧是建议性的，客户端 wait_synack 自带 10s
        // 超时兜底；读循环绝不因写端排队阻塞（死锁环见 WindowState）。
        let packet = frame.encode()?;
        self.writer
            .try_write_packets(
                vec![packet],
                FlushBehavior::Immediate,
                TrafficClass::Control,
            )
            .map_err(|e| anyhow::anyhow!("failed to queue synack rejection: {}", e))
    }

    /// 服务端在收到客户端 `CMD_SETTINGS` 后立即发出的 H2 开场 flight。
    ///
    /// 这把 `control_size::h2_opening_size` 从一张**尺寸表**变成了真正的
    /// **发送时序**。此前那三条 S2C 开场尺寸只是「服务端接下来碰巧要发的前 3 条
    /// 控制记录」被赋予的尺寸，而服务端在没有 SYNACK/padding 要发时根本不说话；
    /// 于是线上既没有 nginx/h2o 那条
    /// `SETTINGS → WINDOW_UPDATE → SETTINGS-ACK` 开场 flight，客户端一侧的
    /// `h2_opening_size(C2S, 0) = SETTINGS-ACK` 也永远被跳过（客户端的第一条控制
    /// 记录是自定尺寸的 CMD_PADDING，走 `self_sized_padding_wire_len` 短路，
    /// 不消费开场序列的 index 0）。
    ///
    /// 现在两侧都对齐真实 H2：
    /// * 服务端收到客户端 SETTINGS ⇒ 回**真 SETTINGS**（换一条 ACK，同时向
    ///   对端声明 `fc=1` 流控支持）+ `WINDOW_UPDATE`（不换应答）+
    ///   `SETTINGS-ACK`（不换应答），三条记录一次 flush，正是 nginx 的开场写；
    ///   首条记录由填充请求改为真 SETTINGS 后**线速尺寸不变**：它由
    ///   `h2_opening_size(S2C, 0)` 的确定性表格决定，写循环对非 padding 的
    ///   control packet 走同一条采样路径，恰好命中同一尺寸（内层内容在 Noise
    ///   加密内，观测者无从分辨）。
    /// * 客户端收到那条 SETTINGS ⇒ 按真实 H2 语义回一条 33 字节
    ///   `SETTINGS-ACK`（`h2_opening_size(C2S, 0)`，见 handle_frame）。
    ///
    /// 这同时取代了旧的「首条数据记录同批注入一条 41 字节 PING 请求」来让出
    /// 方向：PING 是保活帧，把它放在最受关注的位置（论文 `Wo = 25` 窗口的第 0
    /// 条记录）等于用一个新特征换掉旧特征。SETTINGS/SETTINGS-ACK 交换是这个
    /// 位置上唯一站得住脚的 H2 语义，而且同样在一个 RTT 内完成——它由读循环在
    /// 帧层直接回吐，不经 DNS / connect（SYNACK 要等那两步，10–100ms）。
    ///
    /// 尺寸取 `h2_opening_size` 的确定值而不是采样：真实端点的开场帧内容由代码
    /// 决定，逐连接抖动本身就是判别特征（同 `H2_OPENING_MAX_LEN` 的论证）。
    /// 三条记录共用一次 flush，因此线上是**一个** ~121/139 字节的下行分段，与
    /// nginx 把开场帧一次写出的形态一致。
    ///
    /// `post_script_off` 只关掉骨架的 WINDOW_UPDATE / SETTINGS-ACK 两条
    /// 伪装记录；SETTINGS 本身（含 fc 声明）恒发——流控是正确性机制不是
    /// 伪装帧，关闭整形不得连带关闭它（否则客户端永远收不到 fc 声明，
    /// C2S 门控整体旁路，旧版「超限丢数据」会回归）。
    async fn emit_h2_server_opening(&self) {
        if self.is_client {
            return;
        }
        use kanotls_tunnel::control_size::h2_opening_size;
        let mut packets = Vec::new();
        let mut index = 0u64;
        while let Some(size) = h2_opening_size(FlowDirection::S2C, index) {
            // index 0 是服务端自己的 SETTINGS：按 H2 语义必须换来一条
            // SETTINGS-ACK，因此用真 CMD_SETTINGS（载荷携带 fc 声明，尺寸仍
            // 由 h2_opening_size(S2C, 0) 命中）。其余两条（WINDOW_UPDATE、
            // 对客户端 SETTINGS 的 ACK）不换应答 ⇒ flag=1 padding。
            let packet = if index == 0 {
                Frame::cmd_settings()
                    .encode()
                    .expect("settings frame encodes")
            } else {
                if self.post_script_off {
                    break;
                }
                encode_padding_reply_sized(size)
            };
            packets.push(packet);
            index += 1;
        }
        if packets.is_empty() {
            return;
        }
        if let Err(e) = self
            .writer
            .submit_write_packets(packets, FlushBehavior::Auto, TrafficClass::Control)
            .await
        {
            warn!("failed to queue h2 server opening flight: {}", e);
        }
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
                                        self.close_stream_fire_and_forget(frame.stream_id).await;
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
                                self.close_stream_fire_and_forget(frame.stream_id).await;
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
                // 水位在**任何**分支判断之前抬起：GOAWAY 的 last_stream_id 语义
                // 是「可能已被处理」，一条被拒绝的 SYN 同样已经换回了一条
                // SYNACK 拒绝帧，绝不属于「对端没碰过、可安全重试」的那批。
                self.peer_stream_high_water
                    .fetch_max(frame.stream_id, Ordering::Relaxed);
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
                    .insert_new(frame.stream_id);
                if let Some(ref cb) = self.on_new_stream {
                    if !cb(frame.stream_id) {
                        self.pending_open_streams
                            .lock()
                            .await
                            .remove(frame.stream_id);
                        self.release_inbound_stream_reservation();
                        self.send_synack_rejection(frame.stream_id, "server overloaded")
                            .await?;
                    }
                } else {
                    self.pending_open_streams
                        .lock()
                        .await
                        .remove(frame.stream_id);
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
                            mark_stream_read_closed_locked(handle, &self.capacity_stream_count);
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
                    // SYNACK 载荷是定长 32 字节的拒绝原因串，走 oneshot
                    // 通道（`Vec<u8>`）交付；这一次拷贝在量级上不可见。
                    let payload = frame.payload.to_vec();
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
                let first = !*settings_received;
                *settings_received = true;
                // `fc=1` ⇒ 对端支持 H2 流控：此后本端发送侧门控启用
                // （见 WindowState::acquire_credit）。旧对端的 SETTINGS 没有
                // 该声明，门控保持旁路，行为与旧版逐字节一致。
                if frame.payload.windows(4).any(|w| w == b"fc=1") {
                    self.windows.set_peer_flow_control();
                }
                trace!(
                    "client settings: {}",
                    String::from_utf8_lossy(&frame.payload)
                );
                if first {
                    if self.is_client {
                        // 真实 H2 语义：首条对端 SETTINGS 必须换一条
                        // SETTINGS-ACK（33 字节，`h2_opening_size(C2S, 0)`）。
                        // 走 fire-and-forget：读循环绝不因写端排队而阻塞；
                        // 丢失时对端（本端）无从感知也不受影响。
                        let packet = encode_padding_reply_sized(PADDING_SETTINGS_ACK_WIRE);
                        if let Err(e) = self.writer.try_write_packets(
                            vec![packet],
                            FlushBehavior::Auto,
                            TrafficClass::Control,
                        ) {
                            debug!("failed to queue settings-ack: {}", e);
                        }
                    }
                    self.emit_h2_server_opening().await;
                }
            }
            CMD_PADDING => {
                let flag = frame
                    .payload
                    .first()
                    .copied()
                    .unwrap_or(PADDING_FLAG_REQUEST);
                if flag == PADDING_FLAG_GOAWAY {
                    self.note_peer_goaway(&frame.payload);
                } else if flag == PADDING_FLAG_WINDOW_UPDATE {
                    // 真实 H2 流控信贷：连接级（stream_id=0）或每流级
                    // 入账并唤醒门控等待者。纯记账、零 await——读循环
                    // 绝不因信贷路径阻塞。每流信贷挂在句柄上，句柄随流
                    // 拆除即释放；对已关闭流的 WU 静默忽略。
                    if let Some(increment) = decode_padding_window_update(&frame.payload) {
                        if frame.stream_id == 0 {
                            self.windows.add_conn_credit(increment);
                        } else if let Some(handle) = self.streams.read().await.get(&frame.stream_id)
                        {
                            self.windows.add_stream_credit(
                                &handle.send_credit,
                                &handle.pending_notify,
                                increment,
                            );
                        }
                    }
                } else if flag == PADDING_FLAG_REQUEST {
                    // 请求记录的线速尺寸由帧长唯一复原（junk 已按目标反解），
                    // 应答的 H2 角色据此决定——见 padding_reply_wire_len。
                    let request_wire =
                        FRAME_HEADER_SIZE + frame.payload.len() + CONTROL_RECORD_MIN_OVERHEAD;
                    let m = frame
                        .payload
                        .get(1)
                        .copied()
                        .unwrap_or(1)
                        .clamp(1, MAX_PADDING_REPLIES as u8) as usize;
                    // 每条 reply 独立成 packet：write_control_request_now 逐
                    // packet prepare 一条记录，于是 m 条应答就是 m 条独立记录。
                    // 此前全部 reply 连续写进同一个 Vec 并以 `vec![replies]`
                    // 提交，只 prepare 一次 ⇒ 线上只有 1 条记录（m=2 恒 138B、
                    // m=4 恒 252B），设计文档 §3.8 要求的「M 个独立拆分应答」
                    // 从未成立；又因请求侧尺寸同样由 payload 反向决定，m=1 时
                    // 两端恒为 81B，构成成对签名。
                    //
                    // 尺寸取角色常量而非派生自请求载荷长度：旧实现
                    // `total_junk = frame.payload.len() - 2` 让应答尺寸跟着
                    // 请求尺寸联动，本身就是一条「请求尺寸 → 应答尺寸」的
                    // 可观测相关性。
                    let direction = if self.is_client {
                        FlowDirection::C2S
                    } else {
                        FlowDirection::S2C
                    };
                    let replies: Vec<Vec<u8>> = (0..m)
                        .map(|i| {
                            encode_padding_reply_sized(padding_reply_wire_len(
                                request_wire,
                                i,
                                direction,
                            ))
                        })
                        .collect();
                    // 单个 control WriteRequest fire-and-forget 提交：只等入队
                    // 成功，不等 socket 冲刷，读循环不被 reply 拖住。m 条记录
                    // 共用一次 flush——真实 H2 端点同样把同一 flight 的
                    // PING-ACK 与 WINDOW_UPDATE 合并写出。
                    //
                    // 用 try 路径而不是 submit_write_packets().await：读循环
                    // 不得阻塞在写端排队上（死锁环见 WindowState 的论证）。
                    // 队列满时丢弃应答——它们是合成/骨架帧，丢失只影响
                    // 伪装节奏，不损坏任何数据；后续请求还会再来。
                    if let Err(e) = self.writer.try_write_packets(
                        replies,
                        FlushBehavior::Auto,
                        TrafficClass::Control,
                    ) {
                        debug!("failed to queue CMD_PADDING replies: {}", e);
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
        // 四个限额检查全部 O(1)（PendingData 维护运行计数）。此前前两个
        // 分别是全量求和与单队列求和，恰好在背压发生时被逐帧调用。
        if pending.total_bytes().saturating_add(payload.len()) > MAX_PENDING_STREAM_BYTES {
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

        // fc 对端的每流缓冲上限 = 窗口 + 首 RTT 越界余量（对端 SETTINGS
        // 确认前本端可能已超发一个 RTT 的字节，见 WindowState）。窗口本身
        // 界定在途字节，故此限对正常 fc 对端结构性不可达；旧对端沿用
        // 2 MiB 原值，行为与旧版一致。
        let overflow_limit = if self.windows.peer_supports_flow_control() {
            MAX_STREAM_OVERFLOW_BYTES.saturating_mul(2)
        } else {
            MAX_STREAM_OVERFLOW_BYTES
        };
        if pending.stream_bytes(sid).saturating_add(payload.len()) > overflow_limit {
            warn!(
                stream_id = sid,
                "dropping pending stream data: per-stream overflow byte limit exceeded"
            );
            return false;
        }
        if pending.stream_frames(sid) >= MAX_PENDING_STREAM_FRAMES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: per-stream frame limit exceeded"
            );
            return false;
        }
        // 入队放在全部检查之后：此前 `entry(sid)` 在检查前就创建了条目，
        // 被拒绝的载荷会留下一个空队列，虚增 contains()/len() 的口径。
        pending.push_back(sid, payload);
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

    async fn store_pending_open_data(&self, sid: u32, payload: Bytes) -> bool {
        let mut pending = self.pending_open_streams.lock().await;
        if !pending.contains(sid) {
            return false;
        }

        // 两个限额检查都是 O(1)（PendingOpenStreams 维护运行计数）。此前字节
        // 上限是对全部条目的全量求和，而它恰好在每存一帧时被调一次。
        if pending.total_bytes().saturating_add(payload.len()) > MAX_PENDING_STREAM_BYTES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: pending byte limit exceeded"
            );
            return true;
        }

        if pending.stream_frames(sid) >= MAX_PENDING_STREAM_FRAMES {
            warn!(
                stream_id = sid,
                "dropping pending stream data: per-stream frame limit exceeded"
            );
            return true;
        }

        // pre-accept 缓冲同样由 BufferedPayload 入账；
        // flush_pending_accept_stream 投递时只是转移所有权。
        let stored = pending.push_data(
            sid,
            BufferedPayload::new(payload, &self.buffered_stream_bytes),
        );
        debug_assert!(stored, "条目存在性已在同一把锁下检查过");
        true
    }

    async fn store_pending_open_fin(&self, sid: u32) -> bool {
        let mut pending = self.pending_open_streams.lock().await;
        if !pending.set_buffered_fin(sid) {
            return false;
        }
        if pending.release_reservation(sid).unwrap_or(false) {
            drop(pending);
            self.release_inbound_stream_reservation();
        }
        true
    }

    pub(crate) async fn release_pending_open_reservation(&self, sid: u32) -> bool {
        self.pending_open_streams
            .lock()
            .await
            .release_reservation(sid)
            .unwrap_or(false)
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
        if pending.contains(sid) {
            Ok(())
        } else {
            anyhow::bail!("pending stream {} disappeared before accept", sid)
        }
    }

    async fn is_pending_open_stream(&self, sid: u32) -> bool {
        self.pending_open_streams.lock().await.contains(sid)
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
                let Some((pending_data, pending_fin)) = pending.take_ready(sid) else {
                    return PendingAcceptFlushResult::Open;
                };
                if pending_data.is_empty() && !pending_fin {
                    pending.remove(sid);
                    return PendingAcceptFlushResult::Open;
                }
                (pending_data, pending_fin)
            };

            // buffered_data 在 store_pending_open_data 时已入账，投递进
            // data channel 只是转移所有权；投递失败被丢弃时由 Drop 自动回账。
            // channel 满时余量转投 pending_data（与正常投递路径同一缓冲），
            // 而不是杀流：pre-accept 缓冲已被每流窗口界定，对 fc 对端
            // 结构性装得下。
            let mut payloads = pending_data.into_iter();
            let mut overflow_to_pending = Vec::new();
            while let Some(payload) = payloads.next() {
                match data_tx.try_send(payload) {
                    Ok(()) => {
                        delivered_data = true;
                    }
                    Err(mpsc::error::TrySendError::Full(payload)) => {
                        overflow_to_pending.push(payload);
                        delivered_data = true;
                    }
                    Err(mpsc::error::TrySendError::Closed(payload)) => {
                        warn!(
                            stream_id = sid,
                            "closing stream: receiver closed while flushing pending accept data"
                        );
                        drop(payload);
                        drop(payloads);
                        drop(overflow_to_pending);
                        let _ = self.close_stream(sid).await;
                        self.pending_open_streams.lock().await.remove(sid);
                        return PendingAcceptFlushResult::ClosedLocally;
                    }
                }
            }
            for payload in overflow_to_pending {
                self.store_pending_data(sid, payload).await;
            }

            if pending_fin {
                let _ = fin_tx.try_send(());
                if delivered_data {
                    if let Some(handle) = self.streams.write().await.get_mut(&sid) {
                        mark_stream_read_closed_locked(handle, &self.capacity_stream_count);
                    }
                    self.pending_open_streams.lock().await.remove(sid);
                    return PendingAcceptFlushResult::PeerHalfClosed;
                }
                unregister_stream_locked(
                    &mut *self.streams.write().await,
                    &self.capacity_stream_count,
                    sid,
                );
                self.pending_open_streams.lock().await.remove(sid);
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
                        // 读循环内（CMD_SYNACK 分支）：防御性关闭不得等 flush。
                        self.close_stream_fire_and_forget(sid).await;
                        return;
                    }
                }
            } else {
                remaining.push(payload);
            }
        }

        if !remaining.is_empty() {
            let mut pending = self.pending_data.lock().await;
            for item in remaining {
                pending.push_back(sid, item);
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
    #[allow(clippy::too_many_arguments)]
    fn new(
        write_half: SplitWriteHalf,
        close_requested: Arc<AtomicBool>,
        close_notify: Arc<Notify>,
        is_client: bool,
        traffic_script: Option<&[String]>,
        post_script_off: bool,
        pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
        inbound: Arc<InboundSignal>,
        peer_stream_high_water: Arc<AtomicU32>,
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
        let script_owned = traffic_script.map(|s| s.to_vec());
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
                inbound,
                peer_stream_high_water,
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

    pub(crate) fn is_closed(&self) -> bool {
        self.close_requested.load(Ordering::Relaxed)
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
        traffic_script: Option<Vec<String>>,
        post_script_off: bool,
        pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
        inbound: Arc<InboundSignal>,
        peer_stream_high_water: Arc<AtomicU32>,
    ) {
        let mut pending: Vec<u8> = Vec::with_capacity(65536);
        // 仅 Immediate 写请求进入此队列：其字节仍在明文积压 `pending` 里，
        // 要等 drive_shaper 把它们全部 prepare 完才能移交 `batch`（见
        // FlushBatch 的 responder 语义）。Auto 写请求入队即应答（背压由有界
        // bulk channel 的 send().await 提供），不进此队列。
        let mut responders: Vec<oneshot::Sender<Result<(), String>>> = Vec::new();
        // 合并 flush 的批：已 prepare 进 write_buffer、尚未出网的记录与
        // responder。
        let mut batch = FlushBatch::default();
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
                        batch.fail(&msg);
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

                    // 钉住当前 control 请求触及的流：delay 窗口内同流
                    // 控制帧不得越过本请求插队（保序论证见 drive_shaper）。
                    let mut pinned_sids = HashSet::new();
                    for packet in &request.packets {
                        walk_frame_headers(packet, |_cmd, sid, _len| {
                            pinned_sids.insert(sid);
                        });
                    }
                    // 承载 PSH 的 control 请求（gather-open：SETTINGS+SYN+
                    // target+首个数据块）并入 pending，与 bulk 积压同一路径经
                    // TrafficShaper 排空——它承载的是应用数据，尺寸必须由
                    // shaper 决定。详见 request_carries_stream_data。
                    // 字节序不变：先到的 bulk 字节在前，本请求的字节紧随其后，
                    // 包内 SETTINGS→SYN→PSH 的相对序完全保持。
                    let carries_stream_data = request_carries_stream_data(&request);
                    if carries_stream_data {
                        Self::queue_bulk_request(&mut pending, &mut responders, request);
                        match Self::drain_pending_and_respond(
                            &mut pending,
                            &mut shaper,
                            &mut write_half,
                            &mut responders,
                            &mut control_rx,
                            &pending_client_settings,
                            direction,
                            &inbound,
                            pinned_sids,
                            &mut batch,
                        )
                        .await
                        {
                            Ok(deferred) => {
                                if Self::prepare_deferred_control_requests(
                                    deferred,
                                    &mut write_half,
                                    direction,
                                    &mut batch,
                                )
                                .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    } else {
                        let mut deferred_control = Vec::new();
                        if !pending.is_empty() {
                            match Self::drain_pending_and_respond(
                                &mut pending,
                                &mut shaper,
                                &mut write_half,
                                &mut responders,
                                &mut control_rx,
                                &pending_client_settings,
                                direction,
                                &inbound,
                                pinned_sids,
                                &mut batch,
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

                        if Self::prepare_control_request(
                            request,
                            &mut write_half,
                            direction,
                            &mut batch,
                        )
                        .is_err()
                        {
                            break;
                        }

                        // 窗口内暂存的 control 写按到达顺序补发（排在本请求
                        // 之后，与旧版“下一事件循环回合再处理”的相对顺序一致）。
                        if Self::prepare_deferred_control_requests(
                            deferred_control,
                            &mut write_half,
                            direction,
                            &mut batch,
                        )
                        .is_err()
                        {
                            break;
                        }
                    }

                    if Self::flush_or_merge(
                        &mut write_half,
                        &mut batch,
                        &control_rx,
                        &bulk_rx,
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
                        batch.fail(&msg);
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
                            &inbound,
                            HashSet::new(),
                            &mut batch,
                        )
                        .await
                        {
                            Ok(deferred) => {
                                // 窗口内暂存的 control 写按到达顺序补发。
                                if Self::prepare_deferred_control_requests(
                                    deferred,
                                    &mut write_half,
                                    direction,
                                    &mut batch,
                                )
                                .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    if Self::flush_or_merge(
                        &mut write_half,
                        &mut batch,
                        &control_rx,
                        &bulk_rx,
                    )
                    .await
                    .is_err()
                    {
                        break;
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
                &inbound,
                HashSet::new(),
                &mut batch,
            )
            .await;
            // 明文积压已全部 prepare，等待者的字节这才进了 write_buffer。
            batch.responders.append(&mut responders);
        }
        // 主循环退出时批里可能还留着已 prepare 未 flush 的字节：先冲刷并
        // 据实应答，再走 GOAWAY / close_notify。
        let _ = batch.flush(&mut write_half).await;
        Self::emit_h2_goaway(
            &mut write_half,
            post_script_off,
            peer_stream_high_water.load(Ordering::Relaxed),
        )
        .await;
        let _ = write_half.shutdown().await;
    }

    /// 优雅拆除前的 H2 GOAWAY（论证与尺寸依据见 `H2_GOAWAY_WIRE`）。
    ///
    /// 它单独 flush、再由 `shutdown()` 写 close_notify —— 真实端点也是两次
    /// 独立的 `SSL_write`（GOAWAY 记录）+ `SSL_shutdown`（alert 记录），
    /// 线上是 `[41][24]` 两个小分段。
    ///
    /// `last_stream_id` 取本端处理过的最大对端流 id（见
    /// `Session::peer_stream_high_water`）。此前这条记录是 `flag=1` 的纯填充，
    /// 尺寸对了但不带任何语义；载荷改为 `flag=2 + last_stream_id` 之后线速尺寸
    /// 仍是 41（`MIN_GOAWAY_RECORD_WIRE_LEN` 的编译期断言保证），对端因此能
    /// 判定「哪些流对端从未处理、可安全重试」。
    async fn emit_h2_goaway(
        write_half: &mut SplitWriteHalf,
        post_script_off: bool,
        last_stream_id: u32,
    ) {
        if post_script_off {
            return;
        }
        let packet = encode_padding_goaway_sized(last_stream_id, H2_GOAWAY_WIRE);
        let prepared = write_half
            .prepare_control_record(&packet, H2_GOAWAY_WIRE)
            .is_ok();
        if prepared {
            let _ = write_half.flush().await;
        }
    }

    /// 合并 flush 的判定：control/bulk 通道当前都没有立即可取的后续内容时
    /// 才冲刷；否则把本批留在 write_buffer 里，与紧随其后的内容并进同一次
    /// `write()`（= 同一个 TCP 段，见 `FlushBatch`）。
    ///
    /// 不会造成无界延迟，也不会死锁：只有在某个通道**非空**时才延后，而
    /// 非空意味着写循环的 select 下一轮立即就绪；双上限（记录条数 / 缓冲
    /// 字节）另外给出一个确定性的硬上界。
    async fn flush_or_merge(
        write_half: &mut SplitWriteHalf,
        batch: &mut FlushBatch,
        control_rx: &mpsc::Receiver<WriteRequest>,
        bulk_rx: &mpsc::Receiver<WriteRequest>,
    ) -> std::io::Result<()> {
        if batch.is_idle() {
            return Ok(());
        }
        let more_queued = !control_rx.is_empty() || !bulk_rx.is_empty();
        let buffered = write_half.buffered_write_len();
        if more_queued && !batch.is_full(buffered) {
            return Ok(());
        }
        batch.flush(write_half).await
    }

    /// 两个写循环分支共用的“排空 + 收尾”序列：drive_shaper 排空 pending，
    /// prepare fake 帧，并把全部 Immediate 等待者移交合并批。delay 窗口内被
    /// 暂存的 control 写随 Ok 一并返回，由调用方按分支语义补发（control 分支
    /// 排在本请求之后，bulk 分支立即补发）。
    ///
    /// responder 仍严格在字节真正 flush 之后才应答 Ok：它们的字节此前还在
    /// 明文积压 `pending` 里，drive_shaper 返回时才全部进入 write_buffer，
    /// 于是这里移交给 `batch`，由下一次 flush 统一应答。失败时已入队的
    /// responder 以同一错误应答，错误消息返回给调用方做分支专属处理。
    #[allow(clippy::too_many_arguments)]
    async fn drain_pending_and_respond(
        pending: &mut Vec<u8>,
        shaper: &mut TrafficShaper,
        write_half: &mut SplitWriteHalf,
        responders: &mut Vec<oneshot::Sender<Result<(), String>>>,
        control_rx: &mut mpsc::Receiver<WriteRequest>,
        pending_client_settings: &Arc<Mutex<Option<Vec<u8>>>>,
        direction: FlowDirection,
        inbound: &InboundSignal,
        pinned_sids: HashSet<u32>,
        batch: &mut FlushBatch,
    ) -> Result<Vec<WriteRequest>, String> {
        match Self::drive_shaper(
            pending,
            shaper,
            write_half,
            control_rx,
            pending_client_settings,
            direction,
            inbound,
            pinned_sids,
            batch,
        )
        .await
        {
            Ok((fake_responses, deferred)) => {
                let _ = Self::prepare_fake_frames(write_half, &fake_responses, batch);
                batch.responders.append(responders);
                Ok(deferred)
            }
            Err(e) => {
                let msg = e.to_string();
                for responder in responders.drain(..) {
                    let _ = responder.send(Err(msg.clone()));
                }
                batch.fail(&msg);
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
        mut request: WriteRequest,
    ) {
        // 积压为空且请求只有一个包时直接接管其缓冲，省掉一次整包拷贝。
        // 这是稳态大流量的常见形态：drive_shaper 每轮结束都会清空 pending，
        // 于是每批的首个请求都命中此路径。
        if pending.is_empty() && request.packets.len() == 1 {
            *pending = request.packets.pop().expect("length checked above");
        } else {
            for packet in &request.packets {
                pending.extend_from_slice(packet);
            }
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
    /// frames, and no per-record policy consultation.
    ///
    /// 两条路径统一按 STICKY_BULK_FLUSH_MAX_RECORDS /
    /// STICKY_BULK_FLUSH_MAX_BYTES 双上限批量 flush：多次 prepare 在
    /// write_buffer 中自然累积后统一冲刷，record 尺寸/条数/顺序与逐条 flush
    /// 完全一致，仅减少 syscall 与 TCP 分段边界。此前只有 sticky 路径批量，
    /// 非 sticky 路径逐条 flush——而 InteractiveControl 施加延迟的概率只有
    /// 15%，于是 85% 的小记录各自占一个 TCP 分段（socket 开了 TCP_NODELAY），
    /// 真实端点则会把零间隔的连续记录一次写出、由内核按 MSS 分段。批量上限
    /// 是确定值而非抖动值：真实实现在这里也不抖动。批量有界，write_buffer
    /// 不会无界增长。
    ///
    /// 脚本/Markov 策略的 delay 窗口内监听 control 通道：真实协议控制帧
    /// （SYN/FIN/SETTINGS/SYNACK，且不触及 pinned_sids 与 pending 数据流）
    /// 立即 prepare+flush 插队上链——真实 H2 端点本就优先控制帧；其余
    /// control 写（CMD_PADDING 骨架/假响应等）暂存返回，由主循环按到达
    /// 顺序补发。data record 的尺寸、数量、delay 时长分布严格不变。
    ///
    /// 排空**末尾不再自己 flush**：末批交给调用方的 `flush_or_merge` 决定，
    /// 于是「紧跟在数据记录之后的 control 写」（例如对端开场 flight 换来的
    /// SETTINGS-ACK）能与这批数据记录并进同一次 `write()`。记录的尺寸/条数/
    /// 顺序不受影响，只有分段边界变了（见 `FlushBatch`）。
    ///
    /// Returns (fake_responses, deferred_control_writes)：fake 请求的应答条数
    /// 由调用方走 control 路径采样+编码+发出；暂存的 control 写按到达顺序
    /// 补发，其 responder 必须在字节真正 flush 后才应答 Ok。
    #[allow(clippy::too_many_arguments)]
    async fn drive_shaper(
        pending: &mut Vec<u8>,
        shaper: &mut TrafficShaper,
        write_half: &mut SplitWriteHalf,
        control_rx: &mut mpsc::Receiver<WriteRequest>,
        pending_client_settings: &Arc<Mutex<Option<Vec<u8>>>>,
        direction: FlowDirection,
        inbound: &InboundSignal,
        mut pinned_sids: HashSet<u32>,
        batch: &mut FlushBatch,
    ) -> std::io::Result<(Vec<u8>, Vec<WriteRequest>)> {
        let mut fake_responses: Vec<u8> = Vec::new();
        let mut deferred_control = Vec::new();
        let mut consumed = 0usize;

        // next_data_policy 的首次调用提到帧头遍历之前：frame_boundaries 与
        // pinned_sids 只在 policy.delay > 0 的窗口里被读（wait_shaping_delay），
        // 而 sticky bulk 路径的 delay 恒为 Duration::ZERO，于是大流量稳态下
        // 每轮 drain 都在白遍历全部帧头并建两个 HashSet。
        // 窗口进度用**下界**喂给 shaper：flush 次数 + 对端到达次数（论证见
        // `FlushBatch::flushes`）。逐轮 drain 更新一次即可——drain 内部的 flush
        // 只会让真实进度更靠前，而少算只推迟放松，方向保守。
        shaper.begin_drain(batch.flushes.saturating_add(inbound.arrivals()));
        let mut first_policy = if pending.is_empty() {
            None
        } else {
            Some(shaper.next_data_policy(pending.len()))
        };
        let sticky_full_block = first_policy
            .as_ref()
            .is_some_and(|policy| policy.allow_full_block);

        // 钉住 pending 积压中的数据流：同流控制帧（如 FIN）不得越过仍在
        // 积压中的数据插队，否则对端会因 FIN 先至而丢弃其后的数据。
        // 同时记录全部帧边界偏移：wire 协议没有 record 边界标记，对端把
        // 各 record 的块载荷拼接后重组帧，插队 control 帧只能落在完整帧
        // 边界上（旧实现靠“先排空 pending 再写 control”隐式保证）。
        // 偏移天然单调递增，故用有序 Vec + 二分取代 HashSet<usize>，省掉
        // 逐帧哈希与哈希表增长；调用方预填的 pinned_sids 原样保留。
        let mut frame_boundaries: Vec<usize> = Vec::new();
        if !sticky_full_block {
            let mut frame_offset = 0usize;
            walk_frame_headers(pending, |cmd, sid, frame_len| {
                if cmd == CMD_PSH {
                    pinned_sids.insert(sid);
                }
                frame_offset += frame_len;
                frame_boundaries.push(frame_offset);
            });
        }

        // 批量 flush 记账由调用方传入的 `batch` 统一维护：它同时覆盖排空前
        // 已 prepare 的 control 记录，双上限于是作用在整个 write_buffer 上。
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
                        pre_fake: None,
                        allow_full_block: true,
                        quiet_gap: false,
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

            // 插在数据记录之前的 CMD_PADDING 记录只能落在**完整帧边界**上：
            // wire 协议不标记 record 边界，对端把各 record 的块载荷按序拼进
            // 一个 BytesMut 再解帧，若当前 drain 偏移正处在某个 PSH 帧的载荷
            // 中间，插进去的 padding 帧字节会被并进那个帧的载荷，对端的帧重组
            // 直接错乱（→ unknown cmd → 拆会话）。此前 pre_fake 无条件插入，
            // 只因内嵌脚本 6 条规则的 fake_jitter 全为 0、`F:n?k` 负抖动没人用
            // 才没暴露；`consumed == 0` 恒为边界（pending 由整帧拼成，上一轮
            // drain 全部排空）。
            let at_frame_boundary =
                consumed == 0 || frame_boundaries.binary_search(&consumed).is_ok();
            // 让出方向的那一条记录：fake 请求必须与数据记录**同批** prepare、
            // 同批 flush，对端才会在一个 RTT 内回吐应答。此前 fake 请求一律
            // 攒到整个 drain 结束后由 emit_fake_frames 发出，应答自然落在整个
            // 上行 burst 之后，起不到打断 burst 的作用。
            let quiet_gap = policy.quiet_gap;
            let mut inline_fake = if quiet_gap {
                policy.fake.as_ref().map(|spec| spec.responses)
            } else {
                None
            };
            let mut deferred_fake = None;
            if let Some(pre) = policy.pre_fake.as_ref().map(|spec| spec.responses) {
                if at_frame_boundary {
                    inline_fake = Some(inline_fake.unwrap_or(0).saturating_add(pre));
                } else {
                    // 非边界：退化为「本记录之后」的 fake，由 emit_fake_frames
                    // 在整段排空后（必然落在帧边界）发出。
                    deferred_fake = Some(pre);
                }
            }

            // 一次持锁完成「inline fake control 记录 + data 记录 + 读积压量」，
            // 省掉两次额外的 std::Mutex 往返。
            let buffered = {
                let slice = &pending[consumed..consumed + take];
                // 线上序为 control → data：两条记录进的是同一个
                // write_buffer，批量 flush 不改变它们的相对顺序。
                if let Some(responses) = inline_fake {
                    let packet = encode_padding_request_sized(responses, PADDING_REQUEST_WIRE);
                    write_half.prepare_control_record(&packet, PADDING_REQUEST_WIRE)?;
                }
                write_half.prepare_data_record(slice, policy.target_wire_len)?;
                write_half.buffered_write_len()
            };
            if let Some(responses) = deferred_fake {
                fake_responses.push(responses);
            }

            consumed += take;
            shaper.advance();
            batch.note_records(1 + usize::from(inline_fake.is_some()));

            // delay 非零时必须先 flush 再 sleep：否则已 prepare 的字节会攒到
            // sleep 之后一起出网，延迟根本作用不到线上，IAT 模型失效。这同时
            // 保证进入 delay 窗口时 write_buffer 必为空——窗口内的 control
            // 插队路径（wait_shaping_delay → prepare_control_request + flush）
            // 自己 flush 整个 write_buffer，若还残留未 flush 的数据记录，
            // 它们会被那次 flush 一并带出，线上序仍是「已 prepare 的数据 →
            // 插队 control」（与逐条 flush 时一致），但记录归属的时间槽会错。
            // 此处的先 flush 消除了这种情形。
            if quiet_gap || policy.delay > Duration::ZERO || batch.is_full(buffered) {
                let arrivals_before = inbound.arrivals();
                batch.flush(write_half).await?;
                if quiet_gap {
                    // 挂起到对端有记录抵达：burst 只能被方向改变打断，同方向
                    // 连续包的尺寸会累加，时间间隔不算。不等这一下，后续记录
                    // 就会把第一个上行 burst 累加到 300 字节门限以上。
                    wait_for_peer_turn(inbound, arrivals_before).await;
                }
            }

            if let Some(fake) = &policy.fake {
                if !quiet_gap {
                    // 只登记应答条数：尺寸与编码统一在 emit_fake_frames 内发生。
                    // quiet_gap 的那一条已在上面同批发出，不能重复。
                    fake_responses.push(fake.responses);
                }
            }

            if policy.delay > Duration::ZERO {
                Self::wait_shaping_delay(
                    policy.delay,
                    frame_boundaries.binary_search(&consumed).is_ok(),
                    write_half,
                    control_rx,
                    pending_client_settings,
                    direction,
                    &mut pinned_sids,
                    &mut deferred_control,
                    batch,
                )
                .await?;
            }
        }

        // 末批不在此处 flush：交给调用方的 `flush_or_merge`，使紧随其后的
        // control 写能与这批数据记录并进同一次 `write()`（论证见 FlushBatch）。
        pending.clear();
        Ok((fake_responses, deferred_control))
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
        batch: &mut FlushBatch,
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
                        // 插队写立即冲刷，不参与合并：delay 窗口本就是在**刻意
                        // 拉开**记录间隔，把插队的控制帧攒到下一条数据记录上
                        // 反而抵消了「真实 H2 端点优先控制帧」这一语义。
                        Self::prepare_control_request(request, write_half, direction, batch)
                            .map_err(std::io::Error::other)?;
                        batch.flush(write_half).await?;
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

    /// 单条 control 写请求的 prepare + 入批：主 control 分支、delay 窗口
    /// 插队、窗口暂存补发共用同一口径。
    ///
    /// 此前叫 `write_control_request_now`，prepare 完就无条件 flush 一次。
    /// 现在只 prepare 并把 responder 挂进 `batch`，flush 时机由调用方决定
    /// （论证见 `FlushBatch`）——**responder 的语义完全不变**：它仍然只在
    /// 字节真正 flush 之后才收到 Ok，只是与同批的其他请求一起应答。失败时
    /// 先应答 Err，再把错误交调用方终止写循环。
    ///
    /// 每个 packet 编码成一条或多条记录，尺寸决策统一交给
    /// `prepare_control_packet_records`（口径与其文档注释一致）。packet 顺序
    /// 与包内字节序都不变，故 SETTINGS 仍严格先于 SYN 到达对端，control 写
    /// 之间的 FIFO 也不变。
    fn prepare_control_request(
        request: WriteRequest,
        write_half: &mut SplitWriteHalf,
        direction: FlowDirection,
        batch: &mut FlushBatch,
    ) -> Result<(), String> {
        let state = write_half.control_state();
        for packet in &request.packets {
            let result = prepare_control_packet_records(write_half, packet, state, direction);
            match result {
                Ok(records) => batch.note_records(records),
                Err(e) => {
                    let msg = e.to_string();
                    let _ = request.response_tx.send(Err(msg.clone()));
                    return Err(msg);
                }
            }
        }
        batch.push_responder(request.response_tx);
        Ok(())
    }

    /// 窗口暂存 control 写的补发：按到达顺序逐条 prepare 进同一批，任一
    /// 失败即终止（失败请求的 responder 已在 prepare_control_request 内
    /// 应答 Err）。
    fn prepare_deferred_control_requests(
        deferred: Vec<WriteRequest>,
        write_half: &mut SplitWriteHalf,
        direction: FlowDirection,
        batch: &mut FlushBatch,
    ) -> Result<(), String> {
        for request in deferred {
            Self::prepare_control_request(request, write_half, direction, batch)?;
        }
        Ok(())
    }

    /// Prepare the fake-interaction requests the shaper asked for: one
    /// CMD_PADDING request record per entry, `responses[i]` reply records
    /// expected back.
    ///
    /// 尺寸采样/常量与编码必须在同一处发生：此前调用方先按 `m` 编码 junk、
    /// 这里才去采样尺寸，于是 `prepare_control_record` 的 payload 下限把采样
    /// 值吃掉，请求记录恒为 81 / 97 / 129 字节——不对应任何真实 H2 帧尺寸。
    /// 现在按 PING 的确定尺寸编码并以同一目标 prepare，记录精确落在
    /// PADDING_REQUEST_WIRE。
    ///
    /// 同样不再自带 flush：此前 drive_shaper 末尾 flush 一次、这里紧接着又
    /// flush 一次，于是 fake 请求必定独占一个 TCP 分段。
    fn prepare_fake_frames(
        write_half: &mut SplitWriteHalf,
        responses: &[u8],
        batch: &mut FlushBatch,
    ) -> std::io::Result<()> {
        if responses.is_empty() {
            return Ok(());
        }
        for &m in responses {
            let packet = encode_padding_request_sized(m, PADDING_REQUEST_WIRE);
            write_half.prepare_control_record(&packet, PADDING_REQUEST_WIRE)?;
        }
        batch.note_records(responses.len());
        Ok(())
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

/// 隧道重组缓冲的初始容量。
const TUNNEL_REASSEMBLY_CAPACITY: usize = 65536;

/// 单次隧道读取的上限。
///
/// **这个数字是线上可观测的，不能顺手放大。** `InboundSignal::arrivals()`
/// 计的就是「成功 read 的次数」，而它同时是：喂给 `TrafficShaper` 的窗口
/// 进度下界（`begin_drain`）与让出方向的等待条件（`wait_for_peer_turn`）。
/// 一次读得越多，arrivals 涨得越慢，整形窗口就退出得越晚——记录尺寸与延迟
/// 分布随之改变。
const TUNNEL_READ_CHUNK: usize = 16384;

/// 直接读进重组缓冲的未初始化尾部。
///
/// 此前是 `read(&mut read_buf)` + `buf.extend_from_slice(&read_buf[..n])`：
/// 每个字节在解密之后还要再被 memcpy 一次才进入帧重组缓冲。`reserve` 先
/// 保证尾部至少有 `TUNNEL_READ_CHUNK` 的空闲容量，`limit` 再把本次读取
/// **精确**限制在 16 KiB —— 不加 `limit` 的话 `read_buf` 会按 `BytesMut`
/// 的全部剩余容量一次读到 64 KiB，arrivals 掉到四分之一（见
/// `TUNNEL_READ_CHUNK`）。
///
/// 取消安全：`AsyncReadExt::read_buf` 本身是取消安全的（未就绪时不消费
/// 任何字节），因此可以直接放进读循环的 `select!`。
async fn read_tunnel_chunk(
    read_half: &mut SplitReadHalf,
    buf: &mut BytesMut,
) -> std::io::Result<usize> {
    use bytes::BufMut;
    buf.reserve(TUNNEL_READ_CHUNK);
    read_half
        .read_buf(&mut (&mut *buf).limit(TUNNEL_READ_CHUNK))
        .await
}

#[cfg(test)]
mod tests;
