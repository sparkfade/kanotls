//! H2 流控：发送侧窗口（连接级 + 每流）与接收侧回补记账（消费 → WU）。
//!
//! 窗口常量（连接窗口、回补阈值）与回补帧的线速形态也在这里——它们曾是
//! 「假填充」，现在是真信贷，但线速尺寸不变（WINDOW_UPDATE 记录恒定
//! 37 字节），故对未升级的旧对端无害（flag=3 被静默吸收）。

use crate::frame::encode_padding_window_update_sized;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::debug;

use super::{FlushBehavior, SharedTunnelWriter, TrafficClass};

/// 每流发送窗口（H2 的 `SETTINGS_INITIAL_WINDOW_SIZE` 语义）：发送方在同一条
/// 流的在途字节超过此值前可自由发送，之后挂起等对端回补 WINDOW_UPDATE。
///
/// **取值**：32 MiB。窗口/RTT 是单流吞吐的硬上限，而无停顿速率是
/// `(窗口 − 回补阈值)/RTT`（接收方消费满阈值才回补，补回路上要 1 RTT）。
/// 500 Mbps × 175 ms 的 BDP ≈ 10.9 MB：16 MiB 旧值只留 (16−2)/0.175 ≈
/// 640 mbps 的无停顿余量，对 500 mbps 链路只剩 28% 抖动空间；32 MiB +
/// 1/8 窗口回补阈值（4 MiB，与连接级回补节奏同档）给出 (32−4) MiB/175ms
/// ≈ 1.3 gbps。窗口值不上链（WINDOW_UPDATE 记录尺寸恒定 37 字节），唯一
/// 可观测变化是回补节奏。
const STREAM_WINDOW_BYTES: usize = 32 * 1024 * 1024;

/// 测试覆写点：0 表示使用上面的生产常量。窗口只影响**本端发送**的门控与
/// 回补节奏，不改任何线上字节形态（WINDOW_UPDATE 记录本身尺寸恒定）。
pub(crate) static STREAM_WINDOW_OVERRIDE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// 稳态 H2 行为骨架（post-script steady state）：真实 HTTP/2 接收端回发
/// WINDOW_UPDATE，并对收到的 PING 回 PING-ACK。内容加密不可见，只需复刻
/// 尺寸/时序语义。两者都以 CMD_PADDING 帧实现：flag=1 被对端静默吸收
/// （等价 WINDOW_UPDATE 的“无回复”语义），flag=0 m=1 会换来一条 reply
/// （等价 PING/PING-ACK 对）。客户端不做空闲探活 PING（用户明确不需要
/// 保活），flag=0 m=1 的请求只来自脚本 fake 交互与合成 H2 交换。
///
/// WINDOW_UPDATE 的触发阈值是**逐进程常量**，不逐次重采样。此前是
/// `gen_range(1MB..=4MB)` 且每越过一次就重新采样一个新阈值 ⇒ 全随机，而
/// 真实 H2 接收端的规则是确定的：窗口是实现里的编译期常量，消费字节越过
/// 窗口的某个固定比例就回补一条 WINDOW_UPDATE。
///
/// **取值：连接级窗口 32 MiB、回补阈值 = 窗口的 1/8（4 MiB）。** 窗口值的
/// 原型是 Firefox 的 `ASpdySession::kInitialRwin = 12 MiB`，回补规则的原型
/// 是 nghttp2 的「消费达本地窗口一半即回补」。但窗口决定吞吐上限：无停顿
/// 速率 = `(窗口 − 阈值)/RTT`，12 MiB 窗口 + 半窗回补在 175 ms RTT 下只剩
/// (12−6) MiB/0.175s ≈ 288 mbps，把 500 mbps 链路活活钉死。窗口值与阈值
/// 都不上链（WU 记录尺寸恒定 37 字节），可观测的只有回补节奏从「每 6 MiB
/// 一条」变为「每 4 MiB 一条」，仍落在真实 H2 端点的合理区间。32/4 MiB
/// 给出 (32−4)/0.175s ≈ 1.3 gbps 的无停顿余量，覆盖目标链路。
///
/// 用 `OnceLock` 而不是 `const`：语义是「进程内解析一次、此后恒定」，与
/// 真实实现的编译期常量同一口径，同时保留测试覆写点。
const H2_SESSION_WINDOW_BYTES: usize = 32 * 1024 * 1024;
static H2_WINDOW_UPDATE_THRESHOLD: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// 测试覆写点：0 表示使用上面的生产常量。
pub(crate) static H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// WINDOW_UPDATE 阈值：逐进程解析一次，此后恒定（论证见常量定义处）。
fn h2_window_update_threshold() -> usize {
    let override_bytes = H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES.load(Ordering::Relaxed);
    if override_bytes > 0 {
        return override_bytes;
    }
    *H2_WINDOW_UPDATE_THRESHOLD.get_or_init(|| H2_SESSION_WINDOW_BYTES / 8)
}

/// WINDOW_UPDATE 信贷帧的线速尺寸。真实 H2 里它的尺寸是确定值（恒 4 字节
/// 载荷 → 13 字节帧），因此这里也取确定值而不是再过一遍混合分布采样器：
/// 在真实实现恒定的维度上随机化，本身就是一个判别特征。
pub(crate) const PADDING_WINDOW_UPDATE_WIRE: usize =
    kanotls_tunnel::control_size::WINDOW_UPDATE_WIRE;

/// H2 流控状态：发送侧窗口（连接级 + 每流）与接收侧回补记账（消费 → WU）。
///
/// **为什么这是修复而不是新机制**：真实 H2 接收方回补窗口、发送方在窗口
/// 耗尽后停发，接收缓冲由窗口自身界定——此前 KanoTLS 的「缓冲超限 →
/// 丢数据 + 杀流」正是没有窗口语义的产物。这里把伪装常量（连接窗口、
/// 回补阈值）从「假填充」变成真信贷：
///
/// * 发送侧：`acquire_credit` 在提交前检查（连接信贷 && 每流信贷），不足则
///   挂起；WINDOW_UPDATE 帧到达（读循环帧层处理，纯记账）后放行。挂起即
///   背压：中继不再读源站，源站 TCP 窗口自然填满——与真实 H2 逐字节同构。
/// * 接收侧连接级：读循环**收到**数据帧即入账回补（`note_conn_received`）。
///   连接级窗口管的是接收缓冲：字节到达即占缓冲，无论随后交付还是丢弃都
///   已释放，故按收到回补才不会有泄漏路径。
/// * 接收侧每流：`note_consumed` 由中继在字节真正交付本地/远端后调用
///   （每流窗口保留交付语义 = 应用背压，nghttp2 规则），越过 1/8 窗口
///   阈值（4 MiB）回吐一条 WINDOW_UPDATE（尺寸恒为 37 字节的
///   `WINDOW_UPDATE_WIRE`）。
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
    /// 连接级信贷余额（测试直接读数断言）。
    pub(crate) conn_credit: AtomicI64,
    conn_wu_threshold: u64,
    /// 连接级已消费、尚未回补的字节（CAS 记账，多流并发消费安全；测试直接读数断言）。
    pub(crate) conn_consumed_since_wu: AtomicU64,
    stream_window: i64,
    stream_wu_threshold: u64,
    /// 连接级信贷到达信号。所有等待者都在「醒了再查一次」的幂等循环里，
    /// 故用 `notify_waiters` 全量唤醒：一条 WU 到账要放行所有够格的流，
    /// `notify_one` 会让其余流睡到下一条 WU（并发崩塌成锯齿）。
    credit_notify: Notify,
    /// 诊断计数：发送侧因信贷不足而真正挂起的次数与累计微秒。只在挂起
    /// 路径上产生原子操作，畅通路径零成本。会话结束时随读循环摘要输出，
    /// 用于在实验室区分「窗口停等」与「CPU/缓冲」三类瓶颈。
    stall_count: AtomicU64,
    stall_micros: AtomicU64,
}

impl WindowState {
    pub(crate) fn new(writer: SharedTunnelWriter) -> Self {
        // 连接窗口 = 8 × 回补阈值（论证见 `H2_SESSION_WINDOW_BYTES`：无停顿
        // 速率 = (窗口−阈值)/RTT，半窗回补会把可用速率砍半）。测试覆写点
        // `H2_WINDOW_UPDATE_THRESHOLD_OVERRIDE_BYTES` 沿用在阈值上，窗口
        // 随之缩放。
        let conn_wu_threshold = h2_window_update_threshold() as u64;
        let conn_window = (conn_wu_threshold as i64).saturating_mul(8);
        let stream_override = STREAM_WINDOW_OVERRIDE_BYTES.load(Ordering::Relaxed);
        let stream_window = if stream_override > 0 {
            stream_override
        } else {
            STREAM_WINDOW_BYTES
        } as i64;
        Self {
            writer,
            peer_flow_control: AtomicBool::new(false),
            conn_credit: AtomicI64::new(conn_window),
            conn_wu_threshold,
            conn_consumed_since_wu: AtomicU64::new(0),
            stream_window,
            stream_wu_threshold: (stream_window as u64).saturating_div(8).max(1),
            credit_notify: Notify::new(),
            stall_count: AtomicU64::new(0),
            stall_micros: AtomicU64::new(0),
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
    ///
    /// 扣减是两阶段 CAS：先连接级、再流级，流级不足则回滚连接级后等待。
    /// 此前的「先 load 检查、再各自 fetch_sub」不是原子的——并发流可同时
    /// 通过检查再双双扣减，把信贷打成负值，制造无必要的挂起毛刺。
    ///
    /// 等待侧用「先 `enable` 注册、再检查、后 park」的顺序：`notify_waiters`
    /// 不留 permit，若先检查后注册，信贷在间隙到达会丢唤醒（挂起者睡到
    /// 下一条 WU）；先注册则间隙到达的唤醒必然命中已注册的我们。
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
        // 首次真正挂起的时刻：诊断统计只覆盖「真的等过」的调用。
        let mut waited_since: Option<std::time::Instant> = None;
        loop {
            if self.writer.is_closed() {
                break;
            }
            let conn_notified = self.credit_notify.notified();
            let stream_notified = stream_notify.notified();
            tokio::pin!(conn_notified);
            tokio::pin!(stream_notified);
            let _ = conn_notified.as_mut().enable();
            let _ = stream_notified.as_mut().enable();

            let conn = self.conn_credit.load(Ordering::Relaxed);
            if conn >= len
                && self
                    .conn_credit
                    .compare_exchange(conn, conn - len, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                let stream = stream_credit.load(Ordering::Relaxed);
                if stream >= len
                    && stream_credit
                        .compare_exchange(
                            stream,
                            stream - len,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    break;
                }
                // 流级不足：回滚连接级，等任一方向的新信贷再重试。
                self.conn_credit.fetch_add(len, Ordering::Relaxed);
            }
            waited_since.get_or_insert_with(std::time::Instant::now);
            tokio::select! {
                _ = conn_notified => {}
                _ = stream_notified => {}
            }
        }
        if let Some(since) = waited_since {
            self.stall_count.fetch_add(1, Ordering::Relaxed);
            self.stall_micros
                .fetch_add(since.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
    }

    /// 诊断读数：（挂起次数， 累计挂起微秒）。会话结束时由读循环摘要输出。
    pub(crate) fn stall_stats(&self) -> (u64, u64) {
        (
            self.stall_count.load(Ordering::Relaxed),
            self.stall_micros.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn add_conn_credit(&self, increment: u32) {
        self.conn_credit
            .fetch_add(i64::from(increment), Ordering::Relaxed);
        self.credit_notify.notify_waiters();
    }

    pub(crate) fn add_stream_credit(
        &self,
        credit: &AtomicI64,
        notify: &Arc<Notify>,
        increment: u32,
    ) {
        credit.fetch_add(i64::from(increment), Ordering::Relaxed);
        // `pending_notify` 同时服务读侧（pending 数据到达）与写侧（本流信贷
        // 到达）：`notify_one` 可能唤醒错误的一侧把 permit 消耗掉，另一侧
        // 睡到下一个无关事件。两侧都是幂等再查循环，全量唤醒无害。
        notify.notify_waiters();
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

    /// 接收侧连接级回补：读循环每收到一个数据帧即按载荷长度入账（连接级
    /// 窗口管的是接收缓冲，字节到达即占/即释，与应用是否已交付无关）。
    /// 因此 Closing/NotFound/溢出杀流/拆除丢弃等一切「收到但未交付」路径
    /// 自动回补——若按交付回补，这些路径上的每个字节都会从发送方连接级
    /// 信贷里永久流失（窗口只减不增，表现为传输越跑越慢）。
    pub(crate) fn note_conn_received(&self, len: usize) {
        if let Some(conn_total) = self.bump_conn_consumed(len as u64) {
            if !self.send_window_update(0, conn_total) {
                // 入队失败（控制队列满）：把消费量加回去，后续入账会再次
                // 越过阈值补发这条 WU。丢信贷是永久泄漏，恢复只是让回补
                // 迟到；并发 bump 下可能多补一次（≤ 阈值量级），方向是
                // 多给对端信贷，有界且良性。
                self.conn_consumed_since_wu
                    .fetch_add(conn_total as u64, Ordering::Relaxed);
            }
        }
    }

    /// 接收侧每流回补入账：中继在字节真正交付应用层后调用（每流窗口保留
    /// 交付语义 = 应用背压）。`stream_consumed_since_wu` 在流对象上（单
    /// 消费者，fetch_add/fetch_sub 安全）。越过阈值即回吐一条真实
    /// WINDOW_UPDATE（flag=3，尺寸恒为 37 字节的 `WINDOW_UPDATE_WIRE`）。
    pub(crate) fn note_consumed(&self, sid: u32, stream_consumed_since_wu: &AtomicU64, len: usize) {
        let len_u64 = len as u64;
        let stream_total = stream_consumed_since_wu.fetch_add(len_u64, Ordering::Relaxed) + len_u64;
        if stream_total >= self.stream_wu_threshold {
            stream_consumed_since_wu.fetch_sub(stream_total, Ordering::Relaxed);
            if !self.send_window_update(sid, stream_total.min(u32::MAX as u64) as u32) {
                // 与 note_conn_received 同理：恢复计数，下次消费补发，
                // 不让一次控制队列拥塞变成永久信贷泄漏。
                stream_consumed_since_wu.fetch_add(stream_total, Ordering::Relaxed);
            }
        }
    }

    /// 入队一条 WINDOW_UPDATE（fire-and-forget：读循环绝不因写端排队而
    /// 阻塞）。返回是否成功入队；失败时调用方负责恢复对应消费计数。
    fn send_window_update(&self, sid: u32, increment: u32) -> bool {
        let packet = encode_padding_window_update_sized(sid, increment, PADDING_WINDOW_UPDATE_WIRE);
        if let Err(e) =
            self.writer
                .try_write_packets(vec![packet], FlushBehavior::Auto, TrafficClass::Control)
        {
            debug!("window update deferred (control queue full): {}", e);
            false
        } else {
            true
        }
    }
}
