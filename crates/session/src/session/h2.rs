//! H2 行为骨架：合成请求/响应交换、GOAWAY 拆除帧、padding 应答的角色尺寸。
//!
//! 这里只有常量与纯函数；状态机（何时发交换、何时发 GOAWAY）在
//! `session.rs` 的读循环与写循环里。

use crate::frame::MIN_GOAWAY_RECORD_WIRE_LEN;
use kanotls_tunnel::{FlowDirection, SnowyStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::window::PADDING_WINDOW_UPDATE_WIRE;

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
pub(crate) const H2_GOAWAY_WIRE: usize = kanotls_tunnel::control_size::PING_WIRE;

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
pub(crate) const GOAWAY_NOT_RECEIVED: u64 = u64::MAX;

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
pub(crate) const H2_EXCHANGE_OPENING_MIN_COUNT: u32 = 1;
pub(crate) const H2_EXCHANGE_OPENING_MAX_COUNT: u32 = 3;
const H2_EXCHANGE_OPENING_MU_MS: f64 = 3.4; // 中位数 ≈ 30ms
const H2_EXCHANGE_OPENING_SIGMA: f64 = 0.7;
const H2_EXCHANGE_STEADY_MU_MS: f64 = 9.9; // 中位数 ≈ 20s
const H2_EXCHANGE_STEADY_SIGMA: f64 = 1.2;
/// 稳态交换的间隔上限：超过它就没有观测意义，而且会把 sleep 的 deadline
/// 推到不现实的远处。
const H2_EXCHANGE_MAX_INTERVAL_SECS: u64 = 300;

/// 测试覆写点：0 表示使用上面的生产常量。
pub(crate) static H2_EXCHANGE_INTERVAL_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

/// H2 骨架关闭时的定时器“禁用”姿态：分支被 select guard 屏蔽，deadline
/// 只需足够遥远。
pub(crate) const H2_TIMER_DISABLED: Duration = Duration::from_secs(3600);

/// 单条 CMD_PADDING 请求可换取的应答记录上限。
///
/// 真实 H2 没有「一问 m 答」这种语义：PING 换恰好一个 PING-ACK，
/// WINDOW_UPDATE 不换任何应答，SETTINGS 换恰好一个 SETTINGS-ACK。一次交互
/// 里能站得住脚的第二条应答记录只有一种角色——「接收方本来就要发的窗口
/// 更新」，故上限压到 2。此前是 16：m=4 在线上就是「一条请求 → 一簇记录」，
/// 而且（见下方 handle_frame）这一簇还被合并成单条记录，两头都不像 H2。
pub(crate) const MAX_PADDING_REPLIES: usize = 2;

/// CMD_PADDING 记录的角色尺寸。真实 H2 里这三种帧的尺寸都是确定值
/// （PING/PING-ACK 恒 8 字节载荷 → 17 字节帧，WINDOW_UPDATE 恒 4 字节载荷
/// → 13 字节帧，SETTINGS-ACK 恒 9 字节帧），因此这里也取确定值而不是再过一遍
/// 混合分布采样器：在真实实现恒定的维度上随机化，本身就是一个判别特征。
pub(crate) const PADDING_REQUEST_WIRE: usize = kanotls_tunnel::control_size::PING_WIRE;
pub(crate) const PADDING_ACK_WIRE: usize = kanotls_tunnel::control_size::PING_WIRE;
pub(crate) const PADDING_SETTINGS_ACK_WIRE: usize = kanotls_tunnel::control_size::SETTINGS_ACK_WIRE;

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
pub(crate) fn padding_reply_wire_len(
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

/// 下一次合成 H2 交换的间隔：开场窗口内是数十毫秒量级，之后是浏览量级。
pub(crate) fn sample_h2_exchange_interval(opening_left: u32) -> Duration {
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
pub(crate) fn sample_h2_exchange_request_wire() -> usize {
    kanotls_tunnel::control_size::next_headers_frame_wire_len(
        FlowDirection::C2S,
        &mut rand::thread_rng(),
    )
}
