use bytes::{Buf, Bytes, BytesMut};

pub const FRAME_HEADER_SIZE: usize = 7;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// 帧载荷走零拷贝切分的下限。
///
/// `Frame::payload` 是 `Bytes`：`BytesMut::split_to(..).freeze()` 是 O(1) 的
/// 引用计数切分，省掉了此前每帧一次 `to_vec()`（bulk 路径上是每 65535 字节
/// 一次 malloc + memcpy，实测接收路径 CPU 降约 6–10%）。
///
/// 代价是**整块重组缓冲**会一直存活到它上面最后一个切片被丢弃。bulk 帧本就
/// 接近缓冲大小，放大比接近 1，净赚；但一个几字节的帧若被挂进积压队列，就会
/// 用几字节的记账钉住整块缓冲——而积压上限是 1024 流 × 1024 帧，无界放大后
/// 是数十 GiB 量级的远程 OOM，且 `buffered_stream_bytes` 那本账完全看不见它。
///
/// 因此只有「大到放大比有界」的载荷才零拷贝：小载荷继续拷贝，几百字节的
/// memcpy 在任何量级上都不可见，而放大比被钉在个位数。
const ZERO_COPY_PAYLOAD_MIN: usize = 16384;

pub const CMD_SYN: u8 = 0x01;
pub const CMD_PSH: u8 = 0x02;
pub const CMD_FIN: u8 = 0x03;
pub const CMD_SETTINGS: u8 = 0x04;
pub const CMD_SYNACK: u8 = 0x07;
pub const CMD_PADDING: u8 = 0x08;

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: u8,
    pub stream_id: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(cmd: u8, stream_id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            cmd,
            stream_id,
            payload: payload.into(),
        }
    }

    pub fn cmd_settings() -> Self {
        // `fc=1`：向对端声明本端支持 H2 流控（WINDOW_UPDATE 信贷帧）。
        // 对旧对端只是内容多几个字节的未知设置项，静默忽略；对新对端是
        // 发送侧门控的启用条件（见 session::WindowState）。
        //
        // 载荷刻意保持紧凑：SETTINGS 会随服务端开场 flight 的首条记录
        // 上链，而该记录的目标尺寸由 `h2_opening_size(S2C, 0)` 定死
        // （51 字节 ⇒ 27 字节容量），帧体必须装得下。
        Self::new(CMD_SETTINGS, 0, b"v=2;fc=1".to_vec())
    }

    pub fn syn(stream_id: u32) -> Self {
        Self::new(CMD_SYN, stream_id, vec![])
    }

    pub fn psh(stream_id: u32, data: Vec<u8>) -> Self {
        Self::new(CMD_PSH, stream_id, data)
    }

    pub fn fin(stream_id: u32) -> Self {
        Self::new(CMD_FIN, stream_id, vec![])
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            anyhow::bail!(
                "frame payload too large: {} > {}",
                self.payload.len(),
                MAX_PAYLOAD_LEN
            );
        }
        let data_len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data_len as usize);
        buf.push(self.cmd);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    pub fn encode_psh(stream_id: u32, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        Self::encode_psh_into(&mut buf, stream_id, payload)?;
        Ok(buf)
    }

    pub fn encode_psh_into(
        dst: &mut Vec<u8>,
        stream_id: u32,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if payload.len() > MAX_PAYLOAD_LEN {
            anyhow::bail!(
                "frame payload too large: {} > {}",
                payload.len(),
                MAX_PAYLOAD_LEN
            );
        }
        dst.push(CMD_PSH);
        dst.extend_from_slice(&stream_id.to_be_bytes());
        dst.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        dst.extend_from_slice(payload);
        Ok(())
    }

    pub fn encoded_len(payload_len: usize) -> usize {
        FRAME_HEADER_SIZE + payload_len
    }

    pub fn decode(src: &mut BytesMut) -> Option<Frame> {
        if src.len() < FRAME_HEADER_SIZE {
            return None;
        }
        let cmd = src[0];
        let stream_id = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        let data_len = u16::from_be_bytes([src[5], src[6]]) as usize;

        if src.len() < FRAME_HEADER_SIZE + data_len {
            return None;
        }

        src.advance(FRAME_HEADER_SIZE);
        let payload = if data_len >= ZERO_COPY_PAYLOAD_MIN {
            // 零拷贝：`split_to(..).freeze()` 是 O(1) 的引用计数切分。
            src.split_to(data_len).freeze()
        } else {
            // 小载荷照旧拷贝，理由见 `ZERO_COPY_PAYLOAD_MIN`。
            let payload = Bytes::copy_from_slice(&src[..data_len]);
            src.advance(data_len);
            payload
        };

        Some(Frame {
            cmd,
            stream_id,
            payload,
        })
    }
}

/// CMD_PADDING 载荷的固定前缀：`[flag, m]`。
const PADDING_HEADER_LEN: usize = 2;

/// CMD_PADDING 的 `flag` 取值。
///
/// **只有 `REQUEST`(0) 会换来应答**：`Session::handle_frame` 的 CMD_PADDING 分支
/// 形如 `if flag == 0 { …回吐 m 条应答… }`，其余 flag 值走完 match 臂直接
/// `Ok(())`，**静默丢弃**。这一点正是新语义可以向后兼容地加进来的原因——
/// 引入新的 flag 值，旧对端只会当成一条无内容的掩护帧丢掉；而新增一个
/// **CMD 操作码**会落进 `_ => bail!("unknown frame cmd")`，让旧对端立刻拆除
/// 整条会话。
pub(crate) const PADDING_FLAG_REQUEST: u8 = 0;
pub(crate) const PADDING_FLAG_REPLY: u8 = 1;
/// 优雅拆除前的 H2 GOAWAY：载荷在 `[flag, m]` 之后携带 4 字节 last_stream_id。
pub(crate) const PADDING_FLAG_GOAWAY: u8 = 2;
/// 真实的 H2 WINDOW_UPDATE 信贷帧：帧头 stream_id 指明是连接级（0）还是
/// 每流级，载荷在 `[flag, m]` 之后携带 4 字节增量（u32 大端，与 H2
/// WINDOW_UPDATE 帧同宽）。
///
/// **为什么需要它**：此前「WINDOW_UPDATE」只是消费 6 MiB 后注入一条 flag=1
/// 填充，对端静默吸收，不带任何信贷语义——于是接收缓冲只能靠「超限丢数据 +
/// 杀流」兜底（数据损坏 / 传输被掐断）。真实 H2 的接收方按消费量回补窗口，
/// 发送方在窗口耗尽后**停发**，接收缓冲由窗口本身界定。本 flag 把那条填充
/// 变成真正的信贷帧：接收方消费过半窗口即回吐一条，发送方据此放行或挂起。
///
/// 对未升级的旧对端完全无害（同 GOAWAY 的论证）：旧读循环只对 flag=0 作答，
/// 其余 flag 走完 match 直接 `Ok(())` 静默丢弃。
pub(crate) const PADDING_FLAG_WINDOW_UPDATE: u8 = 3;

/// GOAWAY 载荷里 last_stream_id 的字节数（u32 大端，与 H2 GOAWAY 帧同宽）。
const GOAWAY_LAST_STREAM_ID_LEN: usize = 4;
/// WINDOW_UPDATE 载荷里增量的字节数（u32 大端，与 H2 WINDOW_UPDATE 帧同宽）。
const WINDOW_UPDATE_INCREMENT_LEN: usize = 4;

/// 一条能装下 last_stream_id 的 GOAWAY 记录的结构下限（37 字节）。
///
/// last_stream_id 占的是原本的 junk 区，**不改变线速尺寸**：目标取
/// `H2_GOAWAY_WIRE = PING_WIRE = 41` 时 junk 长度为 `41 − 33 = 8`，写掉 4 字节
/// 之后仍余 4 字节零填充，反解等式 `packet.len() + 24 == 41` 原样成立。
pub(crate) const MIN_GOAWAY_RECORD_WIRE_LEN: usize =
    MIN_PADDING_RECORD_WIRE_LEN + GOAWAY_LAST_STREAM_ID_LEN;

/// 一条控制记录在 `SnowyStream::prepare_control_record` 下的固定 wire 开销：
/// block 长度前缀 + TLS record 头 + AEAD tag + inner content type。
pub(crate) const CONTROL_RECORD_MIN_OVERHEAD: usize = kanotls_tunnel::common::BLOCK_LEN_PREFIX_SIZE
    + kanotls_tunnel::common::TLS_RECORD_HEADER_LEN
    + kanotls_tunnel::common::AEAD_TAG_LEN
    + kanotls_tunnel::common::INNER_CONTENT_TYPE_LEN;

/// 单条 CMD_PADDING 控制记录的结构下限（junk 长度为 0 时的线速尺寸）：
/// 33 字节，恰好等于控制尺寸采样池的最小档（H2 SETTINGS_ACK）。目标尺寸
/// 低于此值在结构上不可能达成，也无需额外钳制——采样器与角色常量都不会
/// 给出更小的值（回归见 `sampled_control_sizes_never_undercut_padding_floor`）。
pub(crate) const MIN_PADDING_RECORD_WIRE_LEN: usize =
    CONTROL_RECORD_MIN_OVERHEAD + FRAME_HEADER_SIZE + PADDING_HEADER_LEN;

/// 目标线速尺寸 → junk 长度的反解。
///
/// 此前的 `encode_padding_request_into` / `encode_padding_reply_into` 反过来
/// 做：先按 `m`（应答则按请求载荷长度）算出 junk，调用方之后才去采样线速
/// 尺寸，于是 `prepare_control_record` 里的
/// `.max(payload.len() + BLOCK_LEN_PREFIX + INNER_CONTENT_TYPE)` 把采样值整个
/// 吃掉——实际尺寸由 payload 反向决定，塌缩成 81 / 97 / 129 / 138 / 252 这几个
/// 不对应任何真实 H2 帧尺寸的常量，且因嵌入式默认脚本 6 条规则里 2 条带
/// `F:1`，它们在每条连接开头高频出现。改为先定目标、再反解 junk 后，记录的
/// 线速尺寸重新由调用方唯一决定。
const fn padding_junk_len_for_wire(target_wire_len: usize) -> usize {
    target_wire_len.saturating_sub(MIN_PADDING_RECORD_WIRE_LEN)
}

/// 构造一条线速尺寸恰为 `target_wire_len` 的 CMD_PADDING 请求帧（flag=0）：
/// `m` 指示接收方须回吐多少条应答记录。调用方必须用同一个 `target_wire_len`
/// 去 `prepare_control_record`（或让写循环按 `self_sized_padding_wire_len`
/// 复原同一目标），尺寸才会精确命中。
pub(crate) fn encode_padding_request_sized(m: u8, target_wire_len: usize) -> Vec<u8> {
    encode_padding_frame_sized(PADDING_FLAG_REQUEST, m, target_wire_len)
}

/// 构造一条线速尺寸恰为 `target_wire_len` 的 CMD_PADDING 应答帧（flag=1）。
///
/// 此前的 `encode_padding_reply_into` 对 junk 施加 `.max(16)` 下限，把应答的
/// 最小线速尺寸顶到 49，池内最小的 33/37/41/46 四档全部无法命中；junk 是零
/// 字节、位于 AEAD 明文侧、线上不可见，没有任何理由设下限。
pub(crate) fn encode_padding_reply_sized(target_wire_len: usize) -> Vec<u8> {
    encode_padding_frame_sized(PADDING_FLAG_REPLY, 0, target_wire_len)
}

/// 构造一条线速尺寸恰为 `target_wire_len` 的 GOAWAY 帧（flag=2），载荷携带
/// `last_stream_id`。
///
/// 此前拆除前那条 GOAWAY 尺寸的记录是 `flag=1` 的**纯填充**，不带任何语义：
/// 线上形态对了（真实 nginx/Firefox 关 H2 连接必发 GOAWAY），但对端拿不到
/// 「哪些流对端根本没处理过」这一信息。SOCKS 代理没有 HTTP 层的幂等重试，
/// 应用只看到 socket 被关；而连接池把 `streams_per_connection_target` 提到 256
/// 之后，一条连接的死亡最多牵连 256 条流。带上 last_stream_id 后，
/// `stream_id > last_stream_id` 的流可被判定为「对端从未处理」。
///
/// **线速尺寸不变**：last_stream_id 写在原 junk 区内（见
/// `MIN_GOAWAY_RECORD_WIRE_LEN`），4 个零字节换成 4 个 id 字节，而整帧随后过
/// ChaChaPoly，线上密文长度与内容分布都不变。
pub(crate) fn encode_padding_goaway_sized(last_stream_id: u32, target_wire_len: usize) -> Vec<u8> {
    debug_assert!(
        target_wire_len >= MIN_GOAWAY_RECORD_WIRE_LEN,
        "goaway wire target {} cannot hold a 4-byte last_stream_id (floor {})",
        target_wire_len,
        MIN_GOAWAY_RECORD_WIRE_LEN
    );
    let mut dst = encode_padding_frame_sized(PADDING_FLAG_GOAWAY, 0, target_wire_len);
    let start = FRAME_HEADER_SIZE + PADDING_HEADER_LEN;
    // 用 get_mut 而不是直接切片索引：目标尺寸低于下限时退化为一条不带
    // last_stream_id 的 GOAWAY（接收侧据长度判定，见 decode_padding_goaway），
    // 而不是 panic。生产路径由 session.rs 的编译期断言保证走不到这里。
    if let Some(slot) = dst.get_mut(start..start + GOAWAY_LAST_STREAM_ID_LEN) {
        slot.copy_from_slice(&last_stream_id.to_be_bytes());
    }
    dst
}

/// 若 `payload` 是一条带 last_stream_id 的 GOAWAY 载荷，返回该 id。
///
/// 长度不足的 GOAWAY（理论上只有对端实现有误时才会出现）返回 `None`，语义等同
/// 于「收到了一条不带信息的拆除通告」——绝不能当成 `last_stream_id = 0`，那会
/// 把本端**全部**流误判为可重试。
pub(crate) fn decode_padding_goaway(payload: &[u8]) -> Option<u32> {
    if payload.first().copied()? != PADDING_FLAG_GOAWAY {
        return None;
    }
    let raw = payload.get(PADDING_HEADER_LEN..PADDING_HEADER_LEN + GOAWAY_LAST_STREAM_ID_LEN)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// 构造一条线速尺寸恰为 `target_wire_len` 的 WINDOW_UPDATE 信贷帧
/// （flag=3）：`stream_id` 写进帧头（0 = 连接级，与 H2 同语义），增量写进
/// `[flag, m]` 之后的 4 字节区，余量零填充。目标取 `WINDOW_UPDATE_WIRE`
/// （37）时 `37 − 24 = 13 = 7 帧头 + 2 + 4`，恰好零 junk。
pub(crate) fn encode_padding_window_update_sized(
    stream_id: u32,
    increment: u32,
    target_wire_len: usize,
) -> Vec<u8> {
    let mut dst = encode_padding_frame_sized(PADDING_FLAG_WINDOW_UPDATE, 0, target_wire_len);
    dst[1..5].copy_from_slice(&stream_id.to_be_bytes());
    let start = FRAME_HEADER_SIZE + PADDING_HEADER_LEN;
    // 用 get_mut 而不是直接切片索引：目标尺寸低于结构下限时退化为一条
    // 不带增量的 WINDOW_UPDATE（接收侧据 flag 判定，见
    // decode_padding_window_update），而不是 panic。
    if let Some(slot) = dst.get_mut(start..start + WINDOW_UPDATE_INCREMENT_LEN) {
        slot.copy_from_slice(&increment.to_be_bytes());
    }
    dst
}

/// 若 `payload` 是一条携带增量的 WINDOW_UPDATE 载荷，返回该增量。
///
/// flag 不对或长度不足（理论上只有对端实现有误时才会出现）返回 `None`，
/// 语义等同「没收到信贷」——绝不能当成 `increment = 0` 以外的任何值，
/// 更不得把坏帧当作合法信贷入账。
pub(crate) fn decode_padding_window_update(payload: &[u8]) -> Option<u32> {
    if payload.first().copied()? != PADDING_FLAG_WINDOW_UPDATE {
        return None;
    }
    let raw = payload.get(PADDING_HEADER_LEN..PADDING_HEADER_LEN + WINDOW_UPDATE_INCREMENT_LEN)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn encode_padding_frame_sized(flag: u8, m: u8, target_wire_len: usize) -> Vec<u8> {
    debug_assert!(
        target_wire_len >= MIN_PADDING_RECORD_WIRE_LEN,
        "padding wire target {} below structural floor {}",
        target_wire_len,
        MIN_PADDING_RECORD_WIRE_LEN
    );
    let payload_len = PADDING_HEADER_LEN + padding_junk_len_for_wire(target_wire_len);
    let mut dst = vec![0u8; FRAME_HEADER_SIZE + payload_len];
    dst[0] = CMD_PADDING;
    dst[1..5].copy_from_slice(&0u32.to_be_bytes());
    dst[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    dst[7] = flag;
    dst[8] = m;
    // junk 保持零字节：整帧随后由 ChaChaPoly 加密，填充内容在线上不可见
    // （见 common.rs 的 encrypt_variable_block）。
    dst
}

/// 若 `packet` 恰好是一条完整的 CMD_PADDING 帧，返回它自带的目标线速尺寸。
///
/// junk 已按目标反解（`payload_len = target - MIN_PADDING_RECORD_WIRE_LEN`），
/// 故目标就写在 packet 自身长度里：`target = packet.len() + 24`。写循环据此
/// 复原目标，而不是另采样一次——CMD_PADDING 是唯一一类「角色已知」的控制
/// 帧（H2 WINDOW_UPDATE / PING / PING-ACK），真实 H2 中这三种帧的尺寸都是
/// 确定值，不该再过一遍混合分布采样器。其余控制帧（SYN/FIN/SETTINGS/
/// SYNACK）没有固定的 H2 角色，仍由 `next_control_size` 的状态感知混合
/// 分布定尺寸。
///
/// 多帧合并的 packet（`coalesce_encoded_frames` 的产物）长度校验不通过，
/// 回落到采样路径，尺寸语义不变。
pub(crate) fn self_sized_padding_wire_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < FRAME_HEADER_SIZE || packet[0] != CMD_PADDING {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[5], packet[6]]) as usize;
    if FRAME_HEADER_SIZE + payload_len != packet.len() || payload_len < PADDING_HEADER_LEN {
        return None;
    }
    Some(packet.len() + CONTROL_RECORD_MIN_OVERHEAD)
}

/// Encode `data` into a sequence of CMD_PSH frames for `stream_id`, chunked
/// to MAX_PAYLOAD_LEN. Empty input yields no frames (callers emit an explicit
/// empty PSH themselves where the protocol needs one).
pub(crate) fn encode_psh_frames(stream_id: u32, data: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::with_capacity(data.len().div_ceil(MAX_PAYLOAD_LEN));
    for chunk in data.chunks(MAX_PAYLOAD_LEN) {
        let mut pkt = Vec::with_capacity(Frame::encoded_len(chunk.len()));
        Frame::encode_psh_into(&mut pkt, stream_id, chunk)?;
        packets.push(pkt);
    }
    Ok(packets)
}

pub(crate) fn coalesce_encoded_frames(frames: Vec<Vec<u8>>, max_packet_len: usize) -> Vec<Vec<u8>> {
    // 单帧是最常见形态（write_data、Frame::psh、FIN/SYN 都只有一帧）：此前
    // 无条件走 `current.extend_from_slice(&frame)`，即一次 Vec 分配 + 整包
    // 拷贝，而结果与直接返回原 Vec 逐字节相同（超过 max_packet_len 的单帧
    // 旧路径也是原样 push，语义一致）。空帧除外——旧路径会把它丢掉
    // （current 仍为空 ⇒ 不 push），此处保持该语义。
    if frames.len() == 1 && !frames[0].is_empty() {
        return frames;
    }

    let mut out = Vec::new();
    let mut current = Vec::new();

    for frame in frames {
        if frame.len() > max_packet_len {
            if !current.is_empty() {
                out.push(std::mem::replace(
                    &mut current,
                    Vec::with_capacity(max_packet_len),
                ));
            }
            out.push(frame);
            continue;
        }

        if current.len() + frame.len() > max_packet_len && !current.is_empty() {
            out.push(std::mem::replace(
                &mut current,
                Vec::with_capacity(max_packet_len),
            ));
        }
        current.extend_from_slice(&frame);
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rejects_oversized_payload_instead_of_truncating() {
        let frame = Frame::psh(1, vec![0u8; MAX_PAYLOAD_LEN + 1]);
        assert!(frame.encode().is_err());
    }

    /// C1 回归（编码侧）：junk 必须按目标线速尺寸精确反解，使
    /// `packet.len() + CONTROL_RECORD_MIN_OVERHEAD == target`。这一等式是
    /// `prepare_control_record` 精确命中目标的充要条件：它取
    /// `max(target - TLS_HEADER - TAG, payload + PREFIX + INNER)`，两项在此
    /// 等式下恰好相等，`max` 不再顶高尺寸。
    #[test]
    fn sized_padding_junk_derivation_hits_target_wire_len_exactly() {
        for target in [
            MIN_PADDING_RECORD_WIRE_LEN,
            37,
            41,
            46,
            54,
            64,
            82,
            300,
            824,
        ] {
            for m in [0u8, 1, 2] {
                let request = encode_padding_request_sized(m, target);
                assert_eq!(request.len() + CONTROL_RECORD_MIN_OVERHEAD, target);
                assert_eq!(self_sized_padding_wire_len(&request), Some(target));
                assert_eq!(request[0], CMD_PADDING);
                assert_eq!(request[7], 0, "flag=0 是请求");
                assert_eq!(request[8], m);
            }
            let reply = encode_padding_reply_sized(target);
            assert_eq!(reply.len() + CONTROL_RECORD_MIN_OVERHEAD, target);
            assert_eq!(self_sized_padding_wire_len(&reply), Some(target));
            assert_eq!(reply[7], 1, "flag=1 是应答");
        }
    }

    /// 结构下限即池内最小档：目标取 33 时 junk 为 0，帧只剩
    /// `[flag, m]`——不再有 `junk.max(16)` 那种把最小尺寸顶到 49 的钳制。
    #[test]
    fn floor_target_yields_junk_free_padding_frame() {
        let reply = encode_padding_reply_sized(MIN_PADDING_RECORD_WIRE_LEN);
        assert_eq!(reply.len(), FRAME_HEADER_SIZE + PADDING_HEADER_LEN);
        assert_eq!(padding_junk_len_for_wire(MIN_PADDING_RECORD_WIRE_LEN), 0);
    }

    /// GOAWAY 把 4 字节 last_stream_id 写进原有的 junk 区：帧长、反解等式、
    /// `self_sized_padding_wire_len` 三者全部与同尺寸的纯填充帧一致——线上唯一
    /// 会变的东西（记录尺寸）因此不变。
    #[test]
    fn goaway_carries_last_stream_id_without_moving_the_wire_target() {
        for target in [MIN_GOAWAY_RECORD_WIRE_LEN, 41, 46, 82, 824] {
            let reply = encode_padding_reply_sized(target);
            for last in [0u32, 1, 3, 65535, u32::MAX] {
                let goaway = encode_padding_goaway_sized(last, target);
                assert_eq!(goaway.len(), reply.len());
                assert_eq!(goaway.len() + CONTROL_RECORD_MIN_OVERHEAD, target);
                assert_eq!(self_sized_padding_wire_len(&goaway), Some(target));
                assert_eq!(goaway[0], CMD_PADDING);
                assert_eq!(goaway[7], PADDING_FLAG_GOAWAY);
                assert_eq!(
                    decode_padding_goaway(&goaway[FRAME_HEADER_SIZE..]),
                    Some(last)
                );
            }
        }
    }

    /// 解析必须在「拿不准」时返回 `None`，**绝不**回落到 0：last_stream_id = 0
    /// 的语义是「一条都没处理过」，把它当作缺省值会把对端全部流误判为可重试。
    #[test]
    fn goaway_decode_never_defaults_to_zero() {
        // 非 GOAWAY 的 flag。
        assert_eq!(
            decode_padding_goaway(&encode_padding_reply_sized(41)[FRAME_HEADER_SIZE..]),
            None
        );
        assert_eq!(
            decode_padding_goaway(&encode_padding_request_sized(1, 41)[FRAME_HEADER_SIZE..]),
            None
        );
        // flag 对但载荷装不下 id（对端实现有误 / 帧被截断）。
        assert_eq!(decode_padding_goaway(&[]), None);
        assert_eq!(decode_padding_goaway(&[PADDING_FLAG_GOAWAY]), None);
        assert_eq!(
            decode_padding_goaway(&[PADDING_FLAG_GOAWAY, 0, 1, 2, 3]),
            None
        );
        assert_eq!(
            decode_padding_goaway(&[PADDING_FLAG_GOAWAY, 0, 0, 0, 1, 2]),
            Some(258)
        );
    }

    /// WINDOW_UPDATE 信贷帧：帧头 stream_id、载荷增量、线速尺寸三者必须
    /// 同时精确落位，且 37 字节目标（`WINDOW_UPDATE_WIRE`）下零 junk。
    ///
    /// 结构下限 33 装不下 `[flag, m] + 4 字节增量`（载荷下限 6 > 33 − 24 −
    /// 7 = 2），增量随帧静默退化——生产路径恒取 37，此处只钉住边界不 panic。
    #[test]
    fn window_update_frame_round_trip() {
        for target in [37usize, 41, 82] {
            for stream_id in [0u32, 1, 3, 65535, u32::MAX] {
                for increment in [0u32, 1, 65535, u32::MAX] {
                    let packet = encode_padding_window_update_sized(stream_id, increment, target);
                    assert_eq!(packet[0], CMD_PADDING);
                    assert_eq!(packet[1..5], stream_id.to_be_bytes());
                    assert_eq!(packet.len() + CONTROL_RECORD_MIN_OVERHEAD, target);
                    assert_eq!(self_sized_padding_wire_len(&packet), Some(target));
                    let mut buf = bytes::BytesMut::from(packet.as_slice());
                    let frame = Frame::decode(&mut buf).expect("frame decodes");
                    assert_eq!(frame.stream_id, stream_id);
                    assert_eq!(
                        decode_padding_window_update(&frame.payload),
                        Some(increment)
                    );
                }
            }
        }
        // 结构下限：增量装不下 ⇒ 解码返回 None（绝不入账成 0）。
        let packet = encode_padding_window_update_sized(1, 4096, MIN_PADDING_RECORD_WIRE_LEN);
        assert_eq!(
            decode_padding_window_update(&packet[FRAME_HEADER_SIZE..]),
            None
        );
    }

    /// 37 字节目标恰好等于结构下限 + 4 字节增量：`37 − 24 = 13 = 7 帧头 +
    /// 2 `[flag, m]` + 4 增量`，junk 区为零。
    #[test]
    fn window_update_target_37_carries_increment_without_junk() {
        let packet = encode_padding_window_update_sized(9, 0xDEAD_BEEF, 37);
        assert_eq!(packet.len(), FRAME_HEADER_SIZE + PADDING_HEADER_LEN + 4);
        let payload = &packet[FRAME_HEADER_SIZE..];
        assert_eq!(&payload[..2], &[PADDING_FLAG_WINDOW_UPDATE, 0]);
        assert_eq!(&payload[2..6], &0xDEAD_BEEFu32.to_be_bytes());
    }

    /// 解析必须在「拿不准」时返回 `None`：坏 flag 或长度不足的帧绝不入账，
    /// 更不能当成 `increment = 0` 的合法信贷（那等于让发送方凭空失去一次
    /// 恢复机会之外还多一次无效入账）。
    #[test]
    fn window_update_decode_never_defaults_to_zero() {
        assert_eq!(
            decode_padding_window_update(&encode_padding_reply_sized(41)[FRAME_HEADER_SIZE..]),
            None
        );
        assert_eq!(
            decode_padding_window_update(&encode_padding_request_sized(1, 41)[FRAME_HEADER_SIZE..]),
            None
        );
        assert_eq!(decode_padding_window_update(&[]), None);
        assert_eq!(
            decode_padding_window_update(&[PADDING_FLAG_WINDOW_UPDATE]),
            None
        );
        assert_eq!(
            decode_padding_window_update(&[PADDING_FLAG_WINDOW_UPDATE, 0, 1, 2, 3]),
            None
        );
        assert_eq!(
            decode_padding_window_update(&[PADDING_FLAG_WINDOW_UPDATE, 0, 0, 0, 1, 2]),
            Some(258)
        );
    }

    /// WINDOW_UPDATE 帧必须被 `self_sized_padding_wire_len` 识别：它由接收方
    /// 在消费路径上生成，写循环按反解目标 prepare，记录才能精确落在
    /// `WINDOW_UPDATE_WIRE`。
    #[test]
    fn self_sized_detection_accepts_window_update_frames() {
        for target in [33usize, 37, 41, 82] {
            let packet = encode_padding_window_update_sized(7, 4096, target);
            assert_eq!(self_sized_padding_wire_len(&packet), Some(target));
        }
        let mut merged = encode_padding_window_update_sized(7, 1, 37);
        merged.extend_from_slice(&encode_padding_reply_sized(37));
        assert_eq!(self_sized_padding_wire_len(&merged), None);
    }

    /// 只有「恰好一条完整 CMD_PADDING 帧」的 packet 才自带尺寸；其余
    /// packet 必须回落到采样路径，否则普通控制帧的记录尺寸会被其明文
    /// 长度反向决定。
    #[test]
    fn self_sized_detection_rejects_non_padding_and_merged_packets() {
        let syn = Frame::syn(3).encode().unwrap();
        assert_eq!(self_sized_padding_wire_len(&syn), None);
        assert_eq!(self_sized_padding_wire_len(&[]), None);
        assert_eq!(self_sized_padding_wire_len(&[CMD_PADDING; 3]), None);

        let mut merged = encode_padding_request_sized(1, 41);
        merged.extend_from_slice(&encode_padding_reply_sized(37));
        assert_eq!(self_sized_padding_wire_len(&merged), None);
    }

    /// P5 回归：单帧快路径必须与旧的「拷贝进 current 再 push」逐字节等价，
    /// 包括超长单帧与空帧这两个边界。
    #[test]
    fn coalesce_single_frame_matches_copy_path() {
        assert_eq!(
            coalesce_encoded_frames(vec![vec![9u8; 10]], 32),
            vec![vec![9u8; 10]]
        );
        assert_eq!(
            coalesce_encoded_frames(vec![vec![9u8; 40]], 32),
            vec![vec![9u8; 40]]
        );
        assert!(coalesce_encoded_frames(vec![Vec::new()], 32).is_empty());
        assert!(coalesce_encoded_frames(Vec::new(), 32).is_empty());
    }

    #[test]
    fn encode_decode_round_trip_max_payload() {
        let payload = vec![7u8; MAX_PAYLOAD_LEN];
        let frame = Frame::psh(42, payload.clone());
        let encoded = frame.encode().unwrap();
        let mut buf = BytesMut::from(encoded.as_slice());
        let decoded = Frame::decode(&mut buf).unwrap();
        assert_eq!(decoded.cmd, CMD_PSH);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload, payload);
    }
}
