use bytes::{Buf, BytesMut};
use lazy_static::lazy_static;
use snow::params::NoiseParams;
use snow::StatelessTransportState;
use std::cmp;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{trace, warn};

use crate::control_size::{self, ConnectionState, FlowDirection};
use crate::utils::hash_with_key;
use crate::MAX_TLS_RECORD_PAYLOAD_LEN;

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams =
        "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub const AEAD_TAG_LEN: usize = 16;
pub const PSK_LEN: usize = 32;
pub const TLS_RECORD_HEADER_LEN: usize = 5;
pub const BLOCK_LEN_PREFIX_SIZE: usize = 2;
pub const INNER_CONTENT_TYPE_LEN: usize = 1;
pub const INNER_CONTENT_TYPE_APP_DATA: u8 = 0x17;
pub const INNER_CONTENT_TYPE_ALERT: u8 = 0x15;
// TLS 1.3 max application data = 16384 (2^14). AEAD plaintext = 16384 content
// + 1 byte Inner Content Type = 16385. Ciphertext = 16385 + 16 AEAD tag = 16401.
// Wire = 5 header + 16401 ciphertext = 16406 — matches real Firefox TLS 1.3.
pub const BLOCK_PLAINTEXT_SIZE: usize = 16384 + INNER_CONTENT_TYPE_LEN;
const BLOCK_DATA_CAPACITY: usize =
    BLOCK_PLAINTEXT_SIZE - BLOCK_LEN_PREFIX_SIZE - INNER_CONTENT_TYPE_LEN;
pub const NOISE_RESPONSE_OVERHEAD_LEN: usize = 48;
pub const HANDSHAKE_CONTROL_MAGIC: &[u8; 4] = b"KTL1";
pub const HANDSHAKE_CONTROL_LEN: usize = 6;
pub const MIN_NOISE_RESPONSE_RECORD_LEN: usize =
    NOISE_RESPONSE_OVERHEAD_LEN + HANDSHAKE_CONTROL_LEN;

pub const FLIGHT3_CCS_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
pub const FLIGHT3_FINISHED_PLAINTEXT_LEN: usize = 37;
pub const FLIGHT3_FINISHED_RECORD_LEN: usize =
    TLS_RECORD_HEADER_LEN + FLIGHT3_FINISHED_PLAINTEXT_LEN + AEAD_TAG_LEN;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct H2GhostVariant {
    plaintext: &'static [u8],
    plaintext_len: usize,
}

fn make_h2_ghost_variant(
    settings: &[u8],
    wu: &[u8],
    trailer: u8,
    plaintext_len: usize,
) -> H2GhostVariant {
    let mut buf = vec![0u8; plaintext_len];
    buf[..24].copy_from_slice(H2_PREFACE);
    let delta = 24 + settings.len();
    buf[24..delta].copy_from_slice(settings);
    buf[delta..delta + wu.len()].copy_from_slice(wu);
    let tail = delta + wu.len();
    buf[tail] = trailer;
    let leaked: &'static [u8] = Box::leak(buf.into_boxed_slice());
    H2GhostVariant {
        plaintext: leaked,
        plaintext_len,
    }
}

lazy_static! {
    static ref H2_GHOST_VARIANTS: Vec<H2GhostVariant> = vec![
        make_h2_ghost_variant(
            &[
                0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x04, 0x00, 0x00, 0x60, 0x00,
            ],
            &[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01,],
            0x17,
            65
        ),
        make_h2_ghost_variant(
            &[
                0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xE8, 0x00,
                0x04, 0x00, 0x00, 0x60, 0x00,
            ],
            &[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01,],
            0x17,
            71
        ),
        make_h2_ghost_variant(
            &[
                0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03,
                0xE8, 0x00, 0x04, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00,
            ],
            &[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0x01,],
            0x1e,
            65
        ),
        make_h2_ghost_variant(
            &[
                0x00, 0x00, 0x1E, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xE8, 0x00,
                0x04, 0x00, 0x00, 0x60, 0x00, 0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
            ],
            &[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01,],
            0x17,
            77
        ),
    ];
}

pub fn build_h2_ghost_plaintext(context_hash: u64) -> Vec<u8> {
    let variants = &*H2_GHOST_VARIANTS;
    let variant = &variants[(context_hash as usize) % variants.len()];
    variant.plaintext[..variant.plaintext_len].to_vec()
}

pub fn max_h2_ghost_plaintext_len() -> usize {
    H2_GHOST_VARIANTS
        .iter()
        .map(|v| v.plaintext_len)
        .max()
        .unwrap_or(65)
}

pub fn max_h2_ghost_record_len() -> usize {
    TLS_RECORD_HEADER_LEN + max_h2_ghost_plaintext_len() + AEAD_TAG_LEN
}

pub fn max_flight3_total_wire_len() -> usize {
    FLIGHT3_CCS_RECORD.len() + FLIGHT3_FINISHED_RECORD_LEN + max_h2_ghost_record_len()
}

const CONTEXT: &[u8] = b"kanotls-secure-tunnel-v1";

pub fn derive_psk(key: &[u8]) -> [u8; PSK_LEN] {
    hash_with_key(CONTEXT, key)
}

/// Firefox (Necko) 的内核 TCP keepalive 默认值：
/// `network.tcp.keepalive.idle_time = 600`、`retry_interval = 1`、
/// `probe_count = 4`。
///
/// 此前这里是 idle = 60 + U[0,6] s、interval = 30 + U[0,3] s、
/// retries = 3 + U[0,1]，有两个独立的可观测问题：
///
/// 1. **绝对值不像浏览器。** Firefox 不会在连接空闲 60 秒就发探测。被活跃
///    流持有却长时间无数据的隧道（SSH、long-poll、隧道内 WebSocket）会按
///    60 s / 30 s 的节奏发出零长度 ACK 探测段——真实 Firefox 在这个时间
///    尺度上完全静默，而 keepalive 探测在线上是可见的。
/// 2. **抖动本身就是特征。** 逐连接抖动在这个维度上是反向优化：Firefox 对
///    所有 socket 设同一组常量，抖动反而让「同一客户端 IP 的不同连接有
///    不同的 keepalive 周期」——真实浏览器不会这样。这是「方差过剩」，与
///    §2.3 修掉的 key_share「方差不足」互为镜像。这里的全局常量识别的是
///    「Firefox」而不是「KanoTLS」，因此常量是正确选择。
///
/// 取舍（已知）：死端检测窗口从约 60 + 3×30 = 150 s 变为
/// 600 + 4×1 = 604 s。一个真正失联（无 FIN/RST）且仍持有活跃流的对端会挂
/// 到约 10 分钟。无活跃流的连接不受影响——它们先被服务端 75 s 空闲拆除或
/// 客户端池 30 s idle-drain 回收。
const FIREFOX_KEEPALIVE_IDLE_SECS: u64 = 600;
const FIREFOX_KEEPALIVE_INTERVAL_SECS: u64 = 1;
#[cfg(target_os = "linux")]
const FIREFOX_KEEPALIVE_PROBE_COUNT: u32 = 4;

pub fn apply_tcp_keepalive(tcp: &TcpStream) -> io::Result<()> {
    let idle = Duration::from_secs(FIREFOX_KEEPALIVE_IDLE_SECS);
    let interval = Duration::from_secs(FIREFOX_KEEPALIVE_INTERVAL_SECS);
    let sock_ref = socket2::SockRef::from(tcp);
    let mut keepalive = socket2::TcpKeepalive::new()
        .with_time(idle)
        .with_interval(interval);
    #[cfg(target_os = "linux")]
    {
        keepalive = keepalive.with_retries(FIREFOX_KEEPALIVE_PROBE_COUNT);
    }
    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        warn!(
            "failed to apply kernel TCP Keep-Alive: {}. Long connections may drop.",
            e
        );
    }
    Ok(())
}

/// 单条隧道连接承载全部流量，吞吐的一个硬上限是**本端 TCP 缓冲**：
/// 窗口/RTT 是天花板，500 Mbps × 175 ms 的 BDP ≈ 10.9 MB。不显式设置时
/// Linux 自动调优封顶于宿主 `net.ipv4.tcp_{r,w}mem` max（常见默认 4/6
/// MiB ⇒ 单连接 ~180–270 mbps 封顶）；显式 setsockopt 则封顶于
/// `net.core.{r,w}mem_max`（常见默认 208 KiB ⇒ 更糟，且会**关闭**自动
/// 调优）。因此策略是：先读 `net.core.*_max`，仅当设置后能明显超过常见
/// 自动调优封顶（≥ 8 MiB）才动手，否则保持自动调优并 warn 引导调宿主机。
/// 只改内核缓冲，线上字节零变化。
#[cfg(target_os = "linux")]
const TUNNEL_SOCKET_BUFFER_TARGET: usize = 16 * 1024 * 1024;
#[cfg(target_os = "linux")]
const TUNNEL_SOCKET_BUFFER_FLOOR: usize = 8 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn read_core_mem_max(name: &str) -> Option<usize> {
    let content = std::fs::read_to_string(format!("/proc/sys/net/core/{}", name)).ok()?;
    content.trim().parse().ok()
}

/// 尽量放大隧道 socket 的发送/接收缓冲。任一端不满足下限则该方向保持
/// 自动调优不动；被宿主封顶不是错误（内核静默 clamp），只需读回记录。
#[cfg(target_os = "linux")]
pub fn tune_tunnel_socket_buffers(tcp: &TcpStream) {
    let sock_ref = socket2::SockRef::from(tcp);
    for name in ["wmem_max", "rmem_max"] {
        // 内核把请求值翻倍记账（min(2R, *_max)），可用量 ≈ min(R, *_max/2)。
        let usable_cap = read_core_mem_max(name).map(|m| m / 2).unwrap_or(0);
        let request = TUNNEL_SOCKET_BUFFER_TARGET.min(usable_cap);
        if request < TUNNEL_SOCKET_BUFFER_FLOOR {
            warn!(
                "net.core.{} too small ({} B); keeping TCP autotuning. For high-BDP paths raise net.core.{} and net.ipv4.tcp_*mem to >= 32 MiB",
                name,
                usable_cap * 2,
                name
            );
            continue;
        }
        let (set_result, effective) = if name == "wmem_max" {
            (
                sock_ref.set_send_buffer_size(request),
                sock_ref.send_buffer_size().unwrap_or(0),
            )
        } else {
            (
                sock_ref.set_recv_buffer_size(request),
                sock_ref.recv_buffer_size().unwrap_or(0),
            )
        };
        if let Err(e) = set_result {
            warn!("failed to set tunnel socket buffer ({}): {}", name, e);
            continue;
        }
        // 读回的是翻倍后的记账值；可用量按其一半折算。
        tracing::info!(
            "tunnel socket buffer via setsockopt: {} effective ~{} MiB",
            name,
            effective / 2 / (1024 * 1024)
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn tune_tunnel_socket_buffers(_tcp: &TcpStream) {
    // 非 Linux 平台不读 /proc，保持系统自动调优（自动调优封顶由宿主决定）。
}

/// Noise 传输态：无状态 cipher + **外部** nonce 计数器。
///
/// **为什么不用 `snow::TransportState`**：它把两个方向的 nonce 藏在
/// `&mut self` 后面，于是一条连接的读与写必须共享同一把锁——读半解密一条
/// 16 KB 记录期间，写半连一条 33 字节的控制记录都加密不了。实测（双向各
/// 400 MiB 打满、4 个 worker 线程）：12.2 万次加锁中 5.0% 发生争用，被阻塞
/// 的线程时间累计 0.39 s，占 4 线程 × 0.48 s 线程时间预算的两成；单向大
/// 流量下争用只有 0.43%、累计 8 ms，可以忽略——这把锁的代价**只在双向同时
/// 打满时**出现。
///
/// `StatelessTransportState` 的 `write_message` / `read_message` 都取
/// `&self`，nonce 由调用方传入；写用 `cipherstates.0`、读用
/// `cipherstates.1`（responder 相反），**两个方向触及互不相交的
/// cipherstate**。把计数器搬到外部，读写两半便可各持一份 `Arc`，那把锁整个
/// 消失。
///
/// **线上字节与旧版对端互通性不变**：`CipherState::encrypt` 是「校验 n →
/// 以 n 和同一个 key 加密 → n += 1」，`StatelessCipherState::encrypt(n, …)`
/// 是「校验 n → 以 n 和同一个 key 加密」，两者的 authtext 同为空切片。两端
/// 进入传输态时 n 均为 0，因此外部计数器从 0 起、且**仅在成功时**递增即逐
/// 字节等价；失败不推进 nonce 也与 `encrypt_ad` / `decrypt_ad` 在 `?` 处早退、
/// 不执行 `n += 1` 一致。由 `stateless_transport_matches_stateful_byte_for_byte`
/// 与 `failed_decrypt_does_not_advance_the_receive_nonce` 钉死。
pub struct NoiseTransport {
    sender: NoiseSender,
    receiver: NoiseReceiver,
}

impl NoiseTransport {
    pub fn new(state: StatelessTransportState) -> Self {
        let state = Arc::new(state);
        Self {
            sender: NoiseSender {
                state: state.clone(),
                nonce: 0,
            },
            receiver: NoiseReceiver { state, nonce: 0 },
        }
    }

    /// 与 `TransportState::write_message` 同签名、同语义、同输出字节。
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.sender.write_message(payload, message)
    }

    /// 与 `TransportState::read_message` 同签名、同语义。
    ///
    /// 实参顺序注意：`StatelessTransportState::read_message` 的形参名是
    /// `(payload = 密文输入, message = 明文输出)`，与 `TransportState` 的
    /// `(message = 密文输入, payload = 明文输出)` **命名相反、位置相同**。
    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.receiver.read_message(message, payload)
    }

    /// 发送方向的计数器视图：记录整形层直接驱动加密时用。
    pub fn sender_mut(&mut self) -> &mut NoiseSender {
        &mut self.sender
    }

    /// 拆成两个方向各自独立的计数器视图：此后读半与写半再无共享可变状态。
    fn split(self) -> (NoiseSender, NoiseReceiver) {
        (self.sender, self.receiver)
    }
}

/// 发送方向的 nonce 计数器（写半独占）。
pub struct NoiseSender {
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

impl NoiseSender {
    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error> {
        let len = self.state.write_message(self.nonce, payload, message)?;
        // 仅在成功时推进，与 snow `encrypt_ad` 的 `?` 早退语义一致。
        self.nonce = self.nonce.saturating_add(1);
        Ok(len)
    }
}

/// 接收方向的 nonce 计数器（读半独占）。
pub struct NoiseReceiver {
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

impl NoiseReceiver {
    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        let len = self.state.read_message(self.nonce, message, payload)?;
        // 解密失败不推进接收 nonce，与 snow `decrypt_ad` 的 `?` 早退语义一致。
        self.nonce = self.nonce.saturating_add(1);
        Ok(len)
    }
}

/// 读写两半共享的连接级状态。
///
/// 拆分前这两项是 `SnowyStream` 上的普通字段，由那把大锁顺带串行化；拆分后
/// 它们是**唯一**跨半的可变状态，故改为原子量。语义逐条对应：
///
/// * `closed`：原 `StreamState::{Open, Closed}`。读半在收到 alert / 0x15 /
///   EOF / 解密失败时置位，写半的 `poll_write` 与 `poll_shutdown` 据此不再
///   写字节——**这决定了拆除时线上有没有那条 close_notify 记录**，因此必须
///   共享，不能各持一份。
/// * `close_notify_written`：解密失败时读半置位、写半据此抑制 alert
///   （见 `poll_read` 的 `Err` 分支注释）。
///
/// `Relaxed` 足够：两个标志都不发布任何数据，只做「是否还要写/读字节」的
/// 判定；拆分前该判定与另一半之间同样没有顺序保证（读半可以在写半刚放锁后
/// 立刻置位），因此不存在新增的交错。
struct SnowyShared {
    closed: AtomicBool,
    close_notify_written: AtomicBool,
    /// 连接级配额：与拆分前一致，两半**都**丢弃后才归还。
    _permit: Option<OwnedSemaphorePermit>,
}

pub struct SnowyReadHalf {
    socket: OwnedReadHalf,
    noise: NoiseReceiver,
    shared: Arc<SnowyShared>,
    read_buf_inner: Vec<u8>,
    read_offset: usize,
    tls_rx_buf: BytesMut,
    tls_rx_offset: usize,
    io_buf: Box<[u8; MAX_TLS_RECORD_PAYLOAD_LEN]>,
    decrypt_buf: Box<[u8; MAX_TLS_RECORD_PAYLOAD_LEN]>,
}

pub struct SnowyWriteHalf {
    /// `Option` 只为 `Drop`：`OwnedWriteHalf` 默认在析构时 `shutdown(SHUT_WR)`，
    /// 而拆分前丢弃 `SnowyStream` 只是 `close(fd)`。`forget()` 关掉那次
    /// shutdown，使「未显式 shutdown 就丢弃」这条路径上的线上字节与拆分前
    /// 逐字节一致（否则被中止的写循环会凭空多出一个 FIN）。
    socket: Option<OwnedWriteHalf>,
    noise: NoiseSender,
    shared: Arc<SnowyShared>,
    write_buffer: Vec<u8>,
    write_offset: usize,
    encrypt_buf: Box<[u8; BLOCK_PLAINTEXT_SIZE]>,
    /// 已发出的控制记录条数。除记账之外，它同时是 H2 开场序列的游标：
    /// `next_control_size` 用它在 `control_size::h2_opening_size` 里定位本条
    /// 记录在确定性开场序列中的位置。只被写半使用，故归写半。
    control_frame_count: u64,
}

impl Drop for SnowyWriteHalf {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            socket.forget();
        }
    }
}

pub struct SnowyStream {
    read: SnowyReadHalf,
    write: SnowyWriteHalf,
}

impl SnowyStream {
    pub fn new(socket: TcpStream, noise: NoiseTransport) -> Self {
        Self::new_with_permit(socket, noise, None)
    }

    pub fn new_with_permit(
        socket: TcpStream,
        noise: NoiseTransport,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        let (read_socket, write_socket) = socket.into_split();
        let (sender, receiver) = noise.split();
        let shared = Arc::new(SnowyShared {
            closed: AtomicBool::new(false),
            close_notify_written: AtomicBool::new(false),
            _permit: permit,
        });
        SnowyStream {
            read: SnowyReadHalf {
                socket: read_socket,
                noise: receiver,
                shared: shared.clone(),
                read_buf_inner: Vec::with_capacity(BLOCK_DATA_CAPACITY),
                read_offset: 0,
                tls_rx_buf: BytesMut::with_capacity(
                    MAX_TLS_RECORD_PAYLOAD_LEN + TLS_RECORD_HEADER_LEN,
                ),
                tls_rx_offset: 0,
                io_buf: Box::new([0u8; MAX_TLS_RECORD_PAYLOAD_LEN]),
                decrypt_buf: Box::new([0u8; MAX_TLS_RECORD_PAYLOAD_LEN]),
            },
            write: SnowyWriteHalf {
                socket: Some(write_socket),
                noise: sender,
                shared,
                write_buffer: Vec::with_capacity(
                    TLS_RECORD_HEADER_LEN + BLOCK_PLAINTEXT_SIZE + AEAD_TAG_LEN,
                ),
                write_offset: 0,
                encrypt_buf: Box::new([0u8; BLOCK_PLAINTEXT_SIZE]),
                control_frame_count: 0,
            },
        }
    }

    /// 读写两半从此各自独立：解密与加密不再互相阻塞。
    pub fn into_split(self) -> (SnowyReadHalf, SnowyWriteHalf) {
        (self.read, self.write)
    }

    pub fn control_state(&self) -> ConnectionState {
        self.write.control_state()
    }

    pub fn buffered_write_len(&self) -> usize {
        self.write.buffered_write_len()
    }

    pub fn next_control_size(&mut self, state: ConnectionState, direction: FlowDirection) -> usize {
        self.write.next_control_size(state, direction)
    }

    pub fn prepare_control_record(
        &mut self,
        payload: &[u8],
        target_wire_len: usize,
    ) -> io::Result<()> {
        self.write.prepare_control_record(payload, target_wire_len)
    }

    pub fn prepare_data_record(
        &mut self,
        payload: &[u8],
        target_wire_len: usize,
    ) -> io::Result<()> {
        self.write.prepare_data_record(payload, target_wire_len)
    }

    /// The maximum application-payload capacity of a single wire record. The
    /// slicer must never hand `prepare_data_record` more than this many bytes.
    pub const fn data_record_capacity() -> usize {
        BLOCK_DATA_CAPACITY
    }

    /// Exact on-wire size of a shaped data record carrying `payload_len` bytes
    /// with no extra padding. `payload_len` must be `<= data_record_capacity()`.
    pub const fn data_record_wire_len(payload_len: usize) -> usize {
        TLS_RECORD_HEADER_LEN
            + BLOCK_LEN_PREFIX_SIZE
            + payload_len
            + INNER_CONTENT_TYPE_LEN
            + AEAD_TAG_LEN
    }

    /// On-wire size of a full (MTU/MSS-anchored) data record.
    pub const fn max_data_record_wire_len() -> usize {
        TLS_RECORD_HEADER_LEN + BLOCK_PLAINTEXT_SIZE + AEAD_TAG_LEN
    }
}

impl SnowyWriteHalf {
    #[inline]
    fn socket_mut(&mut self) -> &mut OwnedWriteHalf {
        self.socket
            .as_mut()
            .expect("write-half socket is only taken in Drop")
    }

    pub fn control_state(&self) -> ConnectionState {
        ConnectionState::from_control_count(self.control_frame_count)
    }

    /// 已 prepare 尚未 flush 的字节量：session 写循环的批量 flush 决策依据。
    pub fn buffered_write_len(&self) -> usize {
        self.write_buffer.len() - self.write_offset
    }

    /// 本条控制记录的目标线速尺寸。
    ///
    /// 此前无条件把 `state` 转交给加权抽样器，于是开场的前 6 条控制记录各自
    /// 独立地从一个含 SETTINGS 的池里抽样——位置随机、条数恒为 6。真实 H2
    /// 端点的开场是一段**确定性**序列，所以现在开场阶段改为按
    /// `control_size::h2_opening_size` 逐条取固定尺寸，序列走完才进入稳态
    /// 抽样池。详见 `control_size::H2_OPENING_MAX_LEN`。
    ///
    /// `control_frame_count` 兼作序列游标（由 `prepare_control_record` 递增），
    /// 因此调用方在一次 flush 前只算一次 `control_state()`、复用给多条记录
    /// 也不会错位：`state` 在这里只当「不要回退到开场」的单调下限用，真正
    /// 定位序列的是游标。
    pub fn next_control_size(&mut self, state: ConnectionState, direction: FlowDirection) -> usize {
        if state == ConnectionState::Handshake {
            if let Some(size) = control_size::h2_opening_size(direction, self.control_frame_count) {
                return size;
            }
        }
        // 开场序列已耗尽：稳态一律走 Transport 池（其支撑集不含 SETTINGS
        // 尺寸），SETTINGS 于是像真实 H2 那样在开场后彻底消失。
        control_size::next_control_size(
            ConnectionState::Transport,
            direction,
            &mut rand::thread_rng(),
        )
    }

    pub fn prepare_control_record(
        &mut self,
        payload: &[u8],
        target_wire_len: usize,
    ) -> io::Result<()> {
        self.control_frame_count = self.control_frame_count.saturating_add(1);

        let target_plaintext_len = target_wire_len
            .saturating_sub(TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN)
            .max(payload.len() + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN)
            .min(BLOCK_PLAINTEXT_SIZE);

        encrypt_variable_block(
            &mut self.noise,
            &mut self.write_buffer,
            &mut self.encrypt_buf,
            payload,
            target_plaintext_len,
        )
    }

    /// Encrypt exactly one 0x17 application-data record whose on-wire size is
    /// strictly `target_wire_len` (clamped to the valid record range), zero-padded
    /// per RFC 8446 §5.4. This is the single sizing-controlled
    /// interface for the bulk data path: the upper-layer TrafficShaper dictates
    /// every record's wire length, so plaintext length never maps to wire size.
    ///
    /// `payload` must not exceed `BLOCK_DATA_CAPACITY`; the caller (the slicer)
    /// is responsible for chunking larger buffers.
    pub fn prepare_data_record(
        &mut self,
        payload: &[u8],
        target_wire_len: usize,
    ) -> io::Result<()> {
        debug_assert!(payload.len() <= BLOCK_DATA_CAPACITY);
        let target_plaintext_len = target_wire_len
            .saturating_sub(TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN)
            .max(payload.len() + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN)
            .min(BLOCK_PLAINTEXT_SIZE);

        encrypt_variable_block(
            &mut self.noise,
            &mut self.write_buffer,
            &mut self.encrypt_buf,
            payload,
            target_plaintext_len,
        )
    }
}

fn parse_tls_record(buf: &[u8]) -> io::Result<Option<(usize, u8)>> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }
    let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if length > MAX_TLS_RECORD_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS payload too large",
        ));
    }
    let frame_type = buf[0];
    let total = TLS_RECORD_HEADER_LEN + length;
    if buf.len() < total {
        return Ok(None);
    }
    trace!(
        "parse_tls_record: type=0x{:02x} payload_len={} total={}",
        frame_type,
        length,
        total
    );
    Ok(Some((total, frame_type)))
}

impl AsyncRead for SnowyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for SnowyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl AsyncRead for SnowyReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut progress = false;

        'outer: loop {
            if this.read_offset < this.read_buf_inner.len() {
                let avail = this.read_buf_inner.len() - this.read_offset;
                let n = cmp::min(avail, buf.remaining());
                buf.put_slice(&this.read_buf_inner[this.read_offset..this.read_offset + n]);
                this.read_offset += n;
                progress = true;
                if this.read_offset >= this.read_buf_inner.len() {
                    this.read_offset = 0;
                    this.read_buf_inner.clear();
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }

            loop {
                let frame_info = match parse_tls_record(&this.tls_rx_buf[this.tls_rx_offset..]) {
                    Ok(frame_info) => frame_info,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                if let Some((consumed, frame_type)) = frame_info {
                    let frame_start = this.tls_rx_offset;
                    let frame_end = frame_start + consumed;
                    let payload_start = frame_start + TLS_RECORD_HEADER_LEN;

                    if frame_type == 0x17 && payload_start < frame_end {
                        match this.noise.read_message(
                            &this.tls_rx_buf[payload_start..frame_end],
                            this.decrypt_buf.as_mut_slice(),
                        ) {
                            Ok(len) => {
                                let is_close_notify = len == 3
                                    && this.decrypt_buf[0] == 0x01
                                    && this.decrypt_buf[1] == 0x00
                                    && this.decrypt_buf[2] == INNER_CONTENT_TYPE_ALERT;
                                let is_fatal_alert = len == 3
                                    && this.decrypt_buf[0] == 0x02
                                    && this.decrypt_buf[1] == 0x14
                                    && this.decrypt_buf[2] == INNER_CONTENT_TYPE_ALERT;

                                if is_close_notify || is_fatal_alert {
                                    trace!(
                                        "received TLS alert in 0x17: {}",
                                        if is_close_notify {
                                            "close_notify"
                                        } else {
                                            "fatal alert (0x14)"
                                        }
                                    );
                                    this.tls_rx_offset = frame_end;
                                    if this.tls_rx_offset == this.tls_rx_buf.len() {
                                        this.tls_rx_offset = 0;
                                        this.tls_rx_buf.clear();
                                    }
                                    this.shared.closed.store(true, Ordering::Relaxed);
                                    return Poll::Ready(Ok(()));
                                }

                                let prefix_data_len = if len
                                    >= BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN
                                {
                                    u16::from_be_bytes([this.decrypt_buf[0], this.decrypt_buf[1]])
                                        as usize
                                } else {
                                    0
                                };
                                trace!(
                                    "decrypted 0x17: plaintext_len={} prefix_data_len={} consumed={}",
                                    len,
                                    prefix_data_len,
                                    consumed
                                );
                                let data_range = if len
                                    >= BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN
                                {
                                    let data_len = prefix_data_len
                                        .min(len - BLOCK_LEN_PREFIX_SIZE - INNER_CONTENT_TYPE_LEN);
                                    BLOCK_LEN_PREFIX_SIZE..BLOCK_LEN_PREFIX_SIZE + data_len
                                } else {
                                    0..len
                                };
                                if !data_range.is_empty() {
                                    // 读路径减拷贝：read_buf_inner 为空且调用方
                                    // buf 有余量时，解密数据直接拷入调用方 buf，
                                    // 仅把装不下的剩余部分落入 read_buf_inner，
                                    // 消除常见路径的一次中转拷贝。
                                    if this.read_offset >= this.read_buf_inner.len()
                                        && buf.remaining() > 0
                                    {
                                        let n = cmp::min(data_range.len(), buf.remaining());
                                        buf.put_slice(
                                            &this.decrypt_buf
                                                [data_range.start..data_range.start + n],
                                        );
                                        if n < data_range.len() {
                                            this.read_buf_inner.extend_from_slice(
                                                &this.decrypt_buf
                                                    [data_range.start + n..data_range.end],
                                            );
                                        }
                                        progress = true;
                                    } else {
                                        this.read_buf_inner.extend_from_slice(
                                            &this.decrypt_buf[data_range.clone()],
                                        );
                                    }
                                }
                                this.tls_rx_offset = frame_end;
                                if this.tls_rx_offset == this.tls_rx_buf.len() {
                                    this.tls_rx_offset = 0;
                                    this.tls_rx_buf.clear();
                                }
                                if len > 0 {
                                    continue 'outer;
                                }
                            }
                            Err(e) => {
                                // AEAD 失败后 Session framing 已失同步 (TCP 字节流无
                                // sync marker),任何"跳帧恢复"在多路复用与流密码语义
                                // 下都不可行;也不发 Noise fatal alert —— 经加密的
                                // 0x17 record 在外层具有非典型 TTL、尺寸与时序特征,
                                // 反而暴露"密码学异常处置"语义信号给被动观察者。
                                // 正确策略:静默进入 Closed,由 Session read loop 观测
                                // Err 自动 force_close,连接池 (500ms 监控) Fail-Fast
                                // 检测并补涓,浏览器上层透明重试。
                                //
                                // 接收 nonce 在此**不推进**：`NoiseReceiver::read_message`
                                // 只在 Ok 时递增，与 snow `decrypt_ad` 在 `?` 处早退、
                                // 不执行 `n += 1` 完全一致。
                                this.shared
                                    .close_notify_written
                                    .store(true, Ordering::Relaxed);
                                this.shared.closed.store(true, Ordering::Relaxed);
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("noise decrypt: {}", e),
                                )));
                            }
                        }
                    } else if frame_type == 0x15 {
                        this.shared.closed.store(true, Ordering::Relaxed);
                        return Poll::Ready(Ok(()));
                    } else {
                        this.tls_rx_offset = frame_end;
                        if this.tls_rx_offset == this.tls_rx_buf.len() {
                            this.tls_rx_offset = 0;
                            this.tls_rx_buf.clear();
                        }
                    }
                } else {
                    break;
                }
            }

            if progress {
                return Poll::Ready(Ok(()));
            }

            let mut rb = ReadBuf::new(this.io_buf.as_mut_slice());
            match Pin::new(&mut this.socket).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        if this.tls_rx_offset < this.tls_rx_buf.len() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof mid frame",
                            )));
                        }
                        this.shared.closed.store(true, Ordering::Relaxed);
                        return Poll::Ready(Ok(()));
                    }
                    if this.tls_rx_offset > 0 {
                        this.tls_rx_buf.advance(this.tls_rx_offset);
                        this.tls_rx_offset = 0;
                    }
                    this.tls_rx_buf.extend_from_slice(&this.io_buf[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SnowyWriteHalf {
    /// The bulk AsyncWrite path is permanently sealed. The shaped session
    /// writer drives `prepare_data_record` / `prepare_control_record`
    /// directly; no autonomous chunking or encryption is performed
    /// through this trait. Any attempt to write bulk data through
    /// `poll_write` returns `Unsupported` to guarantee that no bytes
    /// bypass the TrafficShaper and re-introduce passive-size fingerprints.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(0));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "bulk AsyncWrite path retired; use prepare_data_record / prepare_control_record",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        try_flush_write_buffer(this, cx)?;

        if !this.write_buffer.is_empty() {
            return Poll::Pending;
        }

        Pin::new(this.socket_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures::ready;

        ready!(self.as_mut().poll_flush(cx))?;

        {
            let this = self.as_mut().get_mut();

            if !this.shared.close_notify_written.load(Ordering::Relaxed)
                && !this.shared.closed.load(Ordering::Relaxed)
            {
                let alert = [0x01u8, 0x00u8, INNER_CONTENT_TYPE_ALERT];
                let mut ct_buf = [0u8; 3 + AEAD_TAG_LEN];
                if let Ok(ct_len) = this.noise.write_message(&alert, &mut ct_buf) {
                    let current_len = this.write_buffer.len();
                    this.write_buffer
                        .resize(current_len + TLS_RECORD_HEADER_LEN + ct_len, 0);
                    this.write_buffer[current_len] = 0x17;
                    this.write_buffer[current_len + 1] = 0x03;
                    this.write_buffer[current_len + 2] = 0x03;
                    this.write_buffer[current_len + 3..current_len + 5]
                        .copy_from_slice(&(ct_len as u16).to_be_bytes());
                    this.write_buffer[current_len + 5..current_len + 5 + ct_len]
                        .copy_from_slice(&ct_buf[..ct_len]);
                    this.write_buffer
                        .truncate(current_len + TLS_RECORD_HEADER_LEN + ct_len);
                }
                this.shared
                    .close_notify_written
                    .store(true, Ordering::Relaxed);
                this.shared.closed.store(true, Ordering::Relaxed);
            }
        }

        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(self.get_mut().socket_mut()).poll_shutdown(cx)
    }
}

fn try_flush_write_buffer(stream: &mut SnowyWriteHalf, cx: &mut Context<'_>) -> io::Result<()> {
    let SnowyWriteHalf {
        socket,
        write_buffer,
        write_offset,
        ..
    } = stream;
    let socket = socket
        .as_mut()
        .expect("write-half socket is only taken in Drop");
    while *write_offset < write_buffer.len() {
        match Pin::new(&mut *socket).poll_write(cx, &write_buffer[*write_offset..]) {
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
                }
                *write_offset += n;
            }
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => return Ok(()),
        }
    }

    *write_offset = 0;
    write_buffer.clear();
    Ok(())
}

/// Minimum on-wire size of a shaped 0x17 data record carrying zero payload
/// bytes (2-byte length prefix + 1-byte inner content type).
pub const MIN_DATA_WIRE_LEN: usize =
    TLS_RECORD_HEADER_LEN + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN + AEAD_TAG_LEN;

fn encrypt_variable_block(
    noise: &mut NoiseSender,
    write_buffer: &mut Vec<u8>,
    encrypt_buf: &mut Box<[u8; BLOCK_PLAINTEXT_SIZE]>,
    payload: &[u8],
    target_plaintext_len: usize,
) -> io::Result<()> {
    assert!(target_plaintext_len >= payload.len() + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN);
    assert!(target_plaintext_len <= BLOCK_PLAINTEXT_SIZE);

    {
        let block = &mut encrypt_buf[..target_plaintext_len];
        let pad_start = BLOCK_LEN_PREFIX_SIZE + payload.len();
        let pad_end = target_plaintext_len - 1;
        if pad_end > pad_start {
            // 零填充：整个 block 随后由 ChaChaPoly 加密，密文对任何明文都
            // 均匀随机，故填充内容在线上不可见——用高熵字节填充没有任何
            // 收益。RFC 8446 §5.4 规定 TLS 1.3 的 record padding 本就是零
            // 字节，因此零填充反而更保真。
            block[pad_start..pad_end].fill(0);
        }
        block[..BLOCK_LEN_PREFIX_SIZE].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        block[BLOCK_LEN_PREFIX_SIZE..BLOCK_LEN_PREFIX_SIZE + payload.len()]
            .copy_from_slice(payload);
        block[target_plaintext_len - 1] = INNER_CONTENT_TYPE_APP_DATA;
    }

    let ct_len = target_plaintext_len + AEAD_TAG_LEN;
    let record_len = TLS_RECORD_HEADER_LEN + ct_len;

    let current_len = write_buffer.len();
    write_buffer.resize(current_len + record_len, 0);

    let actual_ct = noise
        .write_message(
            &encrypt_buf[..target_plaintext_len],
            &mut write_buffer[current_len + TLS_RECORD_HEADER_LEN..],
        )
        .map_err(|e| io::Error::other(format!("noise encrypt: {}", e)))?;

    write_buffer[current_len] = 0x17;
    write_buffer[current_len + 1] = 0x03;
    write_buffer[current_len + 2] = 0x03;
    write_buffer[current_len + 3..current_len + 5]
        .copy_from_slice(&(actual_ct as u16).to_be_bytes());
    write_buffer.truncate(current_len + TLS_RECORD_HEADER_LEN + actual_ct);
    Ok(())
}

#[cfg(test)]
mod poll_read_fuzz_tests {
    use super::*;
    use crate::common;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    fn build_transport_pair() -> (NoiseTransport, NoiseTransport) {
        let derived_psk = common::derive_psk(b"poll-read-fuzz");
        let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 96];
        let n = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..n], &mut []).unwrap();
        let n = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..n], &mut []).unwrap();
        (
            NoiseTransport::new(initiator.into_stateless_transport_mode().unwrap()),
            NoiseTransport::new(responder.into_stateless_transport_mode().unwrap()),
        )
    }

    // 随机尺寸 record 序列 + 随机 socket 分片 + 随机读 buf 尺寸：
    // 验证 poll_read 总能读完全部载荷且顺序完好（不返回假 EOF、不丢字节）。
    #[tokio::test]
    async fn poll_read_reassembles_fragmented_record_stream() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for round in 0..25 {
            let (mut server_noise, client_noise) = build_transport_pair();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
            let (server_tcp, _) = listener.accept().await.unwrap();
            let client_tcp = connect.await.unwrap();

            // 随机载荷序列：覆盖空载荷、小载荷、整 record、跨界尺寸。
            let mut expected: Vec<u8> = Vec::new();
            let mut wire: Vec<u8> = Vec::new();
            // 直接在内存里加密：手工构造 record 序列。
            let mut records_plain: Vec<Vec<u8>> = Vec::new();
            let sizes = [0usize, 1, 2, 3, 63, 100, 1024, 4096, 16381, 777, 16380, 5];
            let count = rng.gen_range(3..10);
            for i in 0..count {
                let sz = sizes[rng.gen_range(0..sizes.len())];
                let payload: Vec<u8> = (0..sz).map(|j| ((i * 7 + j) % 251) as u8).collect();
                expected.extend_from_slice(&payload);
                records_plain.push(payload);
            }
            let mut wire_tmp = Vec::new();
            let mut encrypt_buf = Box::new([0u8; BLOCK_PLAINTEXT_SIZE]);
            for payload in &records_plain {
                let target = if rng.gen_bool(0.5) {
                    common::SnowyStream::data_record_wire_len(payload.len())
                } else {
                    BLOCK_PLAINTEXT_SIZE + TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN
                };
                let target_plaintext = target
                    .saturating_sub(TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN)
                    .max(payload.len() + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN)
                    .min(BLOCK_PLAINTEXT_SIZE);
                encrypt_variable_block(
                    server_noise.sender_mut(),
                    &mut wire_tmp,
                    &mut encrypt_buf,
                    payload,
                    target_plaintext,
                )
                .unwrap();
            }
            wire.extend_from_slice(&wire_tmp);

            // 随机分片写入。
            let writer = tokio::spawn(async move {
                let mut server_tcp = server_tcp;
                let mut off = 0usize;
                while off < wire.len() {
                    let (n, do_yield) = {
                        let mut rng = rand::thread_rng();
                        (
                            rng.gen_range(1..=wire.len() - off)
                                .min(rng.gen_range(1..70000))
                                .min(wire.len() - off),
                            rng.gen_bool(0.3),
                        )
                    };
                    tokio::io::AsyncWriteExt::write_all(&mut server_tcp, &wire[off..off + n])
                        .await
                        .unwrap();
                    off += n;
                    if do_yield {
                        tokio::task::yield_now().await;
                    }
                }
                server_tcp
            });

            let mut stream = SnowyStream::new(client_tcp, client_noise);
            let mut got: Vec<u8> = Vec::new();
            let read_future = async {
                while got.len() < expected.len() {
                    let cap = rng.gen_range(1..70000);
                    let mut buf = vec![0u8; cap];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(
                        n > 0,
                        "round {}: spurious EOF at {} bytes",
                        round,
                        got.len()
                    );
                    got.extend_from_slice(&buf[..n]);
                }
                got
            };
            let got = tokio::time::timeout(std::time::Duration::from_secs(10), read_future)
                .await
                .unwrap_or_else(|_| panic!("round {}: read stuck", round));
            assert_eq!(got, expected, "round {}: payload mismatch", round);
            let _server_tcp = writer.await.unwrap();
        }
    }

    /// 建一对真实 socket 上的 SnowyStream。对端 TcpStream 一并返回由调用方
    /// 持有：本测试只走 prepare 不 flush，但半连接必须保持存活。
    async fn connected_stream() -> (SnowyStream, TcpStream) {
        let (_server_noise, client_noise) = build_transport_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_tcp, _) = listener.accept().await.unwrap();
        let client_tcp = connect.await.unwrap();
        (SnowyStream::new(client_tcp, client_noise), server_tcp)
    }

    /// 驱动 `control_state` + `next_control_size` + `prepare_control_record`
    /// 的真实调用序（与 `SessionWriter` 一致），收集前 `n` 条控制记录的目标
    /// 线速尺寸。
    async fn first_control_sizes(direction: FlowDirection, n: usize) -> Vec<usize> {
        let (mut stream, _peer) = connected_stream().await;
        let frame = [0x04u8, 0, 0, 0, 0, 0, 0];
        let mut sizes = Vec::with_capacity(n);
        for _ in 0..n {
            let state = stream.control_state();
            let size = stream.next_control_size(state, direction);
            sizes.push(size);
            stream.prepare_control_record(&frame, size).unwrap();
        }
        sizes
    }

    // C3 回归：走真实 SnowyStream 调用序，开场控制记录的线速尺寸必须逐条
    // 复现确定性的 H2 开场序列（此前是从含 SETTINGS 的加权池独立抽样 6 次，
    // 位置随机、条数恒为 6），且开场之后 SETTINGS 尺寸永不再现。
    #[tokio::test]
    async fn control_records_open_with_the_deterministic_h2_sequence() {
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            let expected: Vec<usize> = (0u64..)
                .map_while(|i| control_size::h2_opening_size(direction, i))
                .collect();
            assert!(!expected.is_empty());

            // 跨「连接」（每次新建 SnowyStream）复现同一序列。
            for _ in 0..8 {
                let sizes = first_control_sizes(direction, expected.len() + 24).await;
                assert_eq!(
                    &sizes[..expected.len()],
                    expected.as_slice(),
                    "{:?} opening sizes drifted between connections",
                    direction
                );
                for &size in &sizes[expected.len()..] {
                    assert!(
                        !control_size::is_settings_bearing_wire_size(size),
                        "{:?} re-emitted a SETTINGS wire size ({}) after the opening",
                        direction,
                        size
                    );
                }
            }
        }
    }
}

/// 无状态传输态 ≡ 有状态传输态。
///
/// 这组断言直接钉死本次重构的两条硬约束：**线上字节不变**与**与旧版对端
/// 互通**。做法是用固定的临时密钥跑两次**完全相同**的握手，一份走
/// `into_transport_mode()`（旧路径），一份走 `into_stateless_transport_mode()`
/// + 外部 nonce（新路径），对同一组明文序列逐条比对密文与解密结果。
///
/// 覆盖的载荷尺寸刻意包含：空载荷、1/2/3 字节、整 record、`BLOCK_PLAINTEXT_SIZE`
/// 边界及其两侧——记录整形层正是靠这些尺寸把线速长度与明文长度解耦的。
#[cfg(test)]
mod stateless_equivalence_tests {
    use super::*;
    use snow::HandshakeState;

    const FIXED_E_INITIATOR: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];
    const FIXED_E_RESPONDER: [u8; 32] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e,
        0x0f, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
        0x22, 0x11,
    ];

    /// 两次调用产出**逐比特相同**的握手结果（临时密钥固定 ⇒ 派生出的
    /// cipherstate key 相同），因此可以把一次的结果交给旧路径、另一次交给
    /// 新路径做等价性比对。
    fn deterministic_handshake() -> (HandshakeState, HandshakeState) {
        let derived_psk = derive_psk(b"stateless-equivalence");
        let mut initiator = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(&FIXED_E_INITIATOR)
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(NOISE_PARAMS.clone())
            .psk(0, &derived_psk)
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(&FIXED_E_RESPONDER)
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 128];
        let n = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..n], &mut []).unwrap();
        let n = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..n], &mut []).unwrap();
        (initiator, responder)
    }

    const EQUIVALENCE_PAYLOAD_LENS: [usize; 15] = [
        0,
        1,
        2,
        3,
        16,
        63,
        100,
        1024,
        4096,
        16380,
        16381,
        16382,
        16383,
        BLOCK_PLAINTEXT_SIZE - 1,
        BLOCK_PLAINTEXT_SIZE,
    ];

    fn payload(i: usize, len: usize) -> Vec<u8> {
        (0..len)
            .map(|j| ((i * 31 + j * 7 + 3) % 251) as u8)
            .collect()
    }

    /// 握手本身在两条路径下派生出**同一份**会话材料——否则「同一次握手」的
    /// 前提不成立，后面的逐字节比对也就没有意义。用两条链路的首条密文相等
    /// 来间接断言（NNpsk0 没有静态密钥可比）。
    #[test]
    fn stateless_transport_matches_stateful_byte_for_byte() {
        let (old_init, old_resp) = deterministic_handshake();
        let (new_init, new_resp) = deterministic_handshake();

        let mut old_send = old_init.into_transport_mode().unwrap();
        let mut old_recv = old_resp.into_transport_mode().unwrap();
        let mut new_send = NoiseTransport::new(new_init.into_stateless_transport_mode().unwrap());
        let mut new_recv = NoiseTransport::new(new_resp.into_stateless_transport_mode().unwrap());

        for (i, &len) in EQUIVALENCE_PAYLOAD_LENS.iter().enumerate() {
            let plaintext = payload(i, len);

            // ---- 加密方向（initiator → responder）----
            let mut old_ct = vec![0u8; len + AEAD_TAG_LEN];
            let mut new_ct = vec![0u8; len + AEAD_TAG_LEN];
            let old_len = old_send.write_message(&plaintext, &mut old_ct).unwrap();
            let new_len = new_send.write_message(&plaintext, &mut new_ct).unwrap();
            assert_eq!(
                old_len, new_len,
                "ciphertext length diverged at message {}",
                i
            );
            assert_eq!(
                old_ct, new_ct,
                "ciphertext bytes diverged at message {} (payload_len={})",
                i, len
            );

            // ---- 解密方向（responder 端）----
            let mut old_pt = vec![0u8; len + AEAD_TAG_LEN];
            let mut new_pt = vec![0u8; len + AEAD_TAG_LEN];
            let old_plain = old_recv
                .read_message(&old_ct[..old_len], &mut old_pt)
                .unwrap();
            let new_plain = new_recv
                .read_message(&new_ct[..new_len], &mut new_pt)
                .unwrap();
            assert_eq!(
                old_plain, new_plain,
                "plaintext length diverged at message {}",
                i
            );
            assert_eq!(&old_pt[..old_plain], &plaintext[..], "old path lost bytes");
            assert_eq!(&new_pt[..new_plain], &plaintext[..], "new path lost bytes");
        }
    }

    /// 反向（responder → initiator）用的是另一个 cipherstate，单独比一遍：
    /// `initiator` 标志在两种传输态里的取用规则必须一致，否则读写会串到
    /// 同一个 cipherstate 上——那要到**第二条**记录才暴露。
    #[test]
    fn stateless_transport_matches_stateful_in_the_reverse_direction() {
        let (old_init, old_resp) = deterministic_handshake();
        let (new_init, new_resp) = deterministic_handshake();

        let mut old_send = old_resp.into_transport_mode().unwrap();
        let mut old_recv = old_init.into_transport_mode().unwrap();
        let mut new_send = NoiseTransport::new(new_resp.into_stateless_transport_mode().unwrap());
        let mut new_recv = NoiseTransport::new(new_init.into_stateless_transport_mode().unwrap());

        for (i, &len) in EQUIVALENCE_PAYLOAD_LENS.iter().enumerate() {
            let plaintext = payload(i, len);
            let mut old_ct = vec![0u8; len + AEAD_TAG_LEN];
            let mut new_ct = vec![0u8; len + AEAD_TAG_LEN];
            let old_len = old_send.write_message(&plaintext, &mut old_ct).unwrap();
            let new_len = new_send.write_message(&plaintext, &mut new_ct).unwrap();
            assert_eq!(old_len, new_len);
            assert_eq!(old_ct, new_ct, "S→C ciphertext diverged at message {}", i);

            let mut old_pt = vec![0u8; len + AEAD_TAG_LEN];
            let mut new_pt = vec![0u8; len + AEAD_TAG_LEN];
            let old_plain = old_recv
                .read_message(&old_ct[..old_len], &mut old_pt)
                .unwrap();
            let new_plain = new_recv
                .read_message(&new_ct[..new_len], &mut new_pt)
                .unwrap();
            assert_eq!(&old_pt[..old_plain], &plaintext[..]);
            assert_eq!(&new_pt[..new_plain], &plaintext[..]);
        }
    }

    /// 整条 0x17 记录（2 字节长度前缀 + 零填充 + inner content type + TLS 头）
    /// 在两条路径下必须逐字节相同——这是「线上字节不变」最直接的表述。
    #[test]
    fn shaped_records_are_byte_identical_across_transport_kinds() {
        let (old_init, _) = deterministic_handshake();
        let (new_init, _) = deterministic_handshake();
        let mut old_noise = old_init.into_transport_mode().unwrap();
        let mut new_noise = NoiseTransport::new(new_init.into_stateless_transport_mode().unwrap());

        let mut old_wire: Vec<u8> = Vec::new();
        let mut new_wire: Vec<u8> = Vec::new();
        let mut old_scratch = Box::new([0u8; BLOCK_PLAINTEXT_SIZE]);
        let mut new_scratch = Box::new([0u8; BLOCK_PLAINTEXT_SIZE]);

        // 混合数据记录与控制记录的目标尺寸，覆盖零填充与满载两端。
        let cases: [(usize, usize); 8] = [
            (0, MIN_DATA_WIRE_LEN),
            (1, 33),
            (7, 300),
            (100, 1400),
            (600, 600 + MIN_DATA_WIRE_LEN),
            (BLOCK_DATA_CAPACITY, SnowyStream::max_data_record_wire_len()),
            (16, SnowyStream::max_data_record_wire_len()),
            (1234, SnowyStream::data_record_wire_len(1234)),
        ];
        for (i, (payload_len, target_wire_len)) in cases.into_iter().enumerate() {
            let pt = payload(i, payload_len);
            let target_plaintext_len = target_wire_len
                .saturating_sub(TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN)
                .max(pt.len() + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN)
                .min(BLOCK_PLAINTEXT_SIZE);

            // 旧路径：把 `encrypt_variable_block` 的 block 组装逐字重放一遍，
            // 只把 noise 调用换回 `TransportState`。
            {
                let block = &mut old_scratch[..target_plaintext_len];
                let pad_start = BLOCK_LEN_PREFIX_SIZE + pt.len();
                let pad_end = target_plaintext_len - 1;
                if pad_end > pad_start {
                    block[pad_start..pad_end].fill(0);
                }
                block[..BLOCK_LEN_PREFIX_SIZE].copy_from_slice(&(pt.len() as u16).to_be_bytes());
                block[BLOCK_LEN_PREFIX_SIZE..BLOCK_LEN_PREFIX_SIZE + pt.len()].copy_from_slice(&pt);
                block[target_plaintext_len - 1] = INNER_CONTENT_TYPE_APP_DATA;
            }
            let ct_len = target_plaintext_len + AEAD_TAG_LEN;
            let current_len = old_wire.len();
            old_wire.resize(current_len + TLS_RECORD_HEADER_LEN + ct_len, 0);
            let actual = old_noise
                .write_message(
                    &old_scratch[..target_plaintext_len],
                    &mut old_wire[current_len + TLS_RECORD_HEADER_LEN..],
                )
                .unwrap();
            old_wire[current_len] = 0x17;
            old_wire[current_len + 1] = 0x03;
            old_wire[current_len + 2] = 0x03;
            old_wire[current_len + 3..current_len + 5]
                .copy_from_slice(&(actual as u16).to_be_bytes());
            old_wire.truncate(current_len + TLS_RECORD_HEADER_LEN + actual);

            // 新路径：生产代码本身。
            encrypt_variable_block(
                new_noise.sender_mut(),
                &mut new_wire,
                &mut new_scratch,
                &pt,
                target_plaintext_len,
            )
            .unwrap();

            assert_eq!(
                old_wire, new_wire,
                "record {} (payload_len={}, target_wire_len={}) diverged on the wire",
                i, payload_len, target_wire_len
            );
        }
    }

    /// 解密失败**不推进**接收 nonce：与 snow `decrypt_ad` 在 `?` 处早退、
    /// 不执行 `n += 1` 一致。若外部计数器在失败时也自增，本端与对端的 nonce
    /// 会永久错位——一条被篡改的记录就能把整条连接毒死，而不是只让当前记录
    /// 失败。
    #[test]
    fn failed_decrypt_does_not_advance_the_receive_nonce() {
        let (init, resp) = deterministic_handshake();
        let mut sender = NoiseTransport::new(init.into_stateless_transport_mode().unwrap());
        let mut receiver = NoiseTransport::new(resp.into_stateless_transport_mode().unwrap());

        let first = b"first record".to_vec();
        let second = b"second record".to_vec();
        let mut ct1 = vec![0u8; first.len() + AEAD_TAG_LEN];
        let mut ct2 = vec![0u8; second.len() + AEAD_TAG_LEN];
        let n1 = sender.write_message(&first, &mut ct1).unwrap();
        let n2 = sender.write_message(&second, &mut ct2).unwrap();

        // 篡改第一条：解密必须失败。
        let mut tampered = ct1[..n1].to_vec();
        tampered[0] ^= 0xff;
        let mut out = vec![0u8; 64];
        assert!(receiver.read_message(&tampered, &mut out).is_err());

        // nonce 未推进 ⇒ 原始的第一条仍能解开，随后第二条也能。
        let m1 = receiver.read_message(&ct1[..n1], &mut out).unwrap();
        assert_eq!(&out[..m1], &first[..]);
        let m2 = receiver.read_message(&ct2[..n2], &mut out).unwrap();
        assert_eq!(&out[..m2], &second[..]);
    }

    /// 加密失败（输出缓冲装不下 AEAD tag ⇒ `Error::Input`）同样不推进发送
    /// nonce：`TransportState::write_message` 在同一处检查早退，`n` 不变。
    #[test]
    fn failed_encrypt_does_not_advance_the_send_nonce() {
        let (old_init, _) = deterministic_handshake();
        let (new_init, _) = deterministic_handshake();
        let mut old = old_init.into_transport_mode().unwrap();
        let mut new = NoiseTransport::new(new_init.into_stateless_transport_mode().unwrap());

        let pt = b"payload".to_vec();
        let mut too_small = vec![0u8; pt.len()]; // 少了 AEAD tag 的空间
        assert!(old.write_message(&pt, &mut too_small).is_err());
        assert!(new.write_message(&pt, &mut too_small).is_err());

        let mut a = vec![0u8; pt.len() + AEAD_TAG_LEN];
        let mut b = vec![0u8; pt.len() + AEAD_TAG_LEN];
        let na = old.write_message(&pt, &mut a).unwrap();
        let nb = new.write_message(&pt, &mut b).unwrap();
        assert_eq!(na, nb);
        assert_eq!(a, b, "失败的加密尝试让两条路径的 nonce 走岔了");
    }
}
