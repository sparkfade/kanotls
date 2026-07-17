use bytes::{Buf, BytesMut};
use lazy_static::lazy_static;
use snow::params::NoiseParams;
use snow::TransportState;
use std::cmp;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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

pub fn apply_tcp_keepalive(tcp: &TcpStream) -> io::Result<()> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let idle_base = 60u64;
    let interval_base = 30u64;
    let idle = Duration::from_secs(idle_base + rng.gen_range(0..=6));
    let interval = Duration::from_secs(interval_base + rng.gen_range(0..=3));
    let sock_ref = socket2::SockRef::from(tcp);
    let mut keepalive = socket2::TcpKeepalive::new()
        .with_time(idle)
        .with_interval(interval);
    #[cfg(target_os = "linux")]
    {
        keepalive = keepalive.with_retries(3 + rng.gen_range(0..=1));
    }
    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        warn!(
            "failed to apply kernel TCP Keep-Alive: {}. Long connections may drop.",
            e
        );
    }
    Ok(())
}

pub struct SnowyStream {
    socket: TcpStream,
    noise: TransportState,
    state: StreamState,
    close_notify_written: bool,
    read_buf_inner: Vec<u8>,
    read_offset: usize,
    write_buffer: Vec<u8>,
    write_offset: usize,
    tls_rx_buf: BytesMut,
    tls_rx_offset: usize,
    io_buf: Box<[u8; MAX_TLS_RECORD_PAYLOAD_LEN]>,
    decrypt_buf: Box<[u8; MAX_TLS_RECORD_PAYLOAD_LEN]>,
    encrypt_buf: Box<[u8; BLOCK_PLAINTEXT_SIZE]>,
    control_frame_count: u64,
    _permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug, PartialEq)]
enum StreamState {
    Open,
    Closed,
}

impl StreamState {
    fn readable(&self) -> bool {
        matches!(self, Self::Open)
    }
    fn writable(&self) -> bool {
        matches!(self, Self::Open)
    }
}

impl SnowyStream {
    pub fn new(socket: TcpStream, noise: TransportState) -> Self {
        Self::new_with_permit(socket, noise, None)
    }

    pub fn new_with_permit(
        socket: TcpStream,
        noise: TransportState,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        SnowyStream {
            socket,
            noise,
            state: StreamState::Open,
            close_notify_written: false,
            read_buf_inner: Vec::with_capacity(BLOCK_DATA_CAPACITY),
            read_offset: 0,
            write_buffer: Vec::with_capacity(
                TLS_RECORD_HEADER_LEN + BLOCK_PLAINTEXT_SIZE + AEAD_TAG_LEN,
            ),
            write_offset: 0,
            tls_rx_buf: BytesMut::with_capacity(MAX_TLS_RECORD_PAYLOAD_LEN + TLS_RECORD_HEADER_LEN),
            tls_rx_offset: 0,
            io_buf: Box::new([0u8; MAX_TLS_RECORD_PAYLOAD_LEN]),
            decrypt_buf: Box::new([0u8; MAX_TLS_RECORD_PAYLOAD_LEN]),
            encrypt_buf: Box::new([0u8; BLOCK_PLAINTEXT_SIZE]),
            control_frame_count: 0,
            _permit: permit,
        }
    }

    pub fn control_state(&self) -> ConnectionState {
        ConnectionState::from_control_count(self.control_frame_count)
    }

    pub fn next_control_size(&mut self, state: ConnectionState, direction: FlowDirection) -> usize {
        control_size::next_control_size(state, direction, &mut rand::thread_rng())
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
            PadFill::Zero,
        )
    }

    /// Encrypt exactly one 0x17 application-data record whose on-wire size is
    /// strictly `target_wire_len` (clamped to the valid record range), padded
    /// with high-entropy noise-pool bytes. This is the single sizing-controlled
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
            PadFill::Entropy,
        )
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
        frame_type, length, total
    );
    Ok(Some((total, frame_type)))
}

impl AsyncRead for SnowyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.state.readable() {
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
                                    this.state = StreamState::Closed;
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
                                if len >= BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN {
                                    let data_len = u16::from_be_bytes([
                                        this.decrypt_buf[0],
                                        this.decrypt_buf[1],
                                    ]) as usize;
                                    let data_len = data_len
                                        .min(len - BLOCK_LEN_PREFIX_SIZE - INNER_CONTENT_TYPE_LEN);
                                    this.read_buf_inner.extend_from_slice(
                                        &this.decrypt_buf[BLOCK_LEN_PREFIX_SIZE
                                            ..BLOCK_LEN_PREFIX_SIZE + data_len],
                                    );
                                } else if len > 0 {
                                    this.read_buf_inner
                                        .extend_from_slice(&this.decrypt_buf[..len]);
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
                                this.close_notify_written = true;
                                this.state = StreamState::Closed;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("noise decrypt: {}", e),
                                )));
                            }
                        }
                    } else if frame_type == 0x15 {
                        this.state = StreamState::Closed;
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
                        this.state = StreamState::Closed;
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

impl AsyncWrite for SnowyStream {
    /// The bulk AsyncWrite path is permanently sealed. The shaped session
    /// writer drives `prepare_data_record` / `prepare_control_record` via
    /// `with_stream`; no autonomous chunking or encryption is performed
    /// through this trait. Any attempt to write bulk data through
    /// `poll_write` returns `Unsupported` to guarantee that no bytes
    /// bypass the TrafficShaper and re-introduce passive-size fingerprints.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.state.writable() {
            return Poll::Ready(Ok(0));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "bulk AsyncWrite path retired; use prepare_data_record / prepare_control_record via with_stream",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        try_flush_write_buffer(this, cx)?;

        if !this.write_buffer.is_empty() {
            return Poll::Pending;
        }

        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures::ready;

        ready!(self.as_mut().poll_flush(cx))?;

        {
            let this = self.as_mut().get_mut();

            if !this.close_notify_written && this.state.writable() {
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
                this.close_notify_written = true;
                this.state = StreamState::Closed;
            }
        }

        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

fn try_flush_write_buffer(stream: &mut SnowyStream, cx: &mut Context<'_>) -> io::Result<()> {
    while stream.write_offset < stream.write_buffer.len() {
        match Pin::new(&mut stream.socket)
            .poll_write(cx, &stream.write_buffer[stream.write_offset..])
        {
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
                }
                stream.write_offset += n;
            }
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => return Ok(()),
        }
    }

    stream.write_offset = 0;
    stream.write_buffer.clear();
    Ok(())
}

/// Source of the padding bytes that fill the gap between the real payload and
/// the caller-requested record size.
#[derive(Clone, Copy, Debug)]
pub enum PadFill {
    /// Zero-fill (used by the control path, which is already size-shaped).
    Zero,
    /// Fill from the shared cryptographically isomorphic high-entropy noise
    /// pool. Bytes are statistically indistinguishable from real AEAD
    /// ciphertext, so padded records leak no structure.
    Entropy,
}

/// Minimum on-wire size of a shaped 0x17 data record carrying zero payload
/// bytes (2-byte length prefix + 1-byte inner content type).
pub const MIN_DATA_WIRE_LEN: usize =
    TLS_RECORD_HEADER_LEN + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN + AEAD_TAG_LEN;

fn encrypt_variable_block(
    noise: &mut TransportState,
    write_buffer: &mut Vec<u8>,
    encrypt_buf: &mut Box<[u8; BLOCK_PLAINTEXT_SIZE]>,
    payload: &[u8],
    target_plaintext_len: usize,
    pad_fill: PadFill,
) -> io::Result<()> {
    assert!(target_plaintext_len >= payload.len() + BLOCK_LEN_PREFIX_SIZE + INNER_CONTENT_TYPE_LEN);
    assert!(target_plaintext_len <= BLOCK_PLAINTEXT_SIZE);

    {
        let block = &mut encrypt_buf[..target_plaintext_len];
        let pad_start = BLOCK_LEN_PREFIX_SIZE + payload.len();
        let pad_end = target_plaintext_len - 1;
        if pad_end > pad_start {
            match pad_fill {
                PadFill::Zero => block[pad_start..pad_end].fill(0),
                PadFill::Entropy => crate::entropy::fill_from_pool(&mut block[pad_start..pad_end]),
            }
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
