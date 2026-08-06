pub mod frame;
pub mod server;
pub mod session;
pub mod shaper;
pub mod stream;

/// 中继单次读取的上限，与单帧载荷上限对齐。
///
/// 取 64 KiB 时比 `MAX_PAYLOAD_LEN`（65535）多 1 字节，于是每一次读满的
/// 中继都会被 `encode_psh_frames` 切成 [65535, 1] 两帧——多一次分配、多一
/// 个 7 字节帧头承载 1 字节载荷，并且把本可整帧发出的数据拆散。对齐后
/// 读满即恰好一帧。
pub const RELAY_CHUNK_SIZE: usize = frame::MAX_PAYLOAD_LEN;

/// bulk 积压的尺寸基准：shaper 以此度量积压量级，决定记录按精确尺寸
/// 整批切分（bulk fast path）还是按采样尺寸逐条整形发出。
pub(crate) const MAX_PENDING_FLUSH_SIZE: usize = 256 * 1024;

pub use session::{Session, SessionConfig};
pub use stream::{Stream, StreamReadHalf, StreamWriteHalf, PEER_NEVER_PROCESSED_ERROR};

#[cfg(test)]
mod tests {
    use super::*;

    const _RELAY_CHUNK_SIZE_CHECK: () = assert!(RELAY_CHUNK_SIZE <= 2 * frame::MAX_PAYLOAD_LEN);
}
