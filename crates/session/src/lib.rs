pub mod client_pool;
pub mod frame;
pub mod server;
pub mod session;
pub mod shaper;
pub mod stream;

pub const RELAY_CHUNK_SIZE: usize = 64 * 1024;

/// bulk 积压的尺寸基准：shaper 以此度量积压量级，决定记录按精确尺寸
/// 整批切分（bulk fast path）还是按采样尺寸逐条整形发出。
pub(crate) const MAX_PENDING_FLUSH_SIZE: usize = 256 * 1024;

pub use client_pool::{ClientPool, ClientPoolConnectOptions, PoolBehaviorConfig};
pub use session::{Session, SessionConfig};
pub use stream::Stream;

#[cfg(test)]
mod tests {
    use super::*;

    const _RELAY_CHUNK_SIZE_CHECK: () = assert!(RELAY_CHUNK_SIZE <= 2 * frame::MAX_PAYLOAD_LEN);
}
