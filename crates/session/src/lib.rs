pub mod client_pool;
pub mod frame;
pub mod server;
pub mod session;
pub mod shaper;
pub mod stream;

pub const RELAY_CHUNK_SIZE: usize = 64 * 1024;

/// 写循环 bulk 积压的立即冲刷阈值：pending 达到此量级即绕过懒冲刷，
/// 整批交给 shaper。session 与 shaper 共用同一份定义。
pub(crate) const MAX_PENDING_FLUSH_SIZE: usize = 256 * 1024;

pub use client_pool::{ClientPool, ClientPoolConnectOptions, PoolBehaviorConfig};
pub use session::{Session, SessionConfig};
pub use stream::Stream;

#[cfg(test)]
mod tests {
    use super::*;

    const _RELAY_CHUNK_SIZE_CHECK: () = assert!(RELAY_CHUNK_SIZE <= 2 * frame::MAX_PAYLOAD_LEN);
}
