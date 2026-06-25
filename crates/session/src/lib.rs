pub mod client_pool;
pub mod frame;
pub mod server;
pub mod session;
pub mod stream;

pub const RELAY_CHUNK_SIZE: usize = 64 * 1024;

pub use client_pool::{ClientPool, ClientPoolConnectOptions, PoolBehaviorConfig};
pub use session::{Session, SessionConfig};
pub use stream::Stream;

#[cfg(test)]
mod tests {
    use super::*;

    const _RELAY_CHUNK_SIZE_CHECK: () =
        assert!(RELAY_CHUNK_SIZE <= 2 * frame::MAX_PAYLOAD_LEN);

    #[test]
    fn relay_chunk_size_fits_protocol_frame_limit() {
    }
}
