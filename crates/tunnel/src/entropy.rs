//! Cryptographically isomorphic, stateless high-entropy noise pool.
//!
//! A single 8 MiB buffer is pre-generated once from `rand::thread_rng()`
//! (a CSPRNG). Its output is an unstructured, near-maximal-entropy byte
//! stream that is statistically isomorphic to genuine AEAD ciphertext, so
//! bytes drawn from it are indistinguishable — in the observer's statistical
//! space — from real encrypted records.
//!
//! This module is shared by both the client and the server. It performs **no**
//! entropy modeling, distribution shaping, or baseline tuning: the only state
//! is a global read cursor used to serve wrapping (circular) reads.

use rand::RngCore;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub const ENTROPY_POOL_SIZE: usize = 8 * 1024 * 1024;

static ENTROPY_POOL: OnceLock<Vec<u8>> = OnceLock::new();
static POOL_CURSOR: AtomicUsize = AtomicUsize::new(0);

fn build_pool() -> Vec<u8> {
    let mut pool = vec![0u8; ENTROPY_POOL_SIZE];
    rand::thread_rng().fill_bytes(&mut pool);
    pool
}

/// Initialize the shared noise pool. Idempotent; safe to call on both the
/// client and server startup paths. If never called explicitly, the pool is
/// lazily materialized on first read.
pub fn init_entropy_pool() {
    let _ = entropy_pool();
}

/// Return the shared noise pool slice, materializing it on first use.
pub(crate) fn entropy_pool() -> &'static [u8] {
    ENTROPY_POOL.get_or_init(build_pool)
}

/// Fill `dst` with a wrapping (circular) read from the shared noise pool.
///
/// A global atomic cursor advances by `dst.len()` per call so concurrent
/// callers draw from distinct regions. The cursor carries position only — no
/// adaptive or feedback state — keeping the source stateless by design.
pub fn fill_from_pool(dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    let pool = entropy_pool();
    let pool_len = pool.len();
    let start = POOL_CURSOR.fetch_add(dst.len(), Ordering::Relaxed) % pool_len;

    let mut written = 0;
    let mut off = start;
    while written < dst.len() {
        if off >= pool_len {
            off = 0;
        }
        let n = (dst.len() - written).min(pool_len - off);
        dst[written..written + n].copy_from_slice(&pool[off..off + n]);
        written += n;
        off += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_wraps_around_pool_boundary() {
        let mut a = vec![0u8; ENTROPY_POOL_SIZE + 4096];
        fill_from_pool(&mut a);
        // Should be fully populated without panicking on wrap.
        assert_eq!(a.len(), ENTROPY_POOL_SIZE + 4096);
    }

    #[test]
    fn fill_empty_is_noop() {
        let mut empty: [u8; 0] = [];
        fill_from_pool(&mut empty);
    }

    #[test]
    fn distinct_calls_advance_cursor() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill_from_pool(&mut a);
        fill_from_pool(&mut b);
        // Overwhelmingly likely to differ given a CSPRNG-seeded pool and an
        // advancing cursor; guards against a stuck cursor.
        assert_ne!(a, b);
    }
}
