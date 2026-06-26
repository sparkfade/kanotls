use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::utils::{derive_counter_cache_key, derive_counter_mask, xor_u64_bytes};

pub(super) const MAX_COUNTER_CACHE_ENTRIES: usize = 4096;
pub(super) const REPLAY_RETENTION_SECS: u64 = 600;
pub(super) const MAX_REPLAY_CACHE_ENTRIES: usize = 65536;

#[derive(Clone, Copy, Debug)]
pub(super) struct SlidingWindow {
    highest_seq: u64,
    bitmap: u64,
}

impl SlidingWindow {
    fn new(seq: u64) -> Self {
        SlidingWindow {
            highest_seq: seq,
            bitmap: 1u64,
        }
    }

    fn check(&self, seq: u64) -> bool {
        if seq > self.highest_seq {
            return true;
        }
        if self.highest_seq - seq >= 64 {
            return false;
        }
        let offset = self.highest_seq - seq;
        (self.bitmap & (1u64 << offset)) == 0
    }

    fn commit(&mut self, seq: u64) -> bool {
        if seq > self.highest_seq {
            let diff = seq - self.highest_seq;
            if diff >= 64 {
                self.bitmap = 1u64;
            } else {
                self.bitmap = (self.bitmap << diff) | 1u64;
            }
            self.highest_seq = seq;
            true
        } else if self.highest_seq - seq >= 64 {
            false
        } else {
            let offset = self.highest_seq - seq;
            let bit = 1u64 << offset;
            if (self.bitmap & bit) != 0 {
                false
            } else {
                self.bitmap |= bit;
                true
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ReplayCheck {
    cache_key: [u8; 16],
    sequence: u64,
}

lazy_static::lazy_static! {
    pub(super) static ref REPLAY_CACHE: std::sync::Mutex<LruCache<[u8; 32], Instant>> =
        std::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_REPLAY_CACHE_ENTRIES).expect("non-zero replay cache size")
        ));
    pub(super) static ref COUNTER_CACHE: std::sync::Mutex<LruCache<[u8; 16], SlidingWindow>> =
        std::sync::Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_COUNTER_CACHE_ENTRIES)
                .expect("non-zero counter cache size")
        ));
}

pub(super) fn check_counter_replay(
    derived_psk: &[u8],
    random_copy: &[u8; 32],
    masked_counter: [u8; 8],
) -> Option<ReplayCheck> {
    let mask = derive_counter_mask(derived_psk, random_copy);
    let raw_counter = u64::from_be_bytes(xor_u64_bytes(masked_counter, mask));

    let session_id = raw_counter >> 24;
    let sequence = raw_counter & 0x00FF_FFFF;

    let mut key_material = derived_psk.to_vec();
    key_material.extend_from_slice(&session_id.to_be_bytes());
    let cache_key = derive_counter_cache_key(&key_material);

    match COUNTER_CACHE.lock() {
        Ok(mut cache) => {
            if let Some(window) = cache.get(&cache_key) {
                if !window.check(sequence) {
                    debug!(
                        "counter replay or out-of-window for session 0x{:X}: seq {}",
                        session_id, sequence
                    );
                    return None;
                }
            }
            Some(ReplayCheck {
                cache_key,
                sequence,
            })
        }
        Err(_) => {
            warn!("counter cache mutex poisoned during check, rejecting");
            None
        }
    }
}

pub(super) fn commit_counter_replay(check: &ReplayCheck) -> bool {
    match COUNTER_CACHE.lock() {
        Ok(mut cache) => {
            if let Some(window) = cache.get_mut(&check.cache_key) {
                if !window.commit(check.sequence) {
                    debug!(
                        "counter commit rejected for key {:?}: seq {} already consumed",
                        check.cache_key, check.sequence
                    );
                    return false;
                }
            } else {
                cache.put(check.cache_key, SlidingWindow::new(check.sequence));
            }
            true
        }
        Err(_) => {
            warn!("counter cache mutex poisoned during commit, rejecting");
            false
        }
    }
}

pub(super) fn is_replay(client_ephemeral: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(client_ephemeral) else {
        return true;
    };
    let Ok(mut cache) = REPLAY_CACHE.lock() else {
        warn!("replay cache mutex poisoned, rejecting handshake fail-closed");
        return true;
    };
    let now = Instant::now();
    while let Some((_, seen_at)) = cache.peek_lru() {
        if now.duration_since(*seen_at) <= Duration::from_secs(REPLAY_RETENTION_SECS) {
            break;
        }
        cache.pop_lru();
    }
    if cache.contains(&key) {
        true
    } else {
        cache.put(key, now);
        false
    }
}
