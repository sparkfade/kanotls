use crate::PoolSession;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct PooledConnection<S: PoolSession> {
    pub(crate) seq: u64,
    pub(crate) handle: Arc<S>,
    pub(crate) state: AtomicU8,
    pub(crate) soft_ttl: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) created_at: Instant,
    pub(crate) last_selected_tick: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    Active,
    Draining,
    Closed,
}

impl ConnectionState {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Draining => 1,
            Self::Closed => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Draining,
            _ => Self::Closed,
        }
    }
}

impl<S: PoolSession> PooledConnection<S> {
    pub(crate) fn score(
        &self,
        active_streams: usize,
        buffered_stream_bytes: usize,
    ) -> ConnectionScore {
        ConnectionScore {
            active_streams,
            buffered_stream_bytes,
            last_selected_tick: self.last_selected_tick.load(Ordering::Relaxed),
            created_at: self.created_at,
            seq: self.seq,
        }
    }

    pub(crate) fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
    }

    pub(crate) fn mark_selected(&self, tick: u64) {
        self.last_selected_tick.store(tick, Ordering::Relaxed);
    }

    pub(crate) fn mark_draining(&self) -> bool {
        self.state
            .compare_exchange(
                ConnectionState::Active.as_u8(),
                ConnectionState::Draining.as_u8(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    pub(crate) fn mark_closed(&self) -> bool {
        let previous = self
            .state
            .swap(ConnectionState::Closed.as_u8(), Ordering::Relaxed);
        previous != ConnectionState::Closed.as_u8()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConnectionScore {
    active_streams: usize,
    buffered_stream_bytes: usize,
    last_selected_tick: u64,
    created_at: Instant,
    seq: u64,
}
