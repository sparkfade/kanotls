use crate::session::{Session, SessionConfig};
use crate::stream::Stream;
use futures::future::BoxFuture;
use futures::FutureExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

const MIN_INITIAL_CONNECTIONS: usize = 1;
const MAX_INITIAL_CONNECTIONS: usize = 3;
const DEFAULT_MIN_ACTIVE_CONNECTIONS: usize = 4;
const IDLE_DRAIN_SECS: u64 = 30;
const DEFAULT_MONITOR_INTERVAL_MS: u64 = 500;
const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 15;
const TIME_OF_DAY_BUCKET_SECS: u64 = 4 * 60 * 60;
const MIN_STREAMS_PER_CONNECTION_TARGET: usize = 8;
const MAX_STREAMS_PER_CONNECTION_TARGET: usize = 64;

#[derive(Clone)]
pub struct ClientPoolConnectOptions {
    pub server_addr: String,
    pub sni: String,
    pub psk: Vec<u8>,
    pub insecure: bool,
    pub fingerprint: Option<String>,
    pub custom_template_bytes: Arc<RwLock<Option<Vec<u8>>>>,
}

pub struct ClientPool<C: TunnelConnector = DefaultConnector> {
    inner: Arc<PoolInner<C>>,
}

pub type DefaultClientPool = ClientPool<DefaultConnector>;

#[derive(Clone)]
struct PoolBehaviorContext {
    fingerprint_family: String,
    sni: String,
    startup_epoch_secs: u64,
    time_of_day_bucket: u64,
    random_nonce: u64,
}

#[derive(Clone)]
struct ResolvedPoolBehavior {
    seed: u64,
    target_pool_size: usize,
    initial_connection_count: usize,
    min_active_connections: usize,
    spawn_cluster_len: u64,
}

#[derive(Clone)]
pub struct PoolBehaviorConfig {
    min_target_pool_size: usize,
    max_target_pool_size: usize,
    min_initial_connections: usize,
    max_initial_connections: usize,
    min_active_connections: usize,
    min_startup_jitter_ms: u64,
    max_startup_jitter_ms: u64,
    soft_ttl_secs: u64,
    idle_drain_secs: u64,
    monitor_interval: Duration,
    acquire_timeout: Duration,
}

impl PoolBehaviorConfig {
    pub fn from_psk(psk: &[u8], install_salt: &[u8]) -> Self {
        let h = hash_bytes(0x1337_BEEF, psk);
        let h = hash_bytes(h, install_salt);
        let min_target = seeded_usize_inclusive(h, 4, 8);
        let max_target = seeded_usize_inclusive(h ^ 0x01, min_target + 2, 16);
        let min_jitter = seeded_u64_inclusive(h ^ 0x02, 50, 300);
        let max_jitter = seeded_u64_inclusive(h ^ 0x03, min_jitter + 300, 2500);
        let soft_ttl = seeded_u64_inclusive(h ^ 0x04, 120, 300);
        Self {
            min_target_pool_size: min_target,
            max_target_pool_size: max_target,
            min_initial_connections: MIN_INITIAL_CONNECTIONS,
            max_initial_connections: MAX_INITIAL_CONNECTIONS,
            min_active_connections: DEFAULT_MIN_ACTIVE_CONNECTIONS,
            min_startup_jitter_ms: min_jitter,
            max_startup_jitter_ms: max_jitter,
            soft_ttl_secs: soft_ttl,
            idle_drain_secs: IDLE_DRAIN_SECS,
            monitor_interval: Duration::from_millis(DEFAULT_MONITOR_INTERVAL_MS),
            acquire_timeout: Duration::from_secs(DEFAULT_ACQUIRE_TIMEOUT_SECS),
        }
    }
    fn resolve(&self, context: &PoolBehaviorContext) -> ResolvedPoolBehavior {
        let seed = context.seed();
        let target_pool_size = seeded_usize_inclusive(
            derive_seed(seed, 0x10),
            self.min_target_pool_size,
            self.max_target_pool_size,
        );
        let initial_connection_count = seeded_usize_inclusive(
            derive_seed(seed, 0x11),
            self.min_initial_connections.min(target_pool_size.max(1)),
            self.max_initial_connections.min(target_pool_size.max(1)),
        );

        ResolvedPoolBehavior {
            seed,
            target_pool_size,
            initial_connection_count,
            min_active_connections: self.min_active_connections(target_pool_size),
            spawn_cluster_len: seeded_u64_inclusive(derive_seed(seed, 0x14), 2, 4),
        }
    }

    fn min_active_connections(&self, target_pool_size: usize) -> usize {
        self.min_active_connections.min(target_pool_size.max(1))
    }

    fn lifecycle(&self, _behavior: &ResolvedPoolBehavior, _seq: u64) -> PoolLifecycle {
        PoolLifecycle {
            soft_ttl: Duration::from_secs(self.soft_ttl_secs),
            idle_timeout: Duration::from_secs(self.idle_drain_secs),
        }
    }

    fn staggered_delays(
        &self,
        behavior: &ResolvedPoolBehavior,
        start_slot: u64,
        count: usize,
    ) -> Vec<Duration> {
        let mut delays = Vec::with_capacity(count);
        let mut total_ms = 0u64;
        let burst_gap_max = self
            .min_startup_jitter_ms
            .saturating_add(self.max_startup_jitter_ms)
            .saturating_div(2)
            .max(self.min_startup_jitter_ms);
        for idx in 0..count {
            let slot = start_slot + idx as u64;
            let gap_seed = derive_seed(behavior.seed ^ slot.rotate_left(11), 0x30);
            let gap_ms = if (slot + 1).is_multiple_of(behavior.spawn_cluster_len) {
                seeded_u64_inclusive(gap_seed, burst_gap_max, self.max_startup_jitter_ms)
            } else {
                seeded_u64_inclusive(gap_seed, self.min_startup_jitter_ms, burst_gap_max)
            };
            total_ms = total_ms.saturating_add(gap_ms);
            delays.push(Duration::from_millis(total_ms));
        }
        delays
    }
}

struct PoolLifecycle {
    soft_ttl: Duration,
    idle_timeout: Duration,
}

pub trait TunnelConnector: Send + Sync + 'static {
    type Session: PoolSession;

    fn connect(&self) -> BoxFuture<'_, Result<Arc<Self::Session>, anyhow::Error>>;
}

struct PoolInner<C: TunnelConnector> {
    session_config: SessionConfig,
    behavior: PoolBehaviorConfig,
    resolved_behavior: ResolvedPoolBehavior,
    connector: Arc<C>,
    connections: RwLock<HashMap<u64, Arc<PooledConnection<C::Session>>>>,
    next_seq: AtomicU64,
    target_pool_size: usize,
    max_live_connections: usize,
    initial_connection_count: usize,
    min_active_connections: usize,
    bootstrap_started: AtomicBool,
    acquire_waiters: AtomicUsize,
    next_spawn_slot: AtomicU64,
    pending_spawns: AtomicUsize,
    selection_tick: AtomicU64,
    spawn_lock: Mutex<()>,
    connection_ready: Notify,
    monitor_notify: Notify,
}

struct AcquireWaiterGuard<'a> {
    counter: &'a AtomicUsize,
}

struct PooledConnection<S: PoolSession> {
    seq: u64,
    handle: Arc<S>,
    state: AtomicU8,
    soft_ttl: Duration,
    idle_timeout: Duration,
    created_at: Instant,
    last_selected_tick: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    Active,
    Draining,
    Closed,
}

impl ConnectionState {
    fn as_u8(self) -> u8 {
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

pub trait PoolSession: Send + Sync {
    fn open_stream(&self) -> BoxFuture<'_, Result<Stream, anyhow::Error>>;
    fn active_streams(&self) -> BoxFuture<'_, usize>;
    fn buffered_stream_bytes(&self) -> usize;
    fn is_alive(&self) -> bool;
    fn is_closing(&self) -> bool;
    fn force_close(&self);
}

pub struct DefaultConnector {
    session_config: SessionConfig,
    connect_options: ClientPoolConnectOptions,
}

pub struct LivePoolSession {
    session: Arc<Session>,
}

impl<C: TunnelConnector> ClientPool<C> {
    pub async fn open_stream(&self) -> Result<Stream, anyhow::Error> {
        self.inner.open_stream().await
    }

    #[cfg(test)]
    async fn snapshot(&self) -> TestPoolSnapshot {
        self.inner.test_snapshot().await
    }

    #[cfg(test)]
    async fn spawn_connections_for_test(&self, count: usize, staggered: bool) {
        self.inner.bootstrap_started.store(true, Ordering::Relaxed);
        self.inner.schedule_spawns(count, staggered).await;
    }

    fn new_impl(
        session_config: SessionConfig,
        behavior: PoolBehaviorConfig,
        behavior_context: PoolBehaviorContext,
        connector: Arc<C>,
    ) -> Self {
        let resolved_behavior = behavior.resolve(&behavior_context);
        let max_live_connections = resolved_behavior
            .target_pool_size
            .saturating_add(resolved_behavior.initial_connection_count.max(1));
        let inner = Arc::new(PoolInner {
            session_config,
            behavior,
            resolved_behavior: resolved_behavior.clone(),
            connector,
            connections: RwLock::new(HashMap::new()),
            next_seq: AtomicU64::new(1),
            target_pool_size: resolved_behavior.target_pool_size,
            max_live_connections,
            initial_connection_count: resolved_behavior.initial_connection_count,
            min_active_connections: resolved_behavior.min_active_connections,
            bootstrap_started: AtomicBool::new(false),
            acquire_waiters: AtomicUsize::new(0),
            next_spawn_slot: AtomicU64::new(0),
            pending_spawns: AtomicUsize::new(0),
            selection_tick: AtomicU64::new(0),
            spawn_lock: Mutex::new(()),
            connection_ready: Notify::new(),
            monitor_notify: Notify::new(),
        });

        tokio::spawn(inner.clone().run_monitor());

        Self { inner }
    }
}

impl ClientPool<DefaultConnector> {
    pub fn new(
        session_config: SessionConfig,
        connect_options: ClientPoolConnectOptions,
        behavior: PoolBehaviorConfig,
    ) -> Self {
        Self::new_impl(
            session_config.clone(),
            behavior,
            PoolBehaviorContext::from_connect_options(&connect_options),
            Arc::new(DefaultConnector {
                session_config,
                connect_options,
            }),
        )
    }
}

impl<C: TunnelConnector> PoolInner<C> {
    async fn open_stream(self: &Arc<Self>) -> Result<Stream, anyhow::Error> {
        self.acquire_waiters.fetch_add(1, Ordering::Relaxed);
        let _waiter_guard = AcquireWaiterGuard {
            counter: &self.acquire_waiters,
        };
        self.ensure_started().await;

        let deadline = Instant::now() + self.behavior.acquire_timeout;
        async {
            loop {
                if let Some(connection) = self.select_active_connection().await {
                    match connection.handle.open_stream().await {
                        Ok(stream) => {
                            self.monitor_notify.notify_waiters();
                            return Ok(stream);
                        }
                        Err(err) => {
                            debug!(
                                "open_stream failed on pooled connection seq={}: {}",
                                connection.seq, err
                            );
                            if !connection.handle.is_alive() || connection.handle.is_closing() {
                                self.force_close_connection(connection.seq, "open stream failure")
                                    .await;
                            } else if connection.state() == ConnectionState::Active {
                                self.monitor_notify.notify_waiters();
                            }
                        }
                    }
                }

                self.schedule_replenishment_if_needed().await;

                let now = Instant::now();
                if now >= deadline {
                    anyhow::bail!("timed out waiting for an active tunnel connection");
                }

                let wait_for = (deadline - now).min(self.behavior.monitor_interval);
                tokio::select! {
                    _ = self.connection_ready.notified() => {}
                    _ = self.monitor_notify.notified() => {}
                    _ = tokio::time::sleep(wait_for) => {}
                }
            }
        }
        .await
    }

    async fn ensure_started(self: &Arc<Self>) {
        if self
            .bootstrap_started
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            debug!(
                target_pool_size = self.target_pool_size,
                max_live_connections = self.max_live_connections,
                initial_connection_count = self.initial_connection_count,
                min_active_connections = self.min_active_connections,
                "starting browser-mimicking tunnel pool"
            );
        }

        self.schedule_replenishment_if_needed().await;
    }

    async fn schedule_replenishment_if_needed(self: &Arc<Self>) {
        if !self.bootstrap_started.load(Ordering::Relaxed) {
            return;
        }

        let _spawn_guard = self.spawn_lock.lock().await;
        let entries = self.connection_entries().await;
        let mut active = 0usize;
        let mut live = 0usize;
        let mut busy = 0usize;
        let mut total_active_streams = 0usize;

        for entry in entries {
            if entry.state() == ConnectionState::Closed || !entry.handle.is_alive() {
                continue;
            }

            live += 1;

            if entry.handle.is_closing() {
                continue;
            }

            let active_streams = entry.handle.active_streams().await;
            total_active_streams = total_active_streams.saturating_add(active_streams);

            if active_streams > 0 {
                busy += 1;
            }

            if entry.state() == ConnectionState::Active {
                active += 1;
            }
        }

        let pending = self.pending_spawns.load(Ordering::Relaxed);
        let waiters = self.acquire_waiters.load(Ordering::Relaxed);
        let desired_active =
            self.desired_active_connection_count(waiters, active, busy, total_active_streams);

        if desired_active == 0 {
            return;
        }

        if active + pending >= desired_active {
            return;
        }

        let missing_active = desired_active.saturating_sub(active + pending);
        let missing_live = self.max_live_connections.saturating_sub(live + pending);
        let missing = missing_active.min(missing_live);
        if missing > 0 {
            debug!(
                active_connections = active,
                busy_connections = busy,
                total_active_streams,
                live_connections = live,
                pending_spawns = pending,
                acquire_waiters = waiters,
                desired_active_connections = desired_active,
                target_pool_size = self.target_pool_size,
                "replenishing pooled tunnel connections"
            );
            if live + pending == 0 {
                let immediate = missing.min(self.initial_connection_count.max(1));
                self.schedule_spawns_locked(immediate, false).await;
                let delayed = missing.saturating_sub(immediate);
                if delayed > 0 {
                    self.schedule_spawns_locked(delayed, true).await;
                }
            } else {
                self.schedule_spawns_locked(missing, true).await;
            }
        }
    }

    #[cfg(test)]
    async fn schedule_spawns(self: &Arc<Self>, count: usize, staggered: bool) {
        let _spawn_guard = self.spawn_lock.lock().await;
        self.schedule_spawns_locked(count, staggered).await;
    }

    async fn schedule_spawns_locked(self: &Arc<Self>, count: usize, staggered: bool) {
        if count == 0 {
            return;
        }

        let live = self.live_connection_count().await;
        let pending = self.pending_spawns.load(Ordering::Relaxed);
        let capacity = self.max_live_connections.saturating_sub(live + pending);
        let count = count.min(capacity);
        if count == 0 {
            return;
        }

        let delays = if staggered {
            let start_slot = self
                .next_spawn_slot
                .fetch_add(count as u64, Ordering::Relaxed);
            self.behavior
                .staggered_delays(&self.resolved_behavior, start_slot, count)
        } else {
            vec![Duration::ZERO; count]
        };

        for delay in delays {
            self.pending_spawns.fetch_add(1, Ordering::Relaxed);
            let pool = self.clone();
            tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }

                let result = pool.connector.connect().await;

                match result {
                    Ok(handle) => {
                        pool.register_connection(handle).await;
                        pool.pending_spawns.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        pool.pending_spawns.fetch_sub(1, Ordering::Relaxed);
                        warn!("pooled tunnel connection failed: {}", err);
                        pool.monitor_notify.notify_waiters();
                    }
                }
            });
        }
    }

    async fn register_connection(self: &Arc<Self>, handle: Arc<C::Session>) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let lifecycle = self.behavior.lifecycle(&self.resolved_behavior, seq);
        let connection = Arc::new(PooledConnection {
            seq,
            handle,
            state: AtomicU8::new(ConnectionState::Active.as_u8()),
            soft_ttl: lifecycle.soft_ttl,
            idle_timeout: lifecycle.idle_timeout,
            created_at: Instant::now(),
            last_selected_tick: AtomicU64::new(0),
        });

        debug!(
            seq,
            soft_ttl_secs = connection.soft_ttl.as_secs(),
            idle_timeout_secs = connection.idle_timeout.as_secs(),
            "registered pooled tunnel connection"
        );

        let inserted = {
            let mut connections = self.connections.write().await;
            let live_connections = connections
                .values()
                .filter(|entry| entry.state() != ConnectionState::Closed && entry.handle.is_alive())
                .count();
            if live_connections >= self.max_live_connections {
                false
            } else {
                connections.insert(seq, connection.clone());
                true
            }
        };

        if !inserted {
            debug!(
                seq,
                max_live_connections = self.max_live_connections,
                "dropping pooled tunnel connection above live cap"
            );
            connection.handle.force_close();
            self.connection_ready.notify_waiters();
            self.monitor_notify.notify_waiters();
            return;
        }

        self.connection_ready.notify_waiters();
        self.monitor_notify.notify_waiters();

        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            run_connection_lifecycle(pool, connection).await;
        });
    }

    async fn run_monitor(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.behavior.monitor_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.monitor_notify.notified() => {}
            }

            self.prune_dead_connections().await;
            self.schedule_replenishment_if_needed().await;
        }
    }

    async fn prune_dead_connections(self: &Arc<Self>) {
        let entries = self.connection_entries().await;
        for entry in entries {
            if entry.state() == ConnectionState::Closed {
                self.remove_connection(entry.seq).await;
                continue;
            }

            if !entry.handle.is_alive() && entry.mark_closed() {
                self.remove_connection(entry.seq).await;
                self.monitor_notify.notify_waiters();
            }
        }
    }

    async fn select_active_connection(&self) -> Option<Arc<PooledConnection<C::Session>>> {
        let entries = self.connection_entries().await;
        let mut best: Option<(Arc<PooledConnection<C::Session>>, ConnectionScore)> = None;

        for entry in entries {
            if entry.state() != ConnectionState::Active
                || !entry.handle.is_alive()
                || entry.handle.is_closing()
            {
                continue;
            }

            let active_streams = entry.handle.active_streams().await;
            if active_streams >= self.session_config.max_streams_per_session {
                continue;
            }

            let score = entry.score(active_streams, entry.handle.buffered_stream_bytes());

            match &best {
                Some((_, best_score)) if score >= *best_score => {}
                _ => best = Some((entry, score)),
            }
        }

        best.map(|(entry, _)| {
            let tick = self.selection_tick.fetch_add(1, Ordering::Relaxed) + 1;
            entry.mark_selected(tick);
            entry
        })
    }

    fn desired_active_connection_count(
        &self,
        waiters: usize,
        active_connections: usize,
        busy_connections: usize,
        total_active_streams: usize,
    ) -> usize {
        if waiters == 0 {
            return 0;
        }

        let stream_target = self.streams_per_connection_target();
        let demand_streams = waiters.saturating_add(total_active_streams).max(1);
        let mut desired =
            demand_streams.saturating_add(stream_target.saturating_sub(1)) / stream_target;

        if active_connections == 0 {
            return desired.min(1).min(self.target_pool_size);
        }

        if desired == 0 {
            desired = 1;
        }

        let all_active_busy = busy_connections > 0 && busy_connections >= active_connections;
        let active_capacity_target = active_connections.saturating_mul(stream_target);
        if all_active_busy && total_active_streams >= active_capacity_target {
            desired = desired.max(active_connections.saturating_add(1));
        }

        desired.min(self.target_pool_size)
    }

    fn streams_per_connection_target(&self) -> usize {
        let max_streams = self.session_config.max_streams_per_session.max(1);
        max_streams
            .saturating_div(4)
            .clamp(
                MIN_STREAMS_PER_CONNECTION_TARGET,
                MAX_STREAMS_PER_CONNECTION_TARGET,
            )
            .min(max_streams)
            .max(1)
    }

    async fn live_connection_count(&self) -> usize {
        self.connection_entries()
            .await
            .into_iter()
            .filter(|entry| entry.state() != ConnectionState::Closed && entry.handle.is_alive())
            .count()
    }

    async fn connection_entries(&self) -> Vec<Arc<PooledConnection<C::Session>>> {
        self.connections.read().await.values().cloned().collect()
    }

    async fn mark_draining(&self, seq: u64, reason: &'static str) -> bool {
        let entry = self.connections.read().await.get(&seq).cloned();
        let Some(entry) = entry else {
            return false;
        };

        if entry.mark_draining() {
            debug!(seq, reason, "connection entered draining state");
            self.monitor_notify.notify_waiters();
            true
        } else {
            false
        }
    }

    async fn force_close_connection(&self, seq: u64, reason: &'static str) {
        let entry = self.remove_connection(seq).await;
        let Some(entry) = entry else {
            return;
        };

        entry.mark_closed();
        debug!(seq, reason, "connection closed");
        entry.handle.force_close();
        self.connection_ready.notify_waiters();
        self.monitor_notify.notify_waiters();
    }

    async fn remove_connection(&self, seq: u64) -> Option<Arc<PooledConnection<C::Session>>> {
        self.connections.write().await.remove(&seq)
    }

    #[cfg(test)]
    async fn test_snapshot(&self) -> TestPoolSnapshot {
        let entries = self.connection_entries().await;
        let mut snapshot = TestPoolSnapshot::default();
        for entry in &entries {
            match entry.state() {
                ConnectionState::Active => snapshot.active += 1,
                ConnectionState::Draining => snapshot.draining += 1,
                ConnectionState::Closed => snapshot.closed += 1,
            }
            if entry.state() != ConnectionState::Closed && entry.handle.is_alive() {
                snapshot.live += 1;
                snapshot.total_active_streams = snapshot
                    .total_active_streams
                    .saturating_add(entry.handle.active_streams().await);
            }
        }
        snapshot.pending_spawns = self.pending_spawns.load(Ordering::Relaxed);
        snapshot.acquire_waiters = self.acquire_waiters.load(Ordering::Relaxed);
        snapshot.target_pool_size = self.target_pool_size;
        snapshot.max_live_connections = self.max_live_connections;
        snapshot.min_active_connections = self.min_active_connections;
        snapshot
    }
}

impl<S: PoolSession> PooledConnection<S> {
    fn score(&self, active_streams: usize, buffered_stream_bytes: usize) -> ConnectionScore {
        ConnectionScore {
            active_streams,
            buffered_stream_bytes,
            last_selected_tick: self.last_selected_tick.load(Ordering::Relaxed),
            created_at: self.created_at,
            seq: self.seq,
        }
    }

    fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
    }

    fn mark_selected(&self, tick: u64) {
        self.last_selected_tick.store(tick, Ordering::Relaxed);
    }

    fn mark_draining(&self) -> bool {
        self.state
            .compare_exchange(
                ConnectionState::Active.as_u8(),
                ConnectionState::Draining.as_u8(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    fn mark_closed(&self) -> bool {
        let previous = self
            .state
            .swap(ConnectionState::Closed.as_u8(), Ordering::Relaxed);
        previous != ConnectionState::Closed.as_u8()
    }
}

impl Drop for AcquireWaiterGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ConnectionScore {
    active_streams: usize,
    buffered_stream_bytes: usize,
    last_selected_tick: u64,
    created_at: Instant,
    seq: u64,
}

async fn run_connection_lifecycle<S: PoolSession>(
    pool: Weak<PoolInner<impl TunnelConnector<Session = S>>>,
    connection: Arc<PooledConnection<S>>,
) {
    let soft_ttl = tokio::time::sleep(connection.soft_ttl);
    tokio::pin!(soft_ttl);

    let monitor_interval = pool
        .upgrade()
        .map(|inner| inner.behavior.monitor_interval)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_MONITOR_INTERVAL_MS));
    let mut interval = tokio::time::interval(monitor_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;

    let mut idle_since = None;
    let mut soft_ttl_applied = false;

    loop {
        tokio::select! {
            _ = &mut soft_ttl, if !soft_ttl_applied => {
                if let Some(pool) = pool.upgrade() {
                    pool.mark_draining(connection.seq, "soft ttl expired").await;
                }
                soft_ttl_applied = true;
            }
            _ = interval.tick() => {}
        }

        let Some(pool) = pool.upgrade() else {
            break;
        };

        if !connection.handle.is_alive() || connection.handle.is_closing() {
            pool.force_close_connection(connection.seq, "session ended")
                .await;
            break;
        }

        let active_streams = connection.handle.active_streams().await;
        match connection.state() {
            ConnectionState::Active => {
                if active_streams == 0 {
                    let started = idle_since.get_or_insert_with(Instant::now);
                    if started.elapsed() >= connection.idle_timeout {
                        pool.mark_draining(connection.seq, "idle timeout expired")
                            .await;
                    }
                } else {
                    idle_since = None;
                }
            }
            ConnectionState::Draining => {
                if active_streams == 0 {
                    pool.force_close_connection(connection.seq, "drain complete")
                        .await;
                    break;
                }
            }
            ConnectionState::Closed => break,
        }
    }
}

impl TunnelConnector for DefaultConnector {
    type Session = LivePoolSession;

    fn connect(&self) -> BoxFuture<'_, Result<Arc<LivePoolSession>, anyhow::Error>> {
        let session_config = self.session_config.clone();
        let connect_options = self.connect_options.clone();
        async move {
            let template_bytes = connect_options.custom_template_bytes.read().await;
            let tunnel = kanotls_tunnel::client::client_tunnel(
                &connect_options.server_addr,
                &connect_options.sni,
                &connect_options.psk,
                connect_options.insecure,
                connect_options.fingerprint.as_deref(),
                template_bytes.as_deref(),
            )
            .await?;

            let session = Arc::new(Session::new(tunnel, session_config, None));
            let read_loop = session.clone();
            tokio::spawn(async move {
                let _ = read_loop.run_read_loop().await;
            });

            Ok(Arc::new(LivePoolSession { session }))
        }
        .boxed()
    }
}

impl PoolSession for LivePoolSession {
    fn open_stream(&self) -> BoxFuture<'_, Result<Stream, anyhow::Error>> {
        async move { self.session.open_stream().await }.boxed()
    }

    fn active_streams(&self) -> BoxFuture<'_, usize> {
        async move { self.session.active_stream_count().await }.boxed()
    }

    fn buffered_stream_bytes(&self) -> usize {
        self.session.buffered_stream_bytes()
    }

    fn is_alive(&self) -> bool {
        self.session.is_alive()
    }

    fn is_closing(&self) -> bool {
        self.session.is_closing()
    }

    fn force_close(&self) {
        self.session.force_close();
    }
}

impl SessionConfig {
    pub fn new(is_client: bool) -> Self {
        Self::with_limits(is_client, 256, 45)
    }

    pub fn with_limits(
        is_client: bool,
        max_streams_per_session: usize,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            is_client,
            max_streams_per_session,
            idle_timeout_secs,
            traffic_script: None,
        }
    }

    pub fn with_script(
        is_client: bool,
        max_streams_per_session: usize,
        idle_timeout_secs: u64,
        traffic_script: Option<String>,
    ) -> Self {
        Self {
            is_client,
            max_streams_per_session,
            idle_timeout_secs,
            traffic_script,
        }
    }
}

impl Clone for SessionConfig {
    fn clone(&self) -> Self {
        Self {
            is_client: self.is_client,
            max_streams_per_session: self.max_streams_per_session,
            idle_timeout_secs: self.idle_timeout_secs,
            traffic_script: self.traffic_script.clone(),
        }
    }
}

impl PoolBehaviorContext {
    fn from_connect_options(connect_options: &ClientPoolConnectOptions) -> Self {
        let startup_epoch_secs = current_unix_epoch_secs();
        Self {
            fingerprint_family: normalize_fingerprint_family(
                connect_options.fingerprint.as_deref(),
            )
            .to_string(),
            sni: connect_options.sni.trim().to_ascii_lowercase(),
            startup_epoch_secs,
            time_of_day_bucket: (startup_epoch_secs % 86_400) / TIME_OF_DAY_BUCKET_SECS,
            random_nonce: rand::random::<u64>(),
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            fingerprint_family: "firefox".to_string(),
            sni: "example.com".to_string(),
            startup_epoch_secs: 1_700_000_000,
            time_of_day_bucket: 3,
            random_nonce: 0xDEADBEEF,
        }
    }

    fn seed(&self) -> u64 {
        let mut seed = 0xcbf29ce484222325u64;
        seed = hash_bytes(seed, self.fingerprint_family.as_bytes());
        seed = hash_bytes(seed, self.sni.as_bytes());
        seed = hash_u64(seed, self.time_of_day_bucket);
        seed = hash_u64(seed, self.startup_epoch_secs);
        seed = hash_u64(seed, self.random_nonce);

        let temporal_salt = current_unix_epoch_secs() / 3600;
        seed ^= temporal_salt.wrapping_mul(0x9e3779b97f4a7c15);

        seed
    }
}

fn normalize_fingerprint_family(fingerprint: Option<&str>) -> &'static str {
    match fingerprint
        .unwrap_or("firefox")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "rustls" => "rustls",
        "python-openssl" | "baseline" => "python-openssl",
        _ => "firefox",
    }
}

fn current_unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_bytes(mut seed: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        seed ^= u64::from(*byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    seed
}

fn hash_u64(seed: u64, value: u64) -> u64 {
    hash_bytes(seed, &value.to_le_bytes())
}

fn derive_seed(seed: u64, salt: u64) -> u64 {
    mix_seed(seed ^ salt.wrapping_mul(0x9e3779b97f4a7c15))
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

use splitmix64 as mix_seed;

fn seeded_usize_inclusive(seed: u64, min: usize, max: usize) -> usize {
    if min >= max {
        min
    } else {
        min + (mix_seed(seed) as usize % (max - min + 1))
    }
}

fn seeded_u64_inclusive(seed: u64, min: u64, max: u64) -> u64 {
    if min >= max {
        min
    } else {
        min + (mix_seed(seed) % (max - min + 1))
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct TestPoolSnapshot {
    active: usize,
    draining: usize,
    closed: usize,
    live: usize,
    total_active_streams: usize,
    pending_spawns: usize,
    acquire_waiters: usize,
    target_pool_size: usize,
    max_live_connections: usize,
    min_active_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    type TestPool = ClientPool<FakeConnector>;

    struct FakeConnector {
        calls: AtomicUsize,
        sessions: Mutex<Vec<Arc<FakeSession>>>,
        factory: Box<dyn Fn(usize) -> Arc<FakeSession> + Send + Sync>,
    }

    struct FakeSession {
        active_streams: AtomicUsize,
        buffered_stream_bytes: AtomicUsize,
        alive: AtomicBool,
        closing: AtomicBool,
    }

    impl FakeConnector {
        fn new(factory: impl Fn(usize) -> Arc<FakeSession> + Send + Sync + 'static) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                sessions: Mutex::new(Vec::new()),
                factory: Box::new(factory),
            }
        }

        async fn sessions(&self) -> Vec<Arc<FakeSession>> {
            self.sessions.lock().await.clone()
        }
    }

    impl FakeSession {
        fn new(active_streams: usize) -> Arc<Self> {
            Arc::new(Self {
                active_streams: AtomicUsize::new(active_streams),
                buffered_stream_bytes: AtomicUsize::new(0),
                alive: AtomicBool::new(true),
                closing: AtomicBool::new(false),
            })
        }

        fn set_active_streams(&self, active_streams: usize) {
            self.active_streams.store(active_streams, Ordering::Relaxed);
        }

        fn set_buffered_stream_bytes(&self, buffered_stream_bytes: usize) {
            self.buffered_stream_bytes
                .store(buffered_stream_bytes, Ordering::Relaxed);
        }

        fn is_force_closed(&self) -> bool {
            !self.alive.load(Ordering::Relaxed)
        }
    }

    impl PoolSession for FakeSession {
        fn open_stream(&self) -> BoxFuture<'_, Result<Stream, anyhow::Error>> {
            async move { anyhow::bail!("fake session does not open streams") }.boxed()
        }

        fn active_streams(&self) -> BoxFuture<'_, usize> {
            async move { self.active_streams.load(Ordering::Relaxed) }.boxed()
        }

        fn buffered_stream_bytes(&self) -> usize {
            self.buffered_stream_bytes.load(Ordering::Relaxed)
        }

        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::Relaxed)
        }

        fn is_closing(&self) -> bool {
            self.closing.load(Ordering::Relaxed)
        }

        fn force_close(&self) {
            self.closing.store(true, Ordering::Relaxed);
            self.alive.store(false, Ordering::Relaxed);
        }
    }

    impl TunnelConnector for FakeConnector {
        type Session = FakeSession;

        fn connect(&self) -> BoxFuture<'_, Result<Arc<FakeSession>, anyhow::Error>> {
            async move {
                let idx = self.calls.fetch_add(1, Ordering::Relaxed);
                let session = (self.factory)(idx);
                self.sessions.lock().await.push(session.clone());
                Ok(session)
            }
            .boxed()
        }
    }

    impl TestPool {
        fn new_with_behavior_for_test(
            session_config: SessionConfig,
            behavior: PoolBehaviorConfig,
            connector: Arc<FakeConnector>,
        ) -> Self {
            Self::new_impl(
                session_config,
                behavior,
                PoolBehaviorContext::for_test(),
                connector,
            )
        }
    }

    fn test_behavior() -> PoolBehaviorConfig {
        PoolBehaviorConfig {
            min_target_pool_size: 3,
            max_target_pool_size: 3,
            min_initial_connections: 1,
            max_initial_connections: 1,
            min_active_connections: 2,
            min_startup_jitter_ms: 5,
            max_startup_jitter_ms: 5,
            soft_ttl_secs: 1,
            idle_drain_secs: 1,
            monitor_interval: Duration::from_millis(10),
            acquire_timeout: Duration::from_millis(250),
        }
    }

    fn test_session_config() -> SessionConfig {
        SessionConfig::with_limits(true, 32, 30)
    }

    #[test]
    fn pool_lifecycle_uses_constant_ttls() {
        let mut behavior = test_behavior();
        behavior.soft_ttl_secs = 180;
        behavior.idle_drain_secs = 30;

        let resolved = behavior.resolve(&PoolBehaviorContext::for_test());

        for seq in 1..=8 {
            let lifecycle = behavior.lifecycle(&resolved, seq);
            assert_eq!(lifecycle.soft_ttl, Duration::from_secs(180));
            assert_eq!(lifecycle.idle_timeout, Duration::from_secs(30));
        }
    }

    #[tokio::test]
    async fn pool_transitions_active_to_draining_to_closed() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(1)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 1;
        behavior.max_target_pool_size = 1;
        behavior.min_active_connections = 0;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            behavior,
            connector.clone(),
        );
        pool.spawn_connections_for_test(1, false).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        let sessions = connector.sessions().await;
        let session = sessions[0].clone();
        pool.inner.mark_draining(1, "test drain").await;

        let state = pool
            .inner
            .connections
            .read()
            .await
            .get(&1)
            .map(|entry| entry.state());
        assert_eq!(state, Some(ConnectionState::Draining));

        session.set_active_streams(0);

        tokio::time::sleep(Duration::from_millis(40)).await;
        let state = pool
            .inner
            .connections
            .read()
            .await
            .get(&1)
            .map(|entry| entry.state());
        assert_eq!(state, None);
        assert!(session.is_force_closed());
    }

    #[tokio::test]
    async fn draining_waits_for_active_streams_to_complete() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 1;
        behavior.max_target_pool_size = 1;
        behavior.min_active_connections = 0;
        behavior.monitor_interval = Duration::from_millis(10);

        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            behavior,
            connector.clone(),
        );
        let session = FakeSession::new(1);
        let connection = Arc::new(PooledConnection {
            seq: 1,
            handle: session.clone(),
            state: AtomicU8::new(ConnectionState::Active.as_u8()),
            soft_ttl: Duration::from_millis(20),
            idle_timeout: Duration::from_secs(5),
            created_at: Instant::now(),
            last_selected_tick: AtomicU64::new(0),
        });

        pool.inner
            .connections
            .write()
            .await
            .insert(connection.seq, connection.clone());

        let pool_inner = Arc::downgrade(&pool.inner);
        tokio::spawn(async move {
            run_connection_lifecycle(pool_inner, connection).await;
        });

        tokio::time::sleep(Duration::from_millis(70)).await;
        let state = pool
            .inner
            .connections
            .read()
            .await
            .get(&1)
            .map(|entry| entry.state());
        assert_eq!(state, Some(ConnectionState::Draining));
        assert!(!session.is_force_closed());

        session.set_active_streams(0);
        tokio::time::sleep(Duration::from_millis(30)).await;

        let state = pool
            .inner
            .connections
            .read()
            .await
            .get(&1)
            .map(|entry| entry.state());
        assert_eq!(state, None);
        assert!(session.is_force_closed());
    }

    #[tokio::test]
    async fn pool_selection_prefers_lower_buffered_traffic_when_stream_counts_match() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 2;
        behavior.max_target_pool_size = 2;
        behavior.min_active_connections = 0;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(test_session_config(), behavior, connector);
        let first = FakeSession::new(1);
        first.set_buffered_stream_bytes(4096);
        let second = FakeSession::new(1);
        second.set_buffered_stream_bytes(128);

        pool.inner.register_connection(first).await;
        pool.inner.register_connection(second).await;

        let selected = pool
            .inner
            .select_active_connection()
            .await
            .expect("expected selected connection");

        assert_eq!(selected.seq, 2);
    }

    #[tokio::test]
    async fn pool_selection_spreads_equal_load_by_recency() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 2;
        behavior.max_target_pool_size = 2;
        behavior.min_active_connections = 0;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(test_session_config(), behavior, connector);
        pool.inner.register_connection(FakeSession::new(1)).await;
        pool.inner.register_connection(FakeSession::new(1)).await;

        let first = pool
            .inner
            .select_active_connection()
            .await
            .expect("expected first selected connection");
        let second = pool
            .inner
            .select_active_connection()
            .await
            .expect("expected second selected connection");

        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
    }

    #[tokio::test]
    async fn pool_does_not_replenish_spare_without_waiters() {
        let connector = Arc::new(FakeConnector::new(|idx| {
            if idx == 0 {
                FakeSession::new(1)
            } else {
                FakeSession::new(0)
            }
        }));
        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            test_behavior(),
            connector.clone(),
        );

        pool.spawn_connections_for_test(1, false).await;
        tokio::time::sleep(Duration::from_millis(80)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.target_pool_size, 3);
        assert_eq!(snapshot.max_live_connections, 4);
        assert_eq!(snapshot.min_active_connections, 2);
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);
    }

    #[tokio::test]
    async fn pool_scales_when_waiters_arrive_under_real_session_load() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            test_behavior(),
            connector.clone(),
        );

        pool.inner.acquire_waiters.store(3, Ordering::Relaxed);
        pool.inner.ensure_started().await;

        tokio::time::sleep(Duration::from_millis(30)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);

        let stream_target = pool.inner.streams_per_connection_target();
        let sessions = connector.sessions().await;
        sessions[0].set_active_streams(stream_target.saturating_sub(1));
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);

        sessions[0].set_active_streams(stream_target);
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 2);

        let sessions = connector.sessions().await;
        sessions[1].set_active_streams(stream_target);
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 3);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 3);
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn pool_does_not_spawn_speculative_spare_for_low_stream_demand() {
        let connector = Arc::new(FakeConnector::new(|idx| {
            if idx == 0 {
                FakeSession::new(1)
            } else {
                FakeSession::new(0)
            }
        }));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 2;
        behavior.max_target_pool_size = 2;
        behavior.min_active_connections = 2;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 256, 30),
            behavior,
            connector.clone(),
        );
        pool.spawn_connections_for_test(1, false).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn pool_marks_idle_connection_draining() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 1;
        behavior.max_target_pool_size = 1;
        behavior.min_active_connections = 0;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 0;

        let pool = TestPool::new_with_behavior_for_test(test_session_config(), behavior, connector);
        pool.spawn_connections_for_test(1, false).await;

        tokio::time::sleep(Duration::from_millis(20)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 0);
        assert_eq!(snapshot.draining, 1);
    }

    #[tokio::test]
    async fn pool_allows_idle_drain_to_zero_without_waiters() {
        let connector = Arc::new(FakeConnector::new(|idx| {
            if idx == 0 {
                FakeSession::new(0)
            } else {
                FakeSession::new(1)
            }
        }));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 1;
        behavior.max_target_pool_size = 1;
        behavior.min_active_connections = 1;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 0;

        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            behavior,
            connector.clone(),
        );
        pool.spawn_connections_for_test(1, false).await;

        tokio::time::sleep(Duration::from_millis(80)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 0);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);

        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 2);

        tokio::time::sleep(Duration::from_millis(40)).await;
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn pool_closes_all_idle_connections_even_when_idle_retention_is_configured() {
        let connector = Arc::new(FakeConnector::new(|idx| {
            if idx == 0 {
                FakeSession::new(1)
            } else {
                FakeSession::new(0)
            }
        }));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 2;
        behavior.max_target_pool_size = 2;
        behavior.min_active_connections = 0;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 0;

        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            behavior,
            connector.clone(),
        );
        pool.spawn_connections_for_test(2, false).await;

        tokio::time::sleep(Duration::from_millis(30)).await;
        let sessions = connector.sessions().await;
        sessions[0].set_active_streams(0);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 0);
        assert_eq!(snapshot.draining, 0);
        assert!(sessions[0].is_force_closed());
        assert!(sessions[1].is_force_closed());
    }

    #[tokio::test]
    async fn pool_replaces_draining_connection_before_old_one_closes() {
        let connector = Arc::new(FakeConnector::new(|idx| {
            if idx == 0 {
                FakeSession::new(1)
            } else {
                FakeSession::new(0)
            }
        }));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 1;
        behavior.max_target_pool_size = 1;
        behavior.min_active_connections = 1;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            behavior,
            connector.clone(),
        );
        pool.spawn_connections_for_test(1, false).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        let sessions = connector.sessions().await;
        sessions[0].set_active_streams(1);
        pool.inner.mark_draining(1, "test drain").await;
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.target_pool_size, 1);
        assert_eq!(snapshot.max_live_connections, 2);
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.draining, 1);
        assert_eq!(snapshot.active + snapshot.draining, 2);
        assert_eq!(connector.sessions().await.len(), 2);

        sessions[0].set_active_streams(0);

        tokio::time::sleep(Duration::from_millis(40)).await;
        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.draining, 0);
        assert_eq!(snapshot.active + snapshot.draining, 1);
        assert_eq!(connector.sessions().await.len(), 2);
        assert!(sessions[0].is_force_closed());
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn pool_cold_resume_limits_new_connections_after_idle_gap() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 3;
        behavior.max_target_pool_size = 3;
        behavior.min_active_connections = 2;
        behavior.min_initial_connections = 1;
        behavior.max_initial_connections = 1;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 32, 30),
            behavior,
            connector.clone(),
        );

        pool.inner.acquire_waiters.store(5, Ordering::Relaxed);
        pool.inner.ensure_started().await;

        tokio::time::sleep(Duration::from_millis(40)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);

        pool.inner.acquire_waiters.store(24, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(40)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 3);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 3);
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn pool_reuses_recent_idle_connection_without_extra_spawns() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 2;
        behavior.max_target_pool_size = 2;
        behavior.min_active_connections = 1;
        behavior.min_initial_connections = 1;
        behavior.max_initial_connections = 1;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 32, 30),
            behavior,
            connector.clone(),
        );

        pool.spawn_connections_for_test(1, false).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        pool.inner.acquire_waiters.store(4, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(30)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn pool_does_not_spawn_without_waiters_even_when_sessions_are_busy() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 2;
        behavior.max_target_pool_size = 2;
        behavior.min_active_connections = 2;
        behavior.soft_ttl_secs = 5;
        behavior.idle_drain_secs = 5;

        let pool = TestPool::new_with_behavior_for_test(test_session_config(), behavior, connector);
        let busy = FakeSession::new(pool.inner.streams_per_connection_target());
        pool.inner.register_connection(busy).await;

        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(40)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.pending_spawns, 0);
    }

    #[test]
    fn normalize_fingerprint_family_keeps_python_openssl_distinct() {
        assert_eq!(
            normalize_fingerprint_family(Some("python-openssl")),
            "python-openssl"
        );
        assert_eq!(
            normalize_fingerprint_family(Some("baseline")),
            "python-openssl"
        );
    }
}
