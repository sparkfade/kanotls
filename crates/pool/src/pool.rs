use crate::behavior::{PoolBehaviorConfig, PoolBehaviorContext, ResolvedPoolBehavior};
use crate::connection::{ConnectionState, PooledConnection};
use crate::{PoolSession, TunnelConnector};
use kanotls_session::{SessionConfig, Stream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

const MIN_STREAMS_PER_CONNECTION_TARGET: usize = 8;
const MAX_STREAMS_PER_CONNECTION_TARGET: usize = 64;

/// 隧道连接池：泛型于 [`TunnelConnector`]，由装配层注入连接工厂。
pub struct ClientPool<C: TunnelConnector> {
    inner: Arc<PoolInner<C>>,
}

impl<C: TunnelConnector> ClientPool<C> {
    pub fn new(
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

            let active_streams = entry.handle.active_streams();
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
        let lifecycle = self.behavior.lifecycle();
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
    }

    async fn run_monitor(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.behavior.monitor_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;

        let mut idle_since: HashMap<u64, Instant> = HashMap::new();
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.monitor_notify.notified() => {}
            }

            self.prune_dead_connections().await;
            self.drive_connection_lifecycles(&mut idle_since).await;
            self.schedule_replenishment_if_needed().await;
        }
    }

    /// 连接生命周期统一由 monitor 驱动（原先每连接一个专属任务）：
    /// soft_ttl 到期与持续空闲（active_streams==0 超过 idle_timeout）进入
    /// Draining；Draining 且流排空即关闭；对端已 closing 的连接立即关闭。
    /// 判定粒度为 monitor tick，与旧实现一致。
    async fn drive_connection_lifecycles(&self, idle_since: &mut HashMap<u64, Instant>) {
        let entries = self.connection_entries().await;
        idle_since.retain(|seq, _| entries.iter().any(|entry| entry.seq == *seq));

        for entry in entries {
            if entry.state() == ConnectionState::Closed || !entry.handle.is_alive() {
                continue;
            }

            if entry.handle.is_closing() {
                self.force_close_connection(entry.seq, "session closing")
                    .await;
                continue;
            }

            let active_streams = entry.handle.active_streams();
            match entry.state() {
                ConnectionState::Active => {
                    if active_streams > 0 {
                        idle_since.remove(&entry.seq);
                    } else {
                        let started = idle_since.entry(entry.seq).or_insert_with(Instant::now);
                        if started.elapsed() >= entry.idle_timeout {
                            self.mark_draining(entry.seq, "idle timeout expired").await;
                            continue;
                        }
                    }
                    if entry.created_at.elapsed() >= entry.soft_ttl {
                        self.mark_draining(entry.seq, "soft ttl expired").await;
                    }
                }
                ConnectionState::Draining => {
                    if active_streams == 0 {
                        self.force_close_connection(entry.seq, "drain complete")
                            .await;
                    }
                }
                ConnectionState::Closed => {}
            }
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
        let mut best: Option<(Arc<PooledConnection<C::Session>>, _)> = None;

        for entry in entries {
            if entry.state() != ConnectionState::Active
                || !entry.handle.is_alive()
                || entry.handle.is_closing()
            {
                continue;
            }

            let active_streams = entry.handle.active_streams();
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
                    .saturating_add(entry.handle.active_streams());
            }
        }
        snapshot.pending_spawns = self.pending_spawns.load(Ordering::Relaxed);
        snapshot.acquire_waiters = self.acquire_waiters.load(Ordering::Relaxed);
        snapshot.target_pool_size = self.target_pool_size;
        snapshot.max_live_connections = self.max_live_connections;
        snapshot
    }
}

impl Drop for AcquireWaiterGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::PoolBehaviorContext;
    use crate::PoolSession;
    use futures::future::BoxFuture;
    use futures::FutureExt;
    use std::sync::atomic::{AtomicU8, AtomicUsize};

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

        fn active_streams(&self) -> usize {
            self.active_streams.load(Ordering::Relaxed)
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
            Self::new(
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

        // TTL 与连接序号无关：所有连接拿到同一组常量。
        let lifecycle = behavior.lifecycle();
        assert_eq!(lifecycle.soft_ttl, Duration::from_secs(180));
        assert_eq!(lifecycle.idle_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn pool_transitions_active_to_draining_to_closed() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(1)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 1;
        behavior.max_target_pool_size = 1;
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

        // 生命周期由全局 monitor（10ms tick）统一驱动：soft_ttl 20ms 到期
        // 后进入 Draining，活跃流排空后被关闭并移出映射。
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
}
