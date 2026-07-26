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

                self.try_schedule_replenishment().await;

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

        self.try_schedule_replenishment().await;
    }

    /// 热路径（`open_stream`）用的补充调度：抢不到 `spawn_lock` 就直接返回。
    ///
    /// 已有任务正在补充时，它扫描的是同一份状态，结论对本次调用同样成立，
    /// 因此排队等锁没有意义——而排队会让所有并发的 open_stream 在这把全局
    /// 锁上串行。monitor tick 仍走阻塞版本，保证补充最终一定会发生。
    async fn try_schedule_replenishment(self: &Arc<Self>) {
        if !self.bootstrap_started.load(Ordering::Relaxed) {
            return;
        }
        let Ok(spawn_guard) = self.spawn_lock.try_lock() else {
            return;
        };
        self.replenish_locked(spawn_guard).await;
    }

    async fn schedule_replenishment_if_needed(self: &Arc<Self>) {
        if !self.bootstrap_started.load(Ordering::Relaxed) {
            return;
        }

        let spawn_guard = self.spawn_lock.lock().await;
        self.replenish_locked(spawn_guard).await;
    }

    async fn replenish_locked(self: &Arc<Self>, _spawn_guard: tokio::sync::MutexGuard<'_, ()>) {
        // 统计在 read guard 下就地完成，不再把整张表克隆进 Vec。
        let (active, live, total_active_streams) = {
            let connections = self.connections.read().await;
            let mut active = 0usize;
            let mut live = 0usize;
            let mut total_active_streams = 0usize;

            for entry in connections.values() {
                if entry.state() == ConnectionState::Closed || !entry.handle.is_alive() {
                    continue;
                }

                live += 1;

                if entry.handle.is_closing() {
                    continue;
                }

                total_active_streams =
                    total_active_streams.saturating_add(entry.handle.active_streams());

                if entry.state() == ConnectionState::Active {
                    active += 1;
                }
            }
            (active, live, total_active_streams)
        };

        let pending = self.pending_spawns.load(Ordering::Relaxed);
        let waiters = self.acquire_waiters.load(Ordering::Relaxed);
        let desired_active =
            self.desired_active_connection_count(waiters, active, total_active_streams);

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

    /// 选出当前最优连接。
    ///
    /// 在 read guard 下直接遍历并只克隆胜出者。此前先经 `connection_entries()`
    /// 把整张表克隆进一个新 Vec（一次分配 + 每条连接一对原子增减），而
    /// 本函数在 `open_stream` 的热路径上每条流至少调用一次。评分用到的
    /// 访问器全是同步的，guard 内不跨 await。
    async fn select_active_connection(&self) -> Option<Arc<PooledConnection<C::Session>>> {
        let selected = {
            let connections = self.connections.read().await;
            let mut best: Option<(&Arc<PooledConnection<C::Session>>, _)> = None;

            for entry in connections.values() {
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

            best.map(|(entry, _)| entry.clone())
        };

        selected.inspect(|entry| {
            let tick = self.selection_tick.fetch_add(1, Ordering::Relaxed) + 1;
            entry.mark_selected(tick);
        })
    }

    /// 需要多少条**活跃**连接才能承载当前需求。
    ///
    /// 需求口径是「已在飞的流 + 正在等取流的调用者」，除以单连接的并发目标
    /// 向上取整。此前在末尾还有一条「全忙则 +1」的规则：
    /// `busy >= active && total_active_streams >= active * stream_target`
    /// 时把 desired 抬到 `active + 1`。这条规则**恒不生效**，与阈值取值无关：
    /// 进到这段代码时 `waiters >= 1`（`waiters == 0` 已提前返回 0），于是它的
    /// 触发前提 `total >= active * target` 蕴含
    /// `demand = waiters + total >= active * target + 1`，向上取整已经 ≥
    /// `active + 1`，`max` 拿不到任何新东西。既然它在任何配置下都只是把一个
    /// 已经成立的下界再算一遍，就不该留在这里冒充安全阀——留着会让后来者
    /// 以为存在一条独立于流量需求的扩容路径。`busy_connections` 随之退场，
    /// `replenish_locked` 的逐连接统计也少一个分支。等价性由
    /// `saturation_rule_is_subsumed_by_stream_demand` 在全网格上钉住。
    fn desired_active_connection_count(
        &self,
        waiters: usize,
        active_connections: usize,
        total_active_streams: usize,
    ) -> usize {
        if waiters == 0 {
            return 0;
        }

        let stream_target = self.streams_per_connection_target();
        let demand_streams = waiters.saturating_add(total_active_streams).max(1);
        let desired = demand_streams.saturating_add(stream_target.saturating_sub(1)) / stream_target;

        if active_connections == 0 {
            return desired.min(1).min(self.target_pool_size);
        }

        desired.min(self.target_pool_size)
    }

    /// 单条连接的并发流目标 = 会话自己的并发上限，不再另设池级门限。
    ///
    /// 此前是 `clamp(max_streams_per_session / 4, 8, 64)`，默认配置下等于 64：
    /// 并发流一到 64 就开第二条隧道，把并发**主动分散**出去。于是产生了两个
    /// 可观测特征：(1) 同一 IP:443 上出现多条本可合并的长连接；(2) 更要命的
    /// 是每条新连接的开头都是一次全新的、无遮蔽的内层握手。
    ///
    /// USENIX Security 2024 "Fingerprinting Obfuscated Proxy Traffic with
    /// Encapsulated TLS Handshakes" 的检测器只看一条 TCP 流的**前 25 个**
    /// 承载数据的包（Wo = 25，要求先看到 SYN/SYN-ACK），在其 burst 序列上滑动
    /// 一个握手模板（TLS 1.3 取 Wb = 3 个 burst）。也就是说：一条连接一生只
    /// 在**诞生那一刻**被判定一次，此后再多的内层握手都落在观测窗之外，永远
    /// 不会被这套特征看到。多路复用之所以把 TPR 从 0.74 压到 0.15，正是因为
    /// 别的流的字节挤进了那 25 个包；而论文自己也强调「实际收益比 TPR 差值
    /// 更大，因为穿过防火墙的代理连接数显著减少」。
    ///
    /// 由此，真正的杠杆不是「流怎么在连接间分布」，而是**一共开了几条隧道
    /// 连接**——每开一条就等于多交一份未遮蔽的样本，而审查者只需命中一次。
    /// 阈值从 64 提到会话上限（默认 256）把「第 65..256 条流各自去开新连接、
    /// 其内层握手裸露在新连接的前 25 包里」变成「它们复用已经预热的连接、
    /// 内层握手落在观测窗之外」——不是更难检测，是根本不在取样范围内。
    ///
    /// 取会话上限而非另一个魔数，是因为 H2 里唯一有真实对应物的每连接并发
    /// 门限就是 `SETTINGS_MAX_CONCURRENT_STREAMS`（nginx 默认 128，本项目由
    /// `session.max_streams_per_session` 承担，会话两侧在 session.rs 中强制）。
    /// 任何低于它的池级常量都是没有任何真实实现会有的发明物，而恰恰是它导致
    /// 扇出。真实 Firefox 撞到 MAX_CONCURRENT_STREAMS 时**排队**，不会对同一
    /// origin 再开一条 H2 连接；本池的扩容因此退化为纯粹的溢流阀，只在会话
    /// 自身的并发上限确实耗尽时才动作。
    fn streams_per_connection_target(&self) -> usize {
        self.session_config.max_streams_per_session.max(1)
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

    /// 生命周期时限必须是**常量**，与 PSK / 安装盐无关。
    ///
    /// 真实实现（Firefox 的 keep-alive timeout、nginx 的 keepalive_timeout /
    /// keepalive_time）在这两个维度上都是单一配置值。此前 soft_ttl 逐进程
    /// 从 120–300 秒采样，既是 KanoTLS 独有的「主动回收健康 H2 连接」行为，
    /// 又让同一客户端所有连接的寿命撞在同一点上。本测试钉住「不再按种子
    /// 派生」，防止后续再把常量维度改回随机。
    #[test]
    fn psk_derived_behavior_keeps_lifecycle_timings_constant() {
        let first = PoolBehaviorConfig::from_psk(b"first-password", &[0x11; 16]);
        let second = PoolBehaviorConfig::from_psk(b"a-completely-different-one", &[0xAA; 16]);

        for behavior in [&first, &second] {
            assert_eq!(behavior.idle_drain_secs, crate::behavior::IDLE_DRAIN_SECS);
            assert_eq!(behavior.soft_ttl_secs, crate::behavior::SOFT_TTL_SECS);
        }

        // 客户端的空闲上限必须高于服务端的空闲拆除（默认 75 秒），
        // 先动手关闭的那一侧才会是服务端——与真实 H2 一致。
        assert!(first.idle_drain_secs > 75);
        // soft_ttl 只是资源兜底：必须远高于空闲上限，正常使用下不可观测。
        assert!(first.soft_ttl_secs > first.idle_drain_secs * 8);
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

    /// 热路径的补充调度用 `try_lock`：已有任务在补充时直接跳过，不排队。
    /// 这消除了 open_stream 在全局 spawn_lock 上的串行化，但必须保证
    /// 「跳过」只是延后到下一轮，而不是永久丢失需求。
    #[tokio::test]
    async fn hot_path_replenishment_skips_when_contended_then_recovers() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let pool = TestPool::new_with_behavior_for_test(
            test_session_config(),
            test_behavior(),
            connector.clone(),
        );
        pool.inner.bootstrap_started.store(true, Ordering::Relaxed);
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);

        // 持锁期间热路径必须直接返回，不得阻塞、不得生成连接。
        let held = pool.inner.spawn_lock.lock().await;
        tokio::time::timeout(
            Duration::from_millis(100),
            pool.inner.try_schedule_replenishment(),
        )
        .await
        .expect("contended hot path must return immediately, not queue on the lock");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            connector.sessions().await.len(),
            0,
            "no connection should be spawned while another task holds the spawn lock"
        );

        // 释放后同一调用点必须照常补充。
        drop(held);
        pool.inner.try_schedule_replenishment().await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            connector.sessions().await.len(),
            1,
            "demand must be picked up once the lock is free"
        );
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
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

    /// 冷启动 1 条；随后的积压先由那**一条**连接吸收，直到会话并发上限确实
    /// 不够用才扩容。
    ///
    /// 此前阈值是 `max_streams / 4`（这里 = 8），于是 24 个等待者就足以拉起
    /// 3 条连接；现在阈值等于会话上限（这里 = 32），24 个等待者全部留在同一
    /// 条连接上——每少开一条隧道就少交一份「前 25 包」的未遮蔽样本。
    #[tokio::test]
    async fn pool_cold_resume_absorbs_backlog_on_one_connection_after_idle_gap() {
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

        // 24 个等待者仍在单条连接的承载范围（会话上限 32）之内。
        pool.inner.acquire_waiters.store(24, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(40)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 1);

        // 越过会话上限后才扩容，且按需求逐档扩，不一次性铺满 target_pool_size。
        pool.inner.acquire_waiters.store(40, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(60)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 2);
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

    /// 冷启动只允许开**一条**隧道连接，与瞬时需求高低无关。
    ///
    /// 真实 H2 客户端对单一 origin 通常只维持一条连接；若启动瞬间并发建起
    /// N 条 TLS 握手指向同一 IP:443，这与 H2 多路复用语义直接矛盾，是比任何
    /// 定时器常量都醒目的特征。`desired_active_connection_count` 的
    /// `active_connections == 0` 分支是该性质的唯一保证——它同时压住了
    /// `initial_connection_count`（1–3）：后者只参与 `max_live_connections`
    /// 的上限计算，不能成为冷启动的并发建连数。
    #[tokio::test]
    async fn desired_connection_count_clamps_cold_start_to_one() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 16;
        behavior.max_target_pool_size = 16;
        behavior.min_initial_connections = 3;
        behavior.max_initial_connections = 3;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 256, 30),
            behavior,
            connector,
        );
        let inner = &pool.inner;
        // 单连接并发目标 = 会话并发上限，不再是它的 1/4。
        assert_eq!(inner.streams_per_connection_target(), 256);

        // 无人取流 ⇒ 一条都不开（不做投机预连接）。
        assert_eq!(inner.desired_active_connection_count(0, 0, 0), 0);
        // 池内没有连接时，无论积压多大都只开 1 条。
        assert_eq!(inner.desired_active_connection_count(1, 0, 0), 1);
        assert_eq!(inner.desired_active_connection_count(1_000, 0, 0), 1);
        // 之后按并发流需求逐步扩张：会话并发上限（256）没耗尽就不加。
        assert_eq!(inner.desired_active_connection_count(1, 1, 255), 1);
        assert_eq!(inner.desired_active_connection_count(1, 1, 256), 2);
        // 扩张始终受 target_pool_size 约束。
        assert_eq!(inner.desired_active_connection_count(10_000, 8, 10_000), 16);
    }

    /// 正常浏览负载全部落在**一条**连接上。
    ///
    /// 论文的检测器只看一条 TCP 流的前 25 个承载数据的包：一条连接一生只在
    /// 诞生那一刻被判一次，此后的内层握手全部落在观测窗之外。所以「多开一条
    /// 隧道」等于「多交一份未遮蔽的样本」，而审查者只需命中一次。此前阈值 64
    /// 让第 65 条并发流就去开新连接——把本来会藏进观测窗之外的内层握手，重新
    /// 摆到一条新连接的前 25 个包里。
    #[tokio::test]
    async fn browsing_load_stays_on_a_single_connection() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 16;
        behavior.max_target_pool_size = 16;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 256, 30),
            behavior,
            connector,
        );
        let inner = &pool.inner;

        // 100 / 200 条并发流（含刚好在等取流的那一批）都不触发第二条连接。
        for streams in [100usize, 200] {
            assert_eq!(
                inner.desired_active_connection_count(1, 1, streams),
                1,
                "{streams} concurrent streams must stay on one tunnel connection"
            );
        }
        // 一整批 100 个调用者同时来取流，同样只用这一条。
        assert_eq!(inner.desired_active_connection_count(100, 1, 100), 1);
        // 边界：需求刚好等于会话并发上限时仍是 1 条。
        assert_eq!(inner.desired_active_connection_count(56, 1, 200), 1);
        assert_eq!(inner.desired_active_connection_count(57, 1, 200), 2);
    }

    /// 溢流阀：真正超过会话并发上限时第二条连接仍然开得出来。
    ///
    /// 提高阈值换来的是「更少的隧道连接」，不是「永不扩容」——会话自身的
    /// 并发上限（session.rs 双侧强制）耗尽后，`select_active_connection` 会
    /// 跳过满载连接，取流必须有别的去处，否则调用者只能等到 acquire_timeout。
    #[tokio::test]
    async fn overflow_valve_opens_second_connection_past_session_stream_limit() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 4;
        behavior.max_target_pool_size = 4;
        behavior.soft_ttl_secs = 30;
        behavior.idle_drain_secs = 30;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 256, 30),
            behavior,
            connector.clone(),
        );

        pool.spawn_connections_for_test(1, false).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let sessions = connector.sessions().await;
        // 255 条在飞 + 1 个等待者 = 256：仍在单条连接的承载范围内。
        sessions[0].set_active_streams(255);
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(connector.sessions().await.len(), 1);

        // 会话并发上限耗尽，溢流阀打开。
        sessions[0].set_active_streams(256);
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(60)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.pending_spawns, 0);
        assert_eq!(connector.sessions().await.len(), 2);
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    /// 扩容不震荡：同一份需求反复评估不会继续加连接，需求回落也不会再加。
    #[tokio::test]
    async fn expansion_settles_without_oscillating() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 4;
        behavior.max_target_pool_size = 4;
        behavior.soft_ttl_secs = 30;
        behavior.idle_drain_secs = 30;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 256, 30),
            behavior,
            connector.clone(),
        );

        pool.spawn_connections_for_test(1, false).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        connector.sessions().await[0].set_active_streams(256);
        pool.inner.acquire_waiters.store(1, Ordering::Relaxed);
        pool.inner.schedule_replenishment_if_needed().await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(connector.sessions().await.len(), 2);

        // 需求不变时反复评估：稳在 2 条，不继续爬。
        for _ in 0..5 {
            pool.inner.schedule_replenishment_if_needed().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(connector.sessions().await.len(), 2);

        // 需求回落：既不再加连接，也不会因为「少了一条」而立刻补建。
        let sessions = connector.sessions().await;
        sessions[0].set_active_streams(10);
        sessions[1].set_active_streams(4);
        for _ in 0..5 {
            pool.inner.schedule_replenishment_if_needed().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let snapshot = pool.snapshot().await;
        assert_eq!(connector.sessions().await.len(), 2);
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.pending_spawns, 0);
        pool.inner.acquire_waiters.store(0, Ordering::Relaxed);
    }

    /// 被删掉的「全忙则 +1」规则确实是恒等变换。
    ///
    /// 旧代码在末尾有
    /// `if busy >= active && total >= active * target { desired = max(desired, active + 1) }`。
    /// 本测试在整个参数网格上验证：只要 `waiters >= 1`（`waiters == 0` 已提前
    /// 返回 0），该规则的触发前提就蕴含向上取整结果已经 ≥ `active + 1`，因此
    /// 它从来拿不到任何新东西——这与阈值取 64 还是 256 无关，删除是纯化简。
    #[tokio::test]
    async fn saturation_rule_is_subsumed_by_stream_demand() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 16;
        behavior.max_target_pool_size = 16;

        for max_streams in [1usize, 8, 32, 64, 256] {
            let pool = TestPool::new_with_behavior_for_test(
                SessionConfig::with_limits(true, max_streams, 30),
                behavior.clone(),
                connector.clone(),
            );
            let inner = &pool.inner;
            let target = inner.streams_per_connection_target();
            assert_eq!(target, max_streams);

            for waiters in 1usize..=6 {
                for active in 1usize..=6 {
                    for total in [
                        active * target,
                        active * target + 1,
                        active * target + target / 2,
                        (active + 1) * target,
                    ] {
                        let desired = inner.desired_active_connection_count(waiters, active, total);
                        // 规则的触发前提成立时，纯需求公式已经给出 ≥ active + 1。
                        assert!(
                            desired >= (active + 1).min(inner.target_pool_size),
                            "target={target} waiters={waiters} active={active} total={total} \
                             desired={desired}"
                        );
                    }
                }
            }
        }
    }

    /// 冷启动的实际建连数：`initial_connection_count` 取到上限 3 也只有
    /// 一次握手出去，且这条连接足以服务当前积压。
    #[tokio::test]
    async fn cold_start_spawns_single_connection_with_initial_count_at_max() {
        let connector = Arc::new(FakeConnector::new(|_| FakeSession::new(0)));
        let mut behavior = test_behavior();
        behavior.min_target_pool_size = 16;
        behavior.max_target_pool_size = 16;
        behavior.min_initial_connections = 3;
        behavior.max_initial_connections = 3;
        behavior.soft_ttl_secs = 30;
        behavior.idle_drain_secs = 30;

        let pool = TestPool::new_with_behavior_for_test(
            SessionConfig::with_limits(true, 256, 30),
            behavior,
            connector.clone(),
        );

        // 30 个并发取流请求：远超 initial_connection_count，仍在单条连接的
        // 流目标（64）之内，因此稳态需求也是 1 条。
        pool.inner.acquire_waiters.store(30, Ordering::Relaxed);
        pool.inner.ensure_started().await;
        tokio::time::sleep(Duration::from_millis(80)).await;

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.live, 1, "cold start must not open parallel tunnels");
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
