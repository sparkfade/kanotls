use crate::frame::{Frame, CMD_SYNACK};
use crate::session::{
    register_stream_locked, unregister_stream_locked, BufferedPayload, PendingAcceptFlushResult,
    PendingData, Session, SessionConfig, StreamHandle, TrafficClass,
};
use bytes::Bytes;
use kanotls_tunnel::SnowyStream;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify};
use tracing::warn;

const NEW_STREAM_CHANNEL_CAPACITY: usize = 128;

pub struct ServerSessionHandler {
    pub session: Arc<Session>,
    new_stream_rx: Mutex<mpsc::Receiver<u32>>,
}

impl ServerSessionHandler {
    pub fn new(tunnel: SnowyStream, config: SessionConfig) -> Self {
        let (new_stream_tx, new_stream_rx) = mpsc::channel(NEW_STREAM_CHANNEL_CAPACITY);
        let on_stream: Arc<dyn Fn(u32) -> bool + Send + Sync> = Arc::new(move |sid: u32| {
            if new_stream_tx.try_send(sid).is_err() {
                warn!(
                    stream_id = sid,
                    "dropping new stream notification: queue full"
                );
                false
            } else {
                true
            }
        });

        let session = Arc::new(Session::new(tunnel, config, Some(on_stream)));

        Self {
            session,
            new_stream_rx: Mutex::new(new_stream_rx),
        }
    }

    pub async fn accept_stream(&self) -> Result<(u32, ServerStream), anyhow::Error> {
        let sid = {
            let mut rx = self.new_stream_rx.lock().await;
            tokio::select! {
                sid = rx.recv() => {
                    sid.ok_or_else(|| anyhow::anyhow!("session read loop ended"))?
                }
                _ = self.session.shutdown.notified() => {
                    anyhow::bail!("session shutting down");
                }
            }
        };

        self.session.begin_accept_pending_stream(sid).await?;

        let (data_tx, data_rx) = mpsc::channel(128);
        let (fin_tx, fin_rx) = mpsc::channel(1);
        let pending_notify = Arc::new(Notify::new());
        // 本流发送方向信贷（H2 每流窗口，与句柄共享）：注册即满窗，对端
        // WINDOW_UPDATE 帧入账，写路径（Session::write_data）扣减。
        let send_credit = Arc::new(AtomicI64::new(self.session.windows.stream_window()));

        let handle = StreamHandle {
            data_tx: data_tx.clone(),
            fin_tx: fin_tx.clone(),
            synack_tx: None,
            read_closed: false,
            pending_notify: pending_notify.clone(),
            send_credit: send_credit.clone(),
        };

        register_stream_locked(
            &mut *self.session.streams.write().await,
            &self.session.capacity_stream_count,
            sid,
            handle,
        );
        if self.session.release_pending_open_reservation(sid).await {
            self.session.release_inbound_stream_reservation();
        }
        let flush_result = self
            .session
            .flush_pending_accept_stream(sid, data_tx.clone(), fin_tx.clone())
            .await;

        Ok((
            sid,
            ServerStream {
                sid,
                data_rx,
                fin_rx,
                session: self.session.clone(),
                read_closed: matches!(
                    flush_result,
                    PendingAcceptFlushResult::PeerClosed | PendingAcceptFlushResult::PeerHalfClosed
                ),
                write_closed: Arc::new(AtomicBool::new(false)),
                closed: matches!(flush_result, PendingAcceptFlushResult::ClosedLocally),
                pending_data: self.session.pending_data.clone(),
                pending_notify,
                consumed_since_wu: AtomicU64::new(0),
            },
        ))
    }

    pub fn get_session(&self) -> Arc<Session> {
        self.session.clone()
    }
}

pub struct ServerStream {
    pub sid: u32,
    data_rx: mpsc::Receiver<BufferedPayload>,
    fin_rx: mpsc::Receiver<()>,
    session: Arc<Session>,
    read_closed: bool,
    /// 写侧关闭标志与写句柄共享（`write_handle`）：上行任务里的
    /// `close_write` 与本体上的 `close` 通过同一个原子位去重 FIN。
    write_closed: Arc<AtomicBool>,
    closed: bool,
    pending_data: Arc<Mutex<PendingData>>,
    pending_notify: Arc<Notify>,
    /// 本流**接收**方向已消费、尚未回补的字节（单消费者：本端中继独占）。
    consumed_since_wu: AtomicU64,
}

/// 服务端隧道流的写半句柄：`ServerStream::write`/`close_write` 本就是无
/// 内部可变状态的操作，抽成 Arc 句柄后上行中继任务可独立持有——与客户
/// 端 `Stream::into_split` 同一目的：写方向在流控门（等 WINDOW_UPDATE）
/// 挂起时，读方向的交付与回补照常进行，双向饱和不再互等成死锁环。
pub struct ServerStreamWriter {
    sid: u32,
    session: Arc<Session>,
    write_closed: Arc<AtomicBool>,
}

impl ServerStreamWriter {
    pub async fn write(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        if self.write_closed.load(std::sync::atomic::Ordering::Relaxed) {
            anyhow::bail!("stream write side is closed");
        }
        self.session.write_data(self.sid, data).await
    }

    pub async fn close_write(&self) -> Result<(), anyhow::Error> {
        if self
            .write_closed
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }
        self.session.shutdown_stream(self.sid).await
    }
}

impl ServerStream {
    pub async fn read(&mut self) -> Option<Bytes> {
        loop {
            if let Ok(payload) = self.data_rx.try_recv() {
                return Some(payload.into_bytes());
            }
            // 先注册再检查：pending 数据到达用 `notify_waiters`（不留
            // permit），若先检查后注册，间隙到达的通知会被丢掉。
            let pending_notified = self.pending_notify.notified();
            tokio::pin!(pending_notified);
            let _ = pending_notified.as_mut().enable();
            if let Some(data) = self.try_drain_pending_data() {
                return Some(data);
            }
            if self.read_closed {
                return None;
            }

            tokio::select! {
                payload = self.data_rx.recv() => {
                    return payload.map(BufferedPayload::into_bytes);
                }
                _ = pending_notified => {
                    continue;
                }
                _ = self.fin_rx.recv() => {
                    // 与 Stream::read 同口径：先置 read_closed 再回路排空，
                    // 避免 fin 令牌被中途消费后 read 永远挂在 select 上。
                    self.read_closed = true;
                    continue;
                }
            }
        }
    }

    fn try_drain_pending_data(&self) -> Option<Bytes> {
        let mut pending = self.pending_data.try_lock().ok()?;
        // pop_front 在队列排空时自动移除条目。
        let payload = pending.pop_front(self.sid)?;
        Some(payload.into_bytes())
    }

    pub async fn write(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        if self.write_closed.load(std::sync::atomic::Ordering::Relaxed) || self.closed {
            anyhow::bail!("stream write side is closed");
        }
        self.session.write_data(self.sid, data).await
    }

    /// 抽出一个可独立持有的写半句柄（论证见 `ServerStreamWriter`）。
    pub fn write_handle(&self) -> ServerStreamWriter {
        ServerStreamWriter {
            sid: self.sid,
            session: self.session.clone(),
            write_closed: self.write_closed.clone(),
        }
    }

    /// 接收侧回补入账：中继在字节真正交付远端后调用（H2 语义，见
    /// `WindowState::note_consumed`）。
    pub fn note_consumed(&self, len: usize) {
        self.session
            .windows
            .note_consumed(self.sid, &self.consumed_since_wu, len);
    }

    pub async fn close_write(&mut self) -> Result<(), anyhow::Error> {
        if self.closed || self.write_closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        let result = self.session.shutdown_stream(self.sid).await;
        if result.is_ok() {
            self.write_closed
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    pub async fn send_synack(&self) -> Result<(), anyhow::Error> {
        let synack_frame = Frame::new(CMD_SYNACK, self.sid, vec![]);
        self.session
            .write_frame(&synack_frame, TrafficClass::Control)
            .await
    }

    pub async fn close(&mut self) -> Result<(), anyhow::Error> {
        if self.closed {
            unregister_stream_locked(
                &mut *self.session.streams.write().await,
                &self.session.capacity_stream_count,
                self.sid,
            );
            return Ok(());
        }

        let result = if self.write_closed.load(std::sync::atomic::Ordering::Relaxed) {
            Ok(())
        } else {
            self.close_write().await
        };
        self.session.finish_closing_stream(self.sid).await;
        self.closed = true;
        result
    }
}

impl Drop for ServerStream {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let session = self.session.clone();
        let sid = self.sid;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = session.close_stream(sid).await;
            });
        }
    }
}
