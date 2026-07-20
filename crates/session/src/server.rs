use crate::frame::{Frame, CMD_SYNACK};
use crate::session::{
    register_stream_locked, unregister_stream_locked, BufferedPayload, PendingAcceptFlushResult,
    PendingData, Session, SessionConfig, StreamHandle, TrafficClass,
};
use kanotls_tunnel::SnowyStream;
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

        let handle = StreamHandle {
            data_tx: data_tx.clone(),
            fin_tx: fin_tx.clone(),
            synack_tx: None,
            read_closed: false,
            pending_notify: pending_notify.clone(),
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
                write_closed: false,
                closed: matches!(flush_result, PendingAcceptFlushResult::ClosedLocally),
                pending_data: self.session.pending_data.clone(),
                pending_notify,
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
    write_closed: bool,
    closed: bool,
    pending_data: Arc<Mutex<PendingData>>,
    pending_notify: Arc<Notify>,
}

impl ServerStream {
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Ok(payload) = self.data_rx.try_recv() {
                return Some(payload.into_vec());
            }
            if let Some(data) = self.try_drain_pending_data() {
                return Some(data);
            }
            if self.read_closed {
                return None;
            }

            tokio::select! {
                payload = self.data_rx.recv() => {
                    return payload.map(BufferedPayload::into_vec);
                }
                _ = self.pending_notify.notified() => {
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

    fn try_drain_pending_data(&self) -> Option<Vec<u8>> {
        let mut pending = self.pending_data.try_lock().ok()?;
        let queue = pending.get_mut(self.sid)?;
        let payload = queue.pop_front()?;
        if queue.is_empty() {
            pending.remove(self.sid);
        }
        Some(payload.into_vec())
    }

    pub async fn write(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        if self.write_closed || self.closed {
            anyhow::bail!("stream write side is closed");
        }
        self.session.write_data(self.sid, data).await
    }

    pub async fn close_write(&mut self) -> Result<(), anyhow::Error> {
        if self.closed || self.write_closed {
            return Ok(());
        }

        let result = self.session.shutdown_stream(self.sid).await;
        if result.is_ok() {
            self.write_closed = true;
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

        let result = if self.write_closed {
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
