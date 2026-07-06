use crate::frame::{Frame, CMD_SYNACK};
use crate::session::{
    PendingAcceptFlushResult, PendingData, Session, SessionConfig, StreamHandle, TrafficClass,
};
use kanotls_tunnel::SnowyStream;
use std::sync::atomic::{AtomicUsize, Ordering};
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

        self.session.streams.write().await.insert(sid, handle);
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
                buffered_stream_bytes: self.session.buffered_stream_bytes.clone(),
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
    data_rx: mpsc::Receiver<Vec<u8>>,
    fin_rx: mpsc::Receiver<()>,
    session: Arc<Session>,
    read_closed: bool,
    write_closed: bool,
    closed: bool,
    buffered_stream_bytes: Arc<AtomicUsize>,
    pending_data: Arc<Mutex<PendingData>>,
    pending_notify: Arc<Notify>,
}

impl ServerStream {
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Ok(data) = self.data_rx.try_recv() {
                let _ = self.buffered_stream_bytes.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(data.len())),
                );
                return Some(data);
            }
            if let Some(data) = self.try_drain_pending_data() {
                return Some(data);
            }
            if self.read_closed {
                return None;
            }

            tokio::select! {
                data = self.data_rx.recv() => {
                    if let Some(ref d) = data {
                        let _ = self.buffered_stream_bytes.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |v| Some(v.saturating_sub(d.len())),
                        );
                    }
                    return data;
                }
                _ = self.pending_notify.notified() => {
                    continue;
                }
                _ = self.fin_rx.recv() => {
                    if let Ok(data) = self.data_rx.try_recv() {
                        let _ = self.buffered_stream_bytes.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |v| Some(v.saturating_sub(data.len())),
                        );
                        return Some(data);
                    }
                    if let Some(data) = self.try_drain_pending_data() {
                        return Some(data);
                    }
                    self.read_closed = true;
                    return None;
                }
            }
        }
    }

    fn try_drain_pending_data(&self) -> Option<Vec<u8>> {
        let mut pending = self.pending_data.try_lock().ok()?;
        let queue = pending.get_mut(self.sid)?;
        let data = queue.pop_front()?;
        let _ =
            self.buffered_stream_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(data.len()))
                });
        if queue.is_empty() {
            pending.remove(self.sid);
        }
        Some(data)
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
            self.session.streams.write().await.remove(&self.sid);
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
