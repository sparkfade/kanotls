use crate::frame::{coalesce_encoded_frames, Frame, MAX_PAYLOAD_LEN};
use crate::session::{
    remember_closing_stream_sync, FlushBehavior, PendingWrite, SharedTunnelWriter, StreamHandle,
    TrafficClass,
};
use anyhow::Error;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::{mpsc, oneshot, RwLock};

const SYNACK_TIMEOUT_SECS: u64 = 10;

// Distinguish a deferred open that can still be retried from one whose bytes
// are already committed to the session writer.
pub(crate) enum StreamOpenState {
    DeferredUnsent(Vec<Vec<u8>>),
    Submitted {
        pending_write: Option<PendingWrite>,
        early_data_submitted: bool,
    },
}

#[derive(Clone)]
pub(crate) struct PendingClientSettings {
    slot: Arc<Mutex<Option<Vec<u8>>>>,
}

impl PendingClientSettings {
    pub(crate) fn new(slot: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
        Self { slot }
    }

    async fn take(&self) -> Option<Vec<u8>> {
        self.slot.lock().await.take()
    }

    async fn restore(&self, frame: Vec<u8>) {
        let mut slot = self.slot.lock().await;
        if slot.is_none() {
            *slot = Some(frame);
        }
    }
}

struct PendingClientSettingsGuard {
    settings: PendingClientSettings,
    frame: Option<Vec<u8>>,
    committed: bool,
}

pub(crate) struct StreamParts {
    pub data_rx: mpsc::Receiver<Vec<u8>>,
    pub fin_rx: mpsc::Receiver<()>,
    pub synack_rx: oneshot::Receiver<Vec<u8>>,
}

pub(crate) struct StreamInit {
    pub stream_id: u32,
    pub parts: StreamParts,
    pub writer: SharedTunnelWriter,
    pub streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pub pending_client_settings: Arc<Mutex<Option<Vec<u8>>>>,
    pub pending_data: Arc<Mutex<HashMap<u32, Vec<Vec<u8>>>>>,
    pub pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    pub closing_streams: Arc<Mutex<std::collections::HashSet<u32>>>,
    pub open_state: StreamOpenState,
    pub buffered_stream_bytes: Arc<AtomicUsize>,
}

pub struct Stream {
    pub stream_id: u32,
    data_rx: mpsc::Receiver<Vec<u8>>,
    fin_rx: mpsc::Receiver<()>,
    synack_rx: Option<oneshot::Receiver<Vec<u8>>>,

    writer: SharedTunnelWriter,
    streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pending_client_settings: PendingClientSettings,
    pending_data: Arc<Mutex<HashMap<u32, Vec<Vec<u8>>>>>,
    pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    closing_streams: Arc<Mutex<std::collections::HashSet<u32>>>,
    open_state: StreamOpenState,
    deferred_target: Option<Vec<u8>>,
    read_closed: bool,
    write_closed: bool,
    closed: bool,
    open_failed: Option<String>,
    buffered_stream_bytes: Arc<AtomicUsize>,
}

impl Stream {
    pub(crate) fn new(init: StreamInit) -> Self {
        Self {
            stream_id: init.stream_id,
            data_rx: init.parts.data_rx,
            fin_rx: init.parts.fin_rx,
            synack_rx: Some(init.parts.synack_rx),
            writer: init.writer,
            streams: init.streams,
            pending_client_settings: PendingClientSettings::new(init.pending_client_settings),
            pending_data: init.pending_data,
            pending_fin: init.pending_fin,
            closing_streams: init.closing_streams,
            open_state: init.open_state,
            deferred_target: None,
            read_closed: false,
            write_closed: false,
            closed: false,
            open_failed: None,
            buffered_stream_bytes: init.buffered_stream_bytes,
        }
    }

    pub async fn read(&mut self) -> Option<Vec<u8>> {
        if let Ok(data) = self.data_rx.try_recv() {
            self.buffered_stream_bytes
                .fetch_sub(data.len(), Ordering::Relaxed);
            return Some(data);
        }
        if self.read_closed {
            return None;
        }
        tokio::select! {
            data = self.data_rx.recv() => {
                if let Some(ref d) = data {
                    self.buffered_stream_bytes
                        .fetch_sub(d.len(), Ordering::Relaxed);
                }
                data
            }
            _ = self.fin_rx.recv() => {
                if let Ok(data) = self.data_rx.try_recv() {
                    self.buffered_stream_bytes
                        .fetch_sub(data.len(), Ordering::Relaxed);
                    return Some(data);
                }
                self.read_closed = true;
                None
            }
        }
    }

    async fn wait_synack(&mut self) -> Result<(), anyhow::Error> {
        if let Some(msg) = &self.open_failed {
            anyhow::bail!(msg.clone());
        }
        self.flush_pending_open_frames().await?;
        self.wait_synack_once().await
    }

    pub async fn wait_open(&mut self) -> Result<(), anyhow::Error> {
        self.wait_synack().await
    }

    pub fn defer_target(&mut self, target: &[u8]) {
        self.deferred_target = Some(target.to_vec());
    }

    pub async fn write_early(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        if let Some(msg) = &self.open_failed {
            anyhow::bail!(msg.clone());
        }
        if self.has_deferred_open() {
            return self.write_pending_open_with_data(data).await;
        }

        self.finish_pending_open_submission().await?;
        if self.early_data_already_submitted() {
            return Ok(());
        }

        self.write_data_frame_with_flush(data, FlushBehavior::Immediate)
            .await
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        if let Some(msg) = &self.open_failed {
            anyhow::bail!(msg.clone());
        }

        if let Some(target) = self.deferred_target.take() {
            return self.write_gather_open(&target, data).await;
        }

        if self.has_deferred_open() {
            return self.write_early(data).await;
        }

        self.finish_pending_open_submission().await?;
        self.write_data_frame(data).await
    }

    async fn write_data_frame(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.write_data_frame_with_flush(data, FlushBehavior::Auto)
            .await
    }

    async fn write_data_frame_with_flush(
        &mut self,
        data: &[u8],
        flush: FlushBehavior,
    ) -> Result<(), anyhow::Error> {
        if self.write_closed || self.closed {
            anyhow::bail!("stream write side is closed");
        }
        if data.is_empty() {
            self.write_frame(Frame::psh(self.stream_id, Vec::new()))
                .await?;
            return Ok(());
        }

        let mut packets = Vec::with_capacity(data.len().div_ceil(MAX_PAYLOAD_LEN));
        for chunk in data.chunks(MAX_PAYLOAD_LEN) {
            let payload = Frame::encode_psh(self.stream_id, chunk)?;
            packets.push(payload);
        }
        self.writer.write_packets(packets, flush, TrafficClass::Bulk).await
    }

    async fn write_pending_open_with_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        let Some(mut frames) = self.deferred_open_frames() else {
            return self
                .write_data_frame_with_flush(data, FlushBehavior::Immediate)
                .await;
        };
        let mut settings_guard =
            PendingClientSettingsGuard::take(&self.pending_client_settings).await;
        if let Some(settings) = settings_guard.frame.clone() {
            frames.insert(0, settings);
        }
        if data.is_empty() {
            frames.push(Frame::psh(self.stream_id, Vec::new()).encode()?);
        } else {
            for chunk in data.chunks(MAX_PAYLOAD_LEN) {
                frames.push(Frame::psh(self.stream_id, chunk.to_vec()).encode()?);
            }
        }
        let packets = self.coalesce_and_pad(&frames)?;

        // SETTINGS/SYN and the target payload must reach the peer before we
        // wait on SYNACK; otherwise the bytes can remain buffered inside the
        // tunnel writer and the stream appears to hang or time out.
        let pending_write = match self
            .writer
            .submit_write_packets(packets, FlushBehavior::Immediate, TrafficClass::Control)
            .await
        {
            Ok(pending_write) => pending_write,
            Err(err) => {
                self.writer.close();
                self.open_failed = Some(err.to_string());
                return Err(err);
            }
        };

        settings_guard.commit();
        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: true,
        };

        self.finish_pending_open_submission().await
    }

    async fn write_gather_open(
        &mut self,
        target: &[u8],
        data: &[u8],
    ) -> Result<(), anyhow::Error> {
        let Some(mut frames) = self.deferred_open_frames() else {
            self.finish_pending_open_submission().await?;
            let mut combined_frames = Vec::new();
            for chunk in target.chunks(MAX_PAYLOAD_LEN) {
                combined_frames.push(Frame::psh(self.stream_id, chunk.to_vec()).encode()?);
            }
            if !data.is_empty() {
                for chunk in data.chunks(MAX_PAYLOAD_LEN) {
                    combined_frames.push(Frame::psh(self.stream_id, chunk.to_vec()).encode()?);
                }
            }
            let packets = self.coalesce_and_pad(&combined_frames)?;
            return self.writer.write_packets(packets, FlushBehavior::Immediate, TrafficClass::Bulk).await;
        };

        let mut settings_guard =
            PendingClientSettingsGuard::take(&self.pending_client_settings).await;
        if let Some(settings) = settings_guard.frame.clone() {
            frames.insert(0, settings);
        }

        for chunk in target.chunks(MAX_PAYLOAD_LEN) {
            frames.push(Frame::psh(self.stream_id, chunk.to_vec()).encode()?);
        }
        if !data.is_empty() {
            for chunk in data.chunks(MAX_PAYLOAD_LEN) {
                frames.push(Frame::psh(self.stream_id, chunk.to_vec()).encode()?);
            }
        }
        let packets = self.coalesce_and_pad(&frames)?;

        let pending_write = self.submit_packets_or_fail(packets, TrafficClass::Control).await?;

        settings_guard.commit();
        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: true,
        };

        self.finish_pending_open_submission().await
    }

    async fn flush_pending_open_frames(&mut self) -> Result<(), anyhow::Error> {
        let Some(mut frames) = self.deferred_open_frames() else {
            return self.finish_pending_open_submission().await;
        };
        let mut settings_guard =
            PendingClientSettingsGuard::take(&self.pending_client_settings).await;
        if let Some(settings) = settings_guard.frame.clone() {
            frames.insert(0, settings);
        }
        let packets = self.coalesce_and_pad(&frames)?;

        let pending_write = self.submit_packets_or_fail(packets, TrafficClass::Control).await?;

        settings_guard.commit();
        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: false,
        };

        self.finish_pending_open_submission().await
    }

    async fn finish_pending_open_submission(&mut self) -> Result<(), anyhow::Error> {
        let pending_write = match &mut self.open_state {
            StreamOpenState::DeferredUnsent(_) => return Ok(()),
            StreamOpenState::Submitted { pending_write, .. } => pending_write.as_mut(),
        };

        let Some(pending_write) = pending_write else {
            return Ok(());
        };

        if let Err(err) = pending_write.wait().await {
            self.writer.close();
            self.open_failed = Some(err.to_string());
            return Err(err);
        }

        Ok(())
    }

    fn coalesce_and_pad(&self, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, anyhow::Error> {
        Ok(coalesce_encoded_frames(frames, MAX_PAYLOAD_LEN))
    }

    async fn submit_packets_or_fail(
        &mut self,
        packets: Vec<Vec<u8>>,
        traffic_class: TrafficClass,
    ) -> Result<PendingWrite, anyhow::Error> {
        match self
            .writer
            .submit_write_packets(packets, FlushBehavior::Immediate, traffic_class)
            .await
        {
            Ok(pw) => Ok(pw),
            Err(err) => {
                self.writer.close();
                self.open_failed = Some(err.to_string());
                Err(err)
            }
        }
    }

    fn mark_open_failed(&mut self, err: Error, close_writer: bool) -> anyhow::Error {
        if close_writer {
            self.writer.close();
        }
        let msg = err.to_string();
        self.open_failed = Some(msg.clone());
        anyhow::anyhow!(msg)
    }

    async fn write_frame(&self, frame: Frame) -> Result<(), anyhow::Error> {
        let payload = frame.encode()?;
        self.writer
            .write_packets(vec![payload], FlushBehavior::Immediate, TrafficClass::Bulk)
            .await
    }

    pub async fn close_write(&mut self) -> Result<(), anyhow::Error> {
        if self.closed || self.write_closed {
            return Ok(());
        }

        if self.has_deferred_open() || self.open_failed.is_some() {
            self.deferred_target = None;
            self.write_closed = true;
            self.closed = true;
            self.streams.write().await.remove(&self.stream_id);
            self.clear_pending_client_state().await;
            return Ok(());
        }

        self.deferred_target = None;

        self.finish_pending_open_submission().await?;

        let result = send_fin_frame(
            self.stream_id,
            self.writer.clone(),
        )
        .await;

        if result.is_ok() {
            self.write_closed = true;
        }
        result
    }

    pub async fn close(&mut self) -> Result<(), anyhow::Error> {
        if self.closed {
            self.streams.write().await.remove(&self.stream_id);
            self.clear_pending_client_state().await;
            return Ok(());
        }

        let result = if self.write_closed {
            Ok(())
        } else {
            self.close_write().await
        };
        remember_closing_stream_sync(self.stream_id, &self.closing_streams);
        self.streams.write().await.remove(&self.stream_id);
        self.clear_pending_client_state().await;
        self.closed = true;
        result
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.closed {
            return;
        }

        if self.has_deferred_open() || self.open_failed.is_some() {
            let stream_id = self.stream_id;
            let streams = self.streams.clone();
            let pending_data = self.pending_data.clone();
            let pending_fin = self.pending_fin.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    streams.write().await.remove(&stream_id);
                    pending_data.lock().await.remove(&stream_id);
                    pending_fin.lock().await.remove(&stream_id);
                });
            } else {
                if let Ok(mut streams) = self.streams.try_write() {
                    streams.remove(&stream_id);
                }
                if let Ok(mut pending_data) = self.pending_data.try_lock() {
                    pending_data.remove(&stream_id);
                }
                if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
                    pending_fin.remove(&stream_id);
                }
            }
            return;
        }

        let stream_id = self.stream_id;
        let streams = self.streams.clone();
        let pending_data = self.pending_data.clone();
        let pending_fin = self.pending_fin.clone();
        let closing_streams = self.closing_streams.clone();
        let writer = self.writer.clone();
        let write_closed = self.write_closed;
        let wait_for_pending_open = self.drop_waits_for_pending_open_flush();
        let pending_open_write = self.take_pending_open_write_for_drop();
        remember_closing_stream_sync(stream_id, &closing_streams);
        let fin_queued = !write_closed
            && !wait_for_pending_open
            && try_send_fin_frame(stream_id, &writer)
                .is_ok();
        if let Ok(mut streams) = self.streams.try_write() {
            streams.remove(&stream_id);
        }
        if let Ok(mut pending_data) = self.pending_data.try_lock() {
            pending_data.remove(&stream_id);
        }
        if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
            pending_fin.remove(&stream_id);
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Some(mut pending_write) = pending_open_write {
                    if wait_for_pending_open {
                        let _ = pending_write.wait().await;
                    }
                }
                if !write_closed && !fin_queued {
                    let _ = send_fin_frame(stream_id, writer).await;
                }
                streams.write().await.remove(&stream_id);
                pending_data.lock().await.remove(&stream_id);
                pending_fin.lock().await.remove(&stream_id);
            });
        }
    }
}

impl Stream {
    async fn clear_pending_client_state(&self) {
        self.pending_data.lock().await.remove(&self.stream_id);
        self.pending_fin.lock().await.remove(&self.stream_id);
    }

    fn deferred_open_frames(&self) -> Option<Vec<Vec<u8>>> {
        match &self.open_state {
            StreamOpenState::DeferredUnsent(frames) => Some(frames.clone()),
            StreamOpenState::Submitted { .. } => None,
        }
    }

    fn has_deferred_open(&self) -> bool {
        matches!(self.open_state, StreamOpenState::DeferredUnsent(_))
    }

    fn early_data_already_submitted(&self) -> bool {
        matches!(
            self.open_state,
            StreamOpenState::Submitted {
                early_data_submitted: true,
                ..
            }
        )
    }

    fn take_pending_open_write_for_drop(&mut self) -> Option<PendingWrite> {
        match &mut self.open_state {
            StreamOpenState::DeferredUnsent(_) => None,
            StreamOpenState::Submitted { pending_write, .. } => pending_write.take(),
        }
    }

    fn drop_waits_for_pending_open_flush(&self) -> bool {
        matches!(
            self.open_state,
            StreamOpenState::Submitted {
                early_data_submitted: true,
                ..
            }
        )
    }

    async fn wait_synack_once(&mut self) -> Result<(), anyhow::Error> {
        let Some(rx) = self.synack_rx.as_mut() else {
            return Ok(());
        };

        let payload =
            match tokio::time::timeout(std::time::Duration::from_secs(SYNACK_TIMEOUT_SECS), rx)
                .await
            {
                Ok(Ok(payload)) => payload,
                Ok(Err(_)) => {
                    self.synack_rx = None;
                    remember_closing_stream_sync(self.stream_id, &self.closing_streams);
                    self.streams.write().await.remove(&self.stream_id);
                    self.clear_pending_client_state().await;
                    return Err(self
                        .mark_open_failed(anyhow::anyhow!("stream closed before SYNACK"), false));
                }
                Err(_) => {
                    self.synack_rx = None;
                    remember_closing_stream_sync(self.stream_id, &self.closing_streams);
                    let _ = send_fin_frame(
                        self.stream_id,
                        self.writer.clone(),
                    )
                    .await;
                    self.streams.write().await.remove(&self.stream_id);
                    self.clear_pending_client_state().await;
                    return Err(self
                        .mark_open_failed(anyhow::anyhow!("timed out waiting for SYNACK"), false));
                }
            };

        self.synack_rx = None;
        if !payload.is_empty() {
            let msg = format!(
                "stream open rejected: {}",
                String::from_utf8_lossy(&payload)
            );
            self.open_failed = Some(msg.clone());
            remember_closing_stream_sync(self.stream_id, &self.closing_streams);
            self.streams.write().await.remove(&self.stream_id);
            self.clear_pending_client_state().await;
            anyhow::bail!(msg);
        }

        Ok(())
    }
}

impl PendingClientSettingsGuard {
    async fn take(settings: &PendingClientSettings) -> Self {
        Self {
            settings: settings.clone(),
            frame: settings.take().await,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
        self.frame = None;
    }
}

impl Drop for PendingClientSettingsGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        let Some(frame) = self.frame.take() else {
            return;
        };

        if let Ok(mut slot) = self.settings.slot.try_lock() {
            if slot.is_none() {
                *slot = Some(frame);
            }
            return;
        }

        let settings = self.settings.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                settings.restore(frame).await;
            });
        }
    }
}

pub(crate) async fn send_fin_frame(
    stream_id: u32,
    writer: SharedTunnelWriter,
) -> Result<(), anyhow::Error> {
    let payload = Frame::fin(stream_id).encode()?;
    writer
        .write_packets(vec![payload], FlushBehavior::Immediate, TrafficClass::Control)
        .await
}

pub(crate) fn try_send_fin_frame(
    stream_id: u32,
    writer: &SharedTunnelWriter,
) -> Result<(), anyhow::Error> {
    let payload = Frame::fin(stream_id).encode()?;
    writer.try_write_packets(vec![payload], FlushBehavior::Immediate, TrafficClass::Control)
}


