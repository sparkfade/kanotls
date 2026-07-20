use crate::frame::{coalesce_encoded_frames, encode_psh_frames, Frame, MAX_PAYLOAD_LEN};
use crate::session::{
    mark_stream_read_closed_locked, remember_closing_stream_sync, unregister_stream_locked,
    BufferedPayload, FlushBehavior, PendingData, PendingWrite, SharedTunnelWriter, StreamHandle,
    TrafficClass,
};
use anyhow::Error;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::{mpsc, oneshot, Notify, RwLock};

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

pub(crate) struct StreamParts {
    pub data_rx: mpsc::Receiver<BufferedPayload>,
    pub fin_rx: mpsc::Receiver<()>,
    pub synack_rx: oneshot::Receiver<Vec<u8>>,
}

pub(crate) struct StreamInit {
    pub stream_id: u32,
    pub parts: StreamParts,
    pub writer: SharedTunnelWriter,
    pub streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    pub capacity_stream_count: Arc<AtomicUsize>,
    pub pending_data: Arc<Mutex<PendingData>>,
    pub pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    pub closing_streams: Arc<Mutex<std::collections::HashSet<u32>>>,
    pub pending_notify: Arc<Notify>,
    pub open_state: StreamOpenState,
}

pub struct Stream {
    pub stream_id: u32,
    data_rx: mpsc::Receiver<BufferedPayload>,
    fin_rx: mpsc::Receiver<()>,
    synack_rx: Option<oneshot::Receiver<Vec<u8>>>,

    writer: SharedTunnelWriter,
    streams: Arc<RwLock<HashMap<u32, StreamHandle>>>,
    capacity_stream_count: Arc<AtomicUsize>,
    pending_data: Arc<Mutex<PendingData>>,
    pending_fin: Arc<Mutex<std::collections::HashSet<u32>>>,
    closing_streams: Arc<Mutex<std::collections::HashSet<u32>>>,
    pending_notify: Arc<Notify>,
    open_state: StreamOpenState,
    deferred_target: Option<Vec<u8>>,
    read_closed: bool,
    write_closed: bool,
    closed: bool,
    open_failed: Option<String>,
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
            capacity_stream_count: init.capacity_stream_count,
            pending_data: init.pending_data,
            pending_fin: init.pending_fin,
            closing_streams: init.closing_streams,
            pending_notify: init.pending_notify,
            open_state: init.open_state,
            deferred_target: None,
            read_closed: false,
            write_closed: false,
            closed: false,
            open_failed: None,
        }
    }

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
                    // 先置 read_closed 再回路排空：channel/pending_data 中的
                    // 残留数据仍会在返回 None 之前被投递（见循环开头两步）。
                    // fin 令牌只此一枚——若消费令牌后因恰好又有数据而直接返回，
                    // 却不置位，一旦后续出现乱序/丢帧，read 将永远挂在 select。
                    self.read_closed = true;
                    continue;
                }
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

        let packets = encode_psh_frames(self.stream_id, data)?;
        self.writer
            .write_packets(packets, flush, TrafficClass::Bulk)
            .await
    }

    async fn write_pending_open_with_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        let Some(mut frames) = self.deferred_open_frames() else {
            return self
                .write_data_frame_with_flush(data, FlushBehavior::Immediate)
                .await;
        };
        if data.is_empty() {
            frames.push(Frame::psh(self.stream_id, Vec::new()).encode()?);
        } else {
            frames.extend(encode_psh_frames(self.stream_id, data)?);
        }
        let packets = self.coalesce_and_pad(frames)?;

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

        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: true,
        };

        self.finish_pending_open_submission().await
    }

    async fn write_gather_open(&mut self, target: &[u8], data: &[u8]) -> Result<(), anyhow::Error> {
        let Some(mut frames) = self.deferred_open_frames() else {
            self.finish_pending_open_submission().await?;
            let mut combined_frames = encode_psh_frames(self.stream_id, target)?;
            if !data.is_empty() {
                combined_frames.extend(encode_psh_frames(self.stream_id, data)?);
            }
            let packets = self.coalesce_and_pad(combined_frames)?;
            return self
                .writer
                .write_packets(packets, FlushBehavior::Immediate, TrafficClass::Bulk)
                .await;
        };

        frames.extend(encode_psh_frames(self.stream_id, target)?);
        if !data.is_empty() {
            frames.extend(encode_psh_frames(self.stream_id, data)?);
        }
        let packets = self.coalesce_and_pad(frames)?;

        let pending_write = self
            .submit_packets_or_fail(packets, TrafficClass::Control)
            .await?;

        self.open_state = StreamOpenState::Submitted {
            pending_write: Some(pending_write),
            early_data_submitted: true,
        };

        self.finish_pending_open_submission().await
    }

    async fn flush_pending_open_frames(&mut self) -> Result<(), anyhow::Error> {
        let Some(frames) = self.deferred_open_frames() else {
            return self.finish_pending_open_submission().await;
        };
        let packets = self.coalesce_and_pad(frames)?;

        let pending_write = self
            .submit_packets_or_fail(packets, TrafficClass::Control)
            .await?;

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

    fn coalesce_and_pad(&self, frames: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, anyhow::Error> {
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
            self.unregister_stream().await;
            self.clear_pending_client_state().await;
            return Ok(());
        }

        self.deferred_target = None;

        self.finish_pending_open_submission().await?;

        let result = send_fin_frame(self.stream_id, self.writer.clone()).await;

        if result.is_ok() {
            self.write_closed = true;
        }
        result
    }

    pub async fn close(&mut self) -> Result<(), anyhow::Error> {
        if self.closed {
            self.unregister_stream().await;
            self.clear_pending_client_state().await;
            return Ok(());
        }

        let result = if self.write_closed {
            Ok(())
        } else {
            self.close_write().await
        };
        remember_closing_stream_sync(self.stream_id, &self.closing_streams);
        self.unregister_stream().await;
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
            let capacity_stream_count = self.capacity_stream_count.clone();
            let pending_data = self.pending_data.clone();
            let pending_fin = self.pending_fin.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    unregister_stream_locked(
                        &mut *streams.write().await,
                        &capacity_stream_count,
                        stream_id,
                    );
                    pending_data.lock().await.remove(stream_id);
                    pending_fin.lock().await.remove(&stream_id);
                });
            } else {
                if let Ok(mut streams) = self.streams.try_write() {
                    unregister_stream_locked(&mut streams, &self.capacity_stream_count, stream_id);
                }
                if let Ok(mut pending_data) = self.pending_data.try_lock() {
                    pending_data.remove(stream_id);
                }
                if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
                    pending_fin.remove(&stream_id);
                }
            }
            return;
        }

        let stream_id = self.stream_id;
        let streams = self.streams.clone();
        let capacity_stream_count = self.capacity_stream_count.clone();
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
            && try_send_fin_frame(stream_id, &writer).is_ok();
        if let Ok(mut streams) = self.streams.try_write() {
            if let Some(handle) = streams.get_mut(&stream_id) {
                mark_stream_read_closed_locked(handle, &self.capacity_stream_count);
            }
        }
        if let Ok(mut pending_data) = self.pending_data.try_lock() {
            pending_data.remove(stream_id);
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
                unregister_stream_locked(
                    &mut *streams.write().await,
                    &capacity_stream_count,
                    stream_id,
                );
                pending_data.lock().await.remove(stream_id);
                pending_fin.lock().await.remove(&stream_id);
            });
        }
    }
}

impl Stream {
    async fn unregister_stream(&self) {
        unregister_stream_locked(
            &mut *self.streams.write().await,
            &self.capacity_stream_count,
            self.stream_id,
        );
    }

    async fn clear_pending_client_state(&self) {
        // 移除的入账载荷随队列丢弃自动回账。
        self.pending_data.lock().await.remove(self.stream_id);
        self.pending_fin.lock().await.remove(&self.stream_id);
    }

    fn try_drain_pending_data(&mut self) -> Option<Vec<u8>> {
        let mut pending = self.pending_data.try_lock().ok()?;
        let Some(queue) = pending.get_mut(self.stream_id) else {
            // pending_data 已排空：若 pre-SYNACK 的 FIN 曾因部分投递被退回
            // 重挂（flush_client_pending_stream），此刻即应补投为 EOF。
            drop(pending);
            self.take_queued_pending_fin();
            return None;
        };
        let payload = queue.pop_front()?;
        let drained = queue.is_empty();
        if drained {
            pending.remove(self.stream_id);
        }
        drop(pending);
        if drained {
            self.take_queued_pending_fin();
        }
        Some(payload.into_vec())
    }

    fn take_queued_pending_fin(&mut self) {
        if let Ok(mut pending_fin) = self.pending_fin.try_lock() {
            if pending_fin.remove(&self.stream_id) {
                self.read_closed = true;
            }
        }
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
                    self.unregister_stream().await;
                    self.clear_pending_client_state().await;
                    return Err(self
                        .mark_open_failed(anyhow::anyhow!("stream closed before SYNACK"), false));
                }
                Err(_) => {
                    self.synack_rx = None;
                    remember_closing_stream_sync(self.stream_id, &self.closing_streams);
                    let _ = send_fin_frame(self.stream_id, self.writer.clone()).await;
                    self.unregister_stream().await;
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
            self.unregister_stream().await;
            self.clear_pending_client_state().await;
            anyhow::bail!(msg);
        }

        Ok(())
    }
}

pub(crate) async fn send_fin_frame(
    stream_id: u32,
    writer: SharedTunnelWriter,
) -> Result<(), anyhow::Error> {
    let payload = Frame::fin(stream_id).encode()?;
    // FIN 必须留在 control 通道：与后续 SYN/SYNACK 等 control 帧保持 FIFO；
    // 而写循环的 control 分支会先把 bulk channel 中已到达的请求并入
    // pending 统一冲刷，因此 FIN 也不会越过此前写入的 bulk 数据。
    writer
        .write_packets(
            vec![payload],
            FlushBehavior::Immediate,
            TrafficClass::Control,
        )
        .await
}

pub(crate) fn try_send_fin_frame(
    stream_id: u32,
    writer: &SharedTunnelWriter,
) -> Result<(), anyhow::Error> {
    let payload = Frame::fin(stream_id).encode()?;
    // 同 send_fin_frame：Control 保序；try_send 失败由调用方回退到异步发送。
    writer.try_write_packets(
        vec![payload],
        FlushBehavior::Immediate,
        TrafficClass::Control,
    )
}
