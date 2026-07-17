use bytes::{Buf, BytesMut};

pub const FRAME_HEADER_SIZE: usize = 7;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

pub const CMD_SYN: u8 = 0x01;
pub const CMD_PSH: u8 = 0x02;
pub const CMD_FIN: u8 = 0x03;
pub const CMD_SETTINGS: u8 = 0x04;
pub const CMD_SYNACK: u8 = 0x07;
pub const CMD_PADDING: u8 = 0x08;

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(cmd: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        Self {
            cmd,
            stream_id,
            payload,
        }
    }

    pub fn cmd_settings() -> Self {
        Self::new(CMD_SETTINGS, 0, b"v=2;name=kanotls".to_vec())
    }

    pub fn syn(stream_id: u32) -> Self {
        Self::new(CMD_SYN, stream_id, vec![])
    }

    pub fn psh(stream_id: u32, data: Vec<u8>) -> Self {
        Self::new(CMD_PSH, stream_id, data)
    }

    pub fn fin(stream_id: u32) -> Self {
        Self::new(CMD_FIN, stream_id, vec![])
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            anyhow::bail!(
                "frame payload too large: {} > {}",
                self.payload.len(),
                MAX_PAYLOAD_LEN
            );
        }
        let data_len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data_len as usize);
        buf.push(self.cmd);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    pub fn encode_psh(stream_id: u32, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        Self::encode_psh_into(&mut buf, stream_id, payload)?;
        Ok(buf)
    }

    pub fn encode_psh_into(
        dst: &mut Vec<u8>,
        stream_id: u32,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if payload.len() > MAX_PAYLOAD_LEN {
            anyhow::bail!(
                "frame payload too large: {} > {}",
                payload.len(),
                MAX_PAYLOAD_LEN
            );
        }
        dst.push(CMD_PSH);
        dst.extend_from_slice(&stream_id.to_be_bytes());
        dst.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        dst.extend_from_slice(payload);
        Ok(())
    }

    pub fn encoded_len(payload_len: usize) -> usize {
        FRAME_HEADER_SIZE + payload_len
    }

    pub fn decode(src: &mut BytesMut) -> Option<Frame> {
        if src.len() < FRAME_HEADER_SIZE {
            return None;
        }
        let cmd = src[0];
        let stream_id = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        let data_len = u16::from_be_bytes([src[5], src[6]]) as usize;

        if src.len() < FRAME_HEADER_SIZE + data_len {
            return None;
        }

        src.advance(FRAME_HEADER_SIZE);
        let payload = src.split_to(data_len).to_vec();

        Some(Frame {
            cmd,
            stream_id,
            payload,
        })
    }
}

/// Append an encoded CMD_PADDING request frame to `dst`: 7-byte header
/// (cmd=CMD_PADDING, stream_id=0) + `[flag=0, m]` + entropy-pool junk,
/// written in a single resize. `m` dictates how many reply chunks the
/// receiver must emit.
pub fn encode_padding_request_into(dst: &mut Vec<u8>, m: u8) {
    let junk_len = 32 + (m as usize).saturating_mul(16).min(192);
    encode_padding_frame_into(dst, 0, m, junk_len);
}

/// Append an encoded CMD_PADDING reply frame to `dst`: 7-byte header
/// (cmd=CMD_PADDING, stream_id=0) + `[flag=1, 0]` + entropy-pool junk,
/// written in a single resize. `junk_len` is clamped to a minimum of 16.
pub fn encode_padding_reply_into(dst: &mut Vec<u8>, junk_len: usize) {
    encode_padding_frame_into(dst, 1, 0, junk_len.max(16));
}

fn encode_padding_frame_into(dst: &mut Vec<u8>, flag: u8, m: u8, junk_len: usize) {
    let payload_len = junk_len + 2;
    let start = dst.len();
    dst.resize(start + FRAME_HEADER_SIZE + payload_len, 0);
    dst[start] = CMD_PADDING;
    dst[start + 1..start + 5].copy_from_slice(&0u32.to_be_bytes());
    dst[start + 5..start + 7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    dst[start + 7] = flag;
    dst[start + 8] = m;
    kanotls_tunnel::fill_from_pool(&mut dst[start + FRAME_HEADER_SIZE + 2..]);
}

/// Encode `data` into a sequence of CMD_PSH frames for `stream_id`, chunked
/// to MAX_PAYLOAD_LEN. Empty input yields no frames (callers emit an explicit
/// empty PSH themselves where the protocol needs one).
pub(crate) fn encode_psh_frames(stream_id: u32, data: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::with_capacity(data.len().div_ceil(MAX_PAYLOAD_LEN));
    for chunk in data.chunks(MAX_PAYLOAD_LEN) {
        let mut pkt = Vec::with_capacity(Frame::encoded_len(chunk.len()));
        Frame::encode_psh_into(&mut pkt, stream_id, chunk)?;
        packets.push(pkt);
    }
    Ok(packets)
}

pub(crate) fn coalesce_encoded_frames(
    frames: Vec<Vec<u8>>,
    max_packet_len: usize,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for frame in frames {
        if frame.len() > max_packet_len {
            if !current.is_empty() {
                out.push(std::mem::replace(
                    &mut current,
                    Vec::with_capacity(max_packet_len),
                ));
            }
            out.push(frame);
            continue;
        }

        if current.len() + frame.len() > max_packet_len && !current.is_empty() {
            out.push(std::mem::replace(
                &mut current,
                Vec::with_capacity(max_packet_len),
            ));
        }
        current.extend_from_slice(&frame);
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rejects_oversized_payload_instead_of_truncating() {
        let frame = Frame::psh(1, vec![0u8; MAX_PAYLOAD_LEN + 1]);
        assert!(frame.encode().is_err());
    }

    #[test]
    fn encode_decode_round_trip_max_payload() {
        let payload = vec![7u8; MAX_PAYLOAD_LEN];
        let frame = Frame::psh(42, payload.clone());
        let encoded = frame.encode().unwrap();
        let mut buf = BytesMut::from(encoded.as_slice());
        let decoded = Frame::decode(&mut buf).unwrap();
        assert_eq!(decoded.cmd, CMD_PSH);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload, payload);
    }
}
