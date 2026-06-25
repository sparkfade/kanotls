use bytes::{Buf, BytesMut};

pub const FRAME_HEADER_SIZE: usize = 7;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

pub const CMD_SYN: u8 = 0x01;
pub const CMD_PSH: u8 = 0x02;
pub const CMD_FIN: u8 = 0x03;
pub const CMD_SETTINGS: u8 = 0x04;
pub const CMD_SYNACK: u8 = 0x07;

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
        if payload.len() > MAX_PAYLOAD_LEN {
            anyhow::bail!(
                "frame payload too large: {} > {}",
                payload.len(),
                MAX_PAYLOAD_LEN
            );
        }
        let data_len = payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data_len as usize);
        buf.push(CMD_PSH);
        buf.extend_from_slice(&stream_id.to_be_bytes());
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(payload);
        Ok(buf)
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

pub(crate) fn coalesce_encoded_frames(frames: &[Vec<u8>], max_packet_len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for frame in frames {
        if frame.len() > max_packet_len {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            out.push(frame.clone());
            continue;
        }

        if current.len() + frame.len() > max_packet_len && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current.extend_from_slice(frame);
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
