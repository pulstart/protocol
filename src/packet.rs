/// Wire format: [seq: u16 BE][frame_id: u32 BE][payload_type: u8] = 7 bytes
pub const HEADER_SIZE: usize = 7;
pub const MAX_UDP: usize = 1400;
pub const MAX_PAYLOAD: usize = MAX_UDP - HEADER_SIZE; // 1393
pub const AUDIO_REDUNDANCY_HEADER_SIZE: usize = 2;
pub const FRAME_START_HEADER_SIZE: usize = 2 + 8 + 8;
pub const FRAME_PARITY_HEADER_SIZE: usize = 2 + 2 + 4 + 8 + 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AudioRedundancyMeta {
    pub redundant_len: u16,
}

impl AudioRedundancyMeta {
    pub fn serialize(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= AUDIO_REDUNDANCY_HEADER_SIZE,
            "AudioRedundancyMeta::serialize: buffer too small"
        );
        buf[0..2].copy_from_slice(&self.redundant_len.to_be_bytes());
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < AUDIO_REDUNDANCY_HEADER_SIZE {
            return None;
        }
        let redundant_len = u16::from_be_bytes([buf[0], buf[1]]);
        if redundant_len as usize > buf.len().saturating_sub(AUDIO_REDUNDANCY_HEADER_SIZE) {
            return None;
        }
        Some(Self { redundant_len })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameTimingMeta {
    pub capture_ts_micros: u64,
    pub send_ts_micros: u64,
}

impl FrameTimingMeta {
    pub fn serialize(&self, total_packets: u16, buf: &mut [u8]) {
        assert!(buf.len() >= FRAME_START_HEADER_SIZE, "FrameTimingMeta::serialize: buffer too small");
        buf[0..2].copy_from_slice(&total_packets.to_be_bytes());
        buf[2..10].copy_from_slice(&self.capture_ts_micros.to_be_bytes());
        buf[10..18].copy_from_slice(&self.send_ts_micros.to_be_bytes());
    }

    pub fn deserialize(buf: &[u8]) -> Option<(u16, Self)> {
        if buf.len() < FRAME_START_HEADER_SIZE {
            return None;
        }
        let total_packets = u16::from_be_bytes([buf[0], buf[1]]);
        let capture_ts_micros = u64::from_be_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        let send_ts_micros = u64::from_be_bytes([
            buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        ]);
        Some((
            total_packets,
            Self {
                capture_ts_micros,
                send_ts_micros,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameParityMeta {
    pub start_seq: u16,
    pub total_packets: u16,
    pub chunk_bytes_sum: u32,
    pub timing: FrameTimingMeta,
}

impl FrameParityMeta {
    pub fn serialize(&self, buf: &mut [u8]) {
        assert!(buf.len() >= FRAME_PARITY_HEADER_SIZE, "FrameParityMeta::serialize: buffer too small");
        buf[0..2].copy_from_slice(&self.start_seq.to_be_bytes());
        buf[2..4].copy_from_slice(&self.total_packets.to_be_bytes());
        buf[4..8].copy_from_slice(&self.chunk_bytes_sum.to_be_bytes());
        buf[8..16].copy_from_slice(&self.timing.capture_ts_micros.to_be_bytes());
        buf[16..24].copy_from_slice(&self.timing.send_ts_micros.to_be_bytes());
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < FRAME_PARITY_HEADER_SIZE {
            return None;
        }
        Some(Self {
            start_seq: u16::from_be_bytes([buf[0], buf[1]]),
            total_packets: u16::from_be_bytes([buf[2], buf[3]]),
            chunk_bytes_sum: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            timing: FrameTimingMeta {
                capture_ts_micros: u64::from_be_bytes([
                    buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]),
                send_ts_micros: u64::from_be_bytes([
                    buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
                ]),
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// First packet of a video frame — payload starts with 2-byte total_packets count
    FrameStart = 0,
    /// Continuation packet of a video frame
    Data = 1,
    /// Single audio packet: current Opus payload plus optional previous-packet redundancy.
    Audio = 2,
    /// Single-parity FEC packet for a video unit.
    Parity = 8,
    /// Absolute mouse position input from client to server.
    MouseAbsolute = 3,
    /// Relative mouse delta input from client to server.
    MouseRelative = 4,
    /// Full mouse button state snapshot from client to server.
    MouseButtons = 5,
    /// Mouse wheel input from client to server.
    MouseWheel = 6,
    /// Full keyboard key-state snapshot from client to server.
    KeyboardState = 7,
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::FrameStart),
            1 => Some(Self::Data),
            2 => Some(Self::Audio),
            8 => Some(Self::Parity),
            3 => Some(Self::MouseAbsolute),
            4 => Some(Self::MouseRelative),
            5 => Some(Self::MouseButtons),
            6 => Some(Self::MouseWheel),
            7 => Some(Self::KeyboardState),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub seq: u16,
    pub frame_id: u32,
    pub payload_type: PayloadType,
}

impl PacketHeader {
    pub fn serialize(&self, buf: &mut [u8]) {
        assert!(buf.len() >= HEADER_SIZE, "PacketHeader::serialize: buffer too small");
        buf[0..2].copy_from_slice(&self.seq.to_be_bytes());
        buf[2..6].copy_from_slice(&self.frame_id.to_be_bytes());
        buf[6] = self.payload_type as u8;
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        let seq = u16::from_be_bytes([buf[0], buf[1]]);
        let frame_id = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let payload_type = PayloadType::from_u8(buf[6])?;
        Some(Self {
            seq,
            frame_id,
            payload_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let hdr = PacketHeader {
            seq: 300,
            frame_id: 123456,
            payload_type: PayloadType::FrameStart,
        };
        let mut buf = [0u8; HEADER_SIZE];
        hdr.serialize(&mut buf);
        let hdr2 = PacketHeader::deserialize(&buf).unwrap();
        assert_eq!(hdr.seq, hdr2.seq);
        assert_eq!(hdr.frame_id, hdr2.frame_id);
        assert_eq!(hdr.payload_type, hdr2.payload_type);
    }

    #[test]
    fn too_short() {
        assert!(PacketHeader::deserialize(&[0u8; 5]).is_none());
    }

    #[test]
    fn roundtrip_frame_timing_meta() {
        let meta = FrameTimingMeta {
            capture_ts_micros: 123,
            send_ts_micros: 456,
        };
        let mut buf = [0u8; FRAME_START_HEADER_SIZE];
        meta.serialize(7, &mut buf);
        let (total_packets, decoded) = FrameTimingMeta::deserialize(&buf).unwrap();
        assert_eq!(total_packets, 7);
        assert_eq!(decoded, meta);
    }

    #[test]
    fn roundtrip_frame_parity_meta() {
        let meta = FrameParityMeta {
            start_seq: 91,
            total_packets: 7,
            chunk_bytes_sum: 55_000,
            timing: FrameTimingMeta {
                capture_ts_micros: 123,
                send_ts_micros: 456,
            },
        };
        let mut buf = [0u8; FRAME_PARITY_HEADER_SIZE];
        meta.serialize(&mut buf);
        assert_eq!(FrameParityMeta::deserialize(&buf).unwrap(), meta);
    }

    #[test]
    fn roundtrip_audio_redundancy_meta() {
        let meta = AudioRedundancyMeta { redundant_len: 0 };
        let mut buf = [0u8; AUDIO_REDUNDANCY_HEADER_SIZE];
        meta.serialize(&mut buf);
        assert_eq!(AudioRedundancyMeta::deserialize(&buf).unwrap(), meta);
    }

    #[test]
    fn rejects_invalid_audio_redundancy_meta() {
        let buf = [0x01, 0x00, 0xAA];
        assert!(AudioRedundancyMeta::deserialize(&buf).is_none());
    }
}
