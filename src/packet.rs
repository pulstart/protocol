/// Wire format: [seq: u16 BE][frame_id: u32 BE][payload_type: u8] = 7 bytes
pub const HEADER_SIZE: usize = 7;
pub const MAX_UDP: usize = 1400;
pub const MAX_PAYLOAD: usize = MAX_UDP - HEADER_SIZE; // 1393
pub const FRAME_START_HEADER_SIZE: usize = 2 + 8 + 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameTimingMeta {
    pub capture_ts_micros: u64,
    pub send_ts_micros: u64,
}

impl FrameTimingMeta {
    pub fn serialize(&self, total_packets: u16, buf: &mut [u8]) {
        debug_assert!(buf.len() >= FRAME_START_HEADER_SIZE);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// First packet of a video frame — payload starts with 2-byte total_packets count
    FrameStart = 0,
    /// Continuation packet of a video frame
    Data = 1,
    /// Single audio packet (raw Opus frame, no reassembly needed)
    Audio = 2,
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
        debug_assert!(buf.len() >= HEADER_SIZE);
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
}
