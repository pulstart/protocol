/// Wire format: [seq: u16 BE][frame_id: u32 BE][payload_type: u8] = 7 bytes
pub const HEADER_SIZE: usize = 7;
pub const MAX_UDP: usize = 1400;
pub const MAX_PAYLOAD: usize = MAX_UDP - HEADER_SIZE; // 1393
pub const FRAME_START_HEADER_SIZE: usize = 2 + 8 + 8;
pub const FRAME_PARITY_HEADER_SIZE: usize = 2 + 2 + 4 + 8 + 8;

/// Maximum number of previous opus packets that can be attached to a single
/// audio datagram. A datagram payload starts with a 1-byte chunk count, then
/// that many u16 chunk lengths, then the primary opus packet, then each
/// redundant chunk in oldest-first order.
pub const AUDIO_REDUNDANCY_MAX_DEPTH: usize = 4;

/// Bytes consumed by the redundancy header for `count` attached chunks
/// (1 count byte + 2 length bytes per chunk).
pub const fn audio_redundancy_header_size(count: usize) -> usize {
    1 + count * 2
}

/// Write the audio redundancy header into `buf`. `chunk_lens` is the length of
/// each redundant chunk in oldest-first order. Returns the number of bytes
/// written. The caller is responsible for writing the primary opus payload and
/// the redundant chunks (in matching order) after the returned offset.
pub fn serialize_audio_redundancy_header(buf: &mut [u8], chunk_lens: &[u16]) -> usize {
    assert!(
        chunk_lens.len() <= AUDIO_REDUNDANCY_MAX_DEPTH,
        "serialize_audio_redundancy_header: too many chunks"
    );
    let size = audio_redundancy_header_size(chunk_lens.len());
    assert!(
        buf.len() >= size,
        "serialize_audio_redundancy_header: buffer too small"
    );
    buf[0] = chunk_lens.len() as u8;
    for (i, len) in chunk_lens.iter().enumerate() {
        let offset = 1 + i * 2;
        buf[offset..offset + 2].copy_from_slice(&len.to_be_bytes());
    }
    size
}

/// View into an audio packet payload (the bytes after the 7-byte UDP header).
#[derive(Debug, Clone)]
pub struct AudioPacketView<'a> {
    pub primary: &'a [u8],
    /// Redundant copies of previous opus packets, oldest-first.
    /// `redundant[i]` is the opus packet at `primary_seq - (redundant.len() - i)`.
    pub redundant: Vec<&'a [u8]>,
}

/// Parse an audio payload that contains the redundancy header, the primary
/// opus packet, and zero or more redundant chunks (oldest-first).
pub fn parse_audio_packet(payload: &[u8]) -> Option<AudioPacketView<'_>> {
    if payload.is_empty() {
        return None;
    }
    let count = payload[0] as usize;
    if count > AUDIO_REDUNDANCY_MAX_DEPTH {
        return None;
    }
    let header_size = audio_redundancy_header_size(count);
    if payload.len() < header_size {
        return None;
    }
    let mut chunk_lens = [0usize; AUDIO_REDUNDANCY_MAX_DEPTH];
    let mut total_chunk_bytes: usize = 0;
    for (i, slot) in chunk_lens.iter_mut().enumerate().take(count) {
        let offset = 1 + i * 2;
        let len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        total_chunk_bytes = total_chunk_bytes.checked_add(len)?;
        *slot = len;
    }
    let body = &payload[header_size..];
    if total_chunk_bytes > body.len() {
        return None;
    }
    let primary_len = body.len() - total_chunk_bytes;
    let primary = &body[..primary_len];
    let mut redundant = Vec::with_capacity(count);
    let mut offset = primary_len;
    for &len in &chunk_lens[..count] {
        redundant.push(&body[offset..offset + len]);
        offset += len;
    }
    Some(AudioPacketView { primary, redundant })
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
    fn audio_redundancy_roundtrip_empty() {
        let mut buf = vec![0u8; audio_redundancy_header_size(0)];
        let n = serialize_audio_redundancy_header(&mut buf, &[]);
        assert_eq!(n, 1);
        buf.extend_from_slice(b"primary");
        let view = parse_audio_packet(&buf).unwrap();
        assert_eq!(view.primary, b"primary");
        assert!(view.redundant.is_empty());
    }

    #[test]
    fn audio_redundancy_roundtrip_multiple_chunks() {
        let chunks: Vec<&[u8]> = vec![b"oldest", b"middle", b"newest"];
        let lens: Vec<u16> = chunks.iter().map(|c| c.len() as u16).collect();
        let mut buf = vec![0u8; audio_redundancy_header_size(chunks.len())];
        serialize_audio_redundancy_header(&mut buf, &lens);
        buf.extend_from_slice(b"PRIMARY");
        for chunk in &chunks {
            buf.extend_from_slice(chunk);
        }
        let view = parse_audio_packet(&buf).unwrap();
        assert_eq!(view.primary, b"PRIMARY");
        assert_eq!(view.redundant.len(), 3);
        assert_eq!(view.redundant[0], b"oldest");
        assert_eq!(view.redundant[1], b"middle");
        assert_eq!(view.redundant[2], b"newest");
    }

    #[test]
    fn audio_redundancy_rejects_invalid_payload() {
        // Claims one chunk but body is empty.
        let buf = [0x01u8, 0x00, 0x10];
        assert!(parse_audio_packet(&buf).is_none());
        // Count exceeds the protocol limit.
        let buf = [(AUDIO_REDUNDANCY_MAX_DEPTH as u8) + 1, 0, 0];
        assert!(parse_audio_packet(&buf).is_none());
        // Truncated header (count = 1 needs 3 bytes, only 2 provided).
        let buf = [0x01u8, 0x00];
        assert!(parse_audio_packet(&buf).is_none());
    }
}
