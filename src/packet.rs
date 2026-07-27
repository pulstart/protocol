/// Wire format: [seq: u16 BE][frame_id: u32 BE][payload_type: u8] = 7 bytes
pub const HEADER_SIZE: usize = 7;
pub const MAX_UDP: usize = 1400;
pub const MAX_PAYLOAD: usize = MAX_UDP - HEADER_SIZE; // 1393
/// FrameStart meta: total_packets(2) + capture_ts(8) + send_ts(8) +
/// video_epoch(8) + frame_type(1).
pub const FRAME_START_HEADER_SIZE: usize = 2 + 8 + 8 + 8 + 1;
/// Parity meta: start_seq(2) total_packets(2) chunk_bytes_sum(4) capture_ts(8)
/// send_ts(8) video_epoch(8) + RS extension data_shards(2) parity_shards(2)
/// shard_index(2) shard_len(2) frame_type(1). `parity_shards == 0` is the
/// single-XOR degenerate case (A1); any positive value selects Reed-Solomon
/// block recovery.
pub const FRAME_PARITY_HEADER_SIZE: usize = 2 + 2 + 4 + 8 + 8 + 8 + 2 + 2 + 2 + 2 + 1;

/// Hard cap on the number of packets one encoded video unit may be sliced into.
///
/// The receiver enforces this in `FrameAssembler` (an over-cap `total_packets`
/// fails validation, so the unit can never be reassembled) — which means the
/// *sender* must enforce the same bound, or it emits units that are silently
/// undecodable forever. That is not hypothetical: an over-cap IDR would be
/// dropped by the assembler, the client would ask for another keyframe, and the
/// encoder would answer with another over-cap IDR — a permanent freeze with no
/// error on either side. `FrameSlicer` refuses to slice past this so the failure
/// surfaces as a loud send error instead.
pub const MAX_UNIT_PACKETS: u16 = 4096;

/// FEC scheme for a video unit's parity packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FecMode {
    /// Single XOR parity packet — recovers exactly one lost media packet/unit.
    #[default]
    Xor,
    /// Reed-Solomon block FEC — recovers up to `parity_shards` lost packets/unit.
    Rs,
}

impl FecMode {
    /// Parse the `ST_FEC` env value. `rs` selects Reed-Solomon; anything else
    /// (including unset) keeps the always-correct XOR default.
    pub fn from_env_value(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "rs" | "reed-solomon" | "reedsolomon" => FecMode::Rs,
            _ => FecMode::Xor,
        }
    }
}

/// Frame type carried in the FrameStart header (A4) so the client drives its
/// recovery state machine off an explicit marker instead of trial-decoding.
pub mod frame_type {
    /// Inter (P) frame.
    pub const P: u8 = 1;
    /// IDR keyframe (also the always-correct recovery floor today).
    pub const IDR: u8 = 2;
    /// Recovery frame after reference-frame invalidation / intra-refresh — not a
    /// full IDR. Emitted once the A3 recovery ladder lands; clients exit
    /// recovery on it the same as on an IDR.
    pub const RECOVERY: u8 = 5;

    /// Map the server-side `is_recovery` (== keyframe) bool to a wire frame
    /// type. Today every recovery is a full IDR, so a keyframe is tagged IDR;
    /// non-keyframes are P.
    pub const fn from_is_recovery(is_recovery: bool) -> u8 {
        if is_recovery {
            IDR
        } else {
            P
        }
    }
}

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
    pub video_epoch: u64,
}

impl FrameTimingMeta {
    /// Serialize the FrameStart meta with the frame's `total_packets` and
    /// `frame_type` (see [`frame_type`]).
    pub fn serialize(&self, total_packets: u16, frame_type: u8, buf: &mut [u8]) {
        assert!(
            buf.len() >= FRAME_START_HEADER_SIZE,
            "FrameTimingMeta::serialize: buffer too small"
        );
        buf[0..2].copy_from_slice(&total_packets.to_be_bytes());
        buf[2..10].copy_from_slice(&self.capture_ts_micros.to_be_bytes());
        buf[10..18].copy_from_slice(&self.send_ts_micros.to_be_bytes());
        buf[18..26].copy_from_slice(&self.video_epoch.to_be_bytes());
        buf[26] = frame_type;
    }

    /// Deserialize the FrameStart meta. Returns `(total_packets, frame_type,
    /// timing)`. `buf` is the packet payload, which carries frame data after the
    /// meta, so only the leading header bytes are read.
    pub fn deserialize(buf: &[u8]) -> Option<(u16, u8, Self)> {
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
        let video_epoch = u64::from_be_bytes([
            buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24], buf[25],
        ]);
        Some((
            total_packets,
            buf[26],
            Self {
                capture_ts_micros,
                send_ts_micros,
                video_epoch,
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
    /// RS block: number of data shards (== `total_packets` for the unit). 0 in
    /// the XOR degenerate case.
    pub data_shards: u16,
    /// RS block: number of parity shards (M). 0 ⇒ XOR single-parity.
    pub parity_shards: u16,
    /// RS recovery-shard index this packet carries (`0..parity_shards`).
    pub shard_index: u16,
    /// RS shard byte length (data shards are length-prefixed + zero-padded to
    /// this; even, per `reed-solomon-simd`). 0 in the XOR case.
    pub shard_len: u16,
    /// Frame type of the unit (see [`frame_type`]) so a parity-recovered
    /// FrameStart still knows IDR vs P.
    pub frame_type: u8,
}

impl FrameParityMeta {
    /// True when this parity packet carries a Reed-Solomon shard rather than the
    /// XOR single-parity payload.
    pub fn is_rs(&self) -> bool {
        self.parity_shards > 0
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= FRAME_PARITY_HEADER_SIZE,
            "FrameParityMeta::serialize: buffer too small"
        );
        buf[0..2].copy_from_slice(&self.start_seq.to_be_bytes());
        buf[2..4].copy_from_slice(&self.total_packets.to_be_bytes());
        buf[4..8].copy_from_slice(&self.chunk_bytes_sum.to_be_bytes());
        buf[8..16].copy_from_slice(&self.timing.capture_ts_micros.to_be_bytes());
        buf[16..24].copy_from_slice(&self.timing.send_ts_micros.to_be_bytes());
        buf[24..32].copy_from_slice(&self.timing.video_epoch.to_be_bytes());
        buf[32..34].copy_from_slice(&self.data_shards.to_be_bytes());
        buf[34..36].copy_from_slice(&self.parity_shards.to_be_bytes());
        buf[36..38].copy_from_slice(&self.shard_index.to_be_bytes());
        buf[38..40].copy_from_slice(&self.shard_len.to_be_bytes());
        buf[40] = self.frame_type;
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < FRAME_PARITY_HEADER_SIZE {
            return None;
        }
        let timing = FrameTimingMeta {
            capture_ts_micros: u64::from_be_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            send_ts_micros: u64::from_be_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            video_epoch: u64::from_be_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
        };
        Some(Self {
            start_seq: u16::from_be_bytes([buf[0], buf[1]]),
            total_packets: u16::from_be_bytes([buf[2], buf[3]]),
            chunk_bytes_sum: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            timing,
            data_shards: u16::from_be_bytes([buf[32], buf[33]]),
            parity_shards: u16::from_be_bytes([buf[34], buf[35]]),
            shard_index: u16::from_be_bytes([buf[36], buf[37]]),
            shard_len: u16::from_be_bytes([buf[38], buf[39]]),
            frame_type: buf[40],
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
    /// Server→client liveness keepalive (header only, no payload). Sent on the
    /// media path when no video is flowing (e.g. a static screen, where the
    /// capture backend produces no new frames) so the client can distinguish a
    /// genuinely dead UDP path from an idle one and not false-trigger reconnect.
    Keepalive = 9,
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
            9 => Some(Self::Keepalive),
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
        assert!(
            buf.len() >= HEADER_SIZE,
            "PacketHeader::serialize: buffer too small"
        );
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
            video_epoch: 789,
        };
        let mut buf = [0u8; FRAME_START_HEADER_SIZE];
        meta.serialize(7, frame_type::IDR, &mut buf);
        let (total_packets, ftype, decoded) = FrameTimingMeta::deserialize(&buf).unwrap();
        assert_eq!(total_packets, 7);
        assert_eq!(ftype, frame_type::IDR);
        assert_eq!(decoded, meta);

        // A header shorter than the full meta is rejected.
        assert!(FrameTimingMeta::deserialize(&buf[..FRAME_START_HEADER_SIZE - 1]).is_none());
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
                video_epoch: 789,
            },
            ..Default::default()
        };
        let mut buf = [0u8; FRAME_PARITY_HEADER_SIZE];
        meta.serialize(&mut buf);
        let decoded = FrameParityMeta::deserialize(&buf).unwrap();
        assert_eq!(decoded, meta);
        assert!(!decoded.is_rs());
    }

    #[test]
    fn roundtrip_frame_parity_meta_rs() {
        let meta = FrameParityMeta {
            start_seq: 91,
            total_packets: 7,
            chunk_bytes_sum: 55_000,
            timing: FrameTimingMeta {
                capture_ts_micros: 123,
                send_ts_micros: 456,
                video_epoch: 789,
            },
            data_shards: 7,
            parity_shards: 3,
            shard_index: 2,
            shard_len: 1360,
            frame_type: frame_type::IDR,
        };
        let mut buf = [0u8; FRAME_PARITY_HEADER_SIZE];
        meta.serialize(&mut buf);
        let decoded = FrameParityMeta::deserialize(&buf).unwrap();
        assert_eq!(decoded, meta);
        assert!(decoded.is_rs());

        // A header shorter than the full meta is rejected.
        assert!(FrameParityMeta::deserialize(&buf[..FRAME_PARITY_HEADER_SIZE - 1]).is_none());
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
