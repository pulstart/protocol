use crate::packet::{
    FrameParityMeta, FrameTimingMeta, PacketHeader, PayloadType, FRAME_PARITY_HEADER_SIZE,
    FRAME_START_HEADER_SIZE, HEADER_SIZE,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct CompletedFrame {
    pub frame_id: u32,
    pub video_epoch: u64,
    pub data: Vec<u8>,
    pub timing: FrameTimingMeta,
    /// Frame type from the FrameStart header (see [`crate::packet::frame_type`]).
    /// Lets the client recovery state machine key off an explicit marker instead
    /// of trial-decoding. Defaults to `P` when the FrameStart packet was lost and
    /// the frame was recovered via parity (no header bytes to read it from).
    pub frame_type: u8,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyFeedback {
    pub lost_packets: u32,
    pub late_packets: u32,
    pub dropped_frames: u32,
}

impl AssemblyFeedback {
    fn merge(&mut self, other: Self) {
        self.lost_packets = self.lost_packets.saturating_add(other.lost_packets);
        self.late_packets = self.late_packets.saturating_add(other.late_packets);
        self.dropped_frames = self.dropped_frames.saturating_add(other.dropped_frames);
    }
}

#[derive(Debug, Default)]
pub struct IngestOutcome {
    pub completed: Option<CompletedFrame>,
    pub feedback: AssemblyFeedback,
}

struct PartialFrame {
    total_packets: u16,
    start_seq: Option<u16>,
    received: HashMap<u16, Vec<u8>>,
    payload_bytes: usize,
    expected_payload_bytes: Option<usize>,
    timing: FrameTimingMeta,
    frame_type: u8,
    /// True once a real FrameStart set `frame_type`; keeps a later parity packet
    /// from overwriting the authoritative type.
    frame_type_from_start: bool,
    parity: Option<Vec<u8>>,
    // RS block recovery (A1). `rs_parity_shards == 0` ⇒ XOR / no RS.
    rs_parity_shards: u16,
    rs_shard_len: u16,
    rs_recovery: Vec<(u16, Vec<u8>)>,
    recovered_packets: u16,
    first_arrival: Instant,
    arrival_order: u64,
    #[cfg(test)]
    rs_decode_attempts: usize,
    #[cfg(test)]
    suppress_rs_recovery: bool,
}

/// Maximum number of pending incomplete frames before forcing cleanup.
const MAX_PENDING_FRAMES: usize = 30;
/// Hard resource bounds for one encoded video unit. Shared with the slicer so
/// the sender can never emit a unit this side would refuse to reassemble.
const MAX_FRAME_PACKETS: u16 = crate::packet::MAX_UNIT_PACKETS;
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// The assembler is transport-agnostic: UDP normally uses 1400-byte packets,
/// while the reliable TCP tunnel deliberately slices at 16 KiB.
#[cfg(feature = "tunnel")]
const MAX_FRAME_PACKET_BYTES: usize = crate::tcp_tunnel::TCP_TUNNEL_MAX_MEDIA;
#[cfg(not(feature = "tunnel"))]
const MAX_FRAME_PACKET_BYTES: usize = 16 * 1024;
const MAX_FRAME_PACKET_PAYLOAD: usize = MAX_FRAME_PACKET_BYTES - HEADER_SIZE;
/// Before FrameStart/parity establishes the wrapping sequence range, retain only
/// a small reorder cushion. This prevents all 65k sequence values being stored.
const MAX_PRESTART_PACKETS: usize = 64;
const MAX_PRESTART_BYTES: usize = MAX_PRESTART_PACKETS * MAX_FRAME_PACKET_PAYLOAD;
const MAX_RS_PARITY_SHARDS: u16 = 1024;
/// Arrival/time limits, independent of attacker-controlled frame ids.
const MAX_PENDING_DURATION: Duration = Duration::from_secs(2);
/// Duplicate suppression is intentionally bounded and has no ordering meaning.
const RECENT_COMPLETED_FRAMES: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PacketUpdate {
    Rejected,
    Duplicate,
    Changed,
}

enum ParsedFramePacket<'a> {
    Start {
        total_packets: u16,
        frame_type: u8,
        timing: FrameTimingMeta,
        data: &'a [u8],
    },
    Data(&'a [u8]),
    Parity {
        meta: FrameParityMeta,
        shard: &'a [u8],
    },
}

pub struct FrameAssembler {
    pending: HashMap<u32, PartialFrame>,
    arrival_order: u64,
    completed_order: VecDeque<u32>,
    completed_ids: HashSet<u32>,
}

impl Default for FrameAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            arrival_order: 0,
            completed_order: VecDeque::with_capacity(RECENT_COMPLETED_FRAMES),
            completed_ids: HashSet::with_capacity(RECENT_COMPLETED_FRAMES),
        }
    }

    /// Feed a raw UDP packet. Returns a completed frame if all packets arrived.
    pub fn ingest(&mut self, raw: &[u8]) -> Option<CompletedFrame> {
        self.ingest_with_feedback(raw).completed
    }

    /// Feed a raw UDP packet, returning both the completed frame and any
    /// loss/late feedback inferred from the reassembly state.
    pub fn ingest_with_feedback(&mut self, raw: &[u8]) -> IngestOutcome {
        let now = Instant::now();
        let mut outcome = IngestOutcome::default();
        if raw.len() > MAX_FRAME_PACKET_BYTES {
            return self.finish(outcome, now);
        }
        let Some(header) = PacketHeader::deserialize(raw) else {
            return self.finish(outcome, now);
        };
        let payload = &raw[HEADER_SIZE..];

        if matches!(
            header.payload_type,
            PayloadType::Audio
                | PayloadType::Keepalive
                | PayloadType::MouseAbsolute
                | PayloadType::MouseRelative
                | PayloadType::MouseButtons
                | PayloadType::MouseWheel
                | PayloadType::KeyboardState
        ) {
            return self.finish(outcome, now);
        }

        if self.completed_ids.contains(&header.frame_id) {
            // Data for a recently completed frame is a genuine late packet.
            // Parity and FrameStart are deliberately duplicated redundancy.
            if header.payload_type == PayloadType::Data {
                outcome.feedback.late_packets = 1;
            }
            return self.finish(outcome, now);
        }

        let parsed = match header.payload_type {
            PayloadType::FrameStart => {
                let Some((total_packets, frame_type, timing)) =
                    FrameTimingMeta::deserialize(payload)
                else {
                    return self.finish(outcome, now);
                };
                if !valid_total_packets(total_packets) {
                    return self.finish(outcome, now);
                }
                ParsedFramePacket::Start {
                    total_packets,
                    frame_type,
                    timing,
                    data: &payload[FRAME_START_HEADER_SIZE..],
                }
            }
            PayloadType::Data => {
                if payload.is_empty() {
                    return self.finish(outcome, now);
                }
                ParsedFramePacket::Data(payload)
            }
            PayloadType::Parity => {
                let Some(meta) = FrameParityMeta::deserialize(payload) else {
                    return self.finish(outcome, now);
                };
                let shard = &payload[FRAME_PARITY_HEADER_SIZE..];
                if !valid_parity_packet(meta, shard) {
                    return self.finish(outcome, now);
                }
                ParsedFramePacket::Parity { meta, shard }
            }
            PayloadType::Audio
            | PayloadType::Keepalive
            | PayloadType::MouseAbsolute
            | PayloadType::MouseRelative
            | PayloadType::MouseButtons
            | PayloadType::MouseWheel
            | PayloadType::KeyboardState => unreachable!(),
        };

        self.arrival_order = self.arrival_order.wrapping_add(1);
        let arrival_order = self.arrival_order;
        let update = {
            let frame = self
                .pending
                .entry(header.frame_id)
                .or_insert_with(|| PartialFrame::new(now, arrival_order));
            match parsed {
                ParsedFramePacket::Start {
                    total_packets,
                    frame_type,
                    timing,
                    data,
                } => accept_frame_start(frame, header.seq, total_packets, frame_type, timing, data),
                ParsedFramePacket::Data(data) => accept_data(frame, header.seq, data),
                ParsedFramePacket::Parity { meta, shard } => accept_parity(frame, meta, shard),
            }
        };
        if update != PacketUpdate::Changed {
            return self.finish(outcome, now);
        }

        let complete = {
            let frame = self.pending.get_mut(&header.frame_id).unwrap();
            try_recover_single_loss(frame);
            if rs_recovery_eligible(frame) {
                try_recover_rs(frame);
            }
            frame_is_complete(frame)
        };

        // Check completion
        if complete {
            let Some(partial) = self.pending.remove(&header.frame_id) else {
                return self.finish(outcome, now);
            };
            outcome.feedback.lost_packets = outcome
                .feedback
                .lost_packets
                .saturating_add(u32::from(partial.recovered_packets));
            let mut data = Vec::with_capacity(partial.payload_bytes);
            let start_seq = partial
                .start_seq
                .expect("complete frame has start sequence");
            for offset in 0..partial.total_packets {
                let seq = start_seq.wrapping_add(offset);
                data.extend_from_slice(&partial.received[&seq]);
            }

            self.remember_completed(header.frame_id);

            outcome.completed = Some(CompletedFrame {
                frame_id: header.frame_id,
                video_epoch: partial.timing.video_epoch,
                data,
                timing: partial.timing,
                frame_type: partial.frame_type,
            });
        }

        self.finish(outcome, now)
    }

    /// Expire incomplete frames even when no further media packet arrives.
    /// Call this from a periodic transport/feedback maintenance path.
    pub fn maintenance(&mut self) -> AssemblyFeedback {
        self.prune_pending(Instant::now())
    }

    fn finish(&mut self, mut outcome: IngestOutcome, now: Instant) -> IngestOutcome {
        outcome.feedback.merge(self.prune_pending(now));
        outcome
    }

    fn prune_pending(&mut self, now: Instant) -> AssemblyFeedback {
        let mut feedback = AssemblyFeedback::default();
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter_map(|(&frame_id, frame)| {
                (now.saturating_duration_since(frame.first_arrival) >= MAX_PENDING_DURATION)
                    .then_some(frame_id)
            })
            .collect();
        for frame_id in expired {
            self.drop_pending(frame_id, &mut feedback);
        }

        while self.pending.len() > MAX_PENDING_FRAMES {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, frame)| frame.arrival_order)
                .map(|(&frame_id, _)| frame_id);
            let Some(oldest) = oldest else {
                break;
            };
            self.drop_pending(oldest, &mut feedback);
        }
        feedback
    }

    fn drop_pending(&mut self, frame_id: u32, feedback: &mut AssemblyFeedback) {
        let Some(frame) = self.pending.remove(&frame_id) else {
            return;
        };
        feedback.dropped_frames = feedback.dropped_frames.saturating_add(1);
        feedback.lost_packets = feedback
            .lost_packets
            .saturating_add(missing_packet_count(&frame));
    }

    fn remember_completed(&mut self, frame_id: u32) {
        if !self.completed_ids.insert(frame_id) {
            return;
        }
        self.completed_order.push_back(frame_id);
        if self.completed_order.len() > RECENT_COMPLETED_FRAMES {
            let expired = self.completed_order.pop_front().unwrap();
            self.completed_ids.remove(&expired);
        }
    }
}

impl PartialFrame {
    fn new(now: Instant, arrival_order: u64) -> Self {
        Self {
            total_packets: 0,
            start_seq: None,
            received: HashMap::new(),
            payload_bytes: 0,
            expected_payload_bytes: None,
            timing: FrameTimingMeta::default(),
            frame_type: crate::packet::frame_type::P,
            frame_type_from_start: false,
            parity: None,
            rs_parity_shards: 0,
            rs_shard_len: 0,
            rs_recovery: Vec::new(),
            recovered_packets: 0,
            first_arrival: now,
            arrival_order,
            #[cfg(test)]
            rs_decode_attempts: 0,
            #[cfg(test)]
            suppress_rs_recovery: false,
        }
    }
}

fn valid_total_packets(total_packets: u16) -> bool {
    (1..=MAX_FRAME_PACKETS).contains(&total_packets)
}

fn seq_in_frame(seq: u16, start_seq: u16, total_packets: u16) -> bool {
    seq.wrapping_sub(start_seq) < total_packets
}

fn valid_parity_packet(meta: FrameParityMeta, shard: &[u8]) -> bool {
    if !valid_total_packets(meta.total_packets)
        || shard.is_empty()
        || meta.chunk_bytes_sum as usize > MAX_FRAME_BYTES
    {
        return false;
    }
    if meta.is_rs() {
        meta.data_shards == meta.total_packets
            && meta.parity_shards <= meta.total_packets
            && meta.parity_shards <= MAX_RS_PARITY_SHARDS
            && meta.shard_index < meta.parity_shards
            && meta.shard_len >= 2
            && meta.shard_len.is_multiple_of(2)
            && shard.len() == meta.shard_len as usize
    } else {
        meta.data_shards == 0
            && meta.parity_shards == 0
            && meta.shard_index == 0
            && meta.shard_len == 0
    }
}

fn accept_frame_start(
    frame: &mut PartialFrame,
    seq: u16,
    total_packets: u16,
    frame_type: u8,
    timing: FrameTimingMeta,
    data: &[u8],
) -> PacketUpdate {
    if (frame.total_packets != 0 && frame.total_packets != total_packets)
        || frame.start_seq.is_some_and(|start| start != seq)
        || (frame.start_seq.is_some() && frame.timing != timing)
        || (frame.frame_type_from_start && frame.frame_type != frame_type)
    {
        return PacketUpdate::Rejected;
    }
    if frame.frame_type_from_start {
        return if frame
            .received
            .get(&seq)
            .is_some_and(|existing| existing.as_slice() == data)
        {
            PacketUpdate::Duplicate
        } else {
            PacketUpdate::Rejected
        };
    }
    if frame.rs_parity_shards > 0
        && frame
            .received
            .values()
            .any(|chunk| chunk.len().saturating_add(2) > frame.rs_shard_len as usize)
    {
        return PacketUpdate::Rejected;
    }

    frame.total_packets = total_packets;
    frame.start_seq = Some(seq);
    frame.timing = timing;
    frame.frame_type = frame_type;
    frame.frame_type_from_start = true;
    retain_declared_sequence_range(frame);
    if let Some(previous) = frame.received.remove(&seq) {
        frame.payload_bytes = frame.payload_bytes.saturating_sub(previous.len());
    }
    insert_packet_chunk(frame, seq, data)
}

fn accept_data(frame: &mut PartialFrame, seq: u16, data: &[u8]) -> PacketUpdate {
    if frame.rs_parity_shards > 0 && data.len().saturating_add(2) > frame.rs_shard_len as usize {
        return PacketUpdate::Rejected;
    }
    insert_packet_chunk(frame, seq, data)
}

fn accept_parity(frame: &mut PartialFrame, meta: FrameParityMeta, shard: &[u8]) -> PacketUpdate {
    if (frame.total_packets != 0 && frame.total_packets != meta.total_packets)
        || frame.start_seq.is_some_and(|start| start != meta.start_seq)
        || frame
            .expected_payload_bytes
            .is_some_and(|expected| expected != meta.chunk_bytes_sum as usize)
        || (frame.start_seq.is_some() && frame.timing != meta.timing)
        || (frame.frame_type_from_start && frame.frame_type != meta.frame_type)
    {
        return PacketUpdate::Rejected;
    }

    if meta.is_rs() {
        if frame.parity.is_some()
            || (frame.rs_parity_shards != 0
                && (frame.rs_parity_shards != meta.parity_shards
                    || frame.rs_shard_len != meta.shard_len))
            || frame
                .received
                .values()
                .any(|chunk| chunk.len().saturating_add(2) > meta.shard_len as usize)
        {
            return PacketUpdate::Rejected;
        }
        if let Some((_, existing)) = frame
            .rs_recovery
            .iter()
            .find(|(index, _)| *index == meta.shard_index)
        {
            return if existing.as_slice() == shard {
                PacketUpdate::Duplicate
            } else {
                PacketUpdate::Rejected
            };
        }
        if frame.rs_recovery.len() >= meta.parity_shards as usize {
            return PacketUpdate::Rejected;
        }
    } else if frame.rs_parity_shards != 0 {
        return PacketUpdate::Rejected;
    } else if let Some(existing) = &frame.parity {
        return if existing.as_slice() == shard {
            PacketUpdate::Duplicate
        } else {
            PacketUpdate::Rejected
        };
    }

    frame.total_packets = meta.total_packets;
    frame.start_seq = Some(meta.start_seq);
    frame.expected_payload_bytes = Some(meta.chunk_bytes_sum as usize);
    frame.timing = meta.timing;
    if !frame.frame_type_from_start {
        frame.frame_type = meta.frame_type;
    }
    retain_declared_sequence_range(frame);
    if frame.payload_bytes > meta.chunk_bytes_sum as usize {
        return PacketUpdate::Rejected;
    }

    if meta.is_rs() {
        frame.rs_parity_shards = meta.parity_shards;
        frame.rs_shard_len = meta.shard_len;
        frame.rs_recovery.push((meta.shard_index, shard.to_vec()));
    } else {
        frame.parity = Some(shard.to_vec());
    }
    PacketUpdate::Changed
}

fn retain_declared_sequence_range(frame: &mut PartialFrame) {
    let Some(start_seq) = frame.start_seq else {
        return;
    };
    frame
        .received
        .retain(|&seq, _| seq_in_frame(seq, start_seq, frame.total_packets));
    frame.payload_bytes = frame.received.values().map(Vec::len).sum();
}

fn insert_packet_chunk(frame: &mut PartialFrame, seq: u16, packet: &[u8]) -> PacketUpdate {
    if packet.len() > MAX_FRAME_PACKET_PAYLOAD {
        return PacketUpdate::Rejected;
    }
    if let Some(start_seq) = frame.start_seq {
        if !seq_in_frame(seq, start_seq, frame.total_packets) {
            return PacketUpdate::Rejected;
        }
    } else if !frame.received.contains_key(&seq)
        && (frame.received.len() >= MAX_PRESTART_PACKETS
            || frame.payload_bytes.saturating_add(packet.len()) > MAX_PRESTART_BYTES)
    {
        return PacketUpdate::Rejected;
    }
    if let Some(existing) = frame.received.get(&seq) {
        return if existing.as_slice() == packet {
            PacketUpdate::Duplicate
        } else {
            PacketUpdate::Rejected
        };
    }
    if frame.payload_bytes.saturating_add(packet.len()) > MAX_FRAME_BYTES
        || frame
            .expected_payload_bytes
            .is_some_and(|expected| frame.payload_bytes.saturating_add(packet.len()) > expected)
    {
        return PacketUpdate::Rejected;
    }
    frame.payload_bytes += packet.len();
    frame.received.insert(seq, packet.to_vec());
    PacketUpdate::Changed
}

fn frame_is_complete(frame: &PartialFrame) -> bool {
    if frame.total_packets == 0
        || frame.received.len() != frame.total_packets as usize
        || frame.payload_bytes > MAX_FRAME_BYTES
        || frame
            .expected_payload_bytes
            .is_some_and(|expected| expected != frame.payload_bytes)
    {
        return false;
    }
    let Some(start_seq) = frame.start_seq else {
        return false;
    };
    (0..frame.total_packets)
        .all(|offset| frame.received.contains_key(&start_seq.wrapping_add(offset)))
}

fn missing_packet_count(frame: &PartialFrame) -> u32 {
    if frame.total_packets == 0 {
        0
    } else {
        u32::from(
            frame
                .total_packets
                .saturating_sub(frame.received.len() as u16),
        )
    }
}

fn try_recover_single_loss(frame: &mut PartialFrame) {
    if frame.total_packets == 0 || frame.received.len() + 1 != frame.total_packets as usize {
        return;
    }
    let Some(start_seq) = frame.start_seq else {
        return;
    };
    let Some(expected_payload_bytes) = frame.expected_payload_bytes else {
        return;
    };
    let Some(parity) = frame.parity.as_ref() else {
        return;
    };

    let mut missing_seq = None;
    for offset in 0..frame.total_packets {
        let seq = start_seq.wrapping_add(offset);
        if !frame.received.contains_key(&seq) {
            if missing_seq.is_some() {
                return;
            }
            missing_seq = Some(seq);
        }
    }
    let Some(missing_seq) = missing_seq else {
        return;
    };

    let Some(missing_len) = expected_payload_bytes.checked_sub(frame.payload_bytes) else {
        return;
    };
    if missing_len == 0 || missing_len > parity.len() {
        return;
    }

    let mut recovered = parity.clone();
    for offset in 0..frame.total_packets {
        let seq = start_seq.wrapping_add(offset);
        if seq == missing_seq {
            continue;
        }
        let Some(chunk) = frame.received.get(&seq) else {
            return;
        };
        if chunk.len() > recovered.len() {
            return;
        }
        for (dst, src) in recovered[..chunk.len()].iter_mut().zip(chunk.iter()) {
            *dst ^= *src;
        }
    }
    recovered.truncate(missing_len);
    if insert_packet_chunk(frame, missing_seq, &recovered) == PacketUpdate::Changed {
        frame.recovered_packets = frame.recovered_packets.saturating_add(1);
    }
}

fn rs_recovery_eligible(frame: &PartialFrame) -> bool {
    frame.rs_parity_shards > 0
        && frame.total_packets > 0
        && frame.received.len() < frame.total_packets as usize
        && frame.received.len() + frame.rs_recovery.len() >= frame.total_packets as usize
}

/// Reed-Solomon block recovery (A1): restore any missing data packets once
/// `received_data + recovery_shards >= data_shards`. Each data shard is the
/// length-prefixed, zero-padded media chunk the slicer encoded; restored shards
/// are un-prefixed back to their exact chunk bytes (byte-exact, GF(256)).
fn try_recover_rs(frame: &mut PartialFrame) {
    if frame.rs_parity_shards == 0 || frame.total_packets == 0 {
        return;
    }
    let Some(start_seq) = frame.start_seq else {
        return;
    };
    let shard_len = frame.rs_shard_len as usize;
    if shard_len < 2 {
        return;
    }
    let total = frame.total_packets as usize;

    // Positions already present (no recovery needed if complete).
    let mut received_positions: Vec<usize> = Vec::with_capacity(total);
    for offset in 0..frame.total_packets {
        let seq = start_seq.wrapping_add(offset);
        if frame.received.contains_key(&seq) {
            received_positions.push(offset as usize);
        }
    }
    if received_positions.len() == total {
        return;
    }
    if received_positions.len() + frame.rs_recovery.len() < total {
        return; // not enough shards yet
    }

    // Rebuild original shards for present positions exactly as the slicer did.
    let mut original_shards: Vec<(usize, Vec<u8>)> = Vec::with_capacity(received_positions.len());
    for &pos in &received_positions {
        let seq = start_seq.wrapping_add(pos as u16);
        let Some(chunk) = frame.received.get(&seq) else {
            return;
        };
        if 2 + chunk.len() > shard_len {
            return; // inconsistent shard sizing — bail rather than corrupt
        }
        let mut shard = vec![0u8; shard_len];
        shard[0..2].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
        shard[2..2 + chunk.len()].copy_from_slice(chunk);
        original_shards.push((pos, shard));
    }

    let recovery_iter = frame
        .rs_recovery
        .iter()
        .map(|(idx, s)| (*idx as usize, s.as_slice()));

    #[cfg(test)]
    {
        frame.rs_decode_attempts += 1;
        if frame.suppress_rs_recovery {
            return;
        }
    }

    let restored = match reed_solomon_simd::decode(
        total,
        frame.rs_parity_shards as usize,
        original_shards.iter().map(|(i, s)| (*i, s.as_slice())),
        recovery_iter,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };

    for (pos, shard) in restored {
        if shard.len() != shard_len || pos >= total {
            continue;
        }
        let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
        if 2 + len > shard.len() {
            continue;
        }
        let chunk = shard[2..2 + len].to_vec();
        let seq = start_seq.wrapping_add(pos as u16);
        if !frame.received.contains_key(&seq)
            && insert_packet_chunk(frame, seq, &chunk) == PacketUpdate::Changed
        {
            frame.recovered_packets = frame.recovered_packets.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_slicer::FrameSlicer;

    #[test]
    fn roundtrip_single_packet() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let original = vec![0xCC; 200];
        let packets = slicer.slice(&original, 1).to_vec();
        assert_eq!(packets.len(), 1);

        let result = assembler.ingest(&packets[0]).unwrap();
        assert_eq!(result.frame_id, 1);
        assert_eq!(result.data, original);
    }

    #[test]
    fn roundtrip_multi_packet() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let original = vec![0xDD; 5000];
        let packets = slicer.slice(&original, 7).to_vec();

        // Feed all but last — should return None
        for pkt in &packets[..packets.len() - 1] {
            assert!(assembler.ingest(pkt).is_none());
        }
        // Last packet completes the frame
        let result = assembler.ingest(packets.last().unwrap()).unwrap();
        assert_eq!(result.frame_id, 7);
        assert_eq!(result.data, original);
    }

    #[test]
    fn out_of_order_delivery() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let original = vec![0xEE; 5000];
        let mut packets = slicer.slice(&original, 3).to_vec();
        packets.reverse(); // deliver in reverse order

        let mut completed = None;
        for pkt in &packets {
            if let Some(frame) = assembler.ingest(pkt) {
                completed = Some(frame);
            }
        }
        let result = completed.unwrap();
        assert_eq!(result.frame_id, 3);
        assert_eq!(result.data, original);
    }

    #[test]
    fn late_frame_ids_are_accepted() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let packets = slicer.slice(&[1, 2, 3], 5).to_vec();
        assembler.ingest(&packets[0]).unwrap();

        let late_packets = slicer.slice(&[4, 5, 6], 3).to_vec();
        assert_eq!(assembler.ingest(&late_packets[0]).unwrap().frame_id, 3);
    }

    #[test]
    fn redundancy_packets_after_completion_are_not_counted_late() {
        // Regression guard: the protocol deliberately sends FEC parity and a
        // delayed-duplicate FrameStart for every multi-packet frame. Those
        // routinely arrive after the frame already completed. They must NOT be
        // reported as `late_packets`, or a clean FEC stream looks permanently
        // impaired and the ABR controller stays pinned at its floor.
        use crate::frame_slicer::{FecConfig, FrameSlicer};
        use crate::packet::{frame_type, FecMode};
        use crate::FrameTimingMeta;

        let mut slicer = FrameSlicer::with_config(
            600,
            FecConfig {
                mode: FecMode::Rs,
                fec_pct: 0,
                min_parity: 1,
            },
        );
        let payload = vec![0x5Au8; 6_000];
        let (data, parity) =
            slicer.slice_with_meta_parts(&payload, 1, FrameTimingMeta::default(), frame_type::IDR);
        let data = data.to_vec();
        let parity = parity.to_vec();
        assert!(data.len() > 1, "payload must be multi-packet");
        assert_eq!(parity.len(), 1, "floor-0 RS emits one parity packet");

        let mut asm = FrameAssembler::new();
        let mut completed = false;
        for pkt in &data {
            if asm.ingest(pkt).is_some() {
                completed = true;
            }
        }
        assert!(completed, "frame must complete from its data packets");

        // Parity for the already-completed frame: redundancy, not lateness.
        let parity_outcome = asm.ingest_with_feedback(&parity[0]);
        assert_eq!(
            parity_outcome.feedback,
            AssemblyFeedback::default(),
            "late parity is expected FEC redundancy, not network loss"
        );

        // A duplicate FrameStart (the deliberate delayed copy) after completion
        // is likewise not "late".
        let dup_start_outcome = asm.ingest_with_feedback(&data[0]);
        assert_eq!(
            dup_start_outcome.feedback,
            AssemblyFeedback::default(),
            "duplicate FrameStart is expected redundancy, not network loss"
        );

        // A genuine Data straggler for the completed frame IS late (real reorder).
        let straggler = asm.ingest_with_feedback(&data[1]);
        assert_eq!(
            straggler.feedback.late_packets, 1,
            "a late media Data packet is genuine reordering and must count"
        );
    }

    #[test]
    fn maintenance_reports_dropped_partial_frame() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let frame1 = slicer.slice(&[1, 2, 3], 1).to_vec();
        assert!(assembler.ingest(&frame1[0]).is_some());

        let partial_frame2 = slicer.slice(&vec![7u8; 3000], 2).to_vec();
        assert!(assembler.ingest(&partial_frame2[0]).is_none());

        let frame3 = slicer.slice(&[4, 5, 6], 3).to_vec();
        let outcome = assembler.ingest_with_feedback(&frame3[0]);

        assert_eq!(outcome.feedback, AssemblyFeedback::default());
        assert_eq!(outcome.completed.unwrap().frame_id, 3);
        assert!(assembler.pending.contains_key(&2));

        assembler.pending.get_mut(&2).unwrap().first_arrival =
            Instant::now() - MAX_PENDING_DURATION;
        let feedback = assembler.maintenance();
        assert_eq!(feedback.dropped_frames, 1);
        assert!(feedback.lost_packets >= 1);
    }

    #[test]
    fn pending_partial_frames_stay_bounded_without_completion() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();
        let frame_count = MAX_PENDING_FRAMES as u32 + 10;
        let mut feedback = AssemblyFeedback::default();

        for frame_id in 1..=frame_count {
            let packets = slicer.slice(&vec![frame_id as u8; 3_000], frame_id);
            assert!(packets.len() > 1);
            let outcome = assembler.ingest_with_feedback(&packets[0]);
            assert!(outcome.completed.is_none());
            feedback.merge(outcome.feedback);
            assert!(assembler.pending.len() <= MAX_PENDING_FRAMES);
        }

        assert_eq!(assembler.pending.len(), MAX_PENDING_FRAMES);
        assert!(!assembler.pending.contains_key(&1));
        assert!(assembler.pending.contains_key(&frame_count));
        assert_eq!(feedback.dropped_frames, 10);
        assert!(feedback.lost_packets >= 10);
    }

    #[test]
    fn forged_completed_4096_jump_chain_does_not_evict_legitimate_partial() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let baseline = slicer.slice(&[0x10], 1).to_vec();
        assert_eq!(assembler.ingest(&baseline[0]).unwrap().frame_id, 1);

        let legitimate = slicer.slice(&vec![0x11; 3_000], 2).to_vec();
        assert!(assembler.ingest(&legitimate[0]).is_none());
        for step in 1u32..=8 {
            let forged_id = 1 + step * 4096;
            let forged = slicer.slice(&[step as u8], forged_id).to_vec();
            assert_eq!(assembler.ingest(&forged[0]).unwrap().frame_id, forged_id);
            assert!(assembler.pending.contains_key(&2));
        }

        let mut completed = None;
        for packet in legitimate.iter().skip(1) {
            completed = completed.or_else(|| assembler.ingest(packet));
        }
        assert_eq!(completed.unwrap().frame_id, 2);
    }

    #[test]
    fn stale_partial_pruning_returns_loss_feedback() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();
        let packets = slicer.slice(&vec![0x33; 3_000], 9);
        assert!(assembler.ingest(&packets[0]).is_none());
        assembler.pending.get_mut(&9).unwrap().first_arrival =
            Instant::now() - MAX_PENDING_DURATION;

        let feedback = assembler.maintenance();
        assert_eq!(feedback.dropped_frames, 1);
        assert!(feedback.lost_packets >= 1);
        assert!(assembler.pending.is_empty());
    }

    #[test]
    fn first_wrapping_and_late_frame_ids_are_accepted() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();
        for (frame_id, byte) in [(u32::MAX, 1), (0, 2), (u32::MAX - 1, 3)] {
            let packet = slicer.slice(&[byte], frame_id).to_vec();
            assert_eq!(assembler.ingest(&packet[0]).unwrap().frame_id, frame_id);
        }
    }

    #[test]
    fn recent_completed_id_cache_is_bounded_at_4096() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        for frame_id in 0..RECENT_COMPLETED_FRAMES as u32 {
            let packet = slicer.slice(&[frame_id as u8], frame_id).to_vec();
            assert!(assembler.ingest(&packet[0]).is_some());
        }
        assert_eq!(assembler.completed_ids.len(), RECENT_COMPLETED_FRAMES);
        assert_eq!(assembler.completed_order.len(), RECENT_COMPLETED_FRAMES);

        let duplicate = slicer.slice(&[0], 0).to_vec();
        assert!(assembler.ingest(&duplicate[0]).is_none());

        let boundary = RECENT_COMPLETED_FRAMES as u32;
        let packet = slicer.slice(&[0xAA], boundary).to_vec();
        assert_eq!(assembler.ingest(&packet[0]).unwrap().frame_id, boundary);
        assert_eq!(assembler.completed_ids.len(), RECENT_COMPLETED_FRAMES);
        assert!(!assembler.completed_ids.contains(&0));

        let expired_id = slicer.slice(&[0xBB], 0).to_vec();
        assert_eq!(assembler.ingest(&expired_id[0]).unwrap().frame_id, 0);
    }

    #[test]
    fn pre_framestart_unique_sequence_flood_is_bounded() {
        let mut assembler = FrameAssembler::new();
        for seq in 0..=u16::MAX {
            let mut packet = vec![0u8; HEADER_SIZE + 1];
            PacketHeader {
                seq,
                frame_id: 77,
                payload_type: PayloadType::Data,
            }
            .serialize(&mut packet[..HEADER_SIZE]);
            packet[HEADER_SIZE] = 1;
            assert!(assembler.ingest(&packet).is_none());
        }
        let frame = assembler.pending.get(&77).unwrap();
        assert!(frame.received.len() <= MAX_PRESTART_PACKETS);
        assert!(frame.payload_bytes <= MAX_PRESTART_BYTES);
    }

    #[test]
    fn impossible_packet_counts_and_oversized_packets_do_not_allocate() {
        for total_packets in [0, MAX_FRAME_PACKETS + 1, u16::MAX] {
            let mut packet = vec![0u8; HEADER_SIZE + FRAME_START_HEADER_SIZE + 1];
            PacketHeader {
                seq: 1,
                frame_id: u32::from(total_packets),
                payload_type: PayloadType::FrameStart,
            }
            .serialize(&mut packet[..HEADER_SIZE]);
            FrameTimingMeta::default().serialize(
                total_packets,
                crate::packet::frame_type::P,
                &mut packet[HEADER_SIZE..HEADER_SIZE + FRAME_START_HEADER_SIZE],
            );
            assert!(FrameAssembler::new().ingest(&packet).is_none());
        }

        let mut oversized = vec![0u8; MAX_FRAME_PACKET_BYTES + 1];
        PacketHeader {
            seq: 1,
            frame_id: 1,
            payload_type: PayloadType::Data,
        }
        .serialize(&mut oversized[..HEADER_SIZE]);
        let mut assembler = FrameAssembler::new();
        assert!(assembler.ingest(&oversized).is_none());
        assert!(assembler.pending.is_empty());
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn tcp_tunnel_sized_slicer_packets_roundtrip() {
        let mut slicer = FrameSlicer::with_max_udp(crate::tcp_tunnel::TCP_TUNNEL_MAX_MEDIA);
        slicer.set_parity_enabled(false);
        let original = vec![0xC7; crate::tcp_tunnel::TCP_TUNNEL_MAX_MEDIA * 2];
        let packets = slicer.slice(&original, 91).to_vec();
        assert!(packets
            .iter()
            .any(|packet| packet.len() > crate::packet::MAX_UDP));
        assert!(packets
            .iter()
            .all(|packet| packet.len() <= crate::tcp_tunnel::TCP_TUNNEL_MAX_MEDIA));

        let mut assembler = FrameAssembler::new();
        let mut completed = None;
        for packet in packets {
            completed = completed.or_else(|| assembler.ingest(&packet));
        }
        assert_eq!(completed.unwrap().data, original);
    }

    #[test]
    fn data_outside_declared_wrapping_sequence_range_is_rejected() {
        let mut slicer = FrameSlicer::new();
        slicer.set_seq_for_test(u16::MAX - 1);
        let packets = slicer.slice(&vec![0x44; 3_000], 88).to_vec();
        let mut assembler = FrameAssembler::new();
        assert!(assembler.ingest(&packets[0]).is_none());
        let frame = assembler.pending.get(&88).unwrap();
        let before = frame.received.len();
        let outside_seq = frame.start_seq.unwrap().wrapping_add(frame.total_packets);
        let mut outside = vec![0u8; HEADER_SIZE + 1];
        PacketHeader {
            seq: outside_seq,
            frame_id: 88,
            payload_type: PayloadType::Data,
        }
        .serialize(&mut outside[..HEADER_SIZE]);
        outside[HEADER_SIZE] = 9;
        assert!(assembler.ingest(&outside).is_none());
        assert_eq!(assembler.pending.get(&88).unwrap().received.len(), before);
    }

    #[test]
    fn parity_recovers_missing_middle_packet() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let original = vec![0x5A; 8_000];
        let packets = slicer.slice(&original, 11).to_vec();
        let parity = slicer.parity_packet().unwrap().to_vec();

        let mut completed = None;
        for (idx, pkt) in packets.iter().enumerate() {
            if idx == 1 {
                continue;
            }
            let outcome = assembler.ingest_with_feedback(pkt);
            if outcome.completed.is_some() {
                completed = outcome.completed;
            }
        }
        let outcome = assembler.ingest_with_feedback(&parity);
        assert_eq!(outcome.feedback.lost_packets, 1);
        assert_eq!(outcome.feedback.late_packets, 0);
        assert_eq!(outcome.feedback.dropped_frames, 0);
        completed = completed.or(outcome.completed);

        let result = completed.expect("parity should recover one missing packet");
        assert_eq!(result.frame_id, 11);
        assert_eq!(result.data, original);
    }

    #[test]
    fn parity_from_another_video_epoch_cannot_complete_frame() {
        let mut slicer = FrameSlicer::new();
        let original = vec![0x6B; 8_000];
        let timing = FrameTimingMeta {
            video_epoch: 7,
            ..Default::default()
        };
        let packets = slicer.slice_with_meta(&original, 13, timing).to_vec();
        let parity = slicer.parity_packet().unwrap().to_vec();
        let wrong_epoch_parity = mutate_parity_meta(&parity, |meta| {
            meta.timing.video_epoch = 8;
        });

        let mut assembler = FrameAssembler::new();
        for (index, packet) in packets.iter().enumerate() {
            if index != 1 {
                assert!(assembler.ingest(packet).is_none());
            }
        }
        assert!(assembler.ingest(&wrong_epoch_parity).is_none());
        let completed = assembler
            .ingest(&parity)
            .expect("matching parity should recover the frame");
        assert_eq!(completed.video_epoch, 7);
        assert_eq!(completed.data, original);
    }

    #[test]
    fn parity_recovers_missing_first_packet() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let original = vec![0x7C; 8_000];
        let packets = slicer
            .slice_with_meta(
                &original,
                12,
                FrameTimingMeta {
                    capture_ts_micros: 100,
                    send_ts_micros: 200,
                    video_epoch: 9,
                },
            )
            .to_vec();
        let parity = slicer.parity_packet().unwrap().to_vec();

        for pkt in packets.iter().skip(1) {
            assert!(assembler.ingest(pkt).is_none());
        }
        let recovered = assembler
            .ingest(&parity)
            .expect("parity should recover first packet");
        assert_eq!(recovered.frame_id, 12);
        assert_eq!(recovered.data, original);
        assert_eq!(
            recovered.timing,
            FrameTimingMeta {
                capture_ts_micros: 100,
                send_ts_micros: 200,
                video_epoch: 9,
            }
        );
    }

    // ---- Reed-Solomon (A1) byte-exact multi-loss regression ----
    // Mandatory before `ST_FEC=rs` default-on (CLAUDE.md: probe ≠ correctness).
    use crate::frame_slicer::FecConfig;
    use crate::packet::{frame_type, FecMode};

    /// Deterministic xorshift PRNG (no `rand` dep; reproducible failures).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn rs_slicer(max_udp: usize, fec_pct: u16, min_parity: u16) -> FrameSlicer {
        FrameSlicer::with_config(
            max_udp,
            FecConfig {
                mode: FecMode::Rs,
                fec_pct,
                min_parity,
            },
        )
    }

    #[test]
    fn rs_recovers_two_lost_packets() {
        let mut slicer = rs_slicer(1_400, 40, 2);
        let mut assembler = FrameAssembler::new();
        let original = vec![0xA5; 6_000];
        let (data, parity) = {
            let (d, p) = slicer.slice_with_meta_parts(
                &original,
                21,
                FrameTimingMeta::default(),
                frame_type::IDR,
            );
            (d.to_vec(), p.to_vec())
        };
        assert!(parity.len() >= 2);
        // Drop the first two data packets; deliver the rest + parity.
        let mut completed = None;
        let mut feedback = AssemblyFeedback::default();
        for pkt in data.iter().skip(2).chain(parity.iter()) {
            let outcome = assembler.ingest_with_feedback(pkt);
            feedback.lost_packets = feedback
                .lost_packets
                .saturating_add(outcome.feedback.lost_packets);
            feedback.late_packets = feedback
                .late_packets
                .saturating_add(outcome.feedback.late_packets);
            feedback.dropped_frames = feedback
                .dropped_frames
                .saturating_add(outcome.feedback.dropped_frames);
            completed = completed.or(outcome.completed);
        }
        let result = completed.expect("RS should recover two lost packets");
        assert_eq!(result.frame_id, 21);
        assert_eq!(result.data, original);
        assert_eq!(result.frame_type, frame_type::IDR);
        assert_eq!(feedback.lost_packets, 2);
        assert_eq!(feedback.late_packets, 0);
        assert_eq!(feedback.dropped_frames, 0);
    }

    fn mutate_parity_meta(packet: &[u8], mutate: impl FnOnce(&mut FrameParityMeta)) -> Vec<u8> {
        let mut packet = packet.to_vec();
        let mut meta = FrameParityMeta::deserialize(&packet[HEADER_SIZE..]).unwrap();
        mutate(&mut meta);
        meta.serialize(&mut packet[HEADER_SIZE..HEADER_SIZE + FRAME_PARITY_HEADER_SIZE]);
        packet
    }

    #[test]
    fn rs_rejects_invalid_and_inconsistent_metadata() {
        let mut slicer = rs_slicer(600, 50, 2);
        let (_, parity) = slicer.slice_with_meta_parts(
            &vec![0x6D; 6_000],
            31,
            FrameTimingMeta::default(),
            frame_type::IDR,
        );
        let parity = parity.to_vec();
        assert!(parity.len() >= 2);

        let invalid_packets = [
            mutate_parity_meta(&parity[0], |meta| {
                meta.data_shards = meta.total_packets - 1;
            }),
            mutate_parity_meta(&parity[0], |meta| {
                meta.shard_index = meta.parity_shards;
            }),
            mutate_parity_meta(&parity[0], |meta| {
                meta.shard_len += 2;
            }),
            mutate_parity_meta(&parity[0], |meta| {
                meta.parity_shards = 0;
            }),
        ];
        for packet in invalid_packets {
            let mut assembler = FrameAssembler::new();
            assert!(assembler.ingest(&packet).is_none());
            assert!(assembler.pending.is_empty());
        }

        let mut truncated = parity[0].clone();
        truncated.pop();
        let mut assembler = FrameAssembler::new();
        assert!(assembler.ingest(&truncated).is_none());
        assert!(assembler.pending.is_empty());

        assert!(assembler.ingest(&parity[0]).is_none());
        assert_eq!(assembler.pending.get(&31).unwrap().rs_recovery.len(), 1);
        let inconsistent = mutate_parity_meta(&parity[1], |meta| {
            meta.timing.capture_ts_micros = 1;
        });
        assert!(assembler.ingest(&inconsistent).is_none());
        assert_eq!(assembler.pending.get(&31).unwrap().rs_recovery.len(), 1);
    }

    #[test]
    fn duplicate_data_and_parity_do_not_repeat_rs_decode() {
        let mut slicer = rs_slicer(600, 50, 2);
        let (data, parity) = slicer.slice_with_meta_parts(
            &vec![0xD4; 6_000],
            32,
            FrameTimingMeta::default(),
            frame_type::IDR,
        );
        let data = data.to_vec();
        let parity = parity.to_vec();
        assert!(parity.len() >= 2);

        let mut assembler = FrameAssembler::new();
        for packet in data.iter().skip(1) {
            assert!(assembler.ingest(packet).is_none());
        }
        assembler.pending.get_mut(&32).unwrap().suppress_rs_recovery = true;

        assert!(assembler.ingest(&parity[0]).is_none());
        assert_eq!(assembler.pending.get(&32).unwrap().rs_decode_attempts, 1);
        for _ in 0..100 {
            assert!(assembler.ingest(&parity[0]).is_none());
            assert!(assembler.ingest(&data[1]).is_none());
        }
        assert_eq!(assembler.pending.get(&32).unwrap().rs_decode_attempts, 1);

        assert!(assembler.ingest(&parity[1]).is_none());
        assert_eq!(assembler.pending.get(&32).unwrap().rs_decode_attempts, 2);
    }

    #[test]
    fn rs_recovers_lost_framestart_carries_type() {
        let mut slicer = rs_slicer(1_400, 50, 1);
        let mut assembler = FrameAssembler::new();
        let original = vec![0x3Cu8; 7_000];
        let timing = FrameTimingMeta {
            capture_ts_micros: 11,
            send_ts_micros: 22,
            video_epoch: 33,
        };
        let (data, parity) = {
            let (d, p) = slicer.slice_with_meta_parts(&original, 99, timing, frame_type::IDR);
            (d.to_vec(), p.to_vec())
        };
        // Drop the FrameStart (position 0) entirely.
        let mut completed = None;
        for pkt in data.iter().skip(1).chain(parity.iter()) {
            if let Some(f) = assembler.ingest(pkt) {
                completed = Some(f);
            }
        }
        let r = completed.expect("RS should rebuild a lost FrameStart");
        assert_eq!(r.data, original);
        assert_eq!(r.timing, timing);
        assert_eq!(r.video_epoch, timing.video_epoch);
        // frame_type survives via parity even though FrameStart was lost.
        assert_eq!(r.frame_type, frame_type::IDR);
    }

    #[test]
    fn rs_byte_exact_random_multi_loss_fuzz() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        // Mix of frame sizes incl. single-packet, small multi, and IDR-sized.
        let sizes = [200usize, 1_500, 4_000, 9_000, 30_000, 60_000];
        let mut frame_id: u32 = 0;
        let mut seq_start: u16 = u16::MAX - 5; // exercise wraparound
        for trial in 0..400 {
            let fec_pct = [20u16, 35, 50, 75][rng.below(4)];
            let min_parity = 1 + rng.below(3) as u16;
            let max_udp = [1_200usize, 1_400][rng.below(2)];
            let mut slicer = rs_slicer(max_udp, fec_pct, min_parity);
            slicer.set_seq_for_test(seq_start);
            seq_start = seq_start.wrapping_add(37);

            let size = sizes[rng.below(sizes.len())];
            // Vary bytes so a silent all-zero recovery can't pass.
            let original: Vec<u8> = (0..size).map(|i| (i as u8) ^ (trial as u8)).collect();
            frame_id = frame_id.wrapping_add(1);
            let ftype = if rng.below(2) == 0 {
                frame_type::IDR
            } else {
                frame_type::P
            };

            let (data, parity) = {
                let (d, p) = slicer.slice_with_meta_parts(
                    &original,
                    frame_id,
                    FrameTimingMeta::default(),
                    ftype,
                );
                (d.to_vec(), p.to_vec())
            };

            if data.len() == 1 {
                // Single-packet frame: no FEC; just deliver it.
                let mut asm = FrameAssembler::new();
                let r = asm.ingest(&data[0]).expect("single packet completes");
                assert_eq!(r.data, original);
                continue;
            }

            let parity_count = parity.len();
            // Recoverable iff we drop at most `parity_count` of the data packets
            // (RS recovers up to M erasures across the block).
            let max_drop = parity_count.min(data.len());
            let drop_count = if max_drop == 0 {
                0
            } else {
                rng.below(max_drop + 1)
            };

            // Choose which data packets to drop.
            let mut drop_idx: Vec<usize> = (0..data.len()).collect();
            for i in (1..drop_idx.len()).rev() {
                let j = rng.below(i + 1);
                drop_idx.swap(i, j);
            }
            drop_idx.truncate(drop_count);
            let drop_set: std::collections::HashSet<usize> = drop_idx.into_iter().collect();

            // Also randomly drop some parity packets, but keep enough surviving
            // shards (surviving_data + surviving_parity >= data.len()).
            let surviving_data = data.len() - drop_count;
            let parity_needed = data.len().saturating_sub(surviving_data); // == drop_count
            let parity_keep_min = parity_needed;
            let mut parity_drop = if parity_count > parity_keep_min {
                rng.below(parity_count - parity_keep_min + 1)
            } else {
                0
            };

            let mut asm = FrameAssembler::new();
            let mut completed = None;
            // Deliver surviving data packets (shuffled order).
            let mut order: Vec<usize> = (0..data.len()).collect();
            for i in (1..order.len()).rev() {
                let j = rng.below(i + 1);
                order.swap(i, j);
            }
            for &idx in &order {
                if drop_set.contains(&idx) {
                    continue;
                }
                if let Some(f) = asm.ingest(&data[idx]) {
                    completed = Some(f);
                }
            }
            // Deliver parity packets, dropping `parity_drop` of them.
            for pkt in &parity {
                if parity_drop > 0 {
                    parity_drop -= 1;
                    continue;
                }
                if let Some(f) = asm.ingest(pkt) {
                    completed = Some(f);
                }
            }

            let r = completed.unwrap_or_else(|| {
                panic!(
                    "trial {trial}: RS failed to recover (size={size} data={} parity={parity_count} drop={drop_count})",
                    data.len()
                )
            });
            assert_eq!(
                r.data, original,
                "trial {trial}: byte mismatch after RS recovery"
            );
            assert_eq!(r.frame_id, frame_id);
        }
    }

    #[test]
    fn frame_reassembly_preserves_wrapped_sequence_order() {
        let mut slicer = FrameSlicer::new();
        slicer.set_seq_for_test(u16::MAX - 1);
        let mut assembler = FrameAssembler::new();

        let original = vec![0x22; 6_000];
        let packets = slicer.slice(&original, 13).to_vec();
        let mut completed = None;
        for pkt in packets {
            if let Some(frame) = assembler.ingest(&pkt) {
                completed = Some(frame);
            }
        }

        let result = completed.expect("wrapped frame should complete");
        assert_eq!(result.frame_id, 13);
        assert_eq!(result.data, original);
    }
}
