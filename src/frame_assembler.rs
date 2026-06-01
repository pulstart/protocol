use crate::packet::{
    FrameParityMeta, FrameTimingMeta, PacketHeader, PayloadType, FRAME_PARITY_HEADER_SIZE,
    FRAME_START_HEADER_SIZE, HEADER_SIZE,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct CompletedFrame {
    pub frame_id: u32,
    pub data: Vec<u8>,
    pub timing: FrameTimingMeta,
    /// Frame type from the FrameStart header (see [`crate::packet::frame_type`]).
    /// Lets the client recovery state machine key off an explicit marker instead
    /// of trial-decoding. Defaults to `P` when the FrameStart was recovered via
    /// parity (no header) or sent by a legacy peer.
    pub frame_type: u8,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyFeedback {
    pub lost_packets: u32,
    pub late_packets: u32,
    pub dropped_frames: u32,
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
}

/// Maximum number of pending incomplete frames before forcing cleanup.
const MAX_PENDING_FRAMES: usize = 30;

pub struct FrameAssembler {
    pending: HashMap<u32, PartialFrame>,
    last_completed: u32,
    has_completed: bool,
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
            last_completed: 0,
            has_completed: false,
        }
    }

    /// Feed a raw UDP packet. Returns a completed frame if all packets arrived.
    pub fn ingest(&mut self, raw: &[u8]) -> Option<CompletedFrame> {
        self.ingest_with_feedback(raw).completed
    }

    /// Feed a raw UDP packet, returning both the completed frame and any
    /// loss/late feedback inferred from the reassembly state.
    pub fn ingest_with_feedback(&mut self, raw: &[u8]) -> IngestOutcome {
        let mut outcome = IngestOutcome::default();
        let Some(header) = PacketHeader::deserialize(raw) else {
            return outcome;
        };
        let payload = &raw[HEADER_SIZE..];

        // Discard frames older than what we've already completed.
        // Use wrapping arithmetic so frame_id wraparound (u32::MAX → 0) works.
        if self.has_completed {
            let age = header.frame_id.wrapping_sub(self.last_completed);
            // age >= 0x8000_0000 means header.frame_id is behind last_completed
            // (or equal when age == 0).
            if age == 0 || age >= 0x8000_0000 {
                outcome.feedback.late_packets = 1;
                return outcome;
            }
        }

        let frame = self
            .pending
            .entry(header.frame_id)
            .or_insert_with(|| PartialFrame {
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
            });

        match header.payload_type {
            PayloadType::FrameStart => {
                if payload.len() < 2 {
                    return outcome;
                }
                let (total_packets, ftype, timing, data_offset) =
                    if let Some((total_packets, ftype, timing)) =
                        FrameTimingMeta::deserialize(payload)
                    {
                        (total_packets, ftype, timing, FRAME_START_HEADER_SIZE)
                    } else {
                        (
                            u16::from_be_bytes([payload[0], payload[1]]),
                            crate::packet::frame_type::P,
                            FrameTimingMeta::default(),
                            2,
                        )
                    };
                // Only accept the first FrameStart for a given frame to prevent
                // metadata overwrites from duplicates or retransmissions.
                if frame.start_seq.is_none() {
                    frame.total_packets = total_packets;
                    frame.start_seq = Some(header.seq);
                    frame.timing = timing;
                }
                // FrameStart is authoritative for frame_type even if a parity
                // packet set it first.
                frame.frame_type = ftype;
                frame.frame_type_from_start = true;
                insert_packet_chunk(frame, header.seq, payload[data_offset..].to_vec());
            }
            PayloadType::Data => {
                insert_packet_chunk(frame, header.seq, payload.to_vec());
            }
            PayloadType::Parity => {
                let Some(meta) = FrameParityMeta::deserialize(payload) else {
                    return outcome;
                };
                if frame.total_packets == 0 {
                    frame.total_packets = meta.total_packets;
                } else if frame.total_packets != meta.total_packets {
                    return outcome;
                }
                frame.start_seq.get_or_insert(meta.start_seq);
                frame.expected_payload_bytes = Some(meta.chunk_bytes_sum as usize);
                if frame.timing == FrameTimingMeta::default() {
                    frame.timing = meta.timing;
                }
                // Parity carries the unit's frame type so a lost FrameStart still
                // recovers IDR vs P — but a real FrameStart always wins.
                if !frame.frame_type_from_start {
                    frame.frame_type = meta.frame_type;
                }
                let shard = &payload[FRAME_PARITY_HEADER_SIZE..];
                if meta.is_rs() {
                    frame.rs_parity_shards = meta.parity_shards;
                    frame.rs_shard_len = meta.shard_len;
                    // Dedup recovery shards by index (duplicate datagrams).
                    if !frame
                        .rs_recovery
                        .iter()
                        .any(|(idx, _)| *idx == meta.shard_index)
                    {
                        frame.rs_recovery.push((meta.shard_index, shard.to_vec()));
                    }
                } else {
                    frame.parity = Some(shard.to_vec());
                }
            }
            PayloadType::Audio => {
                // Audio packets are demuxed at the transport layer, not assembled.
                return outcome;
            }
            PayloadType::MouseAbsolute
            | PayloadType::MouseRelative
            | PayloadType::MouseButtons
            | PayloadType::MouseWheel
            | PayloadType::KeyboardState => {
                // Client input travels on the same UDP protocol but is not part of
                // server-to-client media reassembly.
                return outcome;
            }
        }

        try_recover_single_loss(frame);
        try_recover_rs(frame);

        // Check completion
        if frame.total_packets > 0 && frame.received.len() == frame.total_packets as usize {
            let Some(partial) = self.pending.remove(&header.frame_id) else {
                return outcome;
            };
            let mut data = Vec::with_capacity(partial.payload_bytes);
            if let Some(start_seq) = partial.start_seq {
                for offset in 0..partial.total_packets {
                    let seq = start_seq.wrapping_add(offset);
                    let Some(chunk) = partial.received.get(&seq) else {
                        return outcome;
                    };
                    data.extend_from_slice(chunk);
                }
            } else {
                let mut seqs: Vec<u16> = partial.received.keys().copied().collect();
                seqs.sort();
                for seq in seqs {
                    data.extend_from_slice(&partial.received[&seq]);
                }
            }

            // Purge any older pending frames
            if self.has_completed {
                let gap = header.frame_id.wrapping_sub(self.last_completed);
                if gap > 1 && gap < 0x8000_0000 {
                    outcome.feedback.dropped_frames = gap - 1;
                }
            }

            self.last_completed = header.frame_id;
            self.has_completed = true;
            self.pending.retain(|&fid, frame| {
                // Use wrapping distance to handle u32 frame_id wraparound.
                let dist = fid.wrapping_sub(header.frame_id);
                // dist > 0 && dist < 0x8000_0000 means fid is ahead (newer) — keep it.
                if dist > 0 && dist < 0x8000_0000 {
                    return true;
                }
                // fid is older or equal — count lost packets and remove.
                if fid != header.frame_id && frame.total_packets > 0 {
                    outcome.feedback.lost_packets = outcome.feedback.lost_packets.saturating_add(
                        frame
                            .total_packets
                            .saturating_sub(frame.received.len() as u16)
                            as u32,
                    );
                }
                false
            });

            // Safety valve: if too many pending frames accumulated (stream stall
            // or severe loss), purge the oldest to prevent unbounded memory growth.
            while self.pending.len() > MAX_PENDING_FRAMES {
                if let Some(&oldest_fid) = self.pending.keys().min() {
                    self.pending.remove(&oldest_fid);
                } else {
                    break;
                }
            }

            outcome.completed = Some(CompletedFrame {
                frame_id: header.frame_id,
                data,
                timing: partial.timing,
                frame_type: partial.frame_type,
            });
        }

        outcome
    }
}

fn insert_packet_chunk(frame: &mut PartialFrame, seq: u16, packet: Vec<u8>) {
    if frame.total_packets > 0 && frame.received.capacity() < frame.total_packets as usize {
        frame
            .received
            .reserve(frame.total_packets as usize - frame.received.capacity());
    }
    let packet_len = packet.len();
    if let Some(old) = frame.received.insert(seq, packet) {
        frame.payload_bytes = frame.payload_bytes.saturating_sub(old.len());
    }
    frame.payload_bytes = frame.payload_bytes.saturating_add(packet_len);
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

    let missing_len = expected_payload_bytes.saturating_sub(frame.payload_bytes);
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
    insert_packet_chunk(frame, missing_seq, recovered);
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
        if shard.len() < 2 || pos >= total {
            continue;
        }
        let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
        if 2 + len > shard.len() {
            continue;
        }
        let chunk = shard[2..2 + len].to_vec();
        let seq = start_seq.wrapping_add(pos as u16);
        if !frame.received.contains_key(&seq) {
            insert_packet_chunk(frame, seq, chunk);
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
    fn old_frames_discarded() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        // Complete frame 5
        let packets = slicer.slice(&[1, 2, 3], 5).to_vec();
        assembler.ingest(&packets[0]).unwrap();

        // Now try to feed frame 3 — should be discarded
        let old_packets = slicer.slice(&[4, 5, 6], 3).to_vec();
        assert!(assembler.ingest(&old_packets[0]).is_none());
    }

    #[test]
    fn feedback_reports_dropped_partial_frame() {
        let mut slicer = FrameSlicer::new();
        let mut assembler = FrameAssembler::new();

        let frame1 = slicer.slice(&[1, 2, 3], 1).to_vec();
        assert!(assembler.ingest(&frame1[0]).is_some());

        let partial_frame2 = slicer.slice(&vec![7u8; 3000], 2).to_vec();
        assert!(assembler.ingest(&partial_frame2[0]).is_none());

        let frame3 = slicer.slice(&[4, 5, 6], 3).to_vec();
        let outcome = assembler.ingest_with_feedback(&frame3[0]);

        assert_eq!(outcome.feedback.dropped_frames, 1);
        assert!(outcome.feedback.lost_packets >= 1);
        assert_eq!(outcome.completed.unwrap().frame_id, 3);
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
        completed = completed.or(outcome.completed);

        let result = completed.expect("parity should recover one missing packet");
        assert_eq!(result.frame_id, 11);
        assert_eq!(result.data, original);
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
        for pkt in data.iter().skip(2).chain(parity.iter()) {
            if let Some(f) = assembler.ingest(pkt) {
                completed = Some(f);
            }
        }
        let result = completed.expect("RS should recover two lost packets");
        assert_eq!(result.frame_id, 21);
        assert_eq!(result.data, original);
        assert_eq!(result.frame_type, frame_type::IDR);
    }

    #[test]
    fn rs_recovers_lost_framestart_carries_type() {
        let mut slicer = rs_slicer(1_400, 50, 1);
        let mut assembler = FrameAssembler::new();
        let original = vec![0x3Cu8; 7_000];
        let timing = FrameTimingMeta {
            capture_ts_micros: 11,
            send_ts_micros: 22,
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
