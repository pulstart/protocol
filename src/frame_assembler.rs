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
    parity: Option<Vec<u8>>,
}

pub struct FrameAssembler {
    pending: HashMap<u32, PartialFrame>,
    last_completed: u32,
    has_completed: bool,
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

        // Discard frames older than what we've already completed
        if self.has_completed && header.frame_id <= self.last_completed {
            outcome.feedback.late_packets = 1;
            return outcome;
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
                parity: None,
            });

        match header.payload_type {
            PayloadType::FrameStart => {
                if payload.len() < 2 {
                    return outcome;
                }
                let (total_packets, timing, data_offset) =
                    if let Some((total_packets, timing)) = FrameTimingMeta::deserialize(payload) {
                        (total_packets, timing, FRAME_START_HEADER_SIZE)
                    } else {
                        (
                            u16::from_be_bytes([payload[0], payload[1]]),
                            FrameTimingMeta::default(),
                            2,
                        )
                    };
                frame.total_packets = total_packets;
                frame.start_seq = Some(header.seq);
                frame.timing = timing;
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
                frame.parity = Some(payload[FRAME_PARITY_HEADER_SIZE..].to_vec());
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
            if self.last_completed > 0 && header.frame_id > self.last_completed {
                outcome.feedback.dropped_frames =
                    header.frame_id.saturating_sub(self.last_completed + 1);
            }

            self.last_completed = header.frame_id;
            self.has_completed = true;
            self.pending.retain(|&fid, frame| {
                if fid > header.frame_id {
                    return true;
                }
                if fid < header.frame_id && frame.total_packets > 0 {
                    outcome.feedback.lost_packets = outcome.feedback.lost_packets.saturating_add(
                        frame
                            .total_packets
                            .saturating_sub(frame.received.len() as u16)
                            as u32,
                    );
                }
                false
            });

            outcome.completed = Some(CompletedFrame {
                frame_id: header.frame_id,
                data,
                timing: partial.timing,
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
        let packets = slicer.slice_with_meta(
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
        let recovered = assembler.ingest(&parity).expect("parity should recover first packet");
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
