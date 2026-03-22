use crate::packet::{
    FrameTimingMeta, PacketHeader, PayloadType, FRAME_START_HEADER_SIZE, HEADER_SIZE, MAX_PAYLOAD,
};

pub struct FrameSlicer {
    seq: u16,
    packets: Vec<Vec<u8>>,
}

impl FrameSlicer {
    pub fn new() -> Self {
        Self {
            seq: 0,
            packets: Vec::new(),
        }
    }

    /// Slice a NAL unit into MTU-sized UDP packets.
    ///
    /// The first packet of each frame carries:
    /// - 2-byte `total_packets`
    /// - 8-byte server capture timestamp
    /// - 8-byte server send timestamp
    /// followed by NAL data.
    pub fn slice(&mut self, nal_data: &[u8], frame_id: u32) -> &[Vec<u8>] {
        self.slice_with_meta(nal_data, frame_id, FrameTimingMeta::default())
    }

    pub fn slice_with_meta(
        &mut self,
        nal_data: &[u8],
        frame_id: u32,
        timing: FrameTimingMeta,
    ) -> &[Vec<u8>] {
        // First packet reserves metadata for packet count + frame timings.
        let first_payload_cap = MAX_PAYLOAD - FRAME_START_HEADER_SIZE;
        let total_packets = if nal_data.len() <= first_payload_cap {
            1u16
        } else {
            let remaining = nal_data.len() - first_payload_cap;
            1 + ((remaining + MAX_PAYLOAD - 1) / MAX_PAYLOAD) as u16
        };

        // Reuse packet vec — grow if needed, shrink if too many
        let count = total_packets as usize;
        self.packets.resize_with(count, Vec::new);
        self.packets.truncate(count);

        let mut offset = 0usize;

        for i in 0..total_packets {
            let idx = i as usize;
            let is_first = i == 0;
            let payload_cap = if is_first {
                first_payload_cap
            } else {
                MAX_PAYLOAD
            };
            let chunk_end = (offset + payload_cap).min(nal_data.len());
            let chunk = &nal_data[offset..chunk_end];

            let payload_type = if is_first {
                PayloadType::FrameStart
            } else {
                PayloadType::Data
            };

            let header = PacketHeader {
                seq: self.seq,
                frame_id,
                payload_type,
            };
            self.seq = self.seq.wrapping_add(1);

            let packet_len = HEADER_SIZE
                + if is_first {
                    FRAME_START_HEADER_SIZE + chunk.len()
                } else {
                    chunk.len()
                };

            // Reuse existing Vec capacity
            self.packets[idx].clear();
            self.packets[idx].resize(packet_len, 0);
            header.serialize(&mut self.packets[idx][..HEADER_SIZE]);

            if is_first {
                timing.serialize(
                    total_packets,
                    &mut self.packets[idx][HEADER_SIZE..HEADER_SIZE + FRAME_START_HEADER_SIZE],
                );
                self.packets[idx][HEADER_SIZE + FRAME_START_HEADER_SIZE..].copy_from_slice(chunk);
            } else {
                self.packets[idx][HEADER_SIZE..].copy_from_slice(chunk);
            }

            offset = chunk_end;
        }

        &self.packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FrameTimingMeta, PacketHeader};

    #[test]
    fn single_packet_frame() {
        let mut slicer = FrameSlicer::new();
        let data = vec![0xAA; 100];
        let packets = slicer.slice(&data, 1).to_vec();
        assert_eq!(packets.len(), 1);

        let hdr = PacketHeader::deserialize(&packets[0]).unwrap();
        assert_eq!(hdr.frame_id, 1);
        assert_eq!(hdr.payload_type, PayloadType::FrameStart);

        let (total, timing) = FrameTimingMeta::deserialize(&packets[0][HEADER_SIZE..]).unwrap();
        assert_eq!(total, 1);
        assert_eq!(timing, FrameTimingMeta::default());

        // Remaining payload = original data
        assert_eq!(
            &packets[0][HEADER_SIZE + FRAME_START_HEADER_SIZE..],
            &data[..]
        );
    }

    #[test]
    fn multi_packet_frame() {
        let mut slicer = FrameSlicer::new();
        let data = vec![0xBB; 5000]; // > 1393, needs multiple packets
        let packets = slicer.slice(&data, 42).to_vec();
        assert!(packets.len() > 1);

        // Reassemble
        let mut reassembled = Vec::new();
        for (i, pkt) in packets.iter().enumerate() {
            if i == 0 {
                let (total, _) = FrameTimingMeta::deserialize(&pkt[HEADER_SIZE..]).unwrap();
                assert_eq!(total, packets.len() as u16);
                reassembled.extend_from_slice(&pkt[HEADER_SIZE + FRAME_START_HEADER_SIZE..]);
            } else {
                reassembled.extend_from_slice(&pkt[HEADER_SIZE..]);
            }
        }
        assert_eq!(reassembled, data);
    }

    #[test]
    fn seq_wraps() {
        let mut slicer = FrameSlicer::new();
        slicer.seq = u16::MAX;
        let packets = slicer.slice(&[1, 2, 3], 0).to_vec();
        let hdr = PacketHeader::deserialize(&packets[0]).unwrap();
        assert_eq!(hdr.seq, u16::MAX);
        // Next call should wrap
        let packets2 = slicer.slice(&[4, 5, 6], 1).to_vec();
        let hdr2 = PacketHeader::deserialize(&packets2[0]).unwrap();
        assert_eq!(hdr2.seq, 0);
    }
}
