use crate::packet::{
    FrameParityMeta, FrameTimingMeta, PacketHeader, PayloadType, FRAME_PARITY_HEADER_SIZE,
    FRAME_START_HEADER_SIZE, HEADER_SIZE,
};

pub struct FrameSlicer {
    seq: u16,
    packets: Vec<Vec<u8>>,
    max_payload: usize,
    parity_data: Vec<u8>,
    parity_packet: Vec<u8>,
}

impl FrameSlicer {
    pub fn new() -> Self {
        Self::with_max_udp(crate::packet::MAX_UDP)
    }

    pub fn with_max_udp(max_udp: usize) -> Self {
        let min_udp = HEADER_SIZE + FRAME_PARITY_HEADER_SIZE + FRAME_START_HEADER_SIZE + 1;
        let clamped_udp = max_udp.max(min_udp);
        Self {
            seq: 0,
            packets: Vec::new(),
            max_payload: clamped_udp - HEADER_SIZE,
            parity_data: Vec::new(),
            parity_packet: Vec::new(),
        }
    }

    pub fn parity_packet(&self) -> Option<&[u8]> {
        if self.parity_packet.is_empty() {
            None
        } else {
            Some(&self.parity_packet)
        }
    }

    #[cfg(test)]
    pub(crate) fn set_seq_for_test(&mut self, seq: u16) {
        self.seq = seq;
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
        self.slice_with_meta_in_place(nal_data, frame_id, timing);
        &self.packets
    }

    pub fn slice_with_meta_parts(
        &mut self,
        nal_data: &[u8],
        frame_id: u32,
        timing: FrameTimingMeta,
    ) -> (&[Vec<u8>], Option<&[u8]>) {
        self.slice_with_meta_in_place(nal_data, frame_id, timing);
        (&self.packets, self.parity_packet())
    }

    fn slice_with_meta_in_place(
        &mut self,
        nal_data: &[u8],
        frame_id: u32,
        timing: FrameTimingMeta,
    ) {
        self.parity_packet.clear();
        self.parity_data.clear();

        let chunk_payload_cap = self.max_payload - FRAME_PARITY_HEADER_SIZE;
        // First packet reserves metadata for packet count + frame timings.
        let first_payload_cap = chunk_payload_cap - FRAME_START_HEADER_SIZE;
        let total_packets = if nal_data.len() <= first_payload_cap {
            1u16
        } else {
            let remaining = nal_data.len() - first_payload_cap;
            1 + ((remaining + chunk_payload_cap - 1) / chunk_payload_cap) as u16
        };

        // Reuse packet vec — grow if needed, shrink if too many
        let count = total_packets as usize;
        self.packets.resize_with(count, Vec::new);
        self.packets.truncate(count);

        let mut offset = 0usize;
        let start_seq = self.seq;
        let mut chunk_bytes_sum = 0usize;

        for i in 0..total_packets {
            let idx = i as usize;
            let is_first = i == 0;
            let payload_cap = if is_first {
                first_payload_cap
            } else {
                chunk_payload_cap
            };
            let chunk_end = (offset + payload_cap).min(nal_data.len());
            let chunk = &nal_data[offset..chunk_end];
            chunk_bytes_sum += chunk.len();
            if total_packets > 1 {
                if self.parity_data.len() < chunk.len() {
                    self.parity_data.resize(chunk.len(), 0);
                }
                for (dst, src) in self.parity_data[..chunk.len()].iter_mut().zip(chunk.iter()) {
                    *dst ^= *src;
                }
            }

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

        if total_packets > 1 {
            let header = PacketHeader {
                seq: self.seq,
                frame_id,
                payload_type: PayloadType::Parity,
            };
            self.seq = self.seq.wrapping_add(1);
            let packet_len = HEADER_SIZE + FRAME_PARITY_HEADER_SIZE + self.parity_data.len();
            self.parity_packet.clear();
            self.parity_packet.resize(packet_len, 0);
            header.serialize(&mut self.parity_packet[..HEADER_SIZE]);
            FrameParityMeta {
                start_seq,
                total_packets,
                chunk_bytes_sum: chunk_bytes_sum.min(u32::MAX as usize) as u32,
                timing,
            }
            .serialize(
                &mut self.parity_packet
                    [HEADER_SIZE..HEADER_SIZE + FRAME_PARITY_HEADER_SIZE],
            );
            self.parity_packet[HEADER_SIZE + FRAME_PARITY_HEADER_SIZE..]
                .copy_from_slice(&self.parity_data);
        }

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
        slicer.set_seq_for_test(u16::MAX);
        let packets = slicer.slice(&[1, 2, 3], 0).to_vec();
        let hdr = PacketHeader::deserialize(&packets[0]).unwrap();
        assert_eq!(hdr.seq, u16::MAX);
        // Next call should wrap
        let packets2 = slicer.slice(&[4, 5, 6], 1).to_vec();
        let hdr2 = PacketHeader::deserialize(&packets2[0]).unwrap();
        assert_eq!(hdr2.seq, 0);
    }

    #[test]
    fn custom_udp_size_uses_smaller_packets() {
        let mut slicer = FrameSlicer::with_max_udp(1_200);
        let data = vec![0xAB; 10_000];
        let packets = slicer.slice(&data, 9).to_vec();
        assert!(packets.len() > 1);
        assert!(packets.iter().all(|pkt| pkt.len() <= 1_200));
        assert!(slicer.parity_packet().unwrap().len() <= 1_200);
    }
}
