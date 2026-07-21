use crate::packet::{
    frame_type, FecMode, FrameParityMeta, FrameTimingMeta, PacketHeader, PayloadType,
    FRAME_PARITY_HEADER_SIZE, FRAME_START_HEADER_SIZE, HEADER_SIZE,
};

/// FEC parameters for the slicer. For [`FecMode::Rs`], `fec_pct` and `min_parity`
/// pick the parity-shard count per multi-packet unit:
/// `parity = max(min_parity, ceil(data_shards * fec_pct / 100))`.
#[derive(Debug, Clone, Copy)]
pub struct FecConfig {
    pub mode: FecMode,
    pub fec_pct: u16,
    pub min_parity: u16,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            mode: FecMode::Xor,
            fec_pct: 15,
            min_parity: 1,
        }
    }
}

pub struct FrameSlicer {
    seq: u16,
    packets: Vec<Vec<u8>>,
    max_payload: usize,
    fec: FecConfig,
    /// When false, no parity packets are built at all (reliable links such as
    /// the TCP tunnel have nothing to recover, so the per-frame XOR/RS pass is
    /// pure waste). Default true.
    parity_enabled: bool,
    // XOR scratch.
    parity_data: Vec<u8>,
    // Parity packets for the last sliced unit (XOR ⇒ 0/1, RS ⇒ 0..M).
    parity_packets: Vec<Vec<u8>>,
    // RS scratch: equal-length, length-prefixed, zero-padded data shards.
    rs_shards: Vec<Vec<u8>>,
}

impl Default for FrameSlicer {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSlicer {
    pub fn new() -> Self {
        Self::with_max_udp(crate::packet::MAX_UDP)
    }

    pub fn with_max_udp(max_udp: usize) -> Self {
        Self::with_config(max_udp, FecConfig::default())
    }

    pub fn with_config(max_udp: usize, fec: FecConfig) -> Self {
        let min_udp = HEADER_SIZE + FRAME_PARITY_HEADER_SIZE + FRAME_START_HEADER_SIZE + 2;
        let clamped_udp = max_udp.max(min_udp);
        Self {
            seq: 0,
            packets: Vec::new(),
            max_payload: clamped_udp - HEADER_SIZE,
            fec,
            parity_enabled: true,
            parity_data: Vec::new(),
            parity_packets: Vec::new(),
            rs_shards: Vec::new(),
        }
    }

    pub fn set_fec(&mut self, fec: FecConfig) {
        self.fec = fec;
    }

    /// Enable/disable parity construction. Disable on reliable links (TCP
    /// tunnel) so no per-frame XOR/RS work is done for packets that would only
    /// be discarded.
    pub fn set_parity_enabled(&mut self, enabled: bool) {
        self.parity_enabled = enabled;
    }

    pub fn fec_mode(&self) -> FecMode {
        self.fec.mode
    }

    /// Live-update the RS parity percentage (A2 adaptive FEC). No-op effect on
    /// the XOR path, which always emits a single parity packet.
    pub fn set_fec_pct(&mut self, pct: u16) {
        self.fec.fec_pct = pct.min(100);
    }

    pub fn fec_pct(&self) -> u16 {
        self.fec.fec_pct
    }

    /// First parity packet (kept for callers that only handle single-XOR).
    pub fn parity_packet(&self) -> Option<&[u8]> {
        self.parity_packets.first().map(|p| p.as_slice())
    }

    /// All parity packets for the last sliced unit (XOR ⇒ ≤1, RS ⇒ 0..M).
    pub fn parity_packets(&self) -> &[Vec<u8>] {
        &self.parity_packets
    }

    #[cfg(test)]
    pub(crate) fn set_seq_for_test(&mut self, seq: u16) {
        self.seq = seq;
    }

    /// Media chunk byte cap per data packet (excluding the FrameStart meta on
    /// the first packet). For RS the cap is the shard length minus the 2-byte
    /// length prefix so each recovery shard fits the MTU.
    fn chunk_payload_cap(&self) -> usize {
        match self.fec.mode {
            FecMode::Xor => self.max_payload - FRAME_PARITY_HEADER_SIZE,
            FecMode::Rs => self.rs_shard_len() - 2,
        }
    }

    /// Even shard length so an RS recovery packet (header + shard) fits the MTU.
    fn rs_shard_len(&self) -> usize {
        (self.max_payload - FRAME_PARITY_HEADER_SIZE) & !1usize
    }

    /// Slice a NAL unit into MTU-sized UDP packets.
    ///
    /// The first packet of each frame carries:
    /// - 2-byte `total_packets`
    /// - 8-byte server capture timestamp
    /// - 8-byte server send timestamp
    /// - 8-byte video epoch
    /// - 1-byte frame type
    ///
    /// ...all followed by the NAL data itself.
    pub fn slice(&mut self, nal_data: &[u8], frame_id: u32) -> &[Vec<u8>] {
        self.slice_with_meta(nal_data, frame_id, FrameTimingMeta::default())
    }

    pub fn slice_with_meta(
        &mut self,
        nal_data: &[u8],
        frame_id: u32,
        timing: FrameTimingMeta,
    ) -> &[Vec<u8>] {
        self.slice_with_meta_in_place(nal_data, frame_id, timing, frame_type::P);
        &self.packets
    }

    pub fn slice_with_meta_parts(
        &mut self,
        nal_data: &[u8],
        frame_id: u32,
        timing: FrameTimingMeta,
        frame_type: u8,
    ) -> (&[Vec<u8>], &[Vec<u8>]) {
        self.slice_with_meta_in_place(nal_data, frame_id, timing, frame_type);
        (&self.packets, &self.parity_packets)
    }

    fn slice_with_meta_in_place(
        &mut self,
        nal_data: &[u8],
        frame_id: u32,
        timing: FrameTimingMeta,
        frame_type: u8,
    ) {
        self.parity_packets.clear();
        self.parity_data.clear();
        self.rs_shards.clear();

        let chunk_payload_cap = self.chunk_payload_cap();
        // First packet reserves metadata for packet count + frame timings.
        let first_payload_cap = chunk_payload_cap - FRAME_START_HEADER_SIZE;
        let total_packets = if nal_data.len() <= first_payload_cap {
            1u16
        } else {
            let remaining = nal_data.len() - first_payload_cap;
            1 + remaining.div_ceil(chunk_payload_cap) as u16
        };

        // Reuse packet vec — grow if needed, shrink if too many
        let count = total_packets as usize;
        self.packets.resize_with(count, Vec::new);
        self.packets.truncate(count);

        let do_fec = total_packets > 1 && self.parity_enabled;
        let rs = do_fec && self.fec.mode == FecMode::Rs;
        let shard_len = self.rs_shard_len();
        if rs {
            self.rs_shards.clear();
        }

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

            if do_fec && self.fec.mode == FecMode::Xor {
                if self.parity_data.len() < chunk.len() {
                    self.parity_data.resize(chunk.len(), 0);
                }
                for (dst, src) in self.parity_data[..chunk.len()].iter_mut().zip(chunk.iter()) {
                    *dst ^= *src;
                }
            } else if rs {
                // Length-prefixed, zero-padded equal-size data shard.
                let mut shard = vec![0u8; shard_len];
                shard[0..2].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
                shard[2..2 + chunk.len()].copy_from_slice(chunk);
                self.rs_shards.push(shard);
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
                    frame_type,
                    &mut self.packets[idx][HEADER_SIZE..HEADER_SIZE + FRAME_START_HEADER_SIZE],
                );
                self.packets[idx][HEADER_SIZE + FRAME_START_HEADER_SIZE..].copy_from_slice(chunk);
            } else {
                self.packets[idx][HEADER_SIZE..].copy_from_slice(chunk);
            }

            offset = chunk_end;
        }

        if !do_fec {
            return;
        }

        let chunk_bytes_sum_u32 = chunk_bytes_sum.min(u32::MAX as usize) as u32;
        match self.fec.mode {
            FecMode::Xor => {
                let header = PacketHeader {
                    seq: self.seq,
                    frame_id,
                    payload_type: PayloadType::Parity,
                };
                self.seq = self.seq.wrapping_add(1);
                let packet_len = HEADER_SIZE + FRAME_PARITY_HEADER_SIZE + self.parity_data.len();
                let mut pkt = vec![0u8; packet_len];
                header.serialize(&mut pkt[..HEADER_SIZE]);
                FrameParityMeta {
                    start_seq,
                    total_packets,
                    chunk_bytes_sum: chunk_bytes_sum_u32,
                    timing,
                    frame_type,
                    ..Default::default()
                }
                .serialize(&mut pkt[HEADER_SIZE..HEADER_SIZE + FRAME_PARITY_HEADER_SIZE]);
                pkt[HEADER_SIZE + FRAME_PARITY_HEADER_SIZE..].copy_from_slice(&self.parity_data);
                self.parity_packets.push(pkt);
            }
            FecMode::Rs => {
                let data_shards = total_packets as usize;
                let parity_shards = self.rs_parity_count(total_packets);
                let recovery = match reed_solomon_simd::encode(
                    data_shards,
                    parity_shards,
                    self.rs_shards.iter(),
                ) {
                    Ok(r) => r,
                    // Encode failure (unsupported counts / shard size) ⇒ degrade
                    // to XOR for this unit so the stream never loses parity.
                    Err(_) => {
                        self.emit_xor_fallback(
                            frame_id,
                            start_seq,
                            total_packets,
                            chunk_bytes_sum_u32,
                            timing,
                            frame_type,
                        );
                        return;
                    }
                };
                for (shard_index, shard) in recovery.into_iter().enumerate() {
                    let header = PacketHeader {
                        seq: self.seq,
                        frame_id,
                        payload_type: PayloadType::Parity,
                    };
                    self.seq = self.seq.wrapping_add(1);
                    let packet_len = HEADER_SIZE + FRAME_PARITY_HEADER_SIZE + shard.len();
                    let mut pkt = vec![0u8; packet_len];
                    header.serialize(&mut pkt[..HEADER_SIZE]);
                    FrameParityMeta {
                        start_seq,
                        total_packets,
                        chunk_bytes_sum: chunk_bytes_sum_u32,
                        timing,
                        data_shards: data_shards as u16,
                        parity_shards: parity_shards as u16,
                        shard_index: shard_index as u16,
                        shard_len: shard_len as u16,
                        frame_type,
                    }
                    .serialize(&mut pkt[HEADER_SIZE..HEADER_SIZE + FRAME_PARITY_HEADER_SIZE]);
                    pkt[HEADER_SIZE + FRAME_PARITY_HEADER_SIZE..].copy_from_slice(&shard);
                    self.parity_packets.push(pkt);
                }
            }
        }
    }

    fn rs_parity_count(&self, total_packets: u16) -> usize {
        let data = total_packets as usize;
        let by_pct = (data * self.fec.fec_pct as usize).div_ceil(100);
        by_pct.max(self.fec.min_parity as usize).max(1).min(data)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_xor_fallback(
        &mut self,
        frame_id: u32,
        start_seq: u16,
        total_packets: u16,
        chunk_bytes_sum: u32,
        timing: FrameTimingMeta,
        frame_type: u8,
    ) {
        // Recompute XOR parity over the already-built shard chunks.
        self.parity_data.clear();
        for shard in &self.rs_shards {
            let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
            let chunk = &shard[2..2 + len];
            if self.parity_data.len() < chunk.len() {
                self.parity_data.resize(chunk.len(), 0);
            }
            for (dst, src) in self.parity_data[..chunk.len()].iter_mut().zip(chunk.iter()) {
                *dst ^= *src;
            }
        }
        let header = PacketHeader {
            seq: self.seq,
            frame_id,
            payload_type: PayloadType::Parity,
        };
        self.seq = self.seq.wrapping_add(1);
        let packet_len = HEADER_SIZE + FRAME_PARITY_HEADER_SIZE + self.parity_data.len();
        let mut pkt = vec![0u8; packet_len];
        header.serialize(&mut pkt[..HEADER_SIZE]);
        FrameParityMeta {
            start_seq,
            total_packets,
            chunk_bytes_sum,
            timing,
            frame_type,
            ..Default::default()
        }
        .serialize(&mut pkt[HEADER_SIZE..HEADER_SIZE + FRAME_PARITY_HEADER_SIZE]);
        pkt[HEADER_SIZE + FRAME_PARITY_HEADER_SIZE..].copy_from_slice(&self.parity_data);
        self.parity_packets.push(pkt);
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

        let (total, ftype, timing) =
            FrameTimingMeta::deserialize(&packets[0][HEADER_SIZE..]).unwrap();
        assert_eq!(total, 1);
        assert_eq!(ftype, frame_type::P);
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
                let (total, _, _) = FrameTimingMeta::deserialize(&pkt[HEADER_SIZE..]).unwrap();
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

    #[test]
    fn parity_disabled_builds_no_parity_packets() {
        // Reliable links (TCP tunnel) disable parity entirely: the data
        // packets are still produced, but no XOR/RS parity is built or emitted.
        let fec = FecConfig {
            mode: FecMode::Rs,
            fec_pct: 30,
            min_parity: 2,
        };
        let mut slicer = FrameSlicer::with_config(1_400, fec);
        slicer.set_parity_enabled(false);
        let data = vec![0x42; 12_000];
        let (packets, parity) = {
            let (p, q) =
                slicer.slice_with_meta_parts(&data, 1, FrameTimingMeta::default(), frame_type::IDR);
            (p.to_vec(), q.to_vec())
        };
        assert!(packets.len() > 1, "multi-packet unit expected");
        assert!(parity.is_empty(), "no parity should be built when disabled");
    }

    #[test]
    fn rs_emits_multiple_parity_packets_within_mtu() {
        let fec = FecConfig {
            mode: FecMode::Rs,
            fec_pct: 30,
            min_parity: 2,
        };
        let mut slicer = FrameSlicer::with_config(1_400, fec);
        let data = vec![0x9C; 12_000];
        let (packets, parity) = {
            let (p, q) =
                slicer.slice_with_meta_parts(&data, 5, FrameTimingMeta::default(), frame_type::IDR);
            (p.to_vec(), q.to_vec())
        };
        assert!(packets.len() > 1);
        // ceil(N * 30 / 100) but at least min_parity=2.
        let expected = ((packets.len() * 30).div_ceil(100)).max(2);
        assert_eq!(parity.len(), expected);
        assert!(parity.iter().all(|p| p.len() <= 1_400));
        // Every parity packet declares RS with consistent block params.
        for (i, p) in parity.iter().enumerate() {
            let meta = FrameParityMeta::deserialize(&p[HEADER_SIZE..]).unwrap();
            assert!(meta.is_rs());
            assert_eq!(meta.data_shards as usize, packets.len());
            assert_eq!(meta.parity_shards as usize, parity.len());
            assert_eq!(meta.shard_index as usize, i);
            assert_eq!(meta.frame_type, frame_type::IDR);
        }
    }
}
