use crate::tunnel::CryptoContext;
use std::collections::{BTreeMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Channel multiplexing
// ---------------------------------------------------------------------------

/// Channel byte prefixed to every packet before encryption.
const CHANNEL_MEDIA: u8 = 0x00;
const CHANNEL_CONTROL: u8 = 0x01;

/// Reliable header: [seq:u32][ack:u32][ack_bits:u32] = 12 bytes.
const RELIABLE_HEADER_SIZE: usize = 12;

/// Per-packet overhead for punched-socket media: 1 byte channel prefix.
pub const PUNCHED_MEDIA_OVERHEAD: usize = 1;

/// Per-packet overhead for punched-socket control: 1 byte channel + 12 bytes reliable header.
pub const PUNCHED_CONTROL_OVERHEAD: usize = 1 + RELIABLE_HEADER_SIZE;

/// Maximum number of unacked reliable messages in flight.
const MAX_SEND_WINDOW: usize = 64;

/// Hard cap on the local control backlog when the send window is full.
/// Callers that exceed this are throttled out (`send_control` returns Err),
/// matching the old behavior. File transfer / clipboard / etc. now ride the
/// backlog through transient stalls instead of being silently dropped.
const MAX_CONTROL_BACKLOG: usize = 1024;

/// Initial retransmit timeout.
const INITIAL_RTO: Duration = Duration::from_millis(200);

/// Minimum RTO floor.
const MIN_RTO: Duration = Duration::from_millis(50);

/// Maximum RTO ceiling.
const MAX_RTO: Duration = Duration::from_secs(2);
#[cfg(unix)]
const DEFAULT_PUNCHED_UDP_SNDBUF: i32 = 1024 * 1024;
#[cfg(unix)]
const DEFAULT_PUNCHED_UDP_RCVBUF: i32 = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const DEFAULT_PUNCHED_UDP_SO_PRIORITY: i32 = 5;

#[cfg(unix)]
fn set_socket_int_opt(
    socket: &UdpSocket,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &value as *const _ as *const _,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn configure_punched_socket(socket: &UdpSocket, peer: SocketAddr) {
    #[cfg(unix)]
    {
        let send_buf = std::env::var("ST_UDP_SNDBUF")
            .ok()
            .and_then(|raw| raw.parse::<i32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_PUNCHED_UDP_SNDBUF);
        let recv_buf = std::env::var("ST_UDP_RCVBUF")
            .ok()
            .and_then(|raw| raw.parse::<i32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_PUNCHED_UDP_RCVBUF);
        let _ = set_socket_int_opt(socket, libc::SOL_SOCKET, libc::SO_SNDBUF, send_buf);
        let _ = set_socket_int_opt(socket, libc::SOL_SOCKET, libc::SO_RCVBUF, recv_buf);

        if let Some(dscp) = std::env::var("ST_UDP_DSCP")
            .ok()
            .and_then(|raw| raw.parse::<u8>().ok())
            .filter(|value| *value <= 63)
        {
            let tos = i32::from(dscp) << 2;
            let (level, optname) = match peer.ip() {
                std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
                    (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
                }
                _ => (libc::IPPROTO_IP, libc::IP_TOS),
            };
            let _ = set_socket_int_opt(socket, level, optname, tos);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let priority = std::env::var("ST_UDP_SO_PRIORITY")
            .ok()
            .and_then(|raw| raw.parse::<i32>().ok())
            .filter(|value| *value >= 0)
            .unwrap_or(DEFAULT_PUNCHED_UDP_SO_PRIORITY);
        let _ = set_socket_int_opt(socket, libc::SOL_SOCKET, libc::SO_PRIORITY, priority);
    }

    #[cfg(not(unix))]
    let _ = (socket, peer);
}

// ---------------------------------------------------------------------------
// Received message types
// ---------------------------------------------------------------------------

pub enum PunchedMessage {
    /// Unreliable media/input data (channel 0). The payload starts after the
    /// channel byte — it is the original media packet.
    Media(Vec<u8>),
    /// Reliably-delivered control message (channel 1). The payload is the
    /// serialized `ControlMessage` bytes (without reliable header).
    Control(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Reliable state
// ---------------------------------------------------------------------------

struct UnackedMessage {
    seq: u32,
    payload: Vec<u8>, // the full reliable packet (channel + header + data)
    last_sent: Instant,
    send_count: u32,
}

struct ReliableState {
    // -- Send --
    send_seq: u32,
    send_queue: VecDeque<UnackedMessage>,

    // -- Receive --
    /// Highest contiguous sequence number delivered + 1 (next expected).
    recv_next: u32,
    /// Bitmask of received sequences beyond recv_next (bit 0 = recv_next+1, etc.).
    recv_bitmap: u32,
    /// Reorder buffer for out-of-order packets.
    recv_buf: BTreeMap<u32, Vec<u8>>,

    // -- RTT --
    rtt_estimate: Duration,
    rto: Duration,
}

impl ReliableState {
    fn new() -> Self {
        Self {
            send_seq: 0,
            send_queue: VecDeque::new(),
            recv_next: 0,
            recv_bitmap: 0,
            recv_buf: BTreeMap::new(),
            rtt_estimate: Duration::from_millis(100),
            rto: INITIAL_RTO,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    /// Build the [ack:u32][ack_bits:u32] portion of the reliable header.
    fn ack_header(&self) -> (u32, u32) {
        // ack = the highest sequence number we have received (recv_next - 1),
        // or 0 if we haven't received anything yet.
        let ack = self.recv_next.wrapping_sub(1);
        (ack, self.recv_bitmap)
    }

    /// Process an incoming ack, removing acknowledged messages from the send queue.
    fn process_ack(&mut self, ack: u32, ack_bits: u32) {
        let now = Instant::now();
        self.send_queue.retain(|msg| {
            // Check if directly acked (seq == ack).
            let directly_acked = msg.seq == ack;
            // Check if selectively acked via bitmap (bits represent ack+1, ack+2, ...).
            let selectively_acked = {
                let offset = msg.seq.wrapping_sub(ack).wrapping_sub(1);
                offset < 32 && (ack_bits & (1 << offset)) != 0
            };
            // Check cumulative: seq < ack (with wrapping).
            let cumulative_acked = {
                let d = ack.wrapping_sub(msg.seq);
                d > 0 && d < MAX_SEND_WINDOW as u32
            };

            let is_acked = directly_acked || selectively_acked || cumulative_acked;

            if is_acked && msg.send_count == 1 {
                // Update RTT estimate from first-send messages only.
                let rtt = now.duration_since(msg.last_sent);
                // Exponential moving average: rtt_est = 0.875 * rtt_est + 0.125 * rtt.
                self.rtt_estimate = Duration::from_micros(
                    (self.rtt_estimate.as_micros() as u64 * 7 / 8 + rtt.as_micros() as u64 / 8)
                        as u64,
                );
                self.rto = (self.rtt_estimate * 2).max(MIN_RTO).min(MAX_RTO);
            }

            !is_acked
        });
    }

    /// Record an incoming sequence number. Returns the payloads that became
    /// deliverable in order (possibly more than one if this packet plugged a
    /// gap), or an empty vec if it is a duplicate / buffered for reorder.
    ///
    /// Invariant maintained on every `recv_next++`: bitmap bit `k` means
    /// "seq = recv_next + k + 1 has been received". Each time we advance
    /// `recv_next`, we must shift the bitmap right by one to keep that mapping
    /// regardless of whether we actually deliver a buffered packet.
    fn record_recv(&mut self, seq: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let mut deliverable = Vec::new();

        if seq == self.recv_next {
            deliverable.push(payload);
            loop {
                // Advance recv_next and slide the bitmap so bit 0 stays at recv_next+1.
                self.recv_next = self.recv_next.wrapping_add(1);
                let bit0 = self.recv_bitmap & 1 != 0;
                self.recv_bitmap >>= 1;
                if !bit0 {
                    break;
                }
                if let Some(buffered) = self.recv_buf.remove(&self.recv_next) {
                    deliverable.push(buffered);
                }
            }
        } else {
            let offset = seq.wrapping_sub(self.recv_next);
            if offset == 0 || offset >= MAX_SEND_WINDOW as u32 {
                // Duplicate or too far behind.
                return deliverable;
            }
            // offset >= 1: mark in bitmap (bit 0 = recv_next+1, so bit index = offset-1).
            let bit_idx = offset.wrapping_sub(1);
            if bit_idx < 32 {
                if self.recv_bitmap & (1 << bit_idx) != 0 {
                    // Already received, duplicate.
                    return deliverable;
                }
                self.recv_bitmap |= 1 << bit_idx;
                self.recv_buf.insert(seq, payload);
            }
            // else: too far ahead, drop.
        }

        deliverable
    }

    /// Collect packets that need retransmission.
    fn collect_retransmits(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut retransmits = Vec::new();
        for msg in &mut self.send_queue {
            if now.duration_since(msg.last_sent) >= self.rto {
                retransmits.push(msg.payload.clone());
                msg.last_sent = now;
                msg.send_count += 1;
            }
        }
        retransmits
    }
}

// ---------------------------------------------------------------------------
// PunchedSocket
// ---------------------------------------------------------------------------

/// A UDP socket with a confirmed peer address from hole punching,
/// providing encrypted unreliable media and reliable control channels.
pub struct PunchedSocket {
    socket: UdpSocket,
    peer: SocketAddr,
    crypto: Arc<CryptoContext>,
    reliable: Mutex<ReliableState>,
    // Scratch buffers (per-thread callers clone the socket, so these are per-instance).
    encrypt_buf: Mutex<Vec<u8>>,
    /// Messages decoded from a UDP datagram but not yet returned by `try_recv`.
    /// A single datagram can deliver multiple control messages when an in-order
    /// arrival drains buffered reordered packets; `try_recv` returns the first
    /// and leaves the rest here so they aren't silently lost.
    pending_in: Mutex<VecDeque<PunchedMessage>>,
    /// Plaintext control payloads waiting for the reliable send window to free.
    /// Drained by `tick()` as acks arrive.
    pending_out: Mutex<VecDeque<Vec<u8>>>,
}

impl PunchedSocket {
    /// Create from a hole-punched socket and confirmed peer address.
    pub fn new(socket: UdpSocket, peer: SocketAddr, crypto: Arc<CryptoContext>) -> Self {
        configure_punched_socket(&socket, peer);
        Self {
            socket,
            peer,
            crypto,
            reliable: Mutex::new(ReliableState::new()),
            encrypt_buf: Mutex::new(vec![0u8; 2048]),
            pending_in: Mutex::new(VecDeque::new()),
            pending_out: Mutex::new(VecDeque::new()),
        }
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Send an unreliable media/input packet (channel 0).
    pub fn send_media(&self, data: &[u8]) -> Result<(), String> {
        let mut buf = self.encrypt_buf.lock().unwrap();
        let plain_len = 1 + data.len();
        let packet_len = plain_len + crate::tunnel::CRYPTO_OVERHEAD;
        buf.resize(packet_len, 0);
        buf[12] = CHANNEL_MEDIA;
        buf[13..13 + data.len()].copy_from_slice(data);
        let encrypted_len = self
            .crypto
            .encrypt_staged_in_place(&mut buf[..packet_len], plain_len);
        self.socket
            .send_to(&buf[..encrypted_len], self.peer)
            .map_err(|e| format!("send_media: {e}"))?;
        Ok(())
    }

    /// Try to send `data` directly. Returns `true` if it entered the reliable
    /// send window (and was emitted on the wire), `false` if the window was full.
    fn try_send_control_now(&self, data: &[u8]) -> bool {
        let mut state = self.reliable.lock().unwrap();
        if state.send_queue.len() >= MAX_SEND_WINDOW {
            return false;
        }
        let seq = state.next_seq();
        let (ack, ack_bits) = state.ack_header();
        let total = 1 + RELIABLE_HEADER_SIZE + data.len();
        let mut plain = vec![0u8; total];
        plain[0] = CHANNEL_CONTROL;
        plain[1..5].copy_from_slice(&seq.to_be_bytes());
        plain[5..9].copy_from_slice(&ack.to_be_bytes());
        plain[9..13].copy_from_slice(&ack_bits.to_be_bytes());
        plain[13..].copy_from_slice(data);
        let encrypted = self.crypto.encrypt(&plain);
        state.send_queue.push_back(UnackedMessage {
            seq,
            payload: encrypted.clone(),
            last_sent: Instant::now(),
            send_count: 1,
        });
        drop(state);
        let _ = self.socket.send_to(&encrypted, self.peer);
        true
    }

    /// Send a reliable control message (channel 1). If the send window is full
    /// the payload is queued in a bounded local backlog and drained by `tick()`
    /// as acks arrive. Only returns Err when the backlog itself is full
    /// (1024 deep), which keeps long file-transfer bursts from being silently
    /// dropped without unbounded memory growth.
    pub fn send_control(&self, data: &[u8]) -> Result<(), String> {
        if self.try_send_control_now(data) {
            return Ok(());
        }
        let mut backlog = self.pending_out.lock().unwrap();
        if backlog.len() >= MAX_CONTROL_BACKLOG {
            return Err("reliable send backlog full".into());
        }
        backlog.push_back(data.to_vec());
        Ok(())
    }

    /// Drain as much of the local control backlog into the send window as
    /// will fit. Called from `tick()`.
    fn drain_pending_out(&self) {
        loop {
            let next = self.pending_out.lock().unwrap().pop_front();
            let Some(data) = next else { break };
            if !self.try_send_control_now(&data) {
                self.pending_out.lock().unwrap().push_front(data);
                break;
            }
        }
    }

    /// Send a standalone ack (channel 1, empty payload, not queued for reliability).
    fn send_ack(&self) -> Result<(), String> {
        let state = self.reliable.lock().unwrap();
        let (ack, ack_bits) = state.ack_header();
        drop(state);

        let mut plain = [0u8; 1 + RELIABLE_HEADER_SIZE];
        plain[0] = CHANNEL_CONTROL;
        plain[1..5].copy_from_slice(&0u32.to_be_bytes()); // seq 0, ignored for bare acks
        plain[5..9].copy_from_slice(&ack.to_be_bytes());
        plain[9..13].copy_from_slice(&ack_bits.to_be_bytes());

        let encrypted = self.crypto.encrypt(&plain);
        self.socket
            .send_to(&encrypted, self.peer)
            .map_err(|e| format!("send_ack: {e}"))?;
        Ok(())
    }

    /// Try to receive the next message. If a single UDP datagram unblocks
    /// multiple buffered reliable packets, the first one is returned now and
    /// the rest stay queued for subsequent `try_recv` calls — they are not
    /// silently discarded. Returns `None` if both the queue and the socket
    /// have nothing.
    pub fn try_recv(&self) -> Option<PunchedMessage> {
        if let Some(msg) = self.pending_in.lock().unwrap().pop_front() {
            return Some(msg);
        }
        let mut msgs = self.recv_one_datagram();
        if msgs.is_empty() {
            return None;
        }
        let first = msgs.remove(0);
        if !msgs.is_empty() {
            self.pending_in.lock().unwrap().extend(msgs);
        }
        Some(first)
    }

    /// Try to receive everything currently available: anything queued from
    /// prior `try_recv` calls plus one fresh UDP read. Returns empty when both
    /// sources are dry.
    pub fn try_recv_all(&self) -> Vec<PunchedMessage> {
        let mut out: Vec<PunchedMessage> = {
            let mut q = self.pending_in.lock().unwrap();
            q.drain(..).collect()
        };
        out.extend(self.recv_one_datagram());
        out
    }

    /// Read one UDP datagram and decode it. Used by both `try_recv` and
    /// `try_recv_all`.
    fn recv_one_datagram(&self) -> Vec<PunchedMessage> {
        let mut buf = [0u8; 2048];
        let (n, _src) = match self.socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Vec::new();
            }
            Err(_) => return Vec::new(),
        };

        let plaintext = match self.crypto.decrypt_in_place(&mut buf[..n]) {
            Some(pt) => pt,
            None => return Vec::new(),
        };
        if plaintext.is_empty() {
            return Vec::new();
        }

        let channel = plaintext[0];
        match channel {
            CHANNEL_MEDIA => {
                vec![PunchedMessage::Media(plaintext[1..].to_vec())]
            }
            CHANNEL_CONTROL => {
                if plaintext.len() < 1 + RELIABLE_HEADER_SIZE {
                    return Vec::new();
                }
                let seq =
                    u32::from_be_bytes([plaintext[1], plaintext[2], plaintext[3], plaintext[4]]);
                let ack =
                    u32::from_be_bytes([plaintext[5], plaintext[6], plaintext[7], plaintext[8]]);
                let ack_bits =
                    u32::from_be_bytes([plaintext[9], plaintext[10], plaintext[11], plaintext[12]]);
                let payload = plaintext[1 + RELIABLE_HEADER_SIZE..].to_vec();

                let mut state = self.reliable.lock().unwrap();

                // Process piggybacked ack (may free room in send window).
                state.process_ack(ack, ack_bits);

                // Record received seq and get deliverable payloads.
                if payload.is_empty() {
                    // Bare ack or empty control — nothing to deliver.
                    return Vec::new();
                }
                let delivered = state.record_recv(seq, payload);
                drop(state);

                // Acks may have freed window room — flush backlog opportunistically.
                self.drain_pending_out();

                // Send ack back.
                let _ = self.send_ack();

                // Return all deliverable messages (in-order + any consecutive
                // buffered packets that became deliverable).
                delivered.into_iter().map(PunchedMessage::Control).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Blocking receive with timeout. Polls `try_recv()` in a loop.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<PunchedMessage> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(msg) = self.try_recv() {
                return Some(msg);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }

    /// Retransmit unacked reliable messages that have exceeded the RTO, and
    /// drain any backlog that's been waiting for the send window to free.
    /// Call this periodically (e.g. every 10-50ms).
    pub fn tick(&self) {
        // First try to push backlog into the freshly available window space.
        self.drain_pending_out();
        let retransmits = {
            let mut state = self.reliable.lock().unwrap();
            state.collect_retransmits()
        };
        for pkt in retransmits {
            let _ = self.socket.send_to(&pkt, self.peer);
        }
    }

    /// Block until all queued reliable messages have been acknowledged and
    /// the local backlog has drained.
    /// Useful during the handshake phase.
    pub fn flush_control(&self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            {
                let state = self.reliable.lock().unwrap();
                let backlog_empty = self.pending_out.lock().unwrap().is_empty();
                if state.send_queue.is_empty() && backlog_empty {
                    return Ok(());
                }
            }
            self.tick();
            // Also drain incoming packets (they may carry acks).
            while self.try_recv().is_some() {}
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("flush_control timed out".into())
    }

    /// Set the socket to non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), String> {
        self.socket
            .set_nonblocking(nonblocking)
            .map_err(|e| format!("set_nonblocking: {e}"))
    }

    /// Set the socket read timeout.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), String> {
        self.socket
            .set_read_timeout(dur)
            .map_err(|e| format!("set_read_timeout: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(seq: u32) -> Vec<u8> {
        seq.to_be_bytes().to_vec()
    }

    /// Regression guard for the bitmap-alignment bug. seq=7 arrives first
    /// (buffered at offset 2 from recv_next=5). Then seq=5 arrives in-order.
    /// The old code exited the drain loop early because bit 0 was 0 (seq 6
    /// missing) and never shifted the bitmap, leaving bit 1 set under the new
    /// recv_next=6 alignment — which then mis-flagged a future seq=8 as a
    /// duplicate AND stranded seq=7 in recv_buf.
    #[test]
    fn record_recv_bitmap_stays_aligned_after_gap() {
        let mut s = ReliableState::new();
        s.recv_next = 5;

        // seq=7 arrives first.
        assert!(s.record_recv(7, p(7)).is_empty());
        assert_eq!(s.recv_next, 5);
        assert_eq!(s.recv_bitmap, 0b10); // bit 1 = seq recv_next+2

        // seq=5 in-order. recv_next must advance to 6; bitmap must slide to
        // 0b01 so it still says "seq recv_next+1 (= 7) is buffered".
        let delivered = s.record_recv(5, p(5));
        assert_eq!(delivered, vec![p(5)]);
        assert_eq!(s.recv_next, 6);
        assert_eq!(s.recv_bitmap, 0b01);

        // seq=6 in-order must drain seq=7 as well.
        let delivered = s.record_recv(6, p(6));
        assert_eq!(delivered, vec![p(6), p(7)]);
        assert_eq!(s.recv_next, 8);
        assert_eq!(s.recv_bitmap, 0);
        assert!(s.recv_buf.is_empty());

        // After the drain, seq=9 arrives with seq=8 still missing. Must be
        // recorded as buffered (bit 0), NOT mis-flagged as duplicate.
        assert!(s.record_recv(9, p(9)).is_empty());
        assert_eq!(s.recv_bitmap, 0b01);
    }

    /// seq=6 buffered before seq=5; in-order arrival of seq=5 should drain
    /// both. The bitmap must end at 0.
    #[test]
    fn record_recv_drain_consecutive_buffered() {
        let mut s = ReliableState::new();
        s.recv_next = 5;
        assert!(s.record_recv(6, p(6)).is_empty());
        let delivered = s.record_recv(5, p(5));
        assert_eq!(delivered, vec![p(5), p(6)]);
        assert_eq!(s.recv_next, 7);
        assert_eq!(s.recv_bitmap, 0);
    }
}
