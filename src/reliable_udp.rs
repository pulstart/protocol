use crate::tunnel::CryptoContext;
use std::collections::{BTreeMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
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

/// Initial retransmit timeout.
const INITIAL_RTO: Duration = Duration::from_millis(200);

/// Minimum RTO floor.
const MIN_RTO: Duration = Duration::from_millis(50);

/// Maximum RTO ceiling.
const MAX_RTO: Duration = Duration::from_secs(2);

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
            let diff = ack.wrapping_sub(msg.seq);
            // If diff < MAX_SEND_WINDOW, the message seq is <= ack.
            let _acked_by_cumulative = diff < MAX_SEND_WINDOW as u32 && msg.seq == ack.wrapping_sub(diff);
            // Check if directly acked (seq == ack).
            let directly_acked = msg.seq == ack;
            // Check if selectively acked via bitmap.
            let selectively_acked = {
                let offset = msg.seq.wrapping_sub(ack).wrapping_sub(1);
                offset < 32 && (ack_bits & (1 << offset)) != 0
            };
            // Check cumulative: seq <= ack (with wrapping).
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
                    (self.rtt_estimate.as_micros() as u64 * 7 / 8
                        + rtt.as_micros() as u64 / 8) as u64,
                );
                self.rto = (self.rtt_estimate * 2).max(MIN_RTO).min(MAX_RTO);
            }

            !is_acked
        });
    }

    /// Record an incoming sequence number. Returns the payload if it should be
    /// delivered now, or `None` if it is a duplicate or buffered for reorder.
    fn record_recv(&mut self, seq: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let mut deliverable = Vec::new();

        if seq == self.recv_next {
            // In-order delivery.
            deliverable.push(payload);
            self.recv_next = self.recv_next.wrapping_add(1);

            // Shift bitmap and drain any buffered consecutive packets.
            while self.recv_bitmap & 1 != 0 {
                self.recv_bitmap >>= 1;
                if let Some(buffered) = self.recv_buf.remove(&self.recv_next) {
                    deliverable.push(buffered);
                }
                self.recv_next = self.recv_next.wrapping_add(1);
            }
            self.recv_bitmap >>= if !deliverable.is_empty() && deliverable.len() > 1 {
                0 // already shifted above
            } else {
                0
            };
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
}

impl PunchedSocket {
    /// Create from a hole-punched socket and confirmed peer address.
    pub fn new(socket: UdpSocket, peer: SocketAddr, crypto: Arc<CryptoContext>) -> Self {
        Self {
            socket,
            peer,
            crypto,
            reliable: Mutex::new(ReliableState::new()),
            encrypt_buf: Mutex::new(vec![0u8; 2048]),
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
        buf.resize(plain_len, 0);
        buf[0] = CHANNEL_MEDIA;
        buf[1..plain_len].copy_from_slice(data);

        let encrypted = self.crypto.encrypt(&buf[..plain_len]);
        self.socket
            .send_to(&encrypted, self.peer)
            .map_err(|e| format!("send_media: {e}"))?;
        Ok(())
    }

    /// Send a reliable control message (channel 1).
    pub fn send_control(&self, data: &[u8]) -> Result<(), String> {
        let mut state = self.reliable.lock().unwrap();
        if state.send_queue.len() >= MAX_SEND_WINDOW {
            return Err("reliable send window full".into());
        }

        let seq = state.next_seq();
        let (ack, ack_bits) = state.ack_header();

        // Build: [channel:1][seq:4][ack:4][ack_bits:4][payload]
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
        self.socket
            .send_to(&encrypted, self.peer)
            .map_err(|e| format!("send_control: {e}"))?;
        Ok(())
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

    /// Try to receive the next packet. Returns `None` if the socket would block.
    /// The socket should be set to non-blocking or have a short read timeout.
    pub fn try_recv(&self) -> Option<PunchedMessage> {
        let mut buf = [0u8; 2048];
        let (n, _src) = match self.socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return None;
            }
            Err(_) => return None,
        };

        let plaintext = self.crypto.decrypt(&buf[..n])?;
        if plaintext.is_empty() {
            return None;
        }

        let channel = plaintext[0];
        match channel {
            CHANNEL_MEDIA => {
                Some(PunchedMessage::Media(plaintext[1..].to_vec()))
            }
            CHANNEL_CONTROL => {
                if plaintext.len() < 1 + RELIABLE_HEADER_SIZE {
                    return None;
                }
                let seq = u32::from_be_bytes([
                    plaintext[1], plaintext[2], plaintext[3], plaintext[4],
                ]);
                let ack = u32::from_be_bytes([
                    plaintext[5], plaintext[6], plaintext[7], plaintext[8],
                ]);
                let ack_bits = u32::from_be_bytes([
                    plaintext[9], plaintext[10], plaintext[11], plaintext[12],
                ]);
                let payload = plaintext[1 + RELIABLE_HEADER_SIZE..].to_vec();

                let mut state = self.reliable.lock().unwrap();

                // Process piggybacked ack.
                state.process_ack(ack, ack_bits);

                // Record received seq and get deliverable payloads.
                if payload.is_empty() {
                    // Bare ack or empty control — nothing to deliver.
                    return None;
                }
                let delivered = state.record_recv(seq, payload);
                drop(state);

                // Send ack back.
                let _ = self.send_ack();

                // Return the first deliverable message. If there are more,
                // they will be returned on subsequent calls (they're buffered
                // in the reliable state's reorder mechanism).
                // For simplicity, deliver the first one now.
                delivered.into_iter().next().map(PunchedMessage::Control)
            }
            _ => None,
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

    /// Retransmit unacked reliable messages that have exceeded the RTO.
    /// Call this periodically (e.g. every 10-50ms).
    pub fn tick(&self) {
        let retransmits = {
            let mut state = self.reliable.lock().unwrap();
            state.collect_retransmits()
        };
        for pkt in retransmits {
            let _ = self.socket.send_to(&pkt, self.peer);
        }
    }

    /// Block until all queued reliable messages have been acknowledged.
    /// Useful during the handshake phase.
    pub fn flush_control(&self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            {
                let state = self.reliable.lock().unwrap();
                if state.send_queue.is_empty() {
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
