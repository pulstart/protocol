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

const CONTROL_FRAGMENT_SINGLE: u8 = 0;
const CONTROL_FRAGMENT_START: u8 = 1;
const CONTROL_FRAGMENT_MIDDLE: u8 = 2;
const CONTROL_FRAGMENT_END: u8 = 3;
const CONTROL_FRAGMENT_HEADER_SIZE: usize = 5;
const MAX_PUNCHED_DATAGRAM_SIZE: usize = 1200;
const MAX_CONTROL_FRAGMENT_DATA: usize = MAX_PUNCHED_DATAGRAM_SIZE
    - crate::tunnel::CRYPTO_OVERHEAD
    - PUNCHED_CONTROL_OVERHEAD
    - CONTROL_FRAGMENT_HEADER_SIZE;

/// Maximum number of unacked reliable messages in flight.
/// One contiguous packet plus 32 selectively acknowledged packets fits the
/// wire's 32-bit receive bitmap.
const MAX_SEND_WINDOW: usize = 33;

/// Hard cap on the local control backlog when the send window is full.
/// Callers that exceed this are throttled out (`send_control` returns Err),
/// matching the old behavior. File transfer / clipboard / etc. now ride the
/// backlog through transient stalls instead of being silently dropped.
const MAX_CONTROL_BACKLOG: usize = 1024;

/// Largest complete serialized control bundle accepted for fragmentation.
/// A bundle may contain multiple individually length-prefixed control frames.
pub const MAX_PUNCHED_CONTROL_PAYLOAD: usize =
    MAX_CONTROL_FRAGMENT_DATA * (MAX_SEND_WINDOW + MAX_CONTROL_BACKLOG);

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

        // Media DSCP is default-on (CS5 = 40) per the auto-enable rule, mirroring
        // the direct-socket path. `ST_UDP_DSCP=off|0|false|no` disables it.
        let dscp = match std::env::var("ST_UDP_DSCP") {
            Ok(raw) => {
                let trimmed = raw.trim();
                match trimmed.to_ascii_lowercase().as_str() {
                    "off" | "0" | "false" | "no" => None,
                    _ => trimmed.parse::<u8>().ok().filter(|value| *value <= 63),
                }
            }
            Err(_) => Some(40u8),
        };
        if let Some(dscp) = dscp {
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

    #[cfg(test)]
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
        // Bit 0 represents ack+2 because ack+1 is recv_next, the missing packet
        // that currently blocks contiguous delivery.
        (ack, self.recv_bitmap)
    }

    /// Process an incoming ack, removing acknowledged messages from the send queue.
    fn process_ack(&mut self, ack: u32, ack_bits: u32) {
        let now = Instant::now();
        self.send_queue.retain(|msg| {
            // Check if directly acked (seq == ack).
            let directly_acked = msg.seq == ack;
            // Check if selectively acked via bitmap (bits represent ack+2, ack+3, ...).
            let selectively_acked = {
                let offset = msg.seq.wrapping_sub(ack).wrapping_sub(2);
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
                    self.rtt_estimate.as_micros() as u64 * 7 / 8 + rtt.as_micros() as u64 / 8,
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
    recv_buf: Mutex<Vec<u8>>,
    /// All admitted control fragments, in strict wire order. This mutex also
    /// serializes admission and draining into the reliable send window.
    control_send: Mutex<VecDeque<Vec<u8>>>,
    control_reassembly: Mutex<Option<(usize, Vec<u8>)>>,
    /// Messages decoded from a UDP datagram but not yet returned by `try_recv`.
    /// A single datagram can deliver multiple control messages when an in-order
    /// arrival drains buffered reordered packets; `try_recv` returns the first
    /// and leaves the rest here so they aren't silently lost.
    pending_in: Mutex<VecDeque<PunchedMessage>>,
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
            encrypt_buf: Mutex::new(vec![0u8; MAX_PUNCHED_DATAGRAM_SIZE]),
            recv_buf: Mutex::new(vec![0u8; MAX_PUNCHED_DATAGRAM_SIZE]),
            control_send: Mutex::new(VecDeque::new()),
            control_reassembly: Mutex::new(None),
            pending_in: Mutex::new(VecDeque::new()),
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
        if packet_len > MAX_PUNCHED_DATAGRAM_SIZE {
            return Err(format!(
                "media packet exceeds punched UDP limit: {packet_len} > {MAX_PUNCHED_DATAGRAM_SIZE}"
            ));
        }
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

    /// Try to emit the front control fragment. The sequence and retransmit entry
    /// are committed only after the atomic UDP send succeeds.
    fn try_send_control_now(&self, data: &[u8]) -> Result<bool, String> {
        let mut state = self.reliable.lock().unwrap();
        if state.send_queue.len() >= MAX_SEND_WINDOW {
            return Ok(false);
        }
        let seq = state.send_seq;
        let (ack, ack_bits) = state.ack_header();
        let total = 1 + RELIABLE_HEADER_SIZE + data.len();
        let mut plain = vec![0u8; total];
        plain[0] = CHANNEL_CONTROL;
        plain[1..5].copy_from_slice(&seq.to_be_bytes());
        plain[5..9].copy_from_slice(&ack.to_be_bytes());
        plain[9..13].copy_from_slice(&ack_bits.to_be_bytes());
        plain[13..].copy_from_slice(data);
        let encrypted = self.crypto.encrypt(&plain);
        let sent = self
            .socket
            .send_to(&encrypted, self.peer)
            .map_err(|error| format!("send_control: {error}"))?;
        if sent != encrypted.len() {
            return Err(format!(
                "send_control: partial UDP datagram ({sent} < {})",
                encrypted.len()
            ));
        }
        state.send_seq = state.send_seq.wrapping_add(1);
        state.send_queue.push_back(UnackedMessage {
            seq,
            payload: encrypted,
            last_sent: Instant::now(),
            send_count: 1,
        });
        Ok(true)
    }

    /// Send a reliable control message (channel 1). Admission is atomic across
    /// every fragment: once accepted, the full message remains queued through
    /// transient socket errors and is drained by `tick()` as room becomes
    /// available. Returns `Err` only when the bounded queue cannot admit it.
    pub fn send_control(&self, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_PUNCHED_CONTROL_PAYLOAD {
            return Err(format!(
                "reliable control payload exceeds UDP limit: {} > {MAX_PUNCHED_CONTROL_PAYLOAD}",
                data.len()
            ));
        }
        let fragments = control_fragments(data);
        let mut pending = self.control_send.lock().unwrap();
        let queued = self.reliable.lock().unwrap().send_queue.len() + pending.len();
        if queued + fragments.len() > MAX_SEND_WINDOW + MAX_CONTROL_BACKLOG {
            return Err("reliable send backlog full".into());
        }
        pending.extend(fragments);
        self.drain_pending_out_locked(&mut pending);
        Ok(())
    }

    /// Drain as much of the local control backlog into the send window as
    /// will fit. Called from `tick()`.
    fn drain_pending_out(&self) {
        let mut pending = self.control_send.lock().unwrap();
        self.drain_pending_out_locked(&mut pending);
    }

    fn drain_pending_out_locked(&self, pending: &mut VecDeque<Vec<u8>>) {
        while let Some(data) = pending.front() {
            match self.try_send_control_now(data) {
                Ok(true) => {
                    pending.pop_front();
                }
                Ok(false) | Err(_) => break,
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
        let mut buf = self.recv_buf.lock().unwrap();
        let (n, src) = match self.socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Vec::new();
            }
            Err(_) => return Vec::new(),
        };
        if src != self.peer {
            return Vec::new();
        }

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

                let delivered = {
                    let mut state = self.reliable.lock().unwrap();
                    // Process piggybacked ack (may free room in send window).
                    state.process_ack(ack, ack_bits);
                    if payload.is_empty() {
                        Vec::new()
                    } else {
                        state.record_recv(seq, payload)
                    }
                };

                // Acks may have freed window room — flush backlog opportunistically.
                self.drain_pending_out();

                if delivered.is_empty() && plaintext.len() == 1 + RELIABLE_HEADER_SIZE {
                    // Bare ack — nothing to deliver and no ack response needed.
                    return Vec::new();
                }

                // Send ack back.
                let _ = self.send_ack();

                // Return all deliverable messages (in-order + any consecutive
                // buffered packets that became deliverable).
                delivered
                    .into_iter()
                    .filter_map(|fragment| self.reassemble_control(fragment))
                    .map(PunchedMessage::Control)
                    .collect()
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
                let pending = self.control_send.lock().unwrap();
                let state = self.reliable.lock().unwrap();
                if state.send_queue.is_empty() && pending.is_empty() {
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

    fn reassemble_control(&self, fragment: Vec<u8>) -> Option<Vec<u8>> {
        let (&kind, body) = fragment.split_first()?;
        let mut state = self.control_reassembly.lock().unwrap();
        match kind {
            CONTROL_FRAGMENT_SINGLE => {
                *state = None;
                Some(body.to_vec())
            }
            CONTROL_FRAGMENT_START if body.len() >= 4 => {
                let expected = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
                if expected > MAX_PUNCHED_CONTROL_PAYLOAD {
                    *state = None;
                    return None;
                }
                *state = Some((expected, body[4..].to_vec()));
                None
            }
            CONTROL_FRAGMENT_MIDDLE => {
                let (expected, data) = state.as_mut()?;
                if data.len().saturating_add(body.len()) > *expected {
                    *state = None;
                    return None;
                }
                data.extend_from_slice(body);
                None
            }
            CONTROL_FRAGMENT_END => {
                let (expected, mut data) = state.take()?;
                if data.len().saturating_add(body.len()) > expected {
                    return None;
                }
                data.extend_from_slice(body);
                (data.len() == expected).then_some(data)
            }
            _ => {
                *state = None;
                None
            }
        }
    }
}

fn control_fragments(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() <= MAX_CONTROL_FRAGMENT_DATA {
        let mut fragment = Vec::with_capacity(1 + data.len());
        fragment.push(CONTROL_FRAGMENT_SINGLE);
        fragment.extend_from_slice(data);
        return vec![fragment];
    }

    let chunks: Vec<_> = data.chunks(MAX_CONTROL_FRAGMENT_DATA).collect();
    chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let mut fragment = Vec::with_capacity(CONTROL_FRAGMENT_HEADER_SIZE + chunk.len());
            if index == 0 {
                fragment.push(CONTROL_FRAGMENT_START);
                fragment.extend_from_slice(&(data.len() as u32).to_be_bytes());
            } else if index + 1 == chunks.len() {
                fragment.push(CONTROL_FRAGMENT_END);
            } else {
                fragment.push(CONTROL_FRAGMENT_MIDDLE);
            }
            fragment.extend_from_slice(chunk);
            fragment
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x63; 32];

    fn p(seq: u32) -> Vec<u8> {
        seq.to_be_bytes().to_vec()
    }

    fn punched_pair() -> (PunchedSocket, PunchedSocket) {
        let sender_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender_udp.local_addr().unwrap();
        let receiver_addr = receiver_udp.local_addr().unwrap();
        let sender = PunchedSocket::new(
            sender_udp,
            receiver_addr,
            Arc::new(CryptoContext::new(TEST_KEY, false)),
        );
        let receiver = PunchedSocket::new(
            receiver_udp,
            sender_addr,
            Arc::new(CryptoContext::new(TEST_KEY, true)),
        );
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        (sender, receiver)
    }

    fn fill_send_window(socket: &PunchedSocket) {
        let mut state = socket.reliable.lock().unwrap();
        for _ in 0..MAX_SEND_WINDOW {
            let seq = state.next_seq();
            state.send_queue.push_back(UnackedMessage {
                seq,
                payload: vec![seq as u8],
                last_sent: Instant::now(),
                send_count: 1,
            });
        }
    }

    #[test]
    fn punched_control_accepts_aggregate_bundle_and_rejects_oversize() {
        let (sender, receiver) = punched_pair();

        for payload in [
            vec![0x5a; 4 * 1024],
            vec![
                0x6b;
                crate::control::CONTROL_HEADER_SIZE + crate::control::MAX_CONTROL_PAYLOAD + 1024
            ],
        ] {
            sender.send_control(&payload).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                sender.tick();
                receiver.tick();
                let _ = sender.try_recv_all();
                if let Some(PunchedMessage::Control(received)) = receiver.try_recv() {
                    assert_eq!(received, payload);
                    break;
                }
                assert!(Instant::now() < deadline, "control payload timed out");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        assert!(sender
            .send_control(&vec![0; MAX_PUNCHED_CONTROL_PAYLOAD + 1])
            .is_err());
    }

    #[test]
    fn backlogged_fragments_are_not_overtaken_by_a_new_message() {
        let (sender, receiver) = punched_pair();
        fill_send_window(&sender);
        let first = vec![0xa1; MAX_CONTROL_FRAGMENT_DATA + 1];
        let second = vec![0xb2; 8];
        let first_fragments = control_fragments(&first);
        let second_fragments = control_fragments(&second);

        sender.send_control(&first).unwrap();
        sender.reliable.lock().unwrap().send_queue.pop_front();
        sender.send_control(&second).unwrap();

        let state = sender.reliable.lock().unwrap();
        let newest = state.send_queue.back().unwrap();
        assert_eq!(newest.seq, MAX_SEND_WINDOW as u32);
        let plaintext = receiver.crypto.decrypt(&newest.payload).unwrap();
        assert_eq!(&plaintext[1 + RELIABLE_HEADER_SIZE..], first_fragments[0]);
        drop(state);

        let pending: Vec<_> = sender
            .control_send
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(
            pending,
            [first_fragments[1..].to_vec(), second_fragments].concat()
        );
    }

    #[test]
    fn concurrent_control_fragments_never_interleave() {
        let (sender, _receiver) = punched_pair();
        fill_send_window(&sender);
        let sender = Arc::new(sender);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let first = vec![0x11; MAX_CONTROL_FRAGMENT_DATA * 2 + 1];
        let second = vec![0x22; MAX_CONTROL_FRAGMENT_DATA * 2 + 1];

        let handles: Vec<_> = [first.clone(), second.clone()]
            .into_iter()
            .map(|payload| {
                let sender = Arc::clone(&sender);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    sender.send_control(&payload).unwrap();
                })
            })
            .collect();
        barrier.wait();
        for handle in handles {
            handle.join().unwrap();
        }

        let pending: Vec<_> = sender
            .control_send
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        let first_fragments = control_fragments(&first);
        let second_fragments = control_fragments(&second);
        assert!(
            pending == [first_fragments.clone(), second_fragments.clone()].concat()
                || pending == [second_fragments, first_fragments].concat()
        );
    }

    #[test]
    fn bare_ack_drains_the_oldest_pending_fragment() {
        let (sender, peer) = punched_pair();
        fill_send_window(&sender);
        sender.send_control(b"pending").unwrap();
        assert_eq!(sender.control_send.lock().unwrap().len(), 1);

        let mut ack = [0u8; 1 + RELIABLE_HEADER_SIZE];
        ack[0] = CHANNEL_CONTROL;
        ack[5..9].copy_from_slice(&0u32.to_be_bytes());
        let encrypted = peer.crypto.encrypt(&ack);
        peer.socket
            .send_to(&encrypted, sender.socket.local_addr().unwrap())
            .unwrap();

        // Loopback delivery is not synchronous with `send_to`, so poll until the
        // ack has actually been ingested rather than assuming one `try_recv()`
        // observes it. A bare ack never yields a payload, so `try_recv()` still
        // returns `None` on the iteration that drains the pending fragment.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            assert!(sender.try_recv().is_none());
            if sender.control_send.lock().unwrap().is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "bare ack never drained the pending fragment"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let state = sender.reliable.lock().unwrap();
        assert_eq!(state.send_queue.len(), MAX_SEND_WINDOW);
        assert_eq!(state.send_queue.back().unwrap().seq, MAX_SEND_WINDOW as u32);
    }

    #[test]
    fn initial_send_error_keeps_every_fragment_queued() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let incompatible_peer: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(socket.send_to(&[0], incompatible_peer).is_err());
        let sender = PunchedSocket::new(
            socket,
            incompatible_peer,
            Arc::new(CryptoContext::new(TEST_KEY, false)),
        );
        let payload = vec![0x77; MAX_CONTROL_FRAGMENT_DATA * 2 + 1];
        let fragments = control_fragments(&payload);

        sender.send_control(&payload).unwrap();

        let state = sender.reliable.lock().unwrap();
        assert_eq!(state.send_seq, 0);
        assert!(state.send_queue.is_empty());
        drop(state);
        let pending: Vec<_> = sender
            .control_send
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(pending, fragments);
    }

    #[test]
    fn receive_rejects_authenticated_datagram_from_non_peer() {
        let (sender, receiver) = punched_pair();
        let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let attacker_crypto = CryptoContext::new(TEST_KEY, false);
        let forged = attacker_crypto.encrypt(&[CHANNEL_MEDIA, 0xde, 0xad]);
        attacker
            .send_to(&forged, receiver.socket.local_addr().unwrap())
            .unwrap();
        assert!(receiver.try_recv().is_none());

        sender.send_media(b"valid").unwrap();
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Some(PunchedMessage::Media(data)) => assert_eq!(data, b"valid"),
            _ => panic!("valid peer datagram was not received"),
        }
    }

    #[test]
    fn punched_media_is_bounded_by_receive_datagram_size() {
        let (sender, receiver) = punched_pair();
        let max_media =
            MAX_PUNCHED_DATAGRAM_SIZE - crate::tunnel::CRYPTO_OVERHEAD - PUNCHED_MEDIA_OVERHEAD;
        assert_eq!(
            receiver.recv_buf.lock().unwrap().len(),
            MAX_PUNCHED_DATAGRAM_SIZE
        );
        sender.send_media(&vec![0x44; max_media]).unwrap();
        assert!(sender.send_media(&vec![0x44; max_media + 1]).is_err());
    }

    #[test]
    fn selective_ack_does_not_ack_the_missing_contiguous_packet() {
        let mut sender = ReliableState::new();
        for _ in 0..2 {
            let seq = sender.next_seq();
            sender.send_queue.push_back(UnackedMessage {
                seq,
                payload: vec![seq as u8],
                last_sent: Instant::now(),
                send_count: 1,
            });
        }

        let mut receiver = ReliableState::new();
        assert!(receiver.record_recv(1, p(1)).is_empty());
        let (ack, ack_bits) = receiver.ack_header();
        sender.process_ack(ack, ack_bits);

        assert_eq!(
            sender
                .send_queue
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![0]
        );
    }

    #[test]
    fn selective_ack_represents_the_full_reorder_bitmap() {
        let mut sender = ReliableState::new();
        for _ in 0..=32 {
            let seq = sender.next_seq();
            sender.send_queue.push_back(UnackedMessage {
                seq,
                payload: vec![seq as u8],
                last_sent: Instant::now(),
                send_count: 1,
            });
        }
        let mut receiver = ReliableState::new();
        assert!(receiver.record_recv(32, p(32)).is_empty());
        let (ack, ack_bits) = receiver.ack_header();
        sender.process_ack(ack, ack_bits);
        assert!(sender.send_queue.iter().all(|message| message.seq != 32));
        assert!(sender.send_queue.iter().any(|message| message.seq == 0));
    }

    #[test]
    fn full_wire_window_survives_reordering_and_one_loss() {
        let mut receiver = ReliableState::new();
        let missing = 17u32;
        for seq in (1..MAX_SEND_WINDOW as u32).rev() {
            if seq != missing {
                assert!(receiver.record_recv(seq, p(seq)).is_empty());
            }
        }
        assert_eq!(receiver.recv_buf.len(), MAX_SEND_WINDOW - 2);

        let first = receiver.record_recv(0, p(0));
        assert_eq!(first, (0..missing).map(p).collect::<Vec<_>>());
        assert_eq!(receiver.recv_next, missing);

        let rest = receiver.record_recv(missing, p(missing));
        assert_eq!(
            rest,
            (missing..MAX_SEND_WINDOW as u32).map(p).collect::<Vec<_>>()
        );
        assert_eq!(receiver.recv_next, MAX_SEND_WINDOW as u32);
        assert_eq!(receiver.recv_bitmap, 0);
        assert!(receiver.recv_buf.is_empty());
    }

    #[test]
    fn full_wire_window_reordering_and_ack_work_across_u32_wrap() {
        let base = u32::MAX - 16;
        let mut receiver = ReliableState::new();
        receiver.recv_next = base;
        for offset in (1..MAX_SEND_WINDOW as u32).rev() {
            let seq = base.wrapping_add(offset);
            assert!(receiver.record_recv(seq, p(seq)).is_empty());
        }
        let delivered = receiver.record_recv(base, p(base));
        let expected = (0..MAX_SEND_WINDOW as u32)
            .map(|offset| p(base.wrapping_add(offset)))
            .collect::<Vec<_>>();
        assert_eq!(delivered, expected);

        let mut sender = ReliableState::new();
        sender.send_seq = base;
        for _ in 0..MAX_SEND_WINDOW {
            let seq = sender.next_seq();
            sender.send_queue.push_back(UnackedMessage {
                seq,
                payload: p(seq),
                last_sent: Instant::now(),
                send_count: 1,
            });
        }
        let (ack, ack_bits) = receiver.ack_header();
        sender.process_ack(ack, ack_bits);
        assert!(sender.send_queue.is_empty());
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
