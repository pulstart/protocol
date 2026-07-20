use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

/// Per-packet encryption overhead: 12-byte nonce + 16-byte AEAD tag.
pub const CRYPTO_OVERHEAD: usize = 28;
const REPLAY_WINDOW_BITS: u64 = 128;

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

/// Ephemeral X25519 keypair for Diffie-Hellman key exchange via the API server.
pub struct TunnelKeys {
    secret: StaticSecret,
    public: PublicKey,
}

impl TunnelKeys {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// 32-byte public key to upload to the API server (base64-encode before sending).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Compute the shared secret from the partner's public key. Callers must
    /// pass it through [`derive_session_key`] before constructing an AEAD.
    pub fn derive_shared_key(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public_bytes);
        self.secret.diffie_hellman(&peer).to_bytes()
    }

    /// Derive an AEAD key scoped to one API-authorized punch or relay request.
    pub fn derive_session_key(
        &self,
        peer_public_bytes: &[u8; 32],
        context: &SessionKeyContext<'_>,
    ) -> Result<[u8; 32], String> {
        derive_session_key(&self.derive_shared_key(peer_public_bytes), context)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelMode {
    Punch,
    Relay,
}

impl TunnelMode {
    fn label(self) -> &'static str {
        match self {
            Self::Punch => "punch",
            Self::Relay => "relay",
        }
    }
}

/// Signaling values authenticated into a request-scoped tunnel key.
#[derive(Clone, Copy)]
pub struct SessionKeyContext<'a> {
    pub request_context: &'a str,
    pub session_id: &'a str,
    pub mode: TunnelMode,
    pub generation: u64,
    pub host_peer_id: &'a str,
    pub host_lease_id: &'a str,
    pub client_peer_id: &'a str,
    pub client_lease_id: &'a str,
}

/// Expand an X25519 shared secret into a unique key for one signaling request.
pub fn derive_session_key(
    shared_secret: &[u8; 32],
    context: &SessionKeyContext<'_>,
) -> Result<[u8; 32], String> {
    if context.request_context.is_empty()
        || context.session_id.is_empty()
        || context.generation == 0
        || context.host_peer_id.is_empty()
        || context.host_lease_id.is_empty()
        || context.client_peer_id.is_empty()
        || context.client_lease_id.is_empty()
    {
        return Err("incomplete tunnel session key context".into());
    }

    fn append_field(info: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
        let len = u32::try_from(value.len()).map_err(|_| "tunnel key field too long")?;
        info.extend_from_slice(&len.to_be_bytes());
        info.extend_from_slice(value);
        Ok(())
    }

    let mut info = Vec::with_capacity(256);
    info.extend_from_slice(b"st-tunnel-session-key-v1");
    append_field(&mut info, context.session_id.as_bytes())?;
    append_field(&mut info, context.mode.label().as_bytes())?;
    info.extend_from_slice(&context.generation.to_be_bytes());
    append_field(&mut info, context.host_peer_id.as_bytes())?;
    append_field(&mut info, context.host_lease_id.as_bytes())?;
    append_field(&mut info, context.client_peer_id.as_bytes())?;
    append_field(&mut info, context.client_lease_id.as_bytes())?;

    let hkdf = Hkdf::<Sha256>::new(Some(context.request_context.as_bytes()), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| "failed to expand tunnel session key")?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Symmetric encryption context
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 encrypt/decrypt context for the UDP tunnel.
///
/// Each side uses a direction prefix in the 12-byte nonce so that the host and
/// client never reuse the same (key, nonce) pair even if their send counters
/// happen to align.
pub struct CryptoContext {
    cipher: ChaCha20Poly1305,
    send_counter: AtomicU64,
    replay_window: Mutex<ReplayWindow>,
    ordered_highest: Mutex<Option<u64>>,
    /// 0 = host (server), 1 = client
    direction: u8,
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u128,
}

impl ReplayWindow {
    fn can_accept(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }
        let age = highest - counter;
        age < REPLAY_WINDOW_BITS && self.seen & (1u128 << age) == 0
    }

    fn accept(&mut self, counter: u64) -> bool {
        if !self.can_accept(counter) {
            return false;
        }
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.seen = 1;
            }
            Some(highest) if counter > highest => {
                let shift = counter - highest;
                self.seen = if shift >= REPLAY_WINDOW_BITS {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.highest = Some(counter);
            }
            Some(highest) => self.seen |= 1u128 << (highest - counter),
        }
        true
    }
}

impl CryptoContext {
    pub fn new(shared_key: [u8; 32], is_host: bool) -> Self {
        let cipher =
            ChaCha20Poly1305::new_from_slice(&shared_key).expect("shared_key must be 32 bytes");
        Self {
            cipher,
            send_counter: AtomicU64::new(0),
            replay_window: Mutex::new(ReplayWindow::default()),
            ordered_highest: Mutex::new(None),
            direction: if is_host { 0 } else { 1 },
        }
    }

    fn next_send_counter(&self) -> u64 {
        self.send_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
                counter.checked_add(1)
            })
            .expect("tunnel AEAD nonce counter exhausted")
    }

    fn make_nonce(direction: u8, counter: u64) -> chacha20poly1305::Nonce {
        let mut nonce = [0u8; 12];
        nonce[0] = direction;
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
        *chacha20poly1305::Nonce::from_slice(&nonce)
    }

    fn inbound_counter(&self, nonce: &[u8]) -> Option<u64> {
        if nonce.len() != 12 || nonce[0] != (self.direction ^ 1) || nonce[1..4] != [0, 0, 0] {
            return None;
        }
        Some(u64::from_be_bytes(nonce[4..12].try_into().ok()?))
    }

    fn replay_can_accept(&self, counter: u64) -> bool {
        self.replay_window.lock().unwrap().can_accept(counter)
    }

    fn ordered_can_accept(&self, counter: u64) -> bool {
        self.ordered_highest
            .lock()
            .unwrap()
            .is_none_or(|highest| counter > highest)
    }

    fn record_inbound(&self, counter: u64, ordered: bool) -> bool {
        if ordered {
            let mut highest = self.ordered_highest.lock().unwrap();
            if highest.is_some_and(|value| counter <= value) {
                return false;
            }
            *highest = Some(counter);
            true
        } else {
            self.replay_window.lock().unwrap().accept(counter)
        }
    }

    /// Encrypt `plaintext` → `[nonce:12][ciphertext+tag]`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.next_send_counter();
        let nonce = Self::make_nonce(self.direction, counter);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext)
            .expect("ChaCha20-Poly1305 encrypt cannot fail for valid key");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }

    /// Encrypt directly into a caller-supplied buffer.
    /// `out` must be at least `plaintext.len() + CRYPTO_OVERHEAD` bytes.
    /// Returns the number of bytes written.
    pub fn encrypt_into(&self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let required = plaintext.len() + CRYPTO_OVERHEAD;
        assert!(
            out.len() >= required,
            "encrypt_into: buffer too small ({} < {required})",
            out.len()
        );
        let counter = self.next_send_counter();
        let nonce = Self::make_nonce(self.direction, counter);
        out[..12].copy_from_slice(nonce.as_slice());
        let payload_end = 12 + plaintext.len();
        out[12..payload_end].copy_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, b"", &mut out[12..payload_end])
            .expect("ChaCha20-Poly1305 encrypt cannot fail for valid key");
        out[payload_end..required].copy_from_slice(tag.as_slice());
        required
    }

    /// Encrypt plaintext that has already been staged into `buf[12..12+plaintext_len]`.
    /// This avoids an extra copy when callers already own a reusable packet buffer.
    pub fn encrypt_staged_in_place(&self, buf: &mut [u8], plaintext_len: usize) -> usize {
        let required = plaintext_len + CRYPTO_OVERHEAD;
        assert!(
            buf.len() >= required,
            "encrypt_staged_in_place: buffer too small ({} < {required})",
            buf.len()
        );
        let counter = self.next_send_counter();
        let nonce = Self::make_nonce(self.direction, counter);
        buf[..12].copy_from_slice(nonce.as_slice());
        let payload_end = 12 + plaintext_len;
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buf[12..payload_end])
            .expect("ChaCha20-Poly1305 encrypt cannot fail for valid key");
        buf[payload_end..required].copy_from_slice(tag.as_slice());
        required
    }

    /// Decrypt `[nonce:12][ciphertext+tag]` → plaintext.
    /// Returns `None` on authentication failure or truncated input.
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.decrypt_inner(data, false)
    }

    /// Decrypt a frame from a reliable ordered transport. Counters must be
    /// strictly increasing; a duplicate or reordered frame closes the stream.
    pub fn decrypt_ordered(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.decrypt_inner(data, true)
    }

    fn decrypt_inner(&self, data: &[u8], ordered: bool) -> Option<Vec<u8>> {
        if data.len() < CRYPTO_OVERHEAD {
            return None;
        }
        let counter = self.inbound_counter(&data[..12])?;
        let fresh = if ordered {
            self.ordered_can_accept(counter)
        } else {
            self.replay_can_accept(counter)
        };
        if !fresh {
            return None;
        }
        let nonce = chacha20poly1305::Nonce::from_slice(&data[..12]);
        let payload_end = data.len() - 16;
        let mut plaintext = data[12..payload_end].to_vec();
        let tag = chacha20poly1305::Tag::from_slice(&data[payload_end..]);
        self.cipher
            .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .ok()?;
        self.record_inbound(counter, ordered).then_some(plaintext)
    }

    /// Decrypt a packet in-place and return the plaintext slice backed by the
    /// caller-provided buffer.
    pub fn decrypt_in_place<'a>(&self, data: &'a mut [u8]) -> Option<&'a [u8]> {
        if data.len() < CRYPTO_OVERHEAD {
            return None;
        }
        let counter = self.inbound_counter(&data[..12])?;
        if !self.replay_can_accept(counter) {
            return None;
        }
        let (nonce_bytes, rest) = data.split_at_mut(12);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let (plaintext, tag_bytes) = rest.split_at_mut(rest.len() - 16);
        let tag = chacha20poly1305::Tag::clone_from_slice(tag_bytes);
        self.cipher
            .decrypt_in_place_detached(nonce, b"", plaintext, &tag)
            .ok()?;
        self.record_inbound(counter, false).then_some(plaintext)
    }
}

// ---------------------------------------------------------------------------
// UDP hole punching
// ---------------------------------------------------------------------------

/// Perform symmetric UDP hole punching.
///
/// Both peers call this simultaneously. Each side sends encrypted probe packets
/// to every partner candidate address at regular intervals. The first address
/// that sends back a valid (decryptable) response wins.
///
/// `socket` — the local UDP socket to punch through (bind it before calling).
/// `partner_candidates` — IP:port addresses the partner advertised via the API.
/// `crypto` — shared `CryptoContext` derived from the X25519 exchange.
/// `timeout` — give up after this duration.
///
/// Returns the partner's confirmed `SocketAddr` on success.
pub fn hole_punch(
    socket: &UdpSocket,
    partner_candidates: &[SocketAddr],
    crypto: &CryptoContext,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    hole_punch_cancellable(socket, partner_candidates, crypto, timeout, || false)
}

/// Perform symmetric encrypted hole punching, aborting promptly when requested.
pub fn hole_punch_cancellable(
    socket: &UdpSocket,
    partner_candidates: &[SocketAddr],
    crypto: &CryptoContext,
    timeout: Duration,
    should_cancel: impl Fn() -> bool,
) -> Result<SocketAddr, String> {
    if partner_candidates.is_empty() {
        return Err("no partner candidates".into());
    }

    // The punch socket is reused across sessions. A previous live session may
    // have left it non-blocking — clear that explicitly so set_read_timeout
    // actually delivers a 100 ms blocking wait instead of a 100 % CPU spin
    // returning WouldBlock immediately for the full 10 s timeout window.
    socket
        .set_nonblocking(false)
        .map_err(|e| format!("set_nonblocking(false): {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;

    let deadline = Instant::now() + timeout;
    let mut last_send = Instant::now() - Duration::from_secs(1);

    while Instant::now() < deadline {
        if should_cancel() {
            return Err("hole punch cancelled".into());
        }
        // Blast probes to every candidate every 500 ms.
        // Re-encrypt each round so each probe gets a fresh nonce — avoids
        // identical ciphertext that middleboxes might deduplicate.
        if last_send.elapsed() >= Duration::from_millis(500) {
            let probe = crypto.encrypt(b"STPUNCH");
            for addr in partner_candidates {
                let _ = socket.send_to(&probe, addr);
            }
            last_send = Instant::now();
        }

        let mut buf = [0u8; 256];
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(pt) = crypto.decrypt(&buf[..n]) {
                    if pt == b"STPUNCH" || pt == b"STPUNCH_ACK" {
                        // Validate source is one of the expected partner candidates.
                        let src_matches = partner_candidates.contains(&src);
                        if !src_matches {
                            // Accept anyway — NAT may rewrite ports — but the
                            // decryption success already authenticates the peer.
                            eprintln!(
                                "[punch] accepted punch from {src} (not in candidate list, \
                                 but decryption succeeded)"
                            );
                        }
                        // Confirm to the other side (send a few for reliability).
                        let ack = crypto.encrypt(b"STPUNCH_ACK");
                        for _ in 0..3 {
                            let _ = socket.send_to(&ack, src);
                        }
                        return Ok(src);
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {}
        }
    }

    Err("hole punch timed out".into())
}

// ---------------------------------------------------------------------------
// STUN public IP discovery
// ---------------------------------------------------------------------------

/// Public STUN servers we query. Multiple servers serve two purposes:
///   (1) redundancy if one is unreachable
///   (2) detecting symmetric NAT — different external ports for different
///       destinations means the NAT allocates per-(dst_ip, dst_port). We
///       use that signal to seed port-prediction candidates.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
];

/// Overall bound for a full multi-server STUN sweep. The sweep is concurrent on
/// one socket (send all, then collect by transaction id), so this caps the worst
/// case at ~1.5s instead of `servers × 2s` serial — the old behaviour stalled
/// the connect path for up to 6s when STUN servers were slow/blocked.
const STUN_TOTAL_TIMEOUT: Duration = Duration::from_millis(1500);
/// Retransmit still-unanswered requests once at this point (cheap loss recovery
/// — a single dropped reply previously cost a full per-server timeout).
const STUN_RETRANSMIT_AT: Duration = Duration::from_millis(600);

/// Build a STUN Binding Request carrying `tx_id`.
fn stun_request_bytes(tx_id: &[u8; 12]) -> [u8; 20] {
    // Header: type(2) + length(2) + magic_cookie(4) + transaction_id(12).
    let mut request = [0u8; 20];
    request[1] = 0x01; // Binding Request (0x0001), length stays 0
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;
    request[8..20].copy_from_slice(tx_id);
    request
}

/// Parse the (XOR-)MAPPED-ADDRESS from a STUN Binding Response, validating the
/// transaction id. Handles IPv4 (family 0x01) and IPv6 (family 0x02), and both
/// XOR-MAPPED-ADDRESS (0x0020) and legacy MAPPED-ADDRESS (0x0001).
fn parse_stun_mapped_addr(buf: &[u8], expected_tx: &[u8; 12]) -> Option<SocketAddr> {
    let n = buf.len();
    if n < 20 || buf[0] != 0x01 || buf[1] != 0x01 || buf[8..20] != *expected_tx {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let attr_end = (20 + msg_len).min(n);
    let mut pos = 20;
    while pos + 4 <= attr_end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let attr_start = pos + 4;
        let attr_data_end = attr_start + attr_len;
        if attr_data_end > attr_end {
            break;
        }
        let xor = attr_type == 0x0020;
        if (xor || attr_type == 0x0001) && attr_len >= 4 {
            let family = buf[attr_start + 1];
            let raw_port = u16::from_be_bytes([buf[attr_start + 2], buf[attr_start + 3]]);
            let port = if xor { raw_port ^ 0x2112 } else { raw_port };
            if family == 0x01 && attr_len >= 8 {
                let raw_ip = u32::from_be_bytes([
                    buf[attr_start + 4],
                    buf[attr_start + 5],
                    buf[attr_start + 6],
                    buf[attr_start + 7],
                ]);
                let ip = std::net::Ipv4Addr::from(if xor { raw_ip ^ 0x2112A442 } else { raw_ip });
                return Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
            } else if family == 0x02 && attr_len >= 20 {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[attr_start + 4..attr_start + 20]);
                if xor {
                    // XOR key = magic cookie (4) || transaction id (12).
                    let mut key = [0u8; 16];
                    key[0] = 0x21;
                    key[1] = 0x12;
                    key[2] = 0xA4;
                    key[3] = 0x42;
                    key[4..16].copy_from_slice(expected_tx);
                    for (b, k) in ip_bytes.iter_mut().zip(key.iter()) {
                        *b ^= *k;
                    }
                }
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                return Some(SocketAddr::new(std::net::IpAddr::V6(ip), port));
            }
        }
        pos = attr_start + ((attr_len + 3) & !3);
    }
    None
}

/// Discover the public IP:port via STUN. Returns the first mapped address.
pub fn stun_discover_public_addr(local_socket: &UdpSocket) -> Option<SocketAddr> {
    stun_discover_all(local_socket).into_iter().next()
}

/// Query every configured STUN server concurrently on `local_socket` and return
/// the distinct mapped addresses in server order. All requests go out first, then
/// responses are collected (matched by transaction id) within `STUN_TOTAL_TIMEOUT`
/// with one retransmit — bounding the sweep regardless of slow/blocked servers
/// while keeping the single-socket NAT mapping consistent with later punching.
/// Differing ports across servers indicate symmetric NAT (see
/// `predict_symmetric_candidates`); cone NATs answer identically.
pub fn stun_discover_all(local_socket: &UdpSocket) -> Vec<SocketAddr> {
    struct Pending {
        dst: SocketAddr,
        tx: [u8; 12],
        got: Option<SocketAddr>,
    }

    let prev_timeout = local_socket.read_timeout().ok().flatten();
    // Short recv slices so the retransmit/deadline checks get a turn.
    let _ = local_socket.set_read_timeout(Some(Duration::from_millis(100)));

    let mut pending: Vec<Pending> = Vec::new();
    let local_is_ipv4 = local_socket.local_addr().ok().map(|addr| addr.is_ipv4());
    for server in STUN_SERVERS {
        let Ok(destinations) = server.to_socket_addrs() else {
            continue;
        };
        for dst in destinations.filter(|dst| local_is_ipv4.is_none_or(|ipv4| dst.is_ipv4() == ipv4))
        {
            let tx: [u8; 12] = rand::random();
            let _ = local_socket.send_to(&stun_request_bytes(&tx), dst);
            pending.push(Pending { dst, tx, got: None });
        }
    }

    if !pending.is_empty() {
        let start = Instant::now();
        let deadline = start + STUN_TOTAL_TIMEOUT;
        let mut retransmitted = false;
        let mut buf = [0u8; 256];
        while Instant::now() < deadline && pending.iter().any(|p| p.got.is_none()) {
            if !retransmitted && start.elapsed() >= STUN_RETRANSMIT_AT {
                retransmitted = true;
                for p in pending.iter().filter(|p| p.got.is_none()) {
                    let _ = local_socket.send_to(&stun_request_bytes(&p.tx), p.dst);
                }
            }
            match local_socket.recv_from(&mut buf) {
                Ok((n, _src)) => {
                    for p in pending.iter_mut().filter(|p| p.got.is_none()) {
                        if let Some(addr) = parse_stun_mapped_addr(&buf[..n], &p.tx) {
                            p.got = Some(addr);
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }
    }

    let _ = local_socket.set_read_timeout(prev_timeout);

    // Distinct results in server order (cone NATs dedupe to one entry).
    let mut out = Vec::new();
    for p in &pending {
        if let Some(addr) = p.got {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

/// How many predicted ports we emit on each side of the observed STUN port
/// when symmetric NAT is detected. The peer probes all of them; matching one
/// is enough for the connection to succeed. Wider window = better odds vs.
/// concurrent UDP traffic on the host stealing port allocations, capped to
/// keep the probe set small.
pub const SYMMETRIC_PREDICTION_WINDOW: u16 = 6;

/// Given the observed STUN results (in query order), decide whether the NAT
/// behaves like a "sequential symmetric" — different but predictable port per
/// destination — and if so, return additional `ip:port` candidate strings
/// covering the next likely port allocations. The peer then includes those
/// in its punch probe set.
///
/// Returns `Vec::new()` if the NAT looks cone-shaped (all observations share
/// the same port) or random-symmetric (deltas are inconsistent / too large).
pub fn predict_symmetric_candidates(stun_observations: &[SocketAddr]) -> Vec<String> {
    if stun_observations.len() < 2 {
        return Vec::new();
    }

    // All observations must come from the same public IP to compose into a
    // single candidate set. Mixed IPs (e.g. dual-stack edge cases) are not
    // worth predicting around.
    let ip = stun_observations[0].ip();
    if !stun_observations.iter().all(|a| a.ip() == ip) {
        return Vec::new();
    }

    // Cone NAT — same port across destinations. No prediction needed.
    let ports: Vec<u16> = stun_observations.iter().map(|a| a.port()).collect();
    if ports.iter().all(|p| *p == ports[0]) {
        return Vec::new();
    }

    // Sort and compute deltas. A "predictable symmetric" NAT shows small,
    // roughly consistent deltas (often exactly 1). If deltas explode or
    // disagree the NAT is randomly allocating — prediction is pointless.
    let mut sorted = ports.clone();
    sorted.sort_unstable();
    let mut deltas = Vec::with_capacity(sorted.len() - 1);
    for w in sorted.windows(2) {
        let d = w[1].saturating_sub(w[0]);
        if d == 0 {
            continue; // duplicate observation, ignore
        }
        deltas.push(d);
    }
    if deltas.is_empty() {
        return Vec::new();
    }
    let min_delta = *deltas.iter().min().unwrap();
    let max_delta = *deltas.iter().max().unwrap();
    // Reject if any delta is huge (random NAT) or if min/max disagree wildly.
    if max_delta > 16 || max_delta > min_delta.saturating_mul(4).max(1) {
        return Vec::new();
    }
    // Use the smallest observed delta as our stride — it's the closest to the
    // NAT's "true" per-destination increment; larger gaps came from other
    // sockets stealing allocations between our queries.
    let stride = min_delta.max(1);
    let base = *sorted.last().unwrap();

    let mut out = Vec::with_capacity(SYMMETRIC_PREDICTION_WINDOW as usize);
    for k in 1..=SYMMETRIC_PREDICTION_WINDOW {
        if let Some(p) = base.checked_add(stride.saturating_mul(k)) {
            out.push(SocketAddr::new(ip, p).to_string());
        } else {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Candidate gathering (shared by server and client)
// ---------------------------------------------------------------------------

/// Gather local and public network addresses paired with `port` as NAT candidate strings.
///
/// Returns `Vec<String>` in `"ip:port"` format. Used by both the server and client
/// to advertise candidates to the API signaling server.
///
/// If `stun_socket` is provided, performs a STUN binding request to discover the
/// public IP:port as seen by the NAT, and includes it in the candidates. The STUN
/// probe uses the same socket that will later be used for hole punching, so the NAT
/// mapping is consistent.
pub fn gather_local_candidates(port: u16) -> Vec<String> {
    gather_candidates_with_stun(port, None)
}

/// Enumerate non-loopback local IP addresses using platform-specific methods.
fn enumerate_local_ips() -> Vec<std::net::IpAddr> {
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    let mut ips = Vec::new();
    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    let ips = Vec::new();

    #[cfg(target_os = "android")]
    {
        let mut interfaces: *mut libc::ifaddrs = std::ptr::null_mut();
        // Android does not ship the desktop interface-enumeration commands.
        // getifaddrs is available at the minimum supported API level.
        if unsafe { libc::getifaddrs(&mut interfaces) } == 0 {
            let mut current = interfaces;
            while !current.is_null() {
                let address = unsafe { (*current).ifa_addr };
                if !address.is_null() {
                    let ip = match i32::from(unsafe { (*address).sa_family }) {
                        libc::AF_INET => {
                            let address = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
                            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                                u32::from_be(address.sin_addr.s_addr),
                            )))
                        }
                        libc::AF_INET6 => {
                            let address = unsafe { &*(address.cast::<libc::sockaddr_in6>()) };
                            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                                address.sin6_addr.s6_addr,
                            )))
                        }
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        if !ip.is_loopback() && !ip.is_unspecified() && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                current = unsafe { (*current).ifa_next };
            }
            unsafe { libc::freeifaddrs(interfaces) };
        }
    }

    #[cfg(target_os = "linux")]
    {
        // `hostname -I` lists all non-loopback IPs on Linux.
        if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
            for tok in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if let Ok(ip) = tok.parse::<std::net::IpAddr>() {
                    if !ip.is_loopback() && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // `ifconfig` lists interfaces; parse inet lines.
        if let Ok(output) = std::process::Command::new("ifconfig").output() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("inet ") {
                    if let Some(addr_str) = rest.split_whitespace().next() {
                        if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
                            if !ip.is_loopback() && !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
                if let Some(rest) = line.strip_prefix("inet6 ") {
                    if let Some(addr_str) = rest.split_whitespace().next() {
                        // Strip zone ID suffix (e.g. "%en0")
                        let addr_str = addr_str.split('%').next().unwrap_or(addr_str);
                        if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
                            if !ip.is_loopback() && !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Parse `ipconfig` output for IPv4/IPv6 addresses.
        if let Ok(output) = std::process::Command::new("ipconfig").output() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let line = line.trim();
                // Lines look like: "IPv4 Address. . . . . . . . . . . : 192.168.1.5"
                // or "IPv6 Address. . . . . . . . . . . : fe80::..."
                if let Some(pos) = line.rfind(": ") {
                    let addr_str = line[pos + 2..].trim();
                    // Strip IPv6 zone ID suffix (e.g. "%12")
                    let addr_str = addr_str.split('%').next().unwrap_or(addr_str);
                    if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
                        if !ip.is_loopback() && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }

    ips
}

/// Hard cap on the candidate list we advertise. Punching is O(N) probes per
/// round, and on multi-NIC hosts (Docker bridges, libvirt, VPN clients, etc.)
/// `enumerate_local_ips` can produce 10+ addresses that the partner has no
/// route to. 16 is plenty for any realistic deployment.
pub const MAX_GATHERED_CANDIDATES: usize = 16;

fn candidate_string(ip: std::net::IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// Like `gather_local_candidates`, but also performs STUN discovery on the given socket.
///
/// Candidate ordering:
///   1. default-route local IP (the one that would actually carry outbound traffic)
///   2. STUN-discovered public IP:port(s) (what the partner across the internet sees)
///   3. predicted symmetric-NAT ports if the NAT looks predictable (gives
///      the peer something to probe when standard hole punching would fail)
///   4. remaining non-loopback local IPs (additional NICs / VPN tunnels)
///
/// The list is deduplicated and capped at `MAX_GATHERED_CANDIDATES`.
pub fn gather_candidates_with_stun(port: u16, stun_socket: Option<&UdpSocket>) -> Vec<String> {
    use std::net::UdpSocket as StdUdp;

    let mut candidates: Vec<String> = Vec::new();
    let socket_is_ipv4 = stun_socket
        .and_then(|socket| socket.local_addr().ok())
        .map(|addr| addr.is_ipv4());
    let supports_ip = |ip: std::net::IpAddr| socket_is_ipv4.is_none_or(|ipv4| ip.is_ipv4() == ipv4);

    // 1. Default-route local IP via unconnected UDP trick — the partner is
    //    most likely reachable at the same NIC that exits the host.
    if let Ok(sock) = StdUdp::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if supports_ip(local.ip()) {
                    candidates.push(candidate_string(local.ip(), port));
                }
            }
        }
    }

    // 2. STUN discovery — query every configured server so we can also detect
    //    symmetric NAT (different external port per destination).
    let mut stun_obs: Vec<SocketAddr> = Vec::new();
    if let Some(sock) = stun_socket {
        stun_obs = stun_discover_all(sock);
        for addr in &stun_obs {
            let c = addr.to_string();
            if !candidates.contains(&c) {
                eprintln!("[stun] Discovered public address: {c}");
                candidates.push(c);
            }
        }
    }

    // 3. Symmetric-NAT port prediction. When STUN saw different ports across
    //    destinations, the NAT is symmetric; if the per-destination delta is
    //    small and consistent we can guess the next several port allocations
    //    and let the peer probe them. Useful fraction of symmetric NATs use
    //    sequential allocation (Linux netfilter MASQUERADE, older home routers).
    let predicted = predict_symmetric_candidates(&stun_obs);
    if !predicted.is_empty() {
        eprintln!(
            "[stun] Symmetric NAT detected; advertising {} predicted port(s)",
            predicted.len()
        );
        for c in predicted {
            if !candidates.contains(&c) {
                candidates.push(c);
            }
        }
    }

    // 4. Other non-loopback IPs from local interfaces — useful for VPN/LAN
    //    paths the partner shares but we don't route through.
    for ip in enumerate_local_ips() {
        if candidates.len() >= MAX_GATHERED_CANDIDATES {
            break;
        }
        if !supports_ip(ip) {
            continue;
        }
        let c = candidate_string(ip, port);
        if !candidates.contains(&c) {
            candidates.push(c);
        }
    }

    candidates.truncate(MAX_GATHERED_CANDIDATES);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key_context<'a>(
        request_context: &'a str,
        client_peer_id: &'a str,
        client_lease_id: &'a str,
        generation: u64,
    ) -> SessionKeyContext<'a> {
        SessionKeyContext {
            request_context,
            session_id: "api-session",
            mode: TunnelMode::Punch,
            generation,
            host_peer_id: "host",
            host_lease_id: "host-lease",
            client_peer_id,
            client_lease_id,
        }
    }

    #[test]
    fn request_context_derives_symmetric_distinct_aead_keys() {
        let host = TunnelKeys::generate();
        let client = TunnelKeys::generate();
        let contexts = [
            key_context("random-a1", "peer-a", "lease-a1", 1),
            key_context("random-a2", "peer-a", "lease-a1", 2),
            key_context("random-b", "peer-b", "lease-b", 1),
            key_context("random-a3", "peer-a", "lease-a2", 1),
        ];
        let mut keys = Vec::new();
        for context in &contexts {
            let host_key = host
                .derive_session_key(&client.public_key_bytes(), context)
                .unwrap();
            let client_key = client
                .derive_session_key(&host.public_key_bytes(), context)
                .unwrap();
            assert_eq!(host_key, client_key);
            keys.push(host_key);
        }
        for left in 0..keys.len() {
            for right in left + 1..keys.len() {
                assert_ne!(keys[left], keys[right]);
                let left_packet = CryptoContext::new(keys[left], true).encrypt(b"same");
                let right_packet = CryptoContext::new(keys[right], true).encrypt(b"same");
                assert_ne!(
                    (keys[left], &left_packet[..12]),
                    (keys[right], &right_packet[..12])
                );
                assert_ne!(left_packet, right_packet);
            }
        }
    }

    #[test]
    fn udp_replay_window_accepts_reordering_but_rejects_replays_and_old_packets() {
        let sender = CryptoContext::new([0x31; 32], false);
        let receiver = CryptoContext::new([0x31; 32], true);
        let packets: Vec<_> = (0u64..130)
            .map(|counter| sender.encrypt(&counter.to_be_bytes()))
            .collect();

        assert!(receiver.decrypt(&packets[2]).is_some());
        assert!(receiver.decrypt(&packets[0]).is_some());
        assert!(receiver.decrypt(&packets[1]).is_some());
        assert!(receiver.decrypt(&packets[1]).is_none());
        assert!(receiver.decrypt(&packets[129]).is_some());
        assert!(receiver.decrypt(&packets[0]).is_none());
    }

    #[test]
    fn ordered_decrypt_requires_monotonically_increasing_counters() {
        let sender = CryptoContext::new([0x52; 32], false);
        let receiver = CryptoContext::new([0x52; 32], true);
        let first = sender.encrypt(b"first");
        let second = sender.encrypt(b"second");

        assert_eq!(
            receiver.decrypt_ordered(&second).as_deref(),
            Some(&b"second"[..])
        );
        assert!(receiver.decrypt_ordered(&first).is_none());
        assert!(receiver.decrypt_ordered(&second).is_none());
    }

    #[test]
    fn ciphertext_cannot_be_replayed_into_another_request_context() {
        let shared = [0x73; 32];
        let first_key =
            derive_session_key(&shared, &key_context("request-one", "peer", "lease", 1)).unwrap();
        let second_key =
            derive_session_key(&shared, &key_context("request-two", "peer", "lease", 2)).unwrap();
        let first = CryptoContext::new(first_key, false);
        let second = CryptoContext::new(second_key, true);
        let captured = first.encrypt(b"captured");

        assert!(second.decrypt(&captured).is_none());
    }

    #[test]
    fn candidate_strings_use_canonical_socket_address_format() {
        assert_eq!(
            candidate_string("2001:db8::1".parse().unwrap(), 5000),
            "[2001:db8::1]:5000"
        );
        assert_eq!(
            candidate_string("192.0.2.1".parse().unwrap(), 5000),
            "192.0.2.1:5000"
        );
    }

    #[test]
    fn localhost_peers_complete_simultaneous_hole_punch() {
        let host_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host_addr = host_socket.local_addr().unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let key = [0x39; 32];

        let host = std::thread::spawn(move || {
            hole_punch(
                &host_socket,
                &[client_addr],
                &CryptoContext::new(key, true),
                Duration::from_secs(2),
            )
        });
        let client = std::thread::spawn(move || {
            hole_punch(
                &client_socket,
                &[host_addr],
                &CryptoContext::new(key, false),
                Duration::from_secs(2),
            )
        });

        assert_eq!(host.join().unwrap().unwrap(), client_addr);
        assert_eq!(client.join().unwrap().unwrap(), host_addr);
    }

    #[test]
    fn decrypt_rejects_packets_from_the_local_nonce_direction() {
        let key = [0x42; 32];
        let host = CryptoContext::new(key, true);
        let client = CryptoContext::new(key, false);
        let reflected = host.encrypt(b"STPUNCH");

        assert!(host.decrypt(&reflected).is_none());
        assert_eq!(client.decrypt(&reflected).as_deref(), Some(&b"STPUNCH"[..]));
        assert!(client.decrypt(&reflected).is_none());

        let mut reflected = reflected;
        assert!(host.decrypt_in_place(&mut reflected).is_none());
    }

    #[test]
    fn reflected_stpunch_echo_does_not_confirm_a_peer() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_thread = std::thread::spawn(move || {
            let mut packet = [0u8; 256];
            let (len, source) = echo.recv_from(&mut packet).unwrap();
            echo.send_to(&packet[..len], source).unwrap();
        });

        let result = hole_punch(
            &socket,
            &[echo_addr],
            &CryptoContext::new([0x91; 32], true),
            Duration::from_millis(250),
        );
        echo_thread.join().unwrap();
        assert_eq!(result.unwrap_err(), "hole punch timed out");
    }

    #[test]
    fn hole_punch_can_be_cancelled() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let candidate = "127.0.0.1:9".parse().unwrap();
        let error = hole_punch_cancellable(
            &socket,
            &[candidate],
            &CryptoContext::new([7; 32], false),
            Duration::from_secs(10),
            || true,
        )
        .unwrap_err();
        assert_eq!(error, "hole punch cancelled");
    }

    fn sa(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap()), port)
    }

    #[test]
    fn prediction_skipped_when_fewer_than_two_observations() {
        assert!(predict_symmetric_candidates(&[]).is_empty());
        assert!(predict_symmetric_candidates(&[sa("1.2.3.4", 50000)]).is_empty());
    }

    #[test]
    fn prediction_skipped_for_cone_nat() {
        // Same port for both STUN servers → cone NAT, no prediction needed.
        let obs = vec![sa("1.2.3.4", 50000), sa("1.2.3.4", 50000)];
        assert!(predict_symmetric_candidates(&obs).is_empty());
    }

    #[test]
    fn prediction_emits_sequential_ports_for_symmetric_nat() {
        // delta = 1 between observations → sequential symmetric.
        let obs = vec![sa("1.2.3.4", 50000), sa("1.2.3.4", 50001)];
        let preds = predict_symmetric_candidates(&obs);
        assert_eq!(preds.len(), SYMMETRIC_PREDICTION_WINDOW as usize);
        // Starts at base = 50001 (max observed), stride = 1.
        assert_eq!(preds[0], "1.2.3.4:50002");
        assert_eq!(preds[1], "1.2.3.4:50003");
    }

    #[test]
    fn prediction_skipped_for_random_symmetric() {
        // Huge jump between observations → random allocation, prediction useless.
        let obs = vec![sa("1.2.3.4", 50000), sa("1.2.3.4", 62000)];
        assert!(predict_symmetric_candidates(&obs).is_empty());
    }

    #[test]
    fn prediction_uses_smallest_observed_delta_as_stride() {
        // Three observations with deltas 1 and 3 — concurrent socket stole one
        // port between observation 2 and 3. Smaller delta is the truer stride.
        let obs = vec![
            sa("1.2.3.4", 50000),
            sa("1.2.3.4", 50001),
            sa("1.2.3.4", 50004),
        ];
        let preds = predict_symmetric_candidates(&obs);
        assert!(!preds.is_empty());
        assert_eq!(preds[0], "1.2.3.4:50005"); // base 50004 + stride 1
    }

    #[test]
    fn prediction_rejected_on_mixed_ips() {
        let obs = vec![sa("1.2.3.4", 50000), sa("5.6.7.8", 50001)];
        assert!(predict_symmetric_candidates(&obs).is_empty());
    }
}
