use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use rand::rngs::OsRng;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

/// Per-packet encryption overhead: 12-byte nonce + 16-byte AEAD tag.
pub const CRYPTO_OVERHEAD: usize = 28;

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

    /// Compute the shared secret from the partner's public key.
    /// The resulting 32 bytes are used directly as the ChaCha20-Poly1305 key.
    pub fn derive_shared_key(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public_bytes);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
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
    /// 0 = host (server), 1 = client
    direction: u8,
}

impl CryptoContext {
    pub fn new(shared_key: [u8; 32], is_host: bool) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&shared_key)
            .expect("shared_key must be 32 bytes");
        Self {
            cipher,
            send_counter: AtomicU64::new(0),
            direction: if is_host { 0 } else { 1 },
        }
    }

    fn make_nonce(direction: u8, counter: u64) -> chacha20poly1305::Nonce {
        let mut nonce = [0u8; 12];
        nonce[0] = direction;
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
        *chacha20poly1305::Nonce::from_slice(&nonce)
    }

    /// Encrypt `plaintext` → `[nonce:12][ciphertext+tag]`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
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
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
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
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
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
        if data.len() < CRYPTO_OVERHEAD {
            return None;
        }
        let nonce = chacha20poly1305::Nonce::from_slice(&data[..12]);
        let payload_end = data.len() - 16;
        let mut plaintext = data[12..payload_end].to_vec();
        let tag = chacha20poly1305::Tag::from_slice(&data[payload_end..]);
        self.cipher
            .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .ok()?;
        Some(plaintext)
    }

    /// Decrypt a packet in-place and return the plaintext slice backed by the
    /// caller-provided buffer.
    pub fn decrypt_in_place<'a>(&self, data: &'a mut [u8]) -> Option<&'a [u8]> {
        if data.len() < CRYPTO_OVERHEAD {
            return None;
        }
        let (nonce_bytes, rest) = data.split_at_mut(12);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let (plaintext, tag_bytes) = rest.split_at_mut(rest.len() - 16);
        let tag = chacha20poly1305::Tag::clone_from_slice(tag_bytes);
        self.cipher
            .decrypt_in_place_detached(nonce, b"", plaintext, &tag)
            .ok()?;
        Some(plaintext)
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
                        let src_matches = partner_candidates.iter().any(|c| *c == src);
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

/// Send one STUN Binding Request and parse the XOR-MAPPED-ADDRESS.
/// `local_socket` must already be bound; the response is received on the
/// same socket so the NAT mapping is consistent with subsequent hole-punch
/// probes from that socket.
fn stun_query_one(local_socket: &UdpSocket, server: &str) -> Option<SocketAddr> {
    // Header: type(2) + length(2) + magic_cookie(4) + transaction_id(12) = 20 bytes.
    let mut request = [0u8; 20];
    request[0] = 0x00;
    request[1] = 0x01;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;
    let tx_id: [u8; 12] = rand::random();
    request[8..20].copy_from_slice(&tx_id);

    let addr: SocketAddr = server.to_socket_addrs().ok()?.next()?;
    local_socket.send_to(&request, addr).ok()?;

    let mut buf = [0u8; 256];
    let n = local_socket.recv_from(&mut buf).ok()?.0;
    if n < 20 || buf[0] != 0x01 || buf[1] != 0x01 || buf[8..20] != tx_id {
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
        if attr_type == 0x0020 && attr_len >= 8 && buf[attr_start + 1] == 0x01 {
            let xor_port =
                u16::from_be_bytes([buf[attr_start + 2], buf[attr_start + 3]]) ^ 0x2112;
            let xor_ip = u32::from_be_bytes([
                buf[attr_start + 4],
                buf[attr_start + 5],
                buf[attr_start + 6],
                buf[attr_start + 7],
            ]) ^ 0x2112A442;
            let ip = std::net::Ipv4Addr::from(xor_ip);
            return Some(SocketAddr::new(std::net::IpAddr::V4(ip), xor_port));
        } else if attr_type == 0x0001 && attr_len >= 8 && buf[attr_start + 1] == 0x01 {
            let port = u16::from_be_bytes([buf[attr_start + 2], buf[attr_start + 3]]);
            let ip = std::net::Ipv4Addr::new(
                buf[attr_start + 4],
                buf[attr_start + 5],
                buf[attr_start + 6],
                buf[attr_start + 7],
            );
            return Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
        }
        pos = attr_start + ((attr_len + 3) & !3);
    }
    None
}

/// Discover the public IP:port via STUN. Tries each configured server until
/// one succeeds. Returns the first successful XOR-MAPPED-ADDRESS.
pub fn stun_discover_public_addr(local_socket: &UdpSocket) -> Option<SocketAddr> {
    let prev_timeout = local_socket.read_timeout().ok().flatten();
    let _ = local_socket.set_read_timeout(Some(Duration::from_secs(2)));
    let result = STUN_SERVERS.iter().find_map(|s| stun_query_one(local_socket, s));
    let _ = local_socket.set_read_timeout(prev_timeout);
    result
}

/// Query every configured STUN server from `local_socket` and return all
/// distinct results, in query order. If the NAT is full/restricted-cone every
/// query returns the same `ip:port`. If the NAT is symmetric the results
/// differ by destination — that delta is what `predict_symmetric_candidates`
/// later uses to guess the next port allocation for the peer.
pub fn stun_discover_all(local_socket: &UdpSocket) -> Vec<SocketAddr> {
    let prev_timeout = local_socket.read_timeout().ok().flatten();
    let _ = local_socket.set_read_timeout(Some(Duration::from_secs(2)));
    let mut out = Vec::new();
    for server in STUN_SERVERS {
        if let Some(addr) = stun_query_one(local_socket, server) {
            // Dedupe — cone NATs will give the same answer to all queries.
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    let _ = local_socket.set_read_timeout(prev_timeout);
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
    let mut ips = Vec::new();

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

    // 1. Default-route local IP via unconnected UDP trick — the partner is
    //    most likely reachable at the same NIC that exits the host.
    if let Ok(sock) = StdUdp::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                candidates.push(format!("{}:{port}", local.ip()));
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
        let c = format!("{ip}:{port}");
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
