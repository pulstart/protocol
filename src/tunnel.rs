use chacha20poly1305::{
    aead::{Aead, KeyInit},
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
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext)
            .expect("ChaCha20-Poly1305 encrypt cannot fail for valid key");
        let total = 12 + ct.len();
        out[12..total].copy_from_slice(&ct);
        total
    }

    /// Decrypt `[nonce:12][ciphertext+tag]` → plaintext.
    /// Returns `None` on authentication failure or truncated input.
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 + 16 {
            return None;
        }
        let nonce = chacha20poly1305::Nonce::from_slice(&data[..12]);
        self.cipher.decrypt(nonce, &data[12..]).ok()
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

/// Discover the public IP:port via a minimal STUN Binding Request.
///
/// Sends a single STUN Binding Request to a public STUN server and parses the
/// XOR-MAPPED-ADDRESS from the response. This reveals the NAT's external mapping
/// for the given local socket, which is exactly what hole punching needs.
///
/// `local_socket` must already be bound. The STUN response is received on the
/// same socket so the NAT mapping is consistent with subsequent hole-punch probes.
///
/// Returns `Some(SocketAddr)` with the public IP:port, or `None` on failure.
pub fn stun_discover_public_addr(local_socket: &UdpSocket) -> Option<SocketAddr> {
    // STUN servers to try (Google, Cloudflare).
    const STUN_SERVERS: &[&str] = &[
        "stun.l.google.com:19302",
        "stun.cloudflare.com:3478",
    ];

    // Build a minimal STUN Binding Request (RFC 5389).
    // Header: type(2) + length(2) + magic_cookie(4) + transaction_id(12) = 20 bytes.
    let mut request = [0u8; 20];
    // Message Type: 0x0001 (Binding Request)
    request[0] = 0x00;
    request[1] = 0x01;
    // Message Length: 0 (no attributes)
    request[2] = 0x00;
    request[3] = 0x00;
    // Magic Cookie: 0x2112A442
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;
    // Transaction ID: 12 random bytes
    let tx_id: [u8; 12] = rand::random();
    request[8..20].copy_from_slice(&tx_id);

    let prev_timeout = local_socket.read_timeout().ok().flatten();
    let _ = local_socket.set_read_timeout(Some(Duration::from_secs(2)));

    for server in STUN_SERVERS {
        // Resolve STUN server address.
        let addr: SocketAddr = match server.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => continue,
            },
            Err(_) => continue,
        };

        // Send request.
        if local_socket.send_to(&request, addr).is_err() {
            continue;
        }

        // Receive response.
        let mut buf = [0u8; 256];
        let n = match local_socket.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };

        if n < 20 {
            continue;
        }

        // Verify it's a Binding Success Response (0x0101) with matching transaction ID.
        if buf[0] != 0x01 || buf[1] != 0x01 {
            continue;
        }
        if buf[8..20] != tx_id {
            continue;
        }

        // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001).
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

            if attr_type == 0x0020 && attr_len >= 8 {
                // XOR-MAPPED-ADDRESS
                let family = buf[attr_start + 1];
                if family == 0x01 {
                    // IPv4
                    let xor_port =
                        u16::from_be_bytes([buf[attr_start + 2], buf[attr_start + 3]]) ^ 0x2112;
                    let xor_ip = u32::from_be_bytes([
                        buf[attr_start + 4],
                        buf[attr_start + 5],
                        buf[attr_start + 6],
                        buf[attr_start + 7],
                    ]) ^ 0x2112A442;
                    let ip = std::net::Ipv4Addr::from(xor_ip);
                    let _ = local_socket.set_read_timeout(prev_timeout);
                    return Some(SocketAddr::new(std::net::IpAddr::V4(ip), xor_port));
                }
            } else if attr_type == 0x0001 && attr_len >= 8 {
                // MAPPED-ADDRESS (fallback)
                let family = buf[attr_start + 1];
                if family == 0x01 {
                    let port =
                        u16::from_be_bytes([buf[attr_start + 2], buf[attr_start + 3]]);
                    let ip = std::net::Ipv4Addr::new(
                        buf[attr_start + 4],
                        buf[attr_start + 5],
                        buf[attr_start + 6],
                        buf[attr_start + 7],
                    );
                    let _ = local_socket.set_read_timeout(prev_timeout);
                    return Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                }
            }

            // Advance to next attribute (padded to 4-byte boundary).
            pos = attr_start + ((attr_len + 3) & !3);
        }
    }

    let _ = local_socket.set_read_timeout(prev_timeout);
    None
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

/// Like `gather_local_candidates`, but also performs STUN discovery on the given socket.
pub fn gather_candidates_with_stun(port: u16, stun_socket: Option<&UdpSocket>) -> Vec<String> {
    use std::net::UdpSocket as StdUdp;

    let mut candidates = Vec::new();

    // Default-route local IP via unconnected UDP trick.
    if let Ok(sock) = StdUdp::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                let c = format!("{}:{port}", local.ip());
                candidates.push(c);
            }
        }
    }

    // Enumerate all non-loopback IPs from local network interfaces.
    for ip in enumerate_local_ips() {
        let c = format!("{ip}:{port}");
        if !candidates.contains(&c) {
            candidates.push(c);
        }
    }

    // Discover public IP:port via STUN.
    if let Some(sock) = stun_socket {
        if let Some(public_addr) = stun_discover_public_addr(sock) {
            let c = public_addr.to_string();
            if !candidates.contains(&c) {
                eprintln!("[stun] Discovered public address: {c}");
                candidates.push(c);
            }
        }
    }

    candidates
}
