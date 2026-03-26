use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand::rngs::OsRng;
use std::net::{SocketAddr, UdpSocket};
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
    pub fn derive_shared_key(self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
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

    let probe = crypto.encrypt(b"STPUNCH");
    let deadline = Instant::now() + timeout;
    let mut last_send = Instant::now() - Duration::from_secs(1);

    while Instant::now() < deadline {
        // Blast probes to every candidate every 500 ms.
        if last_send.elapsed() >= Duration::from_millis(500) {
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
