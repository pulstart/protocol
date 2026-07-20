//! TCP fallback tunnel: the same media/control channel model as
//! `PunchedSocket`, framed over a single TCP stream.
//!
//! Used when UDP is unavailable (blocked by a firewall/proxy, hole punch
//! failed, or the user forces TCP):
//!   * **Direct tunnel** — the client connects to the server's control port,
//!     writes [`TCP_TUNNEL_PREAMBLE`], and both sides switch to tunnel framing
//!     on the same connection (plaintext, like the normal direct session).
//!   * **Relay tunnel** — both peers dial the API server's TCP relay, which
//!     consumes short-lived tickets, pairs their opaque pair ID, and pipes bytes.
//!     Frames are end-to-end encrypted
//!     with a request-scoped X25519+HKDF `CryptoContext`, so the relay sees only
//!     ciphertext.
//!
//! Wire format, repeated per frame:
//!   `[len: u32 BE][body: len bytes]`
//! where `body` is `[channel: u8][payload]` in the plaintext mode, or
//! `encrypt([channel: u8][payload])` (`[nonce:12][ct][tag:16]`) when a
//! `CryptoContext` is supplied. Channels match `reliable_udp`: 0 = unreliable
//! media/input semantics (here simply ordered+reliable), 1 = control messages.
//! TCP provides ordering and reliability, so no ARQ layer is needed.
//!
//! Threading model: each `TcpTunnel` owns a **reader** thread that parses
//! frames off the socket into a *bounded* queue (so a slow consumer exerts
//! real TCP backpressure on the sender rather than buffering without limit),
//! and a **writer** thread that drains a *bounded* queue of pre-serialized
//! frames and performs the blocking socket writes with a write timeout. No
//! caller ever blocks inside a socket write: `send_*` only enqueue, so a
//! stalled peer can never wedge a latency-critical control loop the way a
//! shared write-mutex would — at worst the bounded queue fills and the write
//! timeout tears the tunnel down.

use crate::reliable_udp::PunchedMessage;
use crate::tunnel::CryptoContext;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// First bytes a client writes on a fresh control-port connection to request
/// tunnel framing instead of the normal control protocol. Chosen so it can
/// never be confused with a `ControlMessage` header sequence a current client
/// would send first ('S' = 0x53 is far outside the assigned type-byte range).
pub const TCP_TUNNEL_PREAMBLE: &[u8; 8] = b"STTUNNL1";

/// Hard cap on a single tunnel frame body. Media packets are tens of KB and
/// control payloads are capped at 64 KB, so anything bigger means a corrupt
/// or hostile stream.
pub const MAX_TUNNEL_FRAME: usize = 256 * 1024;

/// Media payload budget for senders slicing video onto a TCP tunnel. TCP is a
/// reliable, in-order byte stream with no per-packet fragmentation concern, so
/// there is no reason to chop video at the UDP MTU — larger slices mean far
/// fewer frames/syscalls/queue hops per video unit. `FrameStart::total_packets`
/// is a u16 and the reassembler is packet-size-agnostic, so this only needs to
/// stay well under `MAX_TUNNEL_FRAME`.
pub const TCP_TUNNEL_MAX_MEDIA: usize = 16 * 1024;

/// Bounded depth of the reader→consumer queue. A slow decoder fills this, which
/// stops the reader thread reading the socket, which closes the TCP receive
/// window — the backpressure the sender's bitrate control is meant to see.
const READ_QUEUE_CAP: usize = 1024;
/// Bounded depth of the caller→writer queue. Sized to absorb one large video
/// unit's worth of frames without constant blocking.
const WRITE_QUEUE_CAP: usize = 2048;
/// Default socket write timeout. A write blocked this long means the peer has
/// stopped reading (suspend / blackhole with no RST); tear the tunnel down
/// instead of pinning threads for the OS TCP give-up time (~15 min).
/// Overridable with `ST_TCP_WRITE_TIMEOUT_MS`.
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

fn write_timeout() -> Duration {
    std::env::var("ST_TCP_WRITE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_WRITE_TIMEOUT)
}

const CHANNEL_MEDIA: u8 = 0x00;
const CHANNEL_CONTROL: u8 = 0x01;

// ---------------------------------------------------------------------------
// TunnelLink: common interface over PunchedSocket and TcpTunnel
// ---------------------------------------------------------------------------

/// A bidirectional session link carrying unreliable-semantics media packets
/// and reliable control messages. Implemented by `PunchedSocket` (encrypted
/// UDP with ARQ control) and `TcpTunnel` (framed TCP). Method names mirror
/// `PunchedSocket`'s inherent API so existing punched-session code can switch
/// to `Arc<dyn TunnelLink>` without body changes.
pub trait TunnelLink: Send + Sync {
    /// Remote peer address (for logging).
    fn peer(&self) -> SocketAddr;
    /// True when the link is loss-free and ordered (TCP). Senders should
    /// disable loss-recovery machinery (FEC parity, duplicate FrameStart,
    /// audio redundancy) on reliable links — it is pure overhead there.
    fn is_reliable(&self) -> bool;
    /// Largest media payload `send_media` should be handed per packet.
    fn max_media_payload(&self) -> usize;
    fn send_media(&self, data: &[u8]) -> Result<(), String>;
    fn send_control(&self, data: &[u8]) -> Result<(), String>;
    fn try_recv(&self) -> Option<PunchedMessage>;
    fn try_recv_all(&self) -> Vec<PunchedMessage>;
    fn recv_timeout(&self, timeout: Duration) -> Option<PunchedMessage>;
    /// Periodic maintenance (retransmits/backlog on UDP; no-op on TCP).
    fn tick(&self);
    /// Block until queued control messages are on the wire.
    fn flush_control(&self, timeout: Duration) -> Result<(), String>;
    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), String>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), String>;
    /// True once the link is known dead (TCP EOF/error/write timeout). UDP
    /// links return false; callers there rely on inactivity timeouts.
    fn is_closed(&self) -> bool;
}

impl TunnelLink for crate::reliable_udp::PunchedSocket {
    fn peer(&self) -> SocketAddr {
        PunchedSocket::peer(self)
    }
    fn is_reliable(&self) -> bool {
        false
    }
    fn max_media_payload(&self) -> usize {
        // Safe public-internet MTU (1200) minus AEAD overhead minus the
        // 1-byte channel prefix — same budget the server transport used.
        1200 - crate::tunnel::CRYPTO_OVERHEAD - crate::reliable_udp::PUNCHED_MEDIA_OVERHEAD
    }
    fn send_media(&self, data: &[u8]) -> Result<(), String> {
        PunchedSocket::send_media(self, data)
    }
    fn send_control(&self, data: &[u8]) -> Result<(), String> {
        PunchedSocket::send_control(self, data)
    }
    fn try_recv(&self) -> Option<PunchedMessage> {
        PunchedSocket::try_recv(self)
    }
    fn try_recv_all(&self) -> Vec<PunchedMessage> {
        PunchedSocket::try_recv_all(self)
    }
    fn recv_timeout(&self, timeout: Duration) -> Option<PunchedMessage> {
        PunchedSocket::recv_timeout(self, timeout)
    }
    fn tick(&self) {
        PunchedSocket::tick(self)
    }
    fn flush_control(&self, timeout: Duration) -> Result<(), String> {
        PunchedSocket::flush_control(self, timeout)
    }
    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), String> {
        PunchedSocket::set_nonblocking(self, nonblocking)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), String> {
        PunchedSocket::set_read_timeout(self, dur)
    }
    fn is_closed(&self) -> bool {
        false
    }
}

use crate::reliable_udp::PunchedSocket;

// ---------------------------------------------------------------------------
// TcpTunnel
// ---------------------------------------------------------------------------

/// Media/control tunnel over one TCP stream. A reader thread parses inbound
/// frames into a bounded queue; a writer thread drains a bounded queue of
/// pre-serialized frames. `send_*` serialize (and encrypt) on the caller's
/// thread then enqueue — they never touch the socket directly.
pub struct TcpTunnel {
    peer: SocketAddr,
    crypto: Option<Arc<CryptoContext>>,
    write_tx: SyncSender<Vec<u8>>,
    /// Frames enqueued but not yet written, for best-effort `flush_control`.
    write_pending: Arc<AtomicUsize>,
    rx: Mutex<Receiver<PunchedMessage>>,
    closed: Arc<AtomicBool>,
    /// Mirror `PunchedSocket`'s blocking semantics: callers (notably the
    /// server session loop) pace themselves on `try_recv` blocking up to the
    /// configured read timeout. A purely non-blocking `try_recv` would make
    /// those loops spin a full core.
    nonblocking: AtomicBool,
    read_timeout: Mutex<Option<Duration>>,
    /// Kept so `Drop` can shut the socket down and unblock both worker threads.
    stream_for_shutdown: TcpStream,
}

/// Cap for "blocking" reads with no explicit timeout, so a torn-down session
/// can never park a control loop forever.
const DEFAULT_BLOCKING_RECV_SLICE: Duration = Duration::from_millis(100);

impl TcpTunnel {
    /// Wrap an established, handshake-complete TCP stream. `crypto` encrypts
    /// every frame end-to-end (relay mode); `None` sends plaintext frames
    /// (direct mode). Any leftover bytes already read from the stream (e.g.
    /// buffered past the preamble) are injected ahead of fresh reads.
    pub fn new(
        stream: TcpStream,
        crypto: Option<Arc<CryptoContext>>,
        leftover: Vec<u8>,
    ) -> Result<Self, String> {
        let _ = stream.set_nodelay(true);
        let peer = stream
            .peer_addr()
            .map_err(|e| format!("tunnel peer_addr: {e}"))?;
        let reader_stream = stream
            .try_clone()
            .map_err(|e| format!("clone tunnel stream: {e}"))?;
        let writer_stream = stream;
        let shutdown_stream = writer_stream
            .try_clone()
            .map_err(|e| format!("clone tunnel stream: {e}"))?;

        let closed = Arc::new(AtomicBool::new(false));

        // Reader thread → bounded queue (backpressure on a slow consumer).
        let (read_tx, read_rx) = std::sync::mpsc::sync_channel::<PunchedMessage>(READ_QUEUE_CAP);
        let reader_closed = Arc::clone(&closed);
        let reader_crypto = crypto.clone();
        std::thread::Builder::new()
            .name("tcp-tunnel-read".into())
            .spawn(move || {
                run_reader(
                    reader_stream,
                    reader_crypto,
                    leftover,
                    read_tx,
                    reader_closed,
                );
            })
            .map_err(|e| format!("spawn tunnel reader: {e}"))?;

        // Writer thread ← bounded queue of pre-serialized frames.
        let (write_tx, write_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_CAP);
        let write_pending = Arc::new(AtomicUsize::new(0));
        let writer_closed = Arc::clone(&closed);
        let writer_pending = Arc::clone(&write_pending);
        std::thread::Builder::new()
            .name("tcp-tunnel-write".into())
            .spawn(move || {
                run_writer(writer_stream, write_rx, writer_closed, writer_pending);
            })
            .map_err(|e| format!("spawn tunnel writer: {e}"))?;

        Ok(Self {
            peer,
            crypto,
            write_tx,
            write_pending,
            rx: Mutex::new(read_rx),
            closed,
            nonblocking: AtomicBool::new(false),
            read_timeout: Mutex::new(Some(DEFAULT_BLOCKING_RECV_SLICE)),
            stream_for_shutdown: shutdown_stream,
        })
    }

    fn send_frame(&self, channel: u8, payload: &[u8]) -> Result<(), String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("tunnel closed".into());
        }
        let mut plain = Vec::with_capacity(1 + payload.len());
        plain.push(channel);
        plain.extend_from_slice(payload);
        let body = match &self.crypto {
            Some(crypto) => crypto.encrypt(&plain),
            None => plain,
        };
        if body.len() > MAX_TUNNEL_FRAME {
            return Err(format!("tunnel frame too large: {}", body.len()));
        }
        // Build [len][body] as one buffer so the writer issues a single write.
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);

        // Enqueue. The bounded channel blocks under sustained backpressure
        // (which slows the sender / lets ABR react) and errors out once the
        // writer thread has given up on a dead peer.
        self.write_pending.fetch_add(1, Ordering::AcqRel);
        match self.write_tx.send(framed) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.write_pending.fetch_sub(1, Ordering::AcqRel);
                self.closed.store(true, Ordering::Relaxed);
                Err("tunnel writer gone".into())
            }
        }
    }
}

impl TunnelLink for TcpTunnel {
    fn peer(&self) -> SocketAddr {
        self.peer
    }
    fn is_reliable(&self) -> bool {
        true
    }
    fn max_media_payload(&self) -> usize {
        TCP_TUNNEL_MAX_MEDIA
    }
    fn send_media(&self, data: &[u8]) -> Result<(), String> {
        self.send_frame(CHANNEL_MEDIA, data)
    }
    fn send_control(&self, data: &[u8]) -> Result<(), String> {
        self.send_frame(CHANNEL_CONTROL, data)
    }
    fn try_recv(&self) -> Option<PunchedMessage> {
        if self.nonblocking.load(Ordering::Relaxed) {
            return match self.rx.lock().unwrap().try_recv() {
                Ok(msg) => Some(msg),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.closed.store(true, Ordering::Relaxed);
                    None
                }
            };
        }
        // Blocking mode: wait up to the configured read timeout, like a
        // blocking UDP socket would. Capped so callers never park forever.
        let timeout = self
            .read_timeout
            .lock()
            .unwrap()
            .unwrap_or(DEFAULT_BLOCKING_RECV_SLICE);
        self.recv_timeout(timeout)
    }
    fn try_recv_all(&self) -> Vec<PunchedMessage> {
        let rx = self.rx.lock().unwrap();
        let mut out = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(msg) => out.push(msg),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.closed.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        out
    }
    fn recv_timeout(&self, timeout: Duration) -> Option<PunchedMessage> {
        match self.rx.lock().unwrap().recv_timeout(timeout) {
            Ok(msg) => Some(msg),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                self.closed.store(true, Ordering::Relaxed);
                None
            }
        }
    }
    fn tick(&self) {}
    fn flush_control(&self, timeout: Duration) -> Result<(), String> {
        // Best-effort: wait for the writer to drain the queue. Ordering is
        // already guaranteed by TCP, so this only matters for handshake phases
        // that want bytes on the wire before proceeding.
        let deadline = Instant::now() + timeout;
        while self.write_pending.load(Ordering::Acquire) > 0 {
            if self.closed.load(Ordering::Relaxed) {
                return Err("tunnel closed".into());
            }
            if Instant::now() >= deadline {
                return Err("flush_control timed out".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }
    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), String> {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), String> {
        *self.read_timeout.lock().unwrap() = dur;
        Ok(())
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

impl Drop for TcpTunnel {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        // Unblock both worker threads: shutdown errors any pending socket
        // read/write, and dropping write_tx ends the writer's recv.
        let _ = self.stream_for_shutdown.shutdown(Shutdown::Both);
    }
}

/// Writer thread: drain pre-serialized frames and write them with a timeout.
/// On any write error/timeout, mark closed and exit — dropping the receiver so
/// blocked `send_*` callers unblock with an error instead of parking forever.
fn run_writer(
    mut stream: TcpStream,
    write_rx: Receiver<Vec<u8>>,
    closed: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
) {
    let _ = stream.set_write_timeout(Some(write_timeout()));
    while let Ok(frame) = write_rx.recv() {
        let result = stream.write_all(&frame);
        pending.fetch_sub(1, Ordering::AcqRel);
        if result.is_err() {
            closed.store(true, Ordering::Relaxed);
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    }
    // Sender side dropped (TcpTunnel dropped) → close the write half.
    closed.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(Shutdown::Both);
}

fn run_reader(
    mut stream: TcpStream,
    crypto: Option<Arc<CryptoContext>>,
    leftover: Vec<u8>,
    tx: SyncSender<PunchedMessage>,
    closed: Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut pending = leftover;
    // Cursor into `pending`: avoids an O(n) front-drain per parsed frame.
    let mut consumed = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // Deliver every complete frame already buffered.
        loop {
            if pending.len() - consumed < 4 {
                break;
            }
            let len = u32::from_be_bytes([
                pending[consumed],
                pending[consumed + 1],
                pending[consumed + 2],
                pending[consumed + 3],
            ]) as usize;
            if len == 0 || len > MAX_TUNNEL_FRAME {
                closed.store(true, Ordering::Relaxed);
                return;
            }
            if pending.len() - consumed < 4 + len {
                break;
            }
            let body_start = consumed + 4;
            let body = &pending[body_start..body_start + len];
            let plain = match &crypto {
                Some(crypto) => match crypto.decrypt_ordered(body) {
                    Some(pt) => pt,
                    // Authentication failure on a reliable stream means the
                    // stream is corrupt or hostile — tear the tunnel down.
                    None => {
                        closed.store(true, Ordering::Relaxed);
                        return;
                    }
                },
                None => body.to_vec(),
            };
            consumed = body_start + len;
            if plain.is_empty() {
                continue;
            }
            let msg = match plain[0] {
                CHANNEL_MEDIA => PunchedMessage::Media(plain[1..].to_vec()),
                CHANNEL_CONTROL => PunchedMessage::Control(plain[1..].to_vec()),
                _ => continue,
            };
            // Bounded send: blocks when the consumer is slow (backpressure),
            // errors when the consumer is gone (TcpTunnel dropped) → exit.
            if tx.send(msg).is_err() {
                return;
            }
        }

        // Compact the buffer once per read cycle, not once per frame.
        if consumed > 0 {
            pending.drain(..consumed);
            consumed = 0;
        }

        if closed.load(Ordering::Relaxed) {
            return;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                closed.store(true, Ordering::Relaxed);
                return;
            }
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {
                closed.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Relay handshake (shared by client, server, and the api-server)
// ---------------------------------------------------------------------------

/// First token on a ticket-authenticated relay handshake line.
pub const RELAY_HELLO_MAGIC: &str = "STRELAY2";
/// Reply the relay sends once both tickets for an opaque pair are consumed.
pub const RELAY_OK: &[u8] = b"OK\n";

/// Build the relay handshake line: `STRELAY2 <role> <opaque-ticket>\n`.
pub fn relay_hello_line(role: &str, ticket: &str) -> String {
    format!("{RELAY_HELLO_MAGIC} {role} {ticket}\n")
}

/// Parse a relay handshake line into `(role, ticket)`. The ticket is opaque;
/// only the relay can validate and consume it.
pub fn parse_relay_hello(line: &str, max_ticket_len: usize) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != RELAY_HELLO_MAGIC {
        return None;
    }
    let role = parts.next()?.to_string();
    if role != "host" && role != "client" {
        return None;
    }
    let ticket = parts.next()?.to_string();
    if ticket.is_empty()
        || ticket.len() > max_ticket_len
        || parts.next().is_some()
        || !ticket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    Some((role, ticket))
}

/// Resolve the relay address: `env_override` (e.g. `ST_RELAY_ADDR`) wins,
/// otherwise the API host combined with the advertised `relay_port`.
pub fn resolve_relay_addr(
    api_url: &str,
    relay_port: Option<u16>,
    env_override: Option<String>,
) -> Option<String> {
    if let Some(addr) = env_override {
        let addr = addr.trim();
        if !addr.is_empty() {
            return Some(addr.to_string());
        }
    }
    let port = relay_port?;
    let host = api_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?;
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    Some(format!("{host}:{port}"))
}

/// Dial the relay, spend the single-use ticket for `role`, and block until the
/// relay's `OK` arrives (the partner has paired). Returns the stream
/// positioned exactly at the start of tunnel traffic.
pub fn connect_relay(
    addr: &str,
    role: &str,
    ticket: &str,
    pairing_timeout: Duration,
) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve relay {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("relay address {addr} did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))
        .map_err(|e| format!("connect relay {addr}: {e}"))?;
    let _ = stream.set_nodelay(true);
    stream
        .write_all(relay_hello_line(role, ticket).as_bytes())
        .map_err(|e| format!("relay hello: {e}"))?;
    stream
        .set_read_timeout(Some(pairing_timeout))
        .map_err(|e| format!("relay timeout: {e}"))?;
    let mut ok = [0u8; 3];
    stream
        .read_exact(&mut ok)
        .map_err(|e| format!("relay pairing wait (partner did not arrive?): {e}"))?;
    if ok != RELAY_OK {
        return Err("relay pairing failed (unexpected response)".into());
    }
    let _ = stream.set_read_timeout(None);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn tunnel_pair(crypto: bool) -> (TcpTunnel, TcpTunnel) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_stream = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let (host_crypto, client_crypto) = if crypto {
            let key = [7u8; 32];
            (
                Some(Arc::new(CryptoContext::new(key, true))),
                Some(Arc::new(CryptoContext::new(key, false))),
            )
        } else {
            (None, None)
        };
        let server = TcpTunnel::new(server_stream, host_crypto, Vec::new()).unwrap();
        let client = TcpTunnel::new(client_stream, client_crypto, Vec::new()).unwrap();
        (server, client)
    }

    fn roundtrip(server: &TcpTunnel, client: &TcpTunnel) {
        server.send_media(b"video-packet").unwrap();
        server.send_control(b"control-msg").unwrap();
        client.send_media(b"input-packet").unwrap();

        match client.recv_timeout(Duration::from_secs(2)) {
            Some(PunchedMessage::Media(data)) => assert_eq!(data, b"video-packet"),
            other => panic!("expected media, got {:?}", discriminant_name(&other)),
        }
        match client.recv_timeout(Duration::from_secs(2)) {
            Some(PunchedMessage::Control(data)) => assert_eq!(data, b"control-msg"),
            other => panic!("expected control, got {:?}", discriminant_name(&other)),
        }
        match server.recv_timeout(Duration::from_secs(2)) {
            Some(PunchedMessage::Media(data)) => assert_eq!(data, b"input-packet"),
            other => panic!("expected media, got {:?}", discriminant_name(&other)),
        }
    }

    fn discriminant_name(msg: &Option<PunchedMessage>) -> &'static str {
        match msg {
            None => "None",
            Some(PunchedMessage::Media(_)) => "Media",
            Some(PunchedMessage::Control(_)) => "Control",
        }
    }

    #[test]
    fn plaintext_roundtrip() {
        let (server, client) = tunnel_pair(false);
        roundtrip(&server, &client);
    }

    #[test]
    fn encrypted_roundtrip() {
        let (server, client) = tunnel_pair(true);
        roundtrip(&server, &client);
    }

    #[test]
    fn large_frame_roundtrip() {
        // Exercise the bigger reliable-link media payload and multi-read reassembly.
        let (server, client) = tunnel_pair(true);
        let big = vec![0xABu8; TCP_TUNNEL_MAX_MEDIA];
        server.send_media(&big).unwrap();
        match client.recv_timeout(Duration::from_secs(3)) {
            Some(PunchedMessage::Media(data)) => assert_eq!(data, big),
            _ => panic!("expected large media frame"),
        }
    }

    #[test]
    fn leftover_bytes_are_consumed_first() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client_stream = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();

        // Client writes two frames as raw bytes; the first arrives "early" and
        // is handed to the tunnel as leftover, split mid-frame.
        let mut wire = Vec::new();
        for payload in [&b"first"[..], &b"second"[..]] {
            let mut body = vec![CHANNEL_CONTROL];
            body.extend_from_slice(payload);
            wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
            wire.extend_from_slice(&body);
        }
        client_stream.write_all(&wire).unwrap();

        let split = 7; // mid-first-frame
        let mut head = vec![0u8; split];
        let mut reader = server_stream.try_clone().unwrap();
        reader.read_exact(&mut head).unwrap();

        let server = TcpTunnel::new(server_stream, None, head).unwrap();
        match server.recv_timeout(Duration::from_secs(2)) {
            Some(PunchedMessage::Control(data)) => assert_eq!(data, b"first"),
            _ => panic!("expected first control frame"),
        }
        match server.recv_timeout(Duration::from_secs(2)) {
            Some(PunchedMessage::Control(data)) => assert_eq!(data, b"second"),
            _ => panic!("expected second control frame"),
        }
    }

    #[test]
    fn close_detected_on_peer_drop() {
        let (server, client) = tunnel_pair(false);
        drop(client);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let _ = server.try_recv();
            if server.is_closed() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "close not detected");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn relay_hello_roundtrips() {
        let line = relay_hello_line("client", "opaque_ticket-123");
        let (role, ticket) = parse_relay_hello(&line, 128).unwrap();
        assert_eq!(role, "client");
        assert_eq!(ticket, "opaque_ticket-123");
        assert!(parse_relay_hello("GARBAGE x y", 128).is_none());
        assert!(parse_relay_hello(&relay_hello_line("bogus", "t"), 128).is_none());
        assert!(parse_relay_hello("STRELAY2 client invalid+ticket", 128).is_none());
        assert!(parse_relay_hello("STRELAY2 client one trailing", 128).is_none());
        assert!(parse_relay_hello("STRELAY2 client one\nSTRELAY2 host two", 128).is_none());
    }

    #[test]
    fn resolve_relay_addr_prefers_override_then_api_host() {
        assert_eq!(
            resolve_relay_addr("https://api.example.com", Some(3001), None).as_deref(),
            Some("api.example.com:3001")
        );
        assert_eq!(
            resolve_relay_addr("https://api.example.com:8443/", Some(3001), None).as_deref(),
            Some("api.example.com:3001")
        );
        assert_eq!(
            resolve_relay_addr(
                "https://api.example.com",
                Some(3001),
                Some("1.2.3.4:9".into())
            )
            .as_deref(),
            Some("1.2.3.4:9")
        );
        assert_eq!(
            resolve_relay_addr("https://api.example.com", None, None),
            None
        );
    }
}
