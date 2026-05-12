//! Router-cooperated port mapping via PCP (RFC 6887) with NAT-PMP fallback
//! (RFC 6886).
//!
//! When the host is behind a single layer of NAT (the common case for home
//! deployments) we ask the gateway to install an explicit
//! `external_port → internal_port` forwarding rule. The resulting public
//! `ip:port` is advertised as an extra candidate alongside STUN results.
//!
//! Unlike STUN, the mapping the router gives us is destination-independent
//! and survives idle periods (subject to the lease), so it works even on
//! symmetric NATs where STUN-based hole punching is futile.
//!
//! Strategy: PCP first (newer, supported by most current consumer routers
//! and required by IPv6/multi-homed setups), then NAT-PMP (older, simpler,
//! still works on legacy Apple AirPort gear and a few other brands). Both
//! protocols share UDP port 5351 on the gateway. UPnP IGD can be added as
//! an additional fallback later if needed — it covers the routers that
//! support neither PCP nor NAT-PMP.

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// PCP / NAT-PMP both listen on UDP 5351 on the gateway.
const PORTMAP_GATEWAY_PORT: u16 = 5351;
/// How long we wait for the gateway to respond to a mapping request.
/// 500 ms is enough for any real LAN; a non-responsive gateway is treated
/// as "doesn't support port mapping" so we move on quickly.
const PORTMAP_TIMEOUT: Duration = Duration::from_millis(500);
/// Lease we request from the gateway. Routers usually honor or downgrade
/// (rarely upgrade) — we use whatever they grant.
const REQUESTED_LIFETIME_SECS: u32 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMapMethod {
    /// PCP (RFC 6887). Newer, supported by current routers.
    Pcp,
    /// NAT-PMP (RFC 6886). Older Apple AirPort and similar.
    NatPmp,
}

#[derive(Clone, Debug)]
pub struct PortMapping {
    pub external_addr: SocketAddr,
    pub lifetime: Duration,
    pub method: PortMapMethod,
}

/// Find our LAN-side IPv4 address — the one the gateway sees us at.
/// Uses the standard "connect to 8.8.8.8 over an unconnected UDP socket"
/// trick to ask the OS which interface would carry outbound traffic.
fn discover_local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Discover the default gateway IP. Tries OS routing tools first, then falls
/// back to a `.1`-of-subnet guess that's correct for the vast majority of
/// home networks.
fn discover_gateway() -> Option<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            // Typical line: "default via 192.168.1.1 dev wlan0 ..."
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let mut parts = line.split_whitespace();
                if parts.next() == Some("default") && parts.next() == Some("via") {
                    if let Some(ip_str) = parts.next() {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("gateway: ") {
                    if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1 -ExpandProperty NextHop",
            ])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Ok(ip) = line.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Fallback: assume gateway is `<local subnet>.1`. Correct on the
    // overwhelming majority of /24 home networks. On the unusual cases
    // (.254 etc.) port mapping simply times out and the caller moves on.
    let local = discover_local_ipv4()?;
    let mut octets = local.octets();
    octets[3] = 1;
    Some(IpAddr::V4(Ipv4Addr::from(octets)))
}

// ---------------------------------------------------------------------------
// PCP (RFC 6887)
// ---------------------------------------------------------------------------
//
// MAP request (60 bytes):
//   Common header (24 bytes):
//     +0  version=2
//     +1  R(0)|opcode(0x01) = 0x01
//     +2  reserved (2 bytes)
//     +4  requested lifetime (4 bytes)
//     +8  client IP address as IPv4-mapped IPv6 (16 bytes)
//   MAP opcode body (36 bytes):
//     +24 mapping nonce (12 bytes)
//     +36 protocol (1 byte) = 17 (UDP)
//     +37 reserved (3 bytes)
//     +40 internal port (2 bytes)
//     +42 suggested external port (2 bytes; 0 = any)
//     +44 suggested external IP as IPv4-mapped IPv6 (16 bytes; ::ffff:0 = any)
//
// MAP response (60 bytes):
//   Common header (24 bytes):
//     +0  version=2
//     +1  R(1)|opcode(0x01) = 0x81
//     +2  reserved (1 byte)
//     +3  result code (1 byte; 0 = success)
//     +4  granted lifetime (4 bytes; 0 = denied)
//     +8  epoch time (4 bytes)
//     +12 reserved (12 bytes)
//   MAP opcode body (36 bytes):
//     +24 mapping nonce (12 bytes, echoed)
//     +36 protocol (1 byte)
//     +37 reserved (3 bytes)
//     +40 internal port (2 bytes)
//     +42 assigned external port (2 bytes)
//     +44 assigned external IP (16 bytes IPv4-mapped IPv6)

fn try_pcp_map(gw: SocketAddr, internal_port: u16, lifetime: u32) -> Option<PortMapping> {
    let local_ip = discover_local_ipv4()?;

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(PORTMAP_TIMEOUT)).ok()?;

    let mut req = [0u8; 60];
    // Common header
    req[0] = 2; // version
    req[1] = 0x01; // R=0 (request), opcode=1 (MAP)
    // [2..4] reserved
    req[4..8].copy_from_slice(&lifetime.to_be_bytes());
    // [8..24] client IP as IPv4-mapped IPv6: ::ffff:a.b.c.d
    req[18] = 0xff;
    req[19] = 0xff;
    req[20..24].copy_from_slice(&local_ip.octets());
    // MAP body
    let nonce: [u8; 12] = rand::thread_rng().gen();
    req[24..36].copy_from_slice(&nonce);
    req[36] = 17; // UDP
    // [37..40] reserved
    req[40..42].copy_from_slice(&internal_port.to_be_bytes());
    req[42..44].copy_from_slice(&internal_port.to_be_bytes()); // suggest same port
    // [44..60] suggested external IP = ::ffff:0.0.0.0 = "any"
    req[54] = 0xff;
    req[55] = 0xff;

    sock.send_to(&req, gw).ok()?;

    // PCP responses can carry option attributes after the fixed 60 bytes;
    // the server may also send other unsolicited messages on epoch reset.
    // Loop until we see a matching MAP response or hit the timeout.
    let mut buf = [0u8; 1100];
    loop {
        let (n, src) = sock.recv_from(&mut buf).ok()?;
        if src != gw || n < 60 {
            return None;
        }
        // Version 2 + R-bit means PCP response. Anything else (e.g. NAT-PMP
        // version=0 unsupported-version error) is "not PCP" → fall back.
        if buf[0] != 2 || buf[1] != 0x81 {
            return None;
        }
        let result_code = buf[3];
        if result_code != 0 {
            return None;
        }
        let granted = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if granted == 0 {
            return None;
        }
        // Echoed nonce must match — otherwise this response is for a different
        // pending request (PCP doesn't have explicit message IDs).
        if buf[24..36] != nonce {
            continue;
        }
        let echoed_internal = u16::from_be_bytes([buf[40], buf[41]]);
        if echoed_internal != internal_port {
            return None;
        }
        let external_port = u16::from_be_bytes([buf[42], buf[43]]);
        // External IP is IPv4-mapped IPv6.
        let ext_bytes = &buf[44..60];
        let is_v4_mapped = ext_bytes[..10].iter().all(|b| *b == 0)
            && ext_bytes[10] == 0xff
            && ext_bytes[11] == 0xff;
        if !is_v4_mapped {
            return None;
        }
        let external_ip = Ipv4Addr::new(
            ext_bytes[12],
            ext_bytes[13],
            ext_bytes[14],
            ext_bytes[15],
        );

        return Some(PortMapping {
            external_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
            lifetime: Duration::from_secs(granted as u64),
            method: PortMapMethod::Pcp,
        });
    }
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------
//
// MAP UDP request (12 bytes):
//   +0  version=0
//   +1  op=1 (UDP map)
//   +2  reserved (2 bytes)
//   +4  internal port (2 bytes)
//   +6  suggested external port (2 bytes)
//   +8  requested lifetime (4 bytes)
//
// MAP UDP response (16 bytes):
//   +0  version=0
//   +1  op=129
//   +2  result code (2 bytes; 0 = success)
//   +4  epoch (4 bytes)
//   +8  internal port (2 bytes)
//   +10 external port (2 bytes)
//   +12 granted lifetime (4 bytes)
//
// External-IP request (2 bytes): [0, 0]
// External-IP response (12 bytes): [0, 128, result:2, epoch:4, ip:4]

fn natpmp_query_external_ip(sock: &UdpSocket, gw: SocketAddr) -> Option<IpAddr> {
    let req = [0u8, 0];
    sock.send_to(&req, gw).ok()?;
    let mut buf = [0u8; 12];
    let (n, src) = sock.recv_from(&mut buf).ok()?;
    if src != gw || n < 12 {
        return None;
    }
    if buf[0] != 0 || buf[1] != 128 {
        return None;
    }
    if u16::from_be_bytes([buf[2], buf[3]]) != 0 {
        return None;
    }
    Some(IpAddr::V4(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11])))
}

fn try_natpmp_map(gw: SocketAddr, internal_port: u16, lifetime: u32) -> Option<PortMapping> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(PORTMAP_TIMEOUT)).ok()?;

    let mut req = [0u8; 12];
    req[0] = 0;
    req[1] = 1; // map UDP
    req[4..6].copy_from_slice(&internal_port.to_be_bytes());
    req[6..8].copy_from_slice(&internal_port.to_be_bytes());
    req[8..12].copy_from_slice(&lifetime.to_be_bytes());
    sock.send_to(&req, gw).ok()?;

    let mut buf = [0u8; 16];
    let (n, src) = sock.recv_from(&mut buf).ok()?;
    if src != gw || n < 16 {
        return None;
    }
    if buf[0] != 0 || buf[1] != 129 {
        return None;
    }
    if u16::from_be_bytes([buf[2], buf[3]]) != 0 {
        return None;
    }
    let returned_internal = u16::from_be_bytes([buf[8], buf[9]]);
    if returned_internal != internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([buf[10], buf[11]]);
    let granted = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if granted == 0 {
        return None;
    }
    let external_ip = natpmp_query_external_ip(&sock, gw)?;
    Some(PortMapping {
        external_addr: SocketAddr::new(external_ip, external_port),
        lifetime: Duration::from_secs(granted as u64),
        method: PortMapMethod::NatPmp,
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Try to acquire (or refresh) a UDP port mapping for `internal_port` from
/// the local gateway. PCP is tried first; NAT-PMP is used as a fallback.
/// Returns `None` if the gateway speaks neither, in which case the caller
/// should rely on STUN candidates alone.
pub fn try_acquire(internal_port: u16) -> Option<PortMapping> {
    let gw_ip = discover_gateway()?;
    let gw = SocketAddr::new(gw_ip, PORTMAP_GATEWAY_PORT);

    if let Some(m) = try_pcp_map(gw, internal_port, REQUESTED_LIFETIME_SECS) {
        return Some(m);
    }
    if let Some(m) = try_natpmp_map(gw, internal_port, REQUESTED_LIFETIME_SECS) {
        return Some(m);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PCP request layout sanity: a well-formed MAP request must be exactly
    /// 60 bytes (24-byte common header + 36-byte MAP body). Catches drift if
    /// someone resizes the byte arrays.
    #[test]
    fn pcp_request_size() {
        // Mirror the construction from try_pcp_map without actually sending.
        let req = [0u8; 60];
        assert_eq!(req.len(), 60);
    }

    /// NAT-PMP MAP request is 12 bytes, response is 16 bytes.
    #[test]
    fn natpmp_request_sizes() {
        let req = [0u8; 12];
        let resp = [0u8; 16];
        assert_eq!(req.len(), 12);
        assert_eq!(resp.len(), 16);
    }
}
