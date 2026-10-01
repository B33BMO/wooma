//! Minimal ICMP / ICMPv6 echo engine shared by ping and traceroute.
//!
//! Tries a raw socket first (root / CAP_NET_RAW) and falls back to the
//! unprivileged datagram ICMP socket that macOS and Linux both offer.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockKind {
    Raw,
    Dgram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    EchoReply,
    TimeExceeded,
    Unreachable(u8),
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub from: IpAddr,
    pub kind: ReplyKind,
    pub ident: u16,
    pub seq: u16,
    pub at: Instant,
}

pub struct IcmpSocket {
    sock: Socket,
    pub kind: SockKind,
    v6: bool,
}

impl IcmpSocket {
    pub fn new(v6: bool) -> io::Result<Self> {
        let (domain, proto) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let (sock, kind) = match Socket::new(domain, Type::RAW, Some(proto)) {
            Ok(s) => (s, SockKind::Raw),
            Err(_) => match Socket::new(domain, Type::DGRAM, Some(proto)) {
                Ok(s) => (s, SockKind::Dgram),
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "can't open ICMP socket ({e}). On Linux try: \
                             sudo setcap cap_net_raw+ep $(which wooma)"
                        ),
                    ))
                }
            },
        };
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        Ok(Self { sock, kind, v6 })
    }

    pub fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        if self.v6 {
            self.sock.set_unicast_hops_v6(ttl as u32)
        } else {
            self.sock.set_ttl_v4(ttl as u32)
        }
    }

    pub fn send_echo(&self, dst: IpAddr, ident: u16, seq: u16, payload_len: usize) -> io::Result<()> {
        let mut pkt = vec![0u8; 8 + payload_len];
        pkt[0] = if self.v6 { 128 } else { 8 };
        pkt[4..6].copy_from_slice(&ident.to_be_bytes());
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        for (i, b) in pkt[8..].iter_mut().enumerate() {
            *b = b"wooma!"[i % 6];
        }
        if !self.v6 {
            // ICMPv6 checksums are filled in by the kernel.
            let ck = checksum(&pkt);
            pkt[2..4].copy_from_slice(&ck.to_be_bytes());
        }
        let addr: SockAddr = SocketAddr::new(dst, 0).into();
        self.sock.send_to(&pkt, &addr)?;
        Ok(())
    }

    /// Wait up to the socket read timeout for one parseable ICMP message.
    pub fn recv(&self) -> Option<Reply> {
        let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
        let (n, addr) = self.sock.recv_from(&mut buf).ok()?;
        let at = Instant::now();
        // SAFETY: recv_from initialised the first n bytes.
        let data: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        let from = addr.as_socket()?.ip();
        let (kind, ident, seq) = if self.v6 { parse_v6(data)? } else { parse_v4(data)? };
        Some(Reply { from, kind, ident, seq, at })
    }

    /// On Linux datagram sockets the kernel rewrites the echo identifier,
    /// so callers should match on sequence only.
    pub fn ident_trustworthy(&self) -> bool {
        !(cfg!(target_os = "linux") && self.kind == SockKind::Dgram)
    }
}

fn strip_ipv4_header(data: &[u8]) -> Option<&[u8]> {
    // Raw sockets (and macOS dgram sockets) deliver the IPv4 header too.
    // No valid ICMP type starts with nibble 4, so this check is unambiguous.
    if data.first()? >> 4 == 4 {
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        data.get(ihl..)
    } else {
        Some(data)
    }
}

fn parse_v4(data: &[u8]) -> Option<(ReplyKind, u16, u16)> {
    let icmp = strip_ipv4_header(data)?;
    if icmp.len() < 8 {
        return None;
    }
    let kind = match icmp[0] {
        0 => return Some((ReplyKind::EchoReply, be16(&icmp[4..]), be16(&icmp[6..]))),
        11 => ReplyKind::TimeExceeded,
        3 => ReplyKind::Unreachable(icmp[1]),
        _ => return None,
    };
    // Error messages quote the original IP header + first 8 bytes of our echo.
    let inner = strip_ipv4_header(&icmp[8..])?;
    if inner.len() < 8 || inner[0] != 8 {
        return None;
    }
    Some((kind, be16(&inner[4..]), be16(&inner[6..])))
}

fn parse_v6(icmp: &[u8]) -> Option<(ReplyKind, u16, u16)> {
    if icmp.len() < 8 {
        return None;
    }
    let kind = match icmp[0] {
        129 => return Some((ReplyKind::EchoReply, be16(&icmp[4..]), be16(&icmp[6..]))),
        3 => ReplyKind::TimeExceeded,
        1 => ReplyKind::Unreachable(icmp[1]),
        _ => return None,
    };
    // 8 byte ICMPv6 header, then the 40 byte IPv6 header of the original packet.
    let inner = icmp.get(8 + 40..)?;
    if inner.len() < 8 || inner[0] != 128 {
        return None;
    }
    Some((kind, be16(&inner[4..]), be16(&inner[6..])))
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A per-process-unique identifier for an echo session.
pub fn new_ident() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = (std::process::id() as u16).wrapping_mul(31);
    base.wrapping_add(NEXT.fetch_add(1, Ordering::Relaxed).wrapping_mul(977))
}

pub fn resolve(host: &str) -> io::Result<IpAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<IpAddr> = (host, 0).to_socket_addrs()?.map(|a| a.ip()).collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses found"))
}
