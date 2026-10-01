//! Minimal ICMP / ICMPv6 echo engine shared by ping and traceroute.
//!
//! Tries a raw socket first (root / CAP_NET_RAW) and falls back to the
//! unprivileged datagram ICMP socket that macOS and Linux both offer.
//!
//! On Linux a datagram ICMP socket never sees time-exceeded or unreachable
//! messages through a normal read; the kernel queues them on the socket's
//! error queue (IP_RECVERR), so traceroute reads that as well.

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
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(io::Error::new(e.kind(), permission_hint()));
                }
                Err(e) => return Err(io::Error::new(e.kind(), format!("can't open ICMP socket: {e}"))),
            },
        };
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        #[cfg(target_os = "linux")]
        if kind == SockKind::Dgram {
            enable_recverr(&sock, v6)?;
        }
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
        #[cfg(target_os = "linux")]
        if self.kind == SockKind::Dgram
            && let Some(r) = self.recv_err()
        {
            return Some(r);
        }
        let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
        let (n, addr) = match self.sock.recv_from(&mut buf) {
            Ok(v) => v,
            // With IP_RECVERR a queued ICMP error interrupts the read; go fetch it.
            #[cfg(target_os = "linux")]
            Err(e) if self.kind == SockKind::Dgram && !is_timeout(&e) => return self.recv_err(),
            Err(_) => return None,
        };
        let at = Instant::now();
        // SAFETY: recv_from initialised the first n bytes.
        let data: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        let from = addr.as_socket()?.ip();
        let (kind, ident, seq) = if self.v6 { parse_v6(data)? } else { parse_v4(data)? };
        Some(Reply { from, kind, ident, seq, at })
    }

    /// Read one ICMP error (time exceeded / unreachable) from the socket's error queue.
    #[cfg(target_os = "linux")]
    fn recv_err(&self) -> Option<Reply> {
        use std::os::fd::AsRawFd;

        let mut data = [0u8; 512];
        let mut ctrl = [0u64; 64];
        let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
        // SAFETY: msghdr is plain old data; every pointer in it outlives the recvmsg call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&ctrl) as _;
        let flags = libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT;
        // SAFETY: valid fd and a fully initialised msghdr.
        let n = unsafe { libc::recvmsg(self.sock.as_raw_fd(), &mut msg, flags) };
        if n < 0 {
            return None;
        }
        let at = Instant::now();
        // The payload is our original echo request, which carries the sequence number.
        let echo = &data[..n as usize];
        if echo.len() < 8 || echo[0] != if self.v6 { 128 } else { 8 } {
            return None;
        }

        // SAFETY: walking the control buffer the kernel just filled, using the libc CMSG macros.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let c = &*cmsg;
                let recverr = (c.cmsg_level == libc::SOL_IP && c.cmsg_type == libc::IP_RECVERR)
                    || (c.cmsg_level == libc::SOL_IPV6 && c.cmsg_type == libc::IPV6_RECVERR);
                if recverr {
                    let ee_ptr = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;
                    let ee = std::ptr::read_unaligned(ee_ptr);
                    let kind = match (ee.ee_origin, ee.ee_type) {
                        (libc::SO_EE_ORIGIN_ICMP, 11) | (libc::SO_EE_ORIGIN_ICMP6, 3) => ReplyKind::TimeExceeded,
                        (libc::SO_EE_ORIGIN_ICMP, 3) | (libc::SO_EE_ORIGIN_ICMP6, 1) => ReplyKind::Unreachable(ee.ee_code),
                        _ => return None,
                    };
                    let from = sockaddr_ip(libc::SO_EE_OFFENDER(ee_ptr))?;
                    return Some(Reply { from, kind, ident: be16(&echo[4..]), seq: be16(&echo[6..]), at });
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        None
    }

    /// On Linux datagram sockets the kernel rewrites the echo identifier,
    /// so callers should match on sequence only.
    pub fn ident_trustworthy(&self) -> bool {
        !(cfg!(target_os = "linux") && self.kind == SockKind::Dgram)
    }
}

#[cfg(target_os = "linux")]
fn enable_recverr(sock: &Socket, v6: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let (level, opt) = if v6 { (libc::SOL_IPV6, libc::IPV6_RECVERR) } else { (libc::SOL_IP, libc::IP_RECVERR) };
    let on: libc::c_int = 1;
    // SAFETY: valid fd, and optval points at a c_int of the size we pass.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(target_os = "linux")]
fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// The address in a kernel-filled sockaddr_in / sockaddr_in6.
#[cfg(target_os = "linux")]
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    // SAFETY: the caller passes a sockaddr whose family says which struct it really is.
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET => {
                let sin = std::ptr::read_unaligned(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let sin6 = std::ptr::read_unaligned(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

fn permission_hint() -> String {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "wooma".into());
    if cfg!(target_os = "linux") {
        format!(
            "ICMP not permitted\n\
             Grant this binary raw sockets:\n  sudo setcap cap_net_raw+ep {exe}\n\
             or allow unprivileged ping for all users:\n  sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
        )
    } else {
        format!("ICMP not permitted\nTry running with sudo:\n  sudo {exe}")
    }
}

/// A one-line description of which ICMP socket this process can open, for `wooma config`.
pub fn probe() -> String {
    match IcmpSocket::new(false) {
        Ok(s) if s.kind == SockKind::Raw => "raw socket (full access)".into(),
        Ok(_) => "unprivileged datagram socket (ping and trace work)".into(),
        Err(e) => e.to_string(),
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
