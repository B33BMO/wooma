//! TCP connect scanner with light banner grabbing.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;

const CONCURRENCY: usize = 400;
// Long enough to survive one SYN retransmit (1s on most stacks).
const CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);

/// The ports most worth knowing about, roughly in order of how often they're open.
pub const TOP_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 53, 110, 143, 3389, 8080, 3306, 445, 139, 135, 993, 995, 587, 465, 23, 5432, 6379,
    27017, 8443, 8000, 8888, 5900, 1433, 1521, 2049, 111, 389, 636, 5060, 1723, 9200, 9300, 11211, 5672, 15672,
    2375, 2376, 6443, 10250, 9090, 3000, 5000, 5001, 7001, 8081, 8082, 8086, 8090, 8181, 9000, 9001, 9100, 9443,
    1883, 8883, 5683, 161, 162, 69, 123, 179, 514, 873, 1080, 3128, 8008, 8009, 9418, 25565, 27015, 51820, 1194,
    500, 4500, 853, 2083, 2087, 2096, 7547, 49152, 32400, 8200, 8384, 19999, 6881, 4443, 5222, 5269, 6667, 7000,
    7070, 7777, 8291, 10000, 5985, 6000,
];

pub fn service(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 465 | 587 => "smtp",
        53 => "dns",
        69 => "tftp",
        80 | 8000 | 8008 | 8080 | 8081 | 8082 | 8090 | 8181 => "http",
        110 | 995 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        139 | 445 => "smb",
        143 | 993 => "imap",
        161 | 162 => "snmp",
        179 => "bgp",
        389 | 636 => "ldap",
        443 | 8443 | 9443 | 4443 => "https",
        500 | 4500 => "ipsec",
        514 => "syslog",
        853 => "dns-tls",
        873 => "rsync",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 | 8883 => "mqtt",
        2049 => "nfs",
        2083 | 2087 | 2096 => "cpanel",
        2375 | 2376 => "docker",
        3000 => "dev/grafana",
        3128 => "squid",
        3306 => "mysql",
        3389 => "rdp",
        5000 | 5001 => "upnp/dev",
        5060 => "sip",
        5222 | 5269 => "xmpp",
        5432 => "postgres",
        5672 => "amqp",
        5683 => "coap",
        5900 => "vnc",
        5985 => "winrm",
        6000 => "x11",
        6379 => "redis",
        6443 => "kube-api",
        6667 => "irc",
        6881 => "bittorrent",
        7547 => "tr-069",
        8009 => "ajp",
        8086 => "influxdb",
        8200 => "vault",
        8291 => "mikrotik",
        8384 => "syncthing",
        8888 => "http-alt",
        9000 | 9001 => "http-alt",
        9090 => "prometheus",
        9100 => "jetdirect",
        9200 | 9300 => "elastic",
        9418 => "git",
        10000 => "webmin",
        10250 => "kubelet",
        11211 => "memcached",
        15672 => "rabbitmq",
        19999 => "netdata",
        25565 => "minecraft",
        27015 => "steam",
        27017 => "mongodb",
        32400 => "plex",
        51820 => "wireguard",
        _ => "",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Pending,
    Open { ms: f64, banner: Option<String> },
    Closed,
    Filtered,
}

#[derive(Debug)]
pub struct Scan {
    pub input: String,
    pub host: String,
    pub spec: String,
    pub ip: Option<IpAddr>,
    pub error: Option<String>,
    pub started: Instant,
    pub finished: Option<Instant>,
    pub ports: Vec<u16>,
    pub states: Vec<PortState>,
    pub done: usize,
}

impl Scan {
    pub fn count(&self, f: impl Fn(&PortState) -> bool) -> usize {
        self.states.iter().filter(|s| f(s)).count()
    }
}

pub struct ScanHandle {
    pub state: Arc<Mutex<Scan>>,
    stop: Arc<AtomicBool>,
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn parse_spec(spec: &str) -> anyhow::Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "top" {
        return Ok(TOP_PORTS.to_vec());
    }
    if spec == "all" {
        return Ok((1..=65535).collect());
    }
    let mut out = vec![];
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (u16, u16) = (a.trim().parse()?, b.trim().parse()?);
                anyhow::ensure!(a > 0 && a <= b, "bad range {part}");
                out.extend(a..=b);
            }
            None => out.push(part.parse()?),
        }
    }
    out.sort_unstable();
    out.dedup();
    anyhow::ensure!(!out.is_empty(), "no ports");
    Ok(out)
}

/// `input` is "host [ports]", e.g. "example.com 1-1024" or "10.0.0.1 22,80,443".
pub fn start(rt: &Handle, input: &str) -> ScanHandle {
    let mut words = input.split_whitespace();
    let host = words.next().unwrap_or_default().to_string();
    let spec = words.collect::<Vec<_>>().join(",");
    let (ports, error) = match parse_spec(&spec) {
        Ok(p) => (p, None),
        Err(e) => (vec![], Some(format!("port spec: {e}"))),
    };
    let state = Arc::new(Mutex::new(Scan {
        input: input.to_string(),
        host: host.clone(),
        spec: if spec.is_empty() { format!("top {}", TOP_PORTS.len()) } else { spec },
        ip: None,
        error,
        started: Instant::now(),
        finished: None,
        states: vec![PortState::Pending; ports.len()],
        ports: ports.clone(),
        done: 0,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    if state.lock().unwrap().error.is_some() {
        return ScanHandle { state, stop };
    }

    let (st, stop2) = (state.clone(), stop.clone());
    rt.spawn(async move {
        let h = host.clone();
        let ip = match tokio::task::spawn_blocking(move || super::icmp::resolve(&h)).await {
            Ok(Ok(ip)) => ip,
            Ok(Err(e)) => return fail(&st, e.to_string()),
            Err(e) => return fail(&st, e.to_string()),
        };
        st.lock().unwrap().ip = Some(ip);

        let sem = Arc::new(Semaphore::new(CONCURRENCY));
        let mut tasks = Vec::with_capacity(ports.len());
        for (i, port) in ports.into_iter().enumerate() {
            let permit = sem.clone().acquire_owned().await.unwrap();
            if stop2.load(Ordering::Relaxed) {
                break;
            }
            // A light pace (~4k/s): big SYN bursts get dropped, which shows up
            // as fake 1s latencies and false "filtered" results.
            if i % 4 == 3 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let st = st.clone();
            tasks.push(tokio::spawn(async move {
                let result = probe(SocketAddr::new(ip, port)).await;
                drop(permit);
                let mut s = st.lock().unwrap();
                s.states[i] = result;
                s.done += 1;
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        // Re-time open ports one at a time, away from the scan's burst, for honest RTTs.
        let open: Vec<(usize, u16)> = {
            let s = st.lock().unwrap();
            s.states.iter().enumerate().filter(|(_, p)| matches!(p, PortState::Open { .. })).map(|(i, _)| (i, s.ports[i])).collect()
        };
        for (i, port) in open {
            let t = Instant::now();
            if let Ok(Ok(_)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port))).await
                && let PortState::Open { ms, .. } = &mut st.lock().unwrap().states[i] {
                    *ms = t.elapsed().as_secs_f64() * 1000.0;
                }
        }
        st.lock().unwrap().finished = Some(Instant::now());
    });
    ScanHandle { state, stop }
}

fn fail(st: &Mutex<Scan>, e: String) {
    let mut s = st.lock().unwrap();
    s.error = Some(e);
    s.finished = Some(Instant::now());
}

async fn probe(addr: SocketAddr) -> PortState {
    let t = Instant::now();
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Err(_) => PortState::Filtered,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        Ok(Err(_)) => PortState::Filtered,
        Ok(Ok(stream)) => {
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            PortState::Open { ms, banner: banner(stream, addr.port()).await }
        }
    }
}

/// Many services announce themselves on connect (ssh, smtp, ftp...). For
/// plain http ports, ask for the Server header instead.
async fn banner(mut s: TcpStream, port: u16) -> Option<String> {
    let mut buf = [0u8; 512];
    let wait = Duration::from_millis(900);
    let n = match tokio::time::timeout(wait, s.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ if service(port).starts_with("http") || matches!(port, 3000 | 5000 | 9000 | 9090) => {
            s.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.ok()?;
            let n = tokio::time::timeout(wait, s.read(&mut buf)).await.ok()?.ok()?;
            let text = String::from_utf8_lossy(&buf[..n]);
            let status = text.lines().next().unwrap_or_default().to_string();
            let server = text
                .lines()
                .find_map(|l| l.strip_prefix("Server:").or_else(|| l.strip_prefix("server:")))
                .map(|v| format!(" · {}", v.trim()))
                .unwrap_or_default();
            return Some(format!("{status}{server}")).filter(|b| !b.trim().is_empty());
        }
        _ => return None,
    };
    let text: String = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    Some(text).filter(|t| !t.trim().is_empty())
}
