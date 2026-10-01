use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::icmp::{self, IcmpSocket, ReplyKind, SockKind};
use super::stats::Stats;

pub const INTERVAL: Duration = Duration::from_millis(1000);
pub const TIMEOUT: Duration = Duration::from_millis(2000);
/// Consecutive losses before a host is declared down.
const DOWN_AFTER: usize = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Resolving,
    Up,
    Down,
    Error(String),
}

#[derive(Debug)]
pub struct PingState {
    pub ip: Option<IpAddr>,
    pub status: Status,
    pub stats: Stats,
    pub sock_kind: Option<SockKind>,
    /// When the current Up/Down status began.
    pub status_since: Instant,
    pub flaps: u32,
    /// Time of the most recent reply, for the heartbeat animation.
    pub last_reply_at: Option<Instant>,
}

pub struct PingTarget {
    pub host: String,
    pub state: Arc<Mutex<PingState>>,
    pub paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl PingTarget {
    pub fn spawn(host: String) -> Self {
        let state = Arc::new(Mutex::new(PingState {
            ip: None,
            status: Status::Resolving,
            stats: Stats::default(),
            sock_kind: None,
            status_since: Instant::now(),
            flaps: 0,
            last_reply_at: None,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        {
            let (host, state, stop, paused) = (host.clone(), state.clone(), stop.clone(), paused.clone());
            thread::spawn(move || {
                if let Err(e) = run(&host, &state, &stop, &paused) {
                    state.lock().unwrap().status = Status::Error(e.to_string());
                }
            });
        }
        Self { host, state, paused, stop }
    }

    pub fn reset(&self) {
        let mut st = self.state.lock().unwrap();
        st.stats = Stats::default();
        st.flaps = 0;
    }
}

impl Drop for PingTarget {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn run(host: &str, state: &Mutex<PingState>, stop: &AtomicBool, paused: &AtomicBool) -> anyhow::Result<()> {
    let ip = icmp::resolve(host)?;
    let sock = IcmpSocket::new(ip.is_ipv6())?;
    {
        let mut st = state.lock().unwrap();
        st.ip = Some(ip);
        st.sock_kind = Some(sock.kind);
    }
    let ident = icmp::new_ident();
    let mut seq: u16 = 0;
    let mut pending: HashMap<u16, Instant> = HashMap::new();
    let mut next_send = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= next_send {
            next_send = now + INTERVAL;
            if !paused.load(Ordering::Relaxed) {
                seq = seq.wrapping_add(1);
                match sock.send_echo(ip, ident, seq, 56) {
                    Ok(()) => {
                        pending.insert(seq, Instant::now());
                    }
                    // Send failures (no route, etc) count as a lost probe.
                    Err(_) => record(state, None),
                }
            }
        }

        if let Some(r) = sock.recv() {
            let ours = r.from == ip
                && r.kind == ReplyKind::EchoReply
                && (r.ident == ident || !sock.ident_trustworthy());
            if ours
                && let Some(sent) = pending.remove(&r.seq) {
                    let ms = r.at.duration_since(sent).as_secs_f64() * 1000.0;
                    record(state, Some(ms));
                }
        }

        let expired: Vec<u16> = pending
            .iter()
            .filter(|(_, t)| t.elapsed() > TIMEOUT)
            .map(|(s, _)| *s)
            .collect();
        for s in expired {
            pending.remove(&s);
            record(state, None);
        }
    }
    Ok(())
}

fn record(state: &Mutex<PingState>, rtt: Option<f64>) {
    let mut st = state.lock().unwrap();
    st.stats.push(rtt);
    let new_status = if rtt.is_some() {
        st.last_reply_at = Some(Instant::now());
        Status::Up
    } else if st.stats.lost_streak() >= DOWN_AFTER || st.status == Status::Resolving {
        Status::Down
    } else {
        st.status.clone()
    };
    if new_status != st.status {
        if matches!(st.status, Status::Up | Status::Down) {
            st.flaps += 1;
        }
        st.status = new_status;
        st.status_since = Instant::now();
    }
}
