use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::dns::Enricher;
use super::icmp::{self, IcmpSocket, ReplyKind, SockKind};
use super::stats::Stats;

pub const MAX_HOPS: u8 = 30;
const ROUND_INTERVAL: Duration = Duration::from_millis(1000);
const TIMEOUT: Duration = Duration::from_millis(2500);

#[derive(Debug, Default, Clone)]
pub struct Hop {
    /// Every address seen at this TTL, most recent first (ECMP shows up here).
    pub addrs: Vec<IpAddr>,
    pub stats: Stats,
    pub unreachable: Option<u8>,
}

#[derive(Debug)]
pub struct TraceState {
    pub ip: Option<IpAddr>,
    pub error: Option<String>,
    pub hops: Vec<Hop>,
    /// TTL at which the destination answered, once known.
    pub dest_ttl: Option<u8>,
    pub rounds: u64,
    pub sock_kind: Option<SockKind>,
    pub started: Instant,
}

impl TraceState {
    /// Hops worth showing: up to the destination, or up to the last responder.
    pub fn visible_hops(&self) -> &[Hop] {
        let n = match self.dest_ttl {
            Some(t) => t as usize,
            None => {
                let last = self.hops.iter().rposition(|h| !h.addrs.is_empty());
                last.map(|i| (i + 2).min(self.hops.len())).unwrap_or(self.hops.len().min(1))
            }
        };
        &self.hops[..n.min(self.hops.len())]
    }
}

pub struct TraceSession {
    pub host: String,
    pub state: Arc<Mutex<TraceState>>,
    pub paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl TraceSession {
    pub fn spawn(host: String, enricher: Enricher) -> Self {
        let state = Arc::new(Mutex::new(TraceState {
            ip: None,
            error: None,
            hops: vec![Hop::default(); MAX_HOPS as usize],
            dest_ttl: None,
            rounds: 0,
            sock_kind: None,
            started: Instant::now(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        {
            let (host, state, stop, paused) = (host.clone(), state.clone(), stop.clone(), paused.clone());
            thread::spawn(move || {
                if let Err(e) = run(&host, &state, &stop, &paused, &enricher) {
                    state.lock().unwrap().error = Some(e.to_string());
                }
            });
        }
        Self { host, state, paused, stop }
    }

    pub fn reset(&self) {
        let mut st = self.state.lock().unwrap();
        for h in st.hops.iter_mut() {
            h.stats = Stats::default();
        }
        st.rounds = 0;
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn run(
    host: &str,
    state: &Mutex<TraceState>,
    stop: &AtomicBool,
    paused: &AtomicBool,
    enricher: &Enricher,
) -> anyhow::Result<()> {
    let dst = icmp::resolve(host)?;
    let sock = IcmpSocket::new(dst.is_ipv6())?;
    {
        let mut st = state.lock().unwrap();
        st.ip = Some(dst);
        st.sock_kind = Some(sock.kind);
    }
    enricher.lookup(dst);
    let ident = icmp::new_ident();
    let mut seq: u16 = 0;
    // seq -> (ttl, sent at)
    let mut pending: HashMap<u16, (u8, Instant)> = HashMap::new();
    let mut next_round = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        if Instant::now() >= next_round && !paused.load(Ordering::Relaxed) {
            next_round = Instant::now() + ROUND_INTERVAL;
            let max = state.lock().unwrap().dest_ttl.unwrap_or(MAX_HOPS);
            for ttl in 1..=max {
                seq = seq.wrapping_add(1);
                sock.set_ttl(ttl)?;
                if sock.send_echo(dst, ident, seq, 32).is_ok() {
                    pending.insert(seq, (ttl, Instant::now()));
                }
            }
            state.lock().unwrap().rounds += 1;
        }

        while let Some(r) = sock.recv() {
            if sock.ident_trustworthy() && r.ident != ident {
                continue;
            }
            let Some((ttl, sent)) = pending.remove(&r.seq) else { continue };
            let ms = r.at.duration_since(sent).as_secs_f64() * 1000.0;
            let mut st = state.lock().unwrap();
            let is_dest = r.from == dst && r.kind == ReplyKind::EchoReply;
            if is_dest && st.dest_ttl.is_none_or(|d| ttl < d) {
                st.dest_ttl = Some(ttl);
                // Anything past the destination was an artifact of the first round.
                for h in st.hops[ttl as usize..].iter_mut() {
                    *h = Hop::default();
                }
            }
            if st.dest_ttl.is_some_and(|d| ttl > d) {
                continue;
            }
            let hop = &mut st.hops[ttl as usize - 1];
            if let ReplyKind::Unreachable(code) = r.kind {
                hop.unreachable = Some(code);
            }
            if hop.addrs.first() != Some(&r.from) {
                if !hop.addrs.contains(&r.from) {
                    enricher.lookup(r.from);
                }
                hop.addrs.retain(|a| *a != r.from);
                hop.addrs.insert(0, r.from);
            }
            hop.stats.push(Some(ms));
        }

        let expired: Vec<u16> = pending
            .iter()
            .filter(|(_, (_, t))| t.elapsed() > TIMEOUT)
            .map(|(s, _)| *s)
            .collect();
        if !expired.is_empty() {
            let mut st = state.lock().unwrap();
            for s in expired {
                let (ttl, _) = pending.remove(&s).unwrap();
                if st.dest_ttl.is_none_or(|d| ttl <= d) {
                    st.hops[ttl as usize - 1].stats.push(None);
                }
            }
        }
    }
    Ok(())
}
