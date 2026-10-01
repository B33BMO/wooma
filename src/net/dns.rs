use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::TokioResolver;
use tokio::runtime::Handle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverChoice {
    System,
    Cloudflare,
    Google,
    Quad9,
}

impl ResolverChoice {
    pub const ALL: [ResolverChoice; 4] = [Self::System, Self::Cloudflare, Self::Google, Self::Quad9];

    pub fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Cloudflare => "cloudflare 1.1.1.1",
            Self::Google => "google 8.8.8.8",
            Self::Quad9 => "quad9 9.9.9.9",
        }
    }

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|c| *c == self).unwrap();
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    /// A fresh, cache-less resolver so timings reflect real round trips.
    pub fn build(self) -> anyhow::Result<TokioResolver> {
        let provider = TokioRuntimeProvider::default();
        let mut builder = match self {
            Self::System => {
                // The OS config is often UDP-only; add TCP so truncated answers (big TXT sets) retry.
                let (mut config, _) = hickory_resolver::system_conf::read_system_conf()?;
                config.name_servers = config.name_servers.iter().map(|ns| NameServerConfig::udp_and_tcp(ns.ip)).collect();
                TokioResolver::builder_with_config(config, provider)
            }
            Self::Cloudflare => TokioResolver::builder_with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE), provider),
            Self::Google => TokioResolver::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), provider),
            Self::Quad9 => TokioResolver::builder_with_config(ResolverConfig::udp_and_tcp(&QUAD9), provider),
        };
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(3);
        opts.attempts = 1;
        opts.cache_size = 0;
        // hickory aborts with `Truncated` if a second parallel server's truncated reply lands
        // after it has switched to TCP; one server at a time lets the TCP retry finish.
        opts.num_concurrent_reqs = 1;
        Ok(builder.build()?)
    }
}

// ---------------------------------------------------------------------------
// Record explorer
// ---------------------------------------------------------------------------

pub const RECORD_TYPES: [RecordType; 8] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::TXT,
    RecordType::SOA,
    RecordType::CAA,
];

#[derive(Debug, Clone)]
pub struct Rec {
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum QState {
    Pending,
    Found { records: Vec<Rec>, ms: f64 },
    Empty { ms: f64, nxdomain: bool },
    Failed { ms: f64, msg: String },
}

#[derive(Debug, Clone)]
pub struct Section {
    pub rtype: RecordType,
    pub state: QState,
}

#[derive(Debug, Clone)]
pub struct RaceEntry {
    pub resolver: ResolverChoice,
    pub result: Option<Result<f64, String>>,
}

#[derive(Debug)]
pub struct DnsQuery {
    pub input: String,
    pub resolver: ResolverChoice,
    pub started: Instant,
    pub finished: Option<Instant>,
    pub reverse_ip: Option<IpAddr>,
    pub sections: Vec<Section>,
    pub race: Vec<RaceEntry>,
}

impl DnsQuery {
    pub fn pending(&self) -> usize {
        self.sections.iter().filter(|s| matches!(s.state, QState::Pending)).count()
            + self.race.iter().filter(|r| r.result.is_none()).count()
    }
}

pub fn start_query(rt: &Handle, input: &str, resolver: ResolverChoice, enricher: &Enricher) -> Arc<Mutex<DnsQuery>> {
    let input = input.trim().trim_end_matches('.').to_string();
    let reverse_ip = input.parse::<IpAddr>().ok();
    let types: Vec<RecordType> = if reverse_ip.is_some() { vec![RecordType::PTR] } else { RECORD_TYPES.to_vec() };
    let q = Arc::new(Mutex::new(DnsQuery {
        input: input.clone(),
        resolver,
        started: Instant::now(),
        finished: None,
        reverse_ip,
        sections: types.iter().map(|&rtype| Section { rtype, state: QState::Pending }).collect(),
        race: ResolverChoice::ALL.iter().map(|&r| RaceEntry { resolver: r, result: None }).collect(),
    }));
    if let Some(ip) = reverse_ip {
        enricher.lookup(ip);
    }

    let name: Name = match reverse_ip {
        Some(ip) => ip.into(),
        None => format!("{input}.").parse().unwrap_or_else(|_| Name::root()),
    };

    for (i, rtype) in types.into_iter().enumerate() {
        let (q, name) = (q.clone(), name.clone());
        rt.spawn(async move {
            let t = Instant::now();
            let state = match resolver.build() {
                Err(e) => QState::Failed { ms: 0.0, msg: e.to_string() },
                Ok(r) => {
                    let res = r.lookup(name, rtype).await;
                    let ms = t.elapsed().as_secs_f64() * 1000.0;
                    match res {
                        Ok(lookup) => {
                            let records: Vec<Rec> = lookup
                                .answers()
                                .iter()
                                .map(|r| Rec { ttl: r.ttl, value: r.data.to_string() })
                                .collect();
                            if records.is_empty() {
                                QState::Empty { ms, nxdomain: false }
                            } else {
                                QState::Found { records, ms }
                            }
                        }
                        Err(e) if e.is_nx_domain() => QState::Empty { ms, nxdomain: true },
                        Err(e) if e.is_no_records_found() => QState::Empty { ms, nxdomain: false },
                        Err(e) => QState::Failed { ms, msg: e.to_string() },
                    }
                }
            };
            let mut q = q.lock().unwrap();
            q.sections[i].state = state;
            mark_finished(&mut q);
        });
    }

    // Resolver race: same question to every resolver, who answers first?
    let race_type = if reverse_ip.is_some() { RecordType::PTR } else { RecordType::A };
    for (i, choice) in ResolverChoice::ALL.into_iter().enumerate() {
        let (q, name) = (q.clone(), name.clone());
        rt.spawn(async move {
            let result = match choice.build() {
                Err(e) => Err(e.to_string()),
                Ok(r) => {
                    let t = Instant::now();
                    match r.lookup(name, race_type).await {
                        Ok(_) => Ok(t.elapsed().as_secs_f64() * 1000.0),
                        Err(e) if e.is_no_records_found() || e.is_nx_domain() => {
                            Ok(t.elapsed().as_secs_f64() * 1000.0)
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
            };
            let mut q = q.lock().unwrap();
            q.race[i].result = Some(result);
            mark_finished(&mut q);
        });
    }
    q
}

fn mark_finished(q: &mut DnsQuery) {
    if q.pending() == 0 && q.finished.is_none() {
        q.finished = Some(Instant::now());
    }
}

// ---------------------------------------------------------------------------
// Host enrichment: reverse DNS + ASN (via Team Cymru's DNS interface)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct HostInfo {
    pub ptr: Option<String>,
    pub asn: Option<u32>,
    pub as_name: Option<String>,
    pub prefix: Option<String>,
    pub country: Option<String>,
    pub private: bool,
    pub done: bool,
}

#[derive(Clone)]
pub struct Enricher {
    rt: Handle,
    pub cache: Arc<Mutex<HashMap<IpAddr, HostInfo>>>,
}

impl Enricher {
    pub fn new(rt: Handle) -> Self {
        Self { rt, cache: Arc::default() }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<HostInfo> {
        self.cache.lock().unwrap().get(ip).cloned()
    }

    pub fn lookup(&self, ip: IpAddr) {
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.contains_key(&ip) {
                return;
            }
            cache.insert(ip, HostInfo { private: is_private(ip), ..Default::default() });
        }
        let cache = self.cache.clone();
        self.rt.spawn(async move {
            let Ok(resolver) = ResolverChoice::System.build() else { return };
            let ptr = resolver
                .lookup(Name::from(ip), RecordType::PTR)
                .await
                .ok()
                .and_then(|l| l.answers().first().map(|r| r.data.to_string().trim_end_matches('.').to_string()));
            if let Some(p) = &ptr {
                cache.lock().unwrap().entry(ip).or_default().ptr = Some(p.clone());
            }
            if !is_private(ip)
                && let Some(info) = cymru(&resolver, ip).await {
                    let mut c = cache.lock().unwrap();
                    let e = c.entry(ip).or_default();
                    e.asn = Some(info.0);
                    e.prefix = Some(info.1);
                    e.country = Some(info.2);
                    e.as_name = info.3;
                }
            cache.lock().unwrap().entry(ip).or_default().done = true;
        });
    }
}

async fn txt(resolver: &TokioResolver, name: &str) -> Option<String> {
    let l = resolver.lookup(name, RecordType::TXT).await.ok()?;
    l.answers().first().map(|r| r.data.to_string())
}

/// Returns (asn, prefix, country, as name).
async fn cymru(resolver: &TokioResolver, ip: IpAddr) -> Option<(u32, String, String, Option<String>)> {
    let q = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
            let nibbles: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            format!("{}.origin6.asn.cymru.com.", nibbles.join("."))
        }
    };
    // "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
    let origin = txt(resolver, &q).await?;
    let parts: Vec<&str> = origin.split('|').map(str::trim).collect();
    let asn: u32 = parts.first()?.split_whitespace().next()?.parse().ok()?;
    let prefix = parts.get(1).unwrap_or(&"").to_string();
    let country = parts.get(2).unwrap_or(&"").to_string();
    // "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    let as_name = txt(resolver, &format!("AS{asn}.asn.cymru.com."))
        .await
        .and_then(|s| s.split('|').nth(4).map(|n| n.trim().trim_end_matches(&format!(", {country}")).to_string()));
    Some((asn, prefix, country, as_name))
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}
