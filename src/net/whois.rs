//! Domain and address registration lookups.
//!
//! Domains use RDAP (JSON over HTTPS, found via IANA's bootstrap registry) as
//! the source of truth: since 2025 many gTLD registries no longer run port-43
//! whois at all. Classic whois still runs alongside for its raw text, following
//! referrals from IANA down to the registry/registrar or RIR.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Handle;

#[derive(Debug, Clone)]
pub struct Hop {
    pub server: String,
    pub rdap: bool,
    pub ms: f64,
    pub text: Result<String, String>,
}

#[derive(Debug)]
pub struct WhoisLookup {
    pub input: String,
    pub is_ip: bool,
    pub finished: Option<Instant>,
    pub hops: Vec<Hop>,
    /// (label, value) pairs pulled from the responses, most specific server winning.
    pub summary: Vec<(&'static str, String)>,
    pub created: Option<(i32, u32, u32)>,
    pub expires: Option<(i32, u32, u32)>,
    /// Summary from RDAP, preferred over scraping whois text when present.
    pub rdap: Option<Vec<(&'static str, String)>>,
    pending: u8,
}

pub fn start(rt: &Handle, input: &str) -> Arc<Mutex<WhoisLookup>> {
    let input = input.trim().trim_end_matches('.').to_lowercase();
    let is_ip = input.parse::<IpAddr>().is_ok();
    let state = Arc::new(Mutex::new(WhoisLookup {
        input: input.clone(),
        is_ip,
        finished: None,
        hops: vec![],
        summary: vec![],
        created: None,
        expires: None,
        rdap: None,
        pending: if is_ip { 1 } else { 2 },
    }));
    if !is_ip {
        let (st, input) = (state.clone(), input.clone());
        rt.spawn(async move {
            let t = Instant::now();
            let (server, result) = match rdap_domain(&input).await {
                Ok((server, json)) => (server, Ok(json)),
                Err(e) => ("rdap".to_string(), Err(format!("{e:#}"))),
            };
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            let mut s = st.lock().unwrap();
            match result {
                Ok(json) => {
                    s.rdap = Some(rdap_summary(&json));
                    s.hops.push(Hop { server, rdap: true, ms, text: Ok(rdap_raw(&json)) });
                }
                Err(e) => s.hops.push(Hop { server, rdap: true, ms, text: Err(e) }),
            }
            s.pending -= 1;
            summarize(&mut s);
        });
    }
    let st = state.clone();
    rt.spawn(async move {
        let mut server = "whois.iana.org".to_string();
        let mut seen = vec![];
        for _ in 0..4 {
            seen.push(server.clone());
            let t = Instant::now();
            let text = query(&server, &input).await.map_err(|e| e.to_string());
            let next = text.as_ref().ok().and_then(|t| referral(t));
            {
                let mut s = st.lock().unwrap();
                s.hops.push(Hop { server: server.clone(), rdap: false, ms: t.elapsed().as_secs_f64() * 1000.0, text });
                summarize(&mut s);
            }
            match next {
                Some(n) if !seen.contains(&n) => server = n,
                _ => break,
            }
        }
        let mut s = st.lock().unwrap();
        s.pending -= 1;
        summarize(&mut s);
    });
    state
}

async fn query(server: &str, q: &str) -> anyhow::Result<String> {
    let line = match server {
        "whois.arin.net" => format!("n + {q}\r\n"),
        "whois.denic.de" => format!("-T dn,ace {q}\r\n"),
        _ => format!("{q}\r\n"),
    };
    let fut = async {
        let mut s = TcpStream::connect((server, 43)).await?;
        s.write_all(line.as_bytes()).await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        anyhow::Ok(String::from_utf8_lossy(&buf).replace("\r\n", "\n"))
    };
    tokio::time::timeout(Duration::from_secs(10), fut).await.map_err(|_| anyhow::anyhow!("timed out"))?
}

fn referral(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim().to_ascii_lowercase();
        if matches!(k.as_str(), "refer" | "whois" | "registrar whois server" | "referralserver") {
            let v = v.trim().trim_start_matches("whois://");
            // rwhois and http referrals aren't port-43 whois.
            if v.is_empty() || v.contains("://") {
                continue;
            }
            let host = v.split(':').next().unwrap_or(v).trim_end_matches('/').to_ascii_lowercase();
            return Some(host);
        }
    }
    None
}

/// Field label → the keys different registries use for it.
const DOMAIN_FIELDS: &[(&str, &[&str])] = &[
    ("registrar", &["registrar", "sponsoring registrar", "registrar name"]),
    ("registrant", &["registrant organization", "registrant", "org", "registrant name"]),
    ("created", &["creation date", "created", "registered on", "registration time", "domain registration date"]),
    ("updated", &["updated date", "last updated", "changed", "last-update", "last modified"]),
    ("expires", &["registry expiry date", "registrar registration expiration date", "expiry date", "expires", "paid-till", "expiration date", "expiration time"]),
    ("status", &["domain status", "status", "state"]),
    ("dnssec", &["dnssec"]),
    ("nameservers", &["name server", "nserver", "nameservers"]),
    ("abuse", &["registrar abuse contact email"]),
];

const IP_FIELDS: &[(&str, &[&str])] = &[
    ("range", &["netrange", "inetnum", "inet6num"]),
    ("cidr", &["cidr", "route", "route6"]),
    ("netname", &["netname"]),
    ("org", &["orgname", "org-name", "organization", "descr", "owner"]),
    ("country", &["country"]),
    ("created", &["regdate", "created"]),
    ("updated", &["updated", "last-modified"]),
    ("abuse", &["orgabuseemail", "abuse-mailbox", "e-mail"]),
    ("origin", &["originas", "origin"]),
];

fn summarize(s: &mut WhoisLookup) {
    if s.pending == 0 && s.finished.is_none() {
        s.finished = Some(Instant::now());
    }
    // RDAP wins; whois text fills anything RDAP left out (thin registries like
    // .com's omit the registrant, which the registrar's whois often has).
    let mut out = s.rdap.clone().unwrap_or_default();
    for (label, value) in scrape(s) {
        if !out.iter().any(|(l, _)| *l == label) {
            out.push((label, value));
        }
    }
    let order = if s.is_ip { IP_FIELDS } else { DOMAIN_FIELDS };
    out.sort_by_key(|(l, _)| order.iter().position(|(o, _)| o == l).unwrap_or(usize::MAX));
    s.created = out.iter().find(|(k, _)| *k == "created").and_then(|(_, v)| parse_date(v));
    s.expires = out.iter().find(|(k, _)| *k == "expires").and_then(|(_, v)| parse_date(v));
    s.summary = out;
}

/// Pull summary fields out of free-form whois text.
fn scrape(s: &WhoisLookup) -> Vec<(&'static str, String)> {
    let fields = if s.is_ip { IP_FIELDS } else { DOMAIN_FIELDS };
    let mut out: Vec<(&'static str, String)> = vec![];
    // The first (IANA) hop describes the TLD or RIR block, never the target itself.
    let relevant: Vec<&String> = s.hops.iter().filter(|h| !h.rdap).skip(1).filter_map(|h| h.text.as_ref().ok()).collect();
    for (label, keys) in fields {
        let mut values: Vec<String> = vec![];
        // Later (more specific) servers take precedence.
        for text in relevant.iter().rev() {
            for line in text.lines() {
                let Some((k, v)) = line.split_once(':') else { continue };
                let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
                if v.is_empty() || line.starts_with(['%', '#', '>']) {
                    continue;
                }
                if keys.contains(&k.as_str()) && !values.iter().any(|x| x.eq_ignore_ascii_case(v)) {
                    values.push(v.to_string());
                }
            }
            if !values.is_empty() {
                break;
            }
        }
        if values.is_empty() {
            continue;
        }
        let joined = match *label {
            "nameservers" | "status" => values
                .iter()
                .map(|v| v.split_whitespace().next().unwrap_or(v).to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(", "),
            _ => values[0].clone(),
        };
        out.push((label, joined));
    }
    out
}

// ---------------------------------------------------------------------------
// RDAP
// ---------------------------------------------------------------------------

/// IANA's TLD → RDAP server map, fetched once per run.
async fn rdap_bootstrap() -> anyhow::Result<&'static Value> {
    static BOOT: OnceLock<Value> = OnceLock::new();
    if let Some(v) = BOOT.get() {
        return Ok(v);
    }
    let v = super::http::get_json("https://data.iana.org/rdap/dns.json", vec![]).await?;
    Ok(BOOT.get_or_init(|| v))
}

/// Returns (server host, response json).
async fn rdap_domain(domain: &str) -> anyhow::Result<(String, Value)> {
    let boot = rdap_bootstrap().await?;
    // Longest matching suffix wins (e.g. "co.uk" before "uk").
    let labels: Vec<&str> = domain.split('.').collect();
    let base = (1..labels.len())
        .find_map(|i| {
            let suffix = labels[i..].join(".");
            boot["services"].as_array()?.iter().find_map(|svc| {
                let tlds = svc.get(0)?.as_array()?;
                tlds.iter().any(|t| t.as_str() == Some(suffix.as_str())).then(|| svc.get(1)?.get(0)?.as_str()).flatten()
            })
        })
        .ok_or_else(|| anyhow::anyhow!("no RDAP server for this TLD"))?;
    let url = format!("{}/domain/{domain}", base.trim_end_matches('/'));
    let host = super::http::Url::parse(&url)?.host;
    let json = super::http::get_json(&url, vec![("Accept", "application/rdap+json".into())]).await?;
    Ok((host, json))
}

fn vcard(entity: &Value, field: &str) -> Option<String> {
    entity.get("vcardArray")?.get(1)?.as_array()?.iter().find_map(|prop| {
        (prop.get(0)?.as_str()? == field).then(|| prop.get(3)?.as_str().map(str::to_string)).flatten()
    })
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity["roles"].as_array().is_some_and(|r| r.iter().any(|x| x.as_str() == Some(role)))
}

fn rdap_summary(j: &Value) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = vec![];
    let entities = j["entities"].as_array().cloned().unwrap_or_default();
    let named = |role: &str| {
        entities
            .iter()
            .find(|e| has_role(e, role))
            .and_then(|e| vcard(e, "org").or_else(|| vcard(e, "fn")))
            .filter(|n| !n.is_empty() && !n.to_ascii_lowercase().contains("redacted"))
    };
    if let Some(r) = named("registrar") {
        out.push(("registrar", r));
    }
    if let Some(r) = named("registrant") {
        out.push(("registrant", r));
    }
    let event = |action: &str| {
        j["events"].as_array()?.iter().find(|e| e["eventAction"].as_str() == Some(action))?["eventDate"].as_str().map(str::to_string)
    };
    for (label, action) in [("created", "registration"), ("updated", "last changed"), ("expires", "expiration")] {
        if let Some(d) = event(action) {
            out.push((label, d));
        }
    }
    if let Some(st) = j["status"].as_array() {
        let st: Vec<&str> = st.iter().filter_map(Value::as_str).collect();
        if !st.is_empty() {
            out.push(("status", st.join(", ")));
        }
    }
    if let Some(signed) = j["secureDNS"]["delegationSigned"].as_bool() {
        out.push(("dnssec", if signed { "signed" } else { "unsigned" }.into()));
    }
    if let Some(ns) = j["nameservers"].as_array() {
        let ns: Vec<String> = ns.iter().filter_map(|n| n["ldhName"].as_str()).map(str::to_ascii_lowercase).collect();
        if !ns.is_empty() {
            out.push(("nameservers", ns.join(", ")));
        }
    }
    let abuse = entities
        .iter()
        .filter(|e| has_role(e, "registrar"))
        .flat_map(|e| e["entities"].as_array().cloned().unwrap_or_default())
        .find(|e| has_role(e, "abuse"))
        .and_then(|e| vcard(&e, "email"));
    if let Some(a) = abuse {
        out.push(("abuse", a));
    }
    out
}

/// RDAP JSON rendered as whois-style "key: value" lines, so it reads (and
/// highlights) like the rest of the raw output.
fn rdap_raw(j: &Value) -> String {
    let mut out = vec![];
    let str_of = |v: &Value| v.as_str().unwrap_or_default().to_string();
    out.push(format!("domain: {}", str_of(&j["ldhName"])));
    if let Some(h) = j["handle"].as_str() {
        out.push(format!("handle: {h}"));
    }
    for st in j["status"].as_array().into_iter().flatten() {
        out.push(format!("status: {}", str_of(st)));
    }
    for e in j["events"].as_array().into_iter().flatten() {
        out.push(format!("{}: {}", str_of(&e["eventAction"]), str_of(&e["eventDate"])));
    }
    for ns in j["nameservers"].as_array().into_iter().flatten() {
        out.push(format!("nameserver: {}", str_of(&ns["ldhName"]).to_ascii_lowercase()));
    }
    if let Some(signed) = j["secureDNS"]["delegationSigned"].as_bool() {
        out.push(format!("dnssec: {}", if signed { "signed" } else { "unsigned" }));
    }
    for e in j["entities"].as_array().into_iter().flatten() {
        out.push(String::new());
        rdap_entity(e, 0, &mut out);
    }
    let redacted: Vec<String> = j["redacted"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["name"]["description"].as_str().or_else(|| r["name"]["type"].as_str()).map(str::to_string))
        .collect();
    if !redacted.is_empty() {
        out.push(String::new());
        out.push(format!("redacted for privacy: {}", redacted.join(", ")));
    }
    out.join("\n")
}

fn rdap_entity(e: &Value, depth: usize, out: &mut Vec<String>) {
    let pad = "  ".repeat(depth);
    let roles: Vec<&str> = e["roles"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    out.push(format!("{pad}{}: {}", roles.join("/"), e["handle"].as_str().unwrap_or("")));
    for prop in e["vcardArray"].get(1).and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = prop.get(0).and_then(Value::as_str) else { continue };
        let value = match prop.get(3) {
            Some(Value::String(v)) => v.clone(),
            Some(Value::Array(parts)) => {
                parts.iter().filter_map(Value::as_str).filter(|p| !p.is_empty()).collect::<Vec<_>>().join(", ")
            }
            _ => continue,
        };
        if name != "version" && !value.is_empty() {
            out.push(format!("{pad}  {name}: {value}"));
        }
    }
    for id in e["publicIds"].as_array().into_iter().flatten() {
        out.push(format!("{pad}  {}: {}", id["type"].as_str().unwrap_or("id"), id["identifier"].as_str().unwrap_or("")));
    }
    for sub in e["entities"].as_array().into_iter().flatten() {
        rdap_entity(sub, depth + 1, out);
    }
}

/// Finds the first YYYY-MM-DD (or YYYY.MM.DD / YYYY/MM/DD) in a string.
pub fn parse_date(s: &str) -> Option<(i32, u32, u32)> {
    let b = s.as_bytes();
    (0..b.len().saturating_sub(9)).find_map(|i| {
        let w = &s[i..i + 10];
        let sep = w.as_bytes()[4];
        if !matches!(sep, b'-' | b'.' | b'/') || w.as_bytes()[7] != sep {
            return None;
        }
        Some((w[..4].parse().ok()?, w[5..7].parse().ok()?, w[8..10].parse().ok()?))
    })
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil((y, m, d): (i32, u32, u32)) -> i64 {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn today() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64 / 86400).unwrap_or(0)
}
