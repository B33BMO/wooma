//! IP intelligence: geolocation (db-ip), abuse reputation (AbuseIPDB), and
//! network ownership (reverse DNS + ASN via the shared enricher).

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;
use tokio::runtime::Handle;

use super::dns::{is_private, Enricher};
use super::http;

#[derive(Debug, Clone, Default)]
pub struct Geo {
    pub continent: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
}

#[derive(Debug, Clone, Default)]
pub struct Abuse {
    pub score: u8,
    pub reports: u64,
    pub reporters: u64,
    pub last_reported: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub usage: Option<String>,
    pub is_tor: bool,
    pub whitelisted: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum Fetch<T> {
    Pending,
    Done(T),
    Failed(String),
    Skipped(String),
}

#[derive(Debug)]
pub struct IpLookup {
    pub input: String,
    pub started: Instant,
    pub ip: Fetch<IpAddr>,
    /// True when the input was blank and we looked up our own public address.
    pub is_self: bool,
    pub geo: Fetch<Geo>,
    pub abuse: Fetch<Abuse>,
}

pub fn start(rt: &Handle, input: &str, abuse_key: Option<String>, enricher: Enricher) -> Arc<Mutex<IpLookup>> {
    let input = input.trim().to_string();
    let state = Arc::new(Mutex::new(IpLookup {
        input: input.clone(),
        started: Instant::now(),
        ip: Fetch::Pending,
        is_self: input.is_empty(),
        geo: Fetch::Pending,
        abuse: Fetch::Pending,
    }));
    let st = state.clone();
    rt.spawn(async move {
        let ip = match resolve_target(&input).await {
            Ok(ip) => ip,
            Err(e) => {
                let mut s = st.lock().unwrap();
                s.ip = Fetch::Failed(e.to_string());
                s.geo = Fetch::Skipped(String::new());
                s.abuse = Fetch::Skipped(String::new());
                return;
            }
        };
        st.lock().unwrap().ip = Fetch::Done(ip);
        enricher.lookup(ip);
        if is_private(ip) {
            let mut s = st.lock().unwrap();
            s.geo = Fetch::Skipped("private address".into());
            s.abuse = Fetch::Skipped("private address".into());
            return;
        }

        let geo_task = {
            let st = st.clone();
            tokio::spawn(async move {
                let r = geo(ip).await;
                st.lock().unwrap().geo = match r {
                    Ok(g) => Fetch::Done(g),
                    Err(e) => Fetch::Failed(e.to_string()),
                };
            })
        };
        let abuse_result = match abuse_key {
            None => Fetch::Skipped("no api key".into()),
            Some(key) => match abuse(ip, &key).await {
                Ok(a) => Fetch::Done(a),
                Err(e) => Fetch::Failed(e.to_string()),
            },
        };
        st.lock().unwrap().abuse = abuse_result;
        let _ = geo_task.await;
    });
    state
}

async fn resolve_target(input: &str) -> anyhow::Result<IpAddr> {
    if input.is_empty() {
        // Cloudflare's trace endpoint echoes back the caller's address.
        let resp = http::send(http::Request::get(http::Url::parse("https://cloudflare.com/cdn-cgi/trace")?)).await?;
        let body = String::from_utf8_lossy(&resp.body);
        let ip = body
            .lines()
            .find_map(|l| l.strip_prefix("ip="))
            .ok_or_else(|| anyhow::anyhow!("couldn't discover public ip"))?;
        return Ok(ip.trim().parse()?);
    }
    if let Ok(ip) = input.parse() {
        return Ok(ip);
    }
    let host = input.to_string();
    tokio::task::spawn_blocking(move || super::icmp::resolve(&host)).await?.map_err(Into::into)
}

fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn opt_s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

async fn geo(ip: IpAddr) -> anyhow::Result<Geo> {
    let j = http::get_json(&format!("https://api.db-ip.com/v2/free/{ip}"), vec![]).await?;
    if let Some(err) = j.get("error").and_then(Value::as_str) {
        anyhow::bail!("{err}");
    }
    Ok(Geo {
        continent: s(&j, "continentName"),
        country: s(&j, "countryName"),
        country_code: s(&j, "countryCode"),
        region: s(&j, "stateProv"),
        city: s(&j, "city"),
    })
}

async fn abuse(ip: IpAddr, key: &str) -> anyhow::Result<Abuse> {
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    let j = http::get_json(&url, vec![("Key", key.to_string())]).await?;
    let d = j.get("data").ok_or_else(|| anyhow::anyhow!("unexpected response"))?;
    Ok(Abuse {
        score: d.get("abuseConfidenceScore").and_then(Value::as_u64).unwrap_or(0) as u8,
        reports: d.get("totalReports").and_then(Value::as_u64).unwrap_or(0),
        reporters: d.get("numDistinctUsers").and_then(Value::as_u64).unwrap_or(0),
        last_reported: opt_s(d, "lastReportedAt"),
        isp: opt_s(d, "isp"),
        domain: opt_s(d, "domain"),
        usage: opt_s(d, "usageType"),
        is_tor: d.get("isTor").and_then(Value::as_bool).unwrap_or(false),
        whitelisted: d.get("isWhitelisted").and_then(Value::as_bool),
    })
}
