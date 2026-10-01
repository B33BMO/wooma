//! Speed test against Cloudflare's speed.cloudflare.com endpoints.
//!
//! Measures idle latency, download and upload throughput over parallel
//! streams, and latency under load (bufferbloat) while the pipe is full.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::net::TcpStream;
use tokio::runtime::Handle;

use super::http::{self, Request, Url};

const HOST: &str = "speed.cloudflare.com";
const PHASE_SECS: f64 = 10.0;
/// Ignore the first stretch of each transfer while TCP ramps up.
const RAMP_SECS: f64 = 2.0;
const SAMPLE: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Meta,
    Latency,
    Download,
    Upload,
    Done,
}

#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub ip: String,
    pub isp: String,
    pub colo: String,
    pub location: String,
}

#[derive(Debug)]
pub struct SpeedTest {
    pub phase: Phase,
    pub phase_started: Instant,
    pub meta: Option<Meta>,
    pub idle: Vec<f64>,
    pub loaded_down: Vec<f64>,
    pub loaded_up: Vec<f64>,
    /// Mbps samples, one per SAMPLE interval.
    pub down_series: Vec<f64>,
    pub up_series: Vec<f64>,
    pub down_mbps: Option<f64>,
    pub up_mbps: Option<f64>,
    pub current: f64,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub error: Option<String>,
}

pub struct SpeedHandle {
    pub state: Arc<Mutex<SpeedTest>>,
    stop: Arc<AtomicBool>,
}

impl Drop for SpeedHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn median(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    Some(s[s.len() / 2])
}

pub fn jitter(v: &[f64]) -> Option<f64> {
    (v.len() > 1).then(|| v.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (v.len() - 1) as f64)
}

/// Waveform-style bufferbloat grade from the latency increase under load.
pub fn bloat_grade(idle: f64, loaded: f64) -> (&'static str, f64) {
    let inc = (loaded - idle).max(0.0);
    let g = match inc {
        i if i < 5.0 => "A+",
        i if i < 30.0 => "A",
        i if i < 60.0 => "B",
        i if i < 200.0 => "C",
        i if i < 400.0 => "D",
        _ => "F",
    };
    (g, inc)
}

pub fn start(rt: &Handle) -> SpeedHandle {
    let state = Arc::new(Mutex::new(SpeedTest {
        phase: Phase::Meta,
        phase_started: Instant::now(),
        meta: None,
        idle: vec![],
        loaded_down: vec![],
        loaded_up: vec![],
        down_series: vec![],
        up_series: vec![],
        down_mbps: None,
        up_mbps: None,
        current: 0.0,
        bytes_down: 0,
        bytes_up: 0,
        error: None,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let (st, stop2) = (state.clone(), stop.clone());
    rt.spawn(async move {
        if let Err(e) = run(&st, &stop2).await {
            let mut s = st.lock().unwrap();
            s.error = Some(e.to_string());
            s.phase = Phase::Done;
        }
    });
    SpeedHandle { state, stop }
}

fn set_phase(st: &Mutex<SpeedTest>, p: Phase) {
    let mut s = st.lock().unwrap();
    s.phase = p;
    s.phase_started = Instant::now();
    s.current = 0.0;
}

async fn run(st: &Arc<Mutex<SpeedTest>>, stop: &Arc<AtomicBool>) -> anyhow::Result<()> {
    // /meta 403s without a Referer from the speed test page.
    let meta = http::get_json(&format!("https://{HOST}/meta"), vec![("Referer", format!("https://{HOST}/"))]).await.ok();
    st.lock().unwrap().meta = meta.as_ref().map(parse_meta);

    set_phase(st, Phase::Latency);
    let addr = tokio::net::lookup_host((HOST, 443))
        .await?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("can't resolve {HOST}"))?;
    for _ in 0..12 {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        if let Some(ms) = tcp_rtt(addr).await {
            st.lock().unwrap().idle.push(ms);
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    for phase in [Phase::Download, Phase::Upload] {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        set_phase(st, phase);
        let mbps = transfer(st, stop, addr, phase).await;
        let mut s = st.lock().unwrap();
        match phase {
            Phase::Download => s.down_mbps = Some(mbps),
            _ => s.up_mbps = Some(mbps),
        }
    }
    set_phase(st, Phase::Done);
    Ok(())
}

fn parse_meta(j: &Value) -> Meta {
    let s = |k: &str| j.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let colo = match j.get("colo") {
        Some(Value::String(c)) => c.clone(),
        Some(obj) => {
            let iata = obj.get("iata").and_then(Value::as_str).unwrap_or_default();
            let city = obj.get("city").and_then(Value::as_str).unwrap_or_default();
            format!("{iata} {city}").trim().to_string()
        }
        None => String::new(),
    };
    let location = [s("city"), s("country")].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
    Meta { ip: s("clientIp"), isp: s("asOrganization"), colo, location }
}

async fn tcp_rtt(addr: SocketAddr) -> Option<f64> {
    let t = Instant::now();
    tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await.ok()?.ok()?;
    Some(t.elapsed().as_secs_f64() * 1000.0)
}

async fn transfer(st: &Arc<Mutex<SpeedTest>>, stop: &Arc<AtomicBool>, addr: SocketAddr, phase: Phase) -> f64 {
    let download = phase == Phase::Download;
    let counter = Arc::new(AtomicU64::new(0));
    let phase_stop = Arc::new(AtomicBool::new(false));
    let workers = if download { 6 } else { 4 };

    for _ in 0..workers {
        let (counter, phase_stop, stop) = (counter.clone(), phase_stop.clone(), stop.clone());
        tokio::spawn(async move {
            while !phase_stop.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
                let url = if download {
                    format!("https://{HOST}/__down?bytes=25000000")
                } else {
                    format!("https://{HOST}/__up")
                };
                let Ok(url) = Url::parse(&url) else { return };
                let mut req = Request::get(url);
                req.keep_body = 0;
                req.timeout = Duration::from_secs(30);
                req.stop = Some(phase_stop.clone());
                req.headers.push(("Referer", format!("https://{HOST}/")));
                if download {
                    req.rx_counter = Some(counter.clone());
                } else {
                    req.method = "POST";
                    req.upload = 8_000_000;
                    req.tx_counter = Some(counter.clone());
                }
                if http::send(req).await.is_err() {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        });
    }

    // Loaded-latency probes run alongside the transfer.
    {
        let (st, phase_stop) = (st.clone(), phase_stop.clone());
        tokio::spawn(async move {
            while !phase_stop.load(Ordering::Relaxed) {
                if let Some(ms) = tcp_rtt(addr).await {
                    let mut s = st.lock().unwrap();
                    if download { s.loaded_down.push(ms) } else { s.loaded_up.push(ms) }
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        });
    }

    let start = Instant::now();
    let mut window: Vec<(Instant, u64)> = vec![(start, 0)];
    let mut ramp_bytes = None;
    while start.elapsed().as_secs_f64() < PHASE_SECS && !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(SAMPLE).await;
        let now = Instant::now();
        let bytes = counter.load(Ordering::Relaxed);
        window.push((now, bytes));
        if ramp_bytes.is_none() && start.elapsed().as_secs_f64() >= RAMP_SECS {
            ramp_bytes = Some((now, bytes));
        }
        // Instantaneous rate over the last second.
        let (t0, b0) = *window.iter().rev().find(|(t, _)| now.duration_since(*t) >= Duration::from_secs(1)).unwrap_or(&window[0]);
        let secs = now.duration_since(t0).as_secs_f64().max(0.001);
        let mbps = (bytes - b0) as f64 * 8.0 / secs / 1e6;
        let mut s = st.lock().unwrap();
        s.current = mbps;
        if download {
            s.down_series.push(mbps);
            s.bytes_down = bytes;
        } else {
            s.up_series.push(mbps);
            s.bytes_up = bytes;
        }
    }
    phase_stop.store(true, Ordering::Relaxed);

    let end_bytes = counter.load(Ordering::Relaxed);
    let (t0, b0) = ramp_bytes.unwrap_or((start, 0));
    let secs = t0.elapsed().as_secs_f64().max(0.001);
    (end_bytes - b0) as f64 * 8.0 / secs / 1e6
}
