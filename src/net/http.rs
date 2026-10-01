//! A tiny HTTP/1.1 client that times each phase of a request.
//!
//! Hand-rolled (rather than reqwest) because the http tab wants DNS, TCP, TLS,
//! first-byte and download timings separately, plus the raw certificate chain.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const USER_AGENT: &str = concat!("wooma/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            (true, s)
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.ends_with(']') => (h, p.parse().context("bad port")?),
            _ => (authority, if https { 443 } else { 80 }),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        if host.is_empty() {
            bail!("missing host");
        }
        Ok(Self { https, host, port, path })
    }

    pub fn origin(&self) -> String {
        let default = if self.https { 443 } else { 80 };
        let port = if self.port == default { String::new() } else { format!(":{}", self.port) };
        format!("{}://{}{}", if self.https { "https" } else { "http" }, self.host, port)
    }

    /// Resolve a Location header against this URL.
    pub fn join(&self, location: &str) -> anyhow::Result<Url> {
        if location.starts_with("http://") || location.starts_with("https://") {
            Url::parse(location)
        } else if location.starts_with("//") {
            Url::parse(&format!("{}:{location}", if self.https { "https" } else { "http" }))
        } else if location.starts_with('/') {
            Ok(Url { path: location.to_string(), ..self.clone() })
        } else {
            let base = self.path.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
            Ok(Url { path: format!("{base}/{location}"), ..self.clone() })
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.origin(), self.path)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Timings {
    pub dns: f64,
    pub connect: f64,
    pub tls: Option<f64>,
    pub ttfb: f64,
    pub download: f64,
}

impl Timings {
    pub fn total(&self) -> f64 {
        self.dns + self.connect + self.tls.unwrap_or(0.0) + self.ttfb + self.download
    }
}

#[derive(Debug, Clone, Default)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub key: String,
}

#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub chain: Vec<CertInfo>,
    /// Set when the chain did not verify; only possible with `lenient`.
    pub verify_error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub body_bytes: u64,
    pub ip: Option<IpAddr>,
    pub timings: Timings,
    pub tls: Option<TlsInfo>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: Url,
    pub headers: Vec<(&'a str, String)>,
    /// Upload this many bytes of filler as the request body.
    pub upload: u64,
    /// Keep at most this many body bytes in memory.
    pub keep_body: usize,
    /// Accept invalid certificates, recording why in `TlsInfo::verify_error`.
    pub lenient: bool,
    pub timeout: Duration,
    /// Live byte counters and an abort switch, for the speed test.
    pub rx_counter: Option<Arc<AtomicU64>>,
    pub tx_counter: Option<Arc<AtomicU64>>,
    pub stop: Option<Arc<AtomicBool>>,
}

impl<'a> Request<'a> {
    pub fn get(url: Url) -> Self {
        Self {
            method: "GET",
            url,
            headers: vec![],
            upload: 0,
            keep_body: 4 << 20,
            lenient: false,
            timeout: Duration::from_secs(15),
            rx_counter: None,
            tx_counter: None,
            stop: None,
        }
    }

    fn stopped(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed))
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

pub async fn get_json(url: &str, headers: Vec<(&str, String)>) -> anyhow::Result<serde_json::Value> {
    let mut req = Request::get(Url::parse(url)?);
    req.headers = headers;
    req.headers.push(("Accept", "application/json".into()));
    let resp = send(req).await?;
    if resp.status != 200 {
        let msg = resp.json().ok().and_then(|j| error_message(&j)).unwrap_or_default();
        bail!("HTTP {} {} {msg}", resp.status, resp.reason);
    }
    resp.json()
}

fn error_message(j: &serde_json::Value) -> Option<String> {
    j.pointer("/errors/0/detail")
        .or_else(|| j.get("error"))
        .or_else(|| j.get("message"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

pub async fn send(req: Request<'_>) -> anyhow::Result<Response> {
    let timeout = req.timeout;
    tokio::time::timeout(timeout, send_inner(req)).await.map_err(|_| anyhow!("timed out after {timeout:?}"))?
}

async fn send_inner(req: Request<'_>) -> anyhow::Result<Response> {
    let mut resp = Response::default();
    let url = &req.url;

    let t = Instant::now();
    let addr: SocketAddr = match url.host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, url.port),
        Err(_) => {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
                .await
                .with_context(|| format!("can't resolve {}", url.host))?
                .collect();
            *addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).ok_or_else(|| anyhow!("no addresses"))?
        }
    };
    resp.timings.dns = ms(t);
    resp.ip = Some(addr.ip());

    let t = Instant::now();
    let tcp = TcpStream::connect(addr).await.with_context(|| format!("connect to {addr}"))?;
    tcp.set_nodelay(true)?;
    resp.timings.connect = ms(t);

    let mut stream: Box<dyn Io> = if url.https {
        let t = Instant::now();
        let recorder = Arc::new(Mutex::new(None));
        let config = tls_config(req.lenient, recorder.clone());
        let name = ServerName::try_from(url.host.clone())?;
        let tls = TlsConnector::from(config).connect(name, tcp).await.context("TLS handshake")?;
        resp.timings.tls = Some(ms(t));
        let conn = tls.get_ref().1;
        resp.tls = Some(TlsInfo {
            version: conn.protocol_version().map(|v| format!("{v:?}").replace('_', ".")).unwrap_or_default(),
            cipher: conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())).unwrap_or_default(),
            alpn: conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned()),
            chain: conn.peer_certificates().unwrap_or_default().iter().filter_map(|c| cert_info(c)).collect(),
            verify_error: recorder.lock().unwrap().take(),
        });
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    // Request head, then optional filler body.
    let host_hdr = if url.port == if url.https { 443 } else { 80 } {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n",
        req.method, url.path
    );
    for (k, v) in &req.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if req.upload > 0 {
        head.push_str(&format!("Content-Length: {}\r\nContent-Type: application/octet-stream\r\n", req.upload));
    }
    head.push_str("\r\n");
    let t = Instant::now();
    stream.write_all(head.as_bytes()).await?;
    if req.upload > 0 {
        let chunk = vec![b'w'; 64 * 1024];
        let mut left = req.upload;
        while left > 0 && !req.stopped() {
            let n = left.min(chunk.len() as u64) as usize;
            stream.write_all(&chunk[..n]).await?;
            left -= n as u64;
            if let Some(c) = &req.tx_counter {
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        if req.stopped() {
            return Ok(resp);
        }
    }
    stream.flush().await?;

    // Read until the end of the headers; first byte marks TTFB.
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    let mut first = true;
    let header_end = loop {
        let n = read_some(&mut stream, &mut chunk).await?;
        if n == 0 {
            bail!("connection closed before response");
        }
        if first {
            resp.timings.ttfb = ms(t);
            first = false;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 256 * 1024 {
            bail!("response headers too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    resp.status = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("bad status line: {status_line}"))?;
    resp.reason = parts.next().unwrap_or_default().to_string();
    resp.headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    // Body: Content-Length if given, else until the server closes.
    let t = Instant::now();
    let length: Option<u64> = resp.header("content-length").and_then(|v| v.parse().ok());
    let no_body = req.method == "HEAD" || resp.status == 204 || resp.status == 304 || (100..200).contains(&resp.status);
    let mut body = buf[header_end..].to_vec();
    let mut total = body.len() as u64;
    if let Some(c) = &req.rx_counter {
        c.fetch_add(total, Ordering::Relaxed);
    }
    if !no_body {
        while length.is_none_or(|l| total < l) && !req.stopped() {
            let n = read_some(&mut stream, &mut chunk).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if let Some(c) = &req.rx_counter {
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
            if body.len() < req.keep_body {
                body.extend_from_slice(&chunk[..n]);
            }
        }
    }
    resp.timings.download = ms(t);
    resp.body_bytes = total;
    let chunked = resp.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    resp.body = if chunked { dechunk(&body) } else { body };
    resp.body.truncate(req.keep_body);
    Ok(resp)
}

/// Read, treating a TLS peer that hangs up without close_notify as EOF.
async fn read_some(stream: &mut Box<dyn Io>, buf: &mut [u8]) -> anyhow::Result<usize> {
    match stream.read(buf).await {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e.into()),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = find(raw, b"\r\n") {
        let size_txt = String::from_utf8_lossy(&raw[..eol]);
        let Ok(size) = usize::from_str_radix(size_txt.split(';').next().unwrap_or("").trim(), 16) else { break };
        raw = &raw[eol + 2..];
        if size == 0 || raw.len() < size {
            out.extend_from_slice(&raw[..size.min(raw.len())]);
            break;
        }
        out.extend_from_slice(&raw[..size]);
        raw = raw.get(size + 2..).unwrap_or_default();
    }
    out
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| Arc::new(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }))
        .clone()
}

fn tls_config(lenient: bool, recorder: Arc<Mutex<Option<String>>>) -> Arc<ClientConfig> {
    let inner = WebPkiServerVerifier::builder(roots()).build().expect("webpki verifier");
    let verifier = Arc::new(RecordingVerifier { inner, lenient, recorder });
    let mut config = ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Normal webpki verification, except that in lenient mode a failure is
/// recorded instead of aborting, so we can still show the broken cert.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    lenient: bool,
    recorder: Arc<Mutex<Option<String>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Err(e) if self.lenient => {
                *self.recorder.lock().unwrap() = Some(friendly_cert_error(&e));
                Ok(ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn friendly_cert_error(e: &rustls::Error) -> String {
    use rustls::{CertificateError as C, Error};
    match e {
        Error::InvalidCertificate(C::Expired | C::ExpiredContext { .. }) => "certificate has expired".into(),
        Error::InvalidCertificate(C::NotValidYet | C::NotValidYetContext { .. }) => "certificate is not valid yet".into(),
        Error::InvalidCertificate(C::NotValidForName | C::NotValidForNameContext { .. }) => {
            "certificate is not valid for this hostname".into()
        }
        Error::InvalidCertificate(C::UnknownIssuer) => "untrusted issuer (self-signed or missing intermediate)".into(),
        Error::InvalidCertificate(C::Revoked) => "certificate has been revoked".into(),
        other => other.to_string(),
    }
}

fn cert_info(der: &CertificateDer<'_>) -> Option<CertInfo> {
    use x509_parser::extensions::GeneralName;
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    // CN, else O; falls back to picking it out of the full DN when the
    // attribute uses an encoding `as_str` won't decode.
    let short_name = |n: &x509_parser::x509::X509Name| {
        let dn = n.to_string();
        n.iter_common_name()
            .next()
            .or_else(|| n.iter_organization().next())
            .and_then(|a| a.as_str().ok())
            .map(str::to_string)
            .or_else(|| dn.split(", ").find_map(|p| p.strip_prefix("CN=")).map(str::to_string))
            .unwrap_or(dn)
    };
    let issuer_org = cert.issuer().iter_organization().next().and_then(|a| a.as_str().ok());
    let issuer_cn = short_name(cert.issuer());
    let issuer = match issuer_org {
        Some(org) if !issuer_cn.contains(org) => format!("{issuer_cn} ({org})"),
        _ => issuer_cn,
    };
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    GeneralName::IPAddress(b) if b.len() == 4 => Some(IpAddr::from([b[0], b[1], b[2], b[3]]).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let v = cert.validity();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    let pk = cert.public_key();
    let key = match pk.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => format!("RSA {}", rsa.key_size()),
        Ok(x509_parser::public_key::PublicKey::EC(ec)) => format!("EC {}", ec.key_size()),
        _ => pk.algorithm.algorithm.to_id_string(),
    };
    Some(CertInfo {
        subject: short_name(cert.subject()),
        issuer,
        sans,
        not_before: v.not_before.to_string(),
        not_after: v.not_after.to_string(),
        days_left: (v.not_after.timestamp() - now).div_euclid(86400),
        key,
    })
}
