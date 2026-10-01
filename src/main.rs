mod app;
mod config;
mod net;
mod ui;

use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use app::{App, Tab};
use config::Config;

/// wooma: a terminal toolkit for network diagnostics.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ping one or more hosts and watch loss, latency and up/down state
    Ping { hosts: Vec<String> },
    /// Continuous mtr-style traceroute with per-hop stats and ASN info
    #[command(alias = "tracert", alias = "traceroute", alias = "mtr")]
    Trace { host: Option<String> },
    /// Look up every common record type, and race the public resolvers
    #[command(alias = "ns", alias = "nslookup", alias = "dig")]
    Dns { name: Option<String> },
    /// Geolocation, abuse reputation and network owner for an IP (blank = yours)
    #[command(alias = "geo", alias = "abuse", alias = "myip")]
    Ip { target: Option<String> },
    /// Whois for a domain or IP, following registry referrals
    Whois { query: Option<String> },
    /// Request a URL and break down DNS / TCP / TLS / TTFB timings and the cert
    #[command(alias = "curl")]
    Http { url: Option<String> },
    /// TCP port scan: `wooma ports host [top|all|1-1024|22,80,443]`
    #[command(alias = "scan", alias = "nmap")]
    Ports { host: Option<String>, ports: Option<String> },
    /// Download / upload / latency / bufferbloat test via Cloudflare
    #[command(alias = "speedtest")]
    Speed,
    /// Show the config file location and current settings
    Config,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load()?;
    let opt = |o: Option<String>| o.into_iter().collect::<Vec<_>>();
    let (tab, targets) = match cli.cmd {
        None => (Tab::Ping, vec![]),
        Some(Cmd::Ping { hosts }) => (Tab::Ping, hosts),
        Some(Cmd::Trace { host }) => (Tab::Trace, opt(host)),
        Some(Cmd::Dns { name }) => (Tab::Dns, opt(name)),
        Some(Cmd::Ip { target }) => (Tab::Ip, opt(target)),
        Some(Cmd::Whois { query }) => (Tab::Whois, opt(query)),
        Some(Cmd::Http { url }) => (Tab::Http, opt(url)),
        Some(Cmd::Ports { host, ports }) => (Tab::Ports, host.into_iter().chain(ports).collect()),
        Some(Cmd::Speed) => (Tab::Speed, vec![]),
        Some(Cmd::Config) => return print_config(&config),
    };
    raise_fd_limit();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build()?;
    let _guard = rt.enter();
    let mut app = App::new(rt.handle().clone(), config, tab, targets);

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    rt.shutdown_background();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    let frame = Duration::from_millis(100);
    let started = Instant::now();
    while !app.quit {
        terminal.draw(|f| ui::draw(f, app, started.elapsed().as_secs_f32()))?;
        if event::poll(frame)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.on_key(key);
        }
    }
    Ok(())
}

fn print_config(config: &Config) -> anyhow::Result<()> {
    let path = config::path();
    println!("config file:   {}{}", path.display(), if path.exists() { "" } else { "  (not created yet)" });
    let key = match &config.abuseipdb_key {
        Some(k) if k.len() > 8 => format!("{}…{}", &k[..4], &k[k.len() - 4..]),
        Some(_) => "set".into(),
        None => "not set (get a free key at https://www.abuseipdb.com/account/api)".into(),
    };
    println!("abuseipdb_key: {key}");
    let icmp = net::icmp::probe().replace('\n', "\n               ");
    println!("icmp:          {icmp}");
    println!("\nexample config.toml:\n  abuseipdb_key = \"your-key\"");
    println!("\nenv overrides: ABUSEIPDB_KEY=..., WOOMA_CONFIG=/path");
    Ok(())
}

/// The port scanner holds hundreds of sockets open; macOS defaults to 256.
fn raise_fd_limit() {
    // SAFETY: plain libc calls on a stack-allocated struct.
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            lim.rlim_cur = lim.rlim_max.min(8192);
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}
