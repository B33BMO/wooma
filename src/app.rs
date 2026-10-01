use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::runtime::Handle;

use crate::config::Config;
use crate::net::dns::{self, DnsQuery, Enricher, ResolverChoice};
use crate::net::httpcheck::{self, HttpCheck};
use crate::net::ipinfo::{self, IpLookup};
use crate::net::ping::PingTarget;
use crate::net::ports::{self, ScanHandle};
use crate::net::speed::{self, SpeedHandle};
use crate::net::trace::TraceSession;
use crate::net::whois::{self, WhoisLookup};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Ping,
    Trace,
    Dns,
    Ip,
    Whois,
    Http,
    Ports,
    Speed,
}

impl Tab {
    pub const ALL: [Tab; 8] = [Tab::Ping, Tab::Trace, Tab::Dns, Tab::Ip, Tab::Whois, Tab::Http, Tab::Ports, Tab::Speed];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Ping => "ping",
            Tab::Trace => "trace",
            Tab::Dns => "dns",
            Tab::Ip => "ip",
            Tab::Whois => "whois",
            Tab::Http => "http",
            Tab::Ports => "ports",
            Tab::Speed => "speed",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap()
    }
}

pub struct App {
    pub rt: Handle,
    pub enricher: Enricher,
    pub config: Config,
    pub tab: Tab,
    pub quit: bool,
    /// Some(buffer) while the user is typing into the prompt.
    pub input: Option<String>,
    pub scroll: [u16; Tab::ALL.len()],
    pub flash: Option<(String, Instant)>,

    pub pings: Vec<PingTarget>,
    pub ping_sel: usize,

    pub trace: Option<TraceSession>,
    pub show_ips: bool,

    pub dns: Option<Arc<Mutex<DnsQuery>>>,
    pub resolver: ResolverChoice,

    pub ip: Option<Arc<Mutex<IpLookup>>>,
    pub whois: Option<Arc<Mutex<WhoisLookup>>>,
    pub http: Option<Arc<Mutex<HttpCheck>>>,
    pub ports: Option<ScanHandle>,
    pub speed: Option<SpeedHandle>,
}

impl App {
    pub fn new(rt: Handle, config: Config, tab: Tab, targets: Vec<String>) -> Self {
        let enricher = Enricher::new(rt.clone());
        let mut app = Self {
            rt,
            enricher,
            config,
            tab,
            quit: false,
            input: None,
            scroll: [0; Tab::ALL.len()],
            flash: None,
            pings: Vec::new(),
            ping_sel: 0,
            trace: None,
            show_ips: false,
            dns: None,
            resolver: ResolverChoice::System,
            ip: None,
            whois: None,
            http: None,
            ports: None,
            speed: None,
        };
        let joined = targets.join(" ");
        match tab {
            // The ping tab is the landing page, so give it something to show.
            Tab::Ping if targets.is_empty() => app.run(Tab::Ping, "1.1.1.1 8.8.8.8"),
            Tab::Ip | Tab::Speed => app.run(tab, &joined),
            _ if !joined.is_empty() => app.run(tab, &joined),
            _ => {}
        }
        app
    }

    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        // Landing on the ip tab with nothing to show: look ourselves up.
        if tab == Tab::Ip && self.ip.is_none() {
            self.run(Tab::Ip, "");
        }
    }

    pub fn flash(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), Instant::now()));
    }

    pub fn prompt_label(&self) -> &'static str {
        match self.tab {
            Tab::Ping => "add ping targets",
            Tab::Trace => "trace route to",
            Tab::Dns => "look up name or ip",
            Tab::Ip => "ip or host (blank = you)",
            Tab::Whois => "whois domain or ip",
            Tab::Http => "url",
            Tab::Ports => "host [ports: top | all | 1-1024 | 22,80,443]",
            Tab::Speed => "",
        }
    }

    /// Start (or restart) a tab's tool with the given input.
    fn run(&mut self, tab: Tab, text: &str) {
        let text = text.trim();
        self.scroll[tab.index()] = 0;
        match tab {
            Tab::Ping => {
                // Several targets can be added at once: "a.com b.com".
                for host in text.split_whitespace() {
                    self.pings.push(PingTarget::spawn(host.to_string()));
                }
                self.ping_sel = self.pings.len().saturating_sub(1);
            }
            Tab::Trace => self.trace = Some(TraceSession::spawn(text.to_string(), self.enricher.clone())),
            Tab::Dns => self.dns = Some(dns::start_query(&self.rt, text, self.resolver, &self.enricher)),
            Tab::Ip => {
                let key = self.config.abuseipdb_key.clone();
                self.ip = Some(ipinfo::start(&self.rt, text, key, self.enricher.clone()));
            }
            Tab::Whois => self.whois = Some(whois::start(&self.rt, text)),
            Tab::Http => self.http = Some(httpcheck::start(&self.rt, text)),
            Tab::Ports => self.ports = Some(ports::start(&self.rt, text)),
            Tab::Speed => {
                // Drop the old handle first so its workers stop before new ones start.
                self.speed = None;
                self.speed = Some(speed::start(&self.rt));
            }
        }
    }

    /// The input the current tab last ran with, for `r` to rerun.
    fn last_input(&self) -> Option<String> {
        match self.tab {
            Tab::Dns => self.dns.as_ref().map(|q| q.lock().unwrap().input.clone()),
            Tab::Ip => self.ip.as_ref().map(|q| q.lock().unwrap().input.clone()),
            Tab::Whois => self.whois.as_ref().map(|q| q.lock().unwrap().input.clone()),
            Tab::Http => self.http.as_ref().map(|q| q.lock().unwrap().input.clone()),
            Tab::Ports => self.ports.as_ref().map(|q| q.state.lock().unwrap().input.clone()),
            Tab::Speed => Some(String::new()),
            Tab::Trace => self.trace.as_ref().map(|t| t.host.clone()),
            Tab::Ping => None,
        }
    }

    fn submit(&mut self, text: String) {
        let text = text.trim();
        if text.is_empty() && self.tab != Tab::Ip {
            return;
        }
        self.run(self.tab, text);
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }

        if let Some(buf) = self.input.as_mut() {
            match key.code {
                KeyCode::Esc => self.input = None,
                KeyCode::Enter => {
                    let text = self.input.take().unwrap_or_default();
                    self.submit(text);
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => buf.clear(),
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return;
        }

        let n = Tab::ALL.len();
        let ti = self.tab.index();
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char(c @ '1'..='8') => self.set_tab(Tab::ALL[c as usize - '1' as usize]),
            KeyCode::Tab | KeyCode::Right => self.set_tab(Tab::ALL[(self.tab.index() + 1) % n]),
            KeyCode::BackTab | KeyCode::Left => self.set_tab(Tab::ALL[(self.tab.index() + n - 1) % n]),
            KeyCode::Char('/') | KeyCode::Char('a') | KeyCode::Char('i') | KeyCode::Enter => {
                if self.tab == Tab::Speed {
                    self.run(Tab::Speed, "");
                } else {
                    self.input = Some(String::new());
                }
            }
            KeyCode::Char('r') if !matches!(self.tab, Tab::Ping | Tab::Trace) => {
                if let Some(last) = self.last_input() {
                    self.run(self.tab, &last);
                    self.flash("rerun");
                }
            }
            KeyCode::PageUp => self.scroll[ti] = self.scroll[ti].saturating_sub(10),
            KeyCode::PageDown => self.scroll[ti] = self.scroll[ti].saturating_add(10),
            KeyCode::Home | KeyCode::Char('g') => self.scroll[ti] = 0,
            KeyCode::Up | KeyCode::Char('k') if self.tab != Tab::Ping => self.scroll[ti] = self.scroll[ti].saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') if self.tab != Tab::Ping => self.scroll[ti] = self.scroll[ti].saturating_add(1),
            _ => self.on_tab_key(key.code),
        }
    }

    fn on_tab_key(&mut self, code: KeyCode) {
        match self.tab {
            Tab::Ping => match code {
                KeyCode::Up | KeyCode::Char('k') => self.ping_sel = self.ping_sel.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.ping_sel = (self.ping_sel + 1).min(self.pings.len().saturating_sub(1))
                }
                KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace => {
                    if self.ping_sel < self.pings.len() {
                        let t = self.pings.remove(self.ping_sel);
                        self.flash(format!("removed {}", t.host));
                        self.ping_sel = self.ping_sel.min(self.pings.len().saturating_sub(1));
                    }
                }
                KeyCode::Char('r') => {
                    if let Some(t) = self.pings.get(self.ping_sel) {
                        t.reset();
                        self.flash(format!("reset {}", t.host));
                    }
                }
                KeyCode::Char(' ') => {
                    let pause = !self.pings.iter().all(|p| p.paused.load(Ordering::Relaxed));
                    for p in &self.pings {
                        p.paused.store(pause, Ordering::Relaxed);
                    }
                    self.flash(if pause { "paused" } else { "resumed" });
                }
                _ => {}
            },
            Tab::Trace => match code {
                KeyCode::Char('n') => self.show_ips = !self.show_ips,
                KeyCode::Char('r') => {
                    if let Some(t) = &self.trace {
                        t.reset();
                        self.flash("reset stats");
                    }
                }
                KeyCode::Char(' ') => {
                    if let Some(t) = &self.trace {
                        let p = !t.paused.load(Ordering::Relaxed);
                        t.paused.store(p, Ordering::Relaxed);
                        self.flash(if p { "paused" } else { "resumed" });
                    }
                }
                _ => {}
            },
            Tab::Dns => {
                if code == KeyCode::Char('s') {
                    self.resolver = self.resolver.next();
                    self.flash(format!("resolver: {}", self.resolver.label()));
                    if let Some(last) = self.last_input() {
                        self.run(Tab::Dns, &last);
                    }
                }
            }
            _ => {}
        }
    }
}
