use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::theme::*;
use super::{empty_hint, kv, kv_wrap, panel};
use crate::app::App;
use crate::net::ipinfo::{Abuse, Fetch, IpLookup};

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(q) = &app.ip else {
        return empty_hint(f, area, "ip", "No lookup", "press a and enter an ip or host (blank for your own address)");
    };
    let q = q.lock().unwrap();

    let [top, body] = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(area);
    let [geo_area, abuse_area, net_area] =
        Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(36), Constraint::Fill(1)]).areas(body);

    draw_header(f, app, &q, top, t);
    draw_geo(f, &q, geo_area, t);
    draw_abuse(f, &q, abuse_area, t);
    draw_network(f, app, &q, net_area, t);
}

fn pending(t: f32) -> Line<'static> {
    Line::from(Span::styled(format!(" {} looking up", spinner(t)), Style::default().fg(DIM)))
}

fn draw_header(f: &mut Frame, app: &App, q: &IpLookup, area: Rect, t: f32) {
    let mut first = vec![Span::raw(" ")];
    let mut second = vec![Span::raw(" ")];
    match &q.ip {
        Fetch::Done(ip) => {
            first.push(Span::styled(ip.to_string(), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)));
            if q.is_self {
                first.push(Span::styled("  (your public address)", Style::default().fg(DIM)));
            } else if q.input != ip.to_string() {
                first.push(Span::styled(format!("  ({})", q.input), Style::default().fg(DIM)));
            }
            let ptr = app.enricher.get(ip).and_then(|i| i.ptr);
            second.push(Span::styled(ptr.unwrap_or_else(|| "no reverse dns".into()), Style::default().fg(DIM)));
        }
        Fetch::Failed(e) => first.push(Span::styled(e.clone(), Style::default().fg(BAD))),
        _ => first.push(Span::styled(
            if q.is_self { "finding your public ip".to_string() } else { q.input.clone() },
            Style::default().fg(TEXT),
        )),
    }
    let busy = [matches!(q.geo, Fetch::Pending), matches!(q.abuse, Fetch::Pending), matches!(q.ip, Fetch::Pending)];
    if busy.iter().any(|b| *b) {
        second.push(Span::styled(format!("   {}", spinner(t)), Style::default().fg(DIM)));
    }
    f.render_widget(Paragraph::new(vec![Line::from(first), Line::from(second)]).block(panel("ip intel")), area);
}

fn draw_geo(f: &mut Frame, q: &IpLookup, area: Rect, t: f32) {
    let lines = match &q.geo {
        Fetch::Pending => vec![pending(t)],
        Fetch::Skipped(why) => vec![Line::from(Span::styled(format!(" {why}"), Style::default().fg(DIM)))],
        Fetch::Failed(e) => vec![Line::from(Span::styled(format!(" {e}"), Style::default().fg(BAD)))],
        Fetch::Done(g) => {
            let or_dash = |s: &str| if s.is_empty() { "-".to_string() } else { s.to_string() };
            vec![
                Line::raw(""),
                kv("city", or_dash(&g.city), TEXT, 10),
                kv("region", or_dash(&g.region), TEXT, 10),
                kv("country", format!("{} ({})", or_dash(&g.country), g.country_code), TEXT, 10),
                kv("continent", or_dash(&g.continent), TEXT, 10),
                Line::raw(""),
                Line::from(Span::styled(" via db-ip.com", Style::default().fg(FAINT))),
            ]
        }
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("location")), area);
}

fn verdict(score: u8) -> (&'static str, Color) {
    match score {
        0 => ("clean", GOOD),
        1..=24 => ("low risk", GOOD),
        25..=74 => ("suspicious", WARN),
        _ => ("malicious", BAD),
    }
}

fn draw_abuse(f: &mut Frame, q: &IpLookup, area: Rect, t: f32) {
    let lines = match &q.abuse {
        Fetch::Pending => vec![pending(t)],
        Fetch::Failed(e) => vec![Line::from(Span::styled(format!(" {e}"), Style::default().fg(BAD)))],
        Fetch::Skipped(why) if why == "no api key" => vec![
            Line::raw(""),
            Line::from(Span::styled(" AbuseIPDB lookups need a free API key.", Style::default().fg(TEXT))),
            Line::raw(""),
            Line::from(Span::styled(" 1. get one at abuseipdb.com/account/api", Style::default().fg(DIM))),
            Line::from(Span::styled(" 2. add it to ~/.config/wooma/config.toml:", Style::default().fg(DIM))),
            Line::from(Span::styled("    abuseipdb_key = \"...\"", Style::default().fg(TEXT))),
            Line::from(Span::styled("    or set ABUSEIPDB_KEY", Style::default().fg(DIM))),
        ],
        Fetch::Skipped(why) => vec![Line::from(Span::styled(format!(" {why}"), Style::default().fg(DIM)))],
        Fetch::Done(a) => abuse_lines(a, area),
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("abuse reputation")), area);
}

fn abuse_lines(a: &Abuse, area: Rect) -> Vec<Line<'static>> {
    let (word, color) = verdict(a.score);
    let mut lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled(format!(" {}%", a.score), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled("  confidence of abuse, ", Style::default().fg(DIM)),
            Span::styled(word, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]),
    ];
    let w = area.width.saturating_sub(4) as usize;
    let mut m = meter(a.score as f64 / 100.0, w, color);
    m.spans.insert(0, Span::raw(" "));
    lines.push(m);
    lines.push(Line::raw(""));
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
    lines.push(kv("reports", format!("{} from {} users (90d)", a.reports, a.reporters), TEXT, 10));
    lines.push(kv("last seen", opt(&a.last_reported).chars().take(10).collect::<String>(), TEXT, 10));
    lines.push(kv("isp", opt(&a.isp), TEXT, 10));
    lines.push(kv("usage", opt(&a.usage), TEXT, 10));
    lines.push(kv("domain", opt(&a.domain), TEXT, 10));
    let mut flags = vec![];
    if a.is_tor {
        flags.push("tor exit");
    }
    if a.whitelisted == Some(true) {
        flags.push("whitelisted");
    }
    if !flags.is_empty() {
        lines.push(kv("flags", flags.join(", "), WARN, 10));
    }
    lines
}

fn draw_network(f: &mut Frame, app: &App, q: &IpLookup, area: Rect, t: f32) {
    let Fetch::Done(ip) = q.ip else {
        let l = if matches!(q.ip, Fetch::Pending) { vec![pending(t)] } else { vec![] };
        f.render_widget(Paragraph::new(l).block(panel("network")), area);
        return;
    };
    let info = app.enricher.get(&ip).unwrap_or_default();
    let val = |v: Option<String>| match v {
        Some(v) => (v, TEXT),
        None if !info.done => (spinner(t).to_string(), FAINT),
        None => ("-".into(), FAINT),
    };
    let rows = [
        ("asn", val(info.asn.map(|a| format!("AS{a}")))),
        ("owner", val(info.as_name.clone())),
        ("prefix", val(info.prefix.clone())),
        ("country", val(info.country.clone())),
        ("ptr", val(info.ptr.clone())),
        ("version", (if ip.is_ipv4() { "IPv4" } else { "IPv6" }.to_string(), TEXT)),
        ("scope", (if info.private { "private" } else { "public" }.to_string(), if info.private { WARN } else { TEXT })),
    ];
    let mut lines = vec![Line::raw("")];
    let w = area.width.saturating_sub(2);
    lines.extend(rows.into_iter().flat_map(|(k, (v, c))| kv_wrap(k, &v, c, 9, w)));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(" via team cymru", Style::default().fg(FAINT))));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("network")), area);
}
