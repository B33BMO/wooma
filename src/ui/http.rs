use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::theme::*;
use super::{empty_hint, kv, panel};
use crate::app::{App, Tab};
use crate::net::http::{Response, TlsInfo};
use crate::net::httpcheck::HttpCheck;

const SECURITY_HEADERS: [(&str, &str); 6] = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
];

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(q) = &app.http else {
        return empty_hint(f, area, "http", "No request", "press a and enter a url, e.g. example.com");
    };
    let q = q.lock().unwrap();
    let chain_h = (q.hops.len() as u16).clamp(1, 6) + 2;
    let [top, waterfall, bottom] =
        Layout::vertical([Constraint::Length(chain_h), Constraint::Length(8), Constraint::Fill(1)]).areas(area);
    let [tls_area, right] = Layout::horizontal([Constraint::Percentage(45), Constraint::Fill(1)]).areas(bottom);
    let [sec_area, hdr_area] = Layout::vertical([Constraint::Length(8), Constraint::Fill(1)]).areas(right);

    draw_chain(f, &q, top, t);
    let Some((_, resp)) = q.last_ok() else {
        for a in [waterfall, tls_area, sec_area, hdr_area] {
            f.render_widget(Paragraph::new("").block(panel("")), a);
        }
        return;
    };
    draw_waterfall(f, resp, waterfall);
    draw_tls(f, resp, tls_area);
    draw_security(f, resp, sec_area);
    draw_headers(f, app, resp, hdr_area);
}

fn status_color(code: u16) -> Color {
    match code {
        200..=299 => GOOD,
        300..=399 => ACCENT,
        400..=499 => WARN,
        _ => BAD,
    }
}

fn draw_chain(f: &mut Frame, q: &HttpCheck, area: Rect, t: f32) {
    let mut lines = vec![];
    for (i, (url, res)) in q.hops.iter().enumerate() {
        let arrow = if i == 0 { " " } else { " → " };
        let mut spans = vec![Span::styled(arrow, Style::default().fg(FAINT))];
        match res {
            Ok(r) => {
                spans.push(Span::styled(
                    format!("{} {}", r.status, r.reason),
                    Style::default().fg(status_color(r.status)).add_modifier(Modifier::BOLD),
                ));
                spans.push(Span::styled(format!("  {url}"), Style::default().fg(TEXT)));
                spans.push(Span::styled(format!("  {:.0} ms", r.timings.total()), Style::default().fg(DIM)));
                if let Some(ip) = r.ip {
                    spans.push(Span::styled(format!("  {ip}"), Style::default().fg(FAINT)));
                }
            }
            Err(e) => {
                spans.push(Span::styled(format!("{url}  "), Style::default().fg(TEXT)));
                spans.push(Span::styled(e.clone(), Style::default().fg(BAD)));
            }
        }
        lines.push(Line::from(spans));
    }
    if q.finished.is_none() {
        lines.push(Line::from(Span::styled(format!(" {} requesting {}", spinner(t), q.input), Style::default().fg(DIM))));
    }
    let skip = lines.len().saturating_sub(area.height.saturating_sub(2) as usize);
    let title = if q.hops.len() > 1 { format!("request ({} redirects)", q.hops.len() - 1) } else { "request".into() };
    f.render_widget(Paragraph::new(lines.split_off(skip)).block(panel(&title)), area);
}

fn draw_waterfall(f: &mut Frame, r: &Response, area: Rect) {
    let tm = &r.timings;
    let phases: Vec<(&str, f64, Color)> = [
        ("dns", Some(tm.dns), ACCENT),
        ("tcp", Some(tm.connect), ACCENT2),
        ("tls", tm.tls, Color::Magenta),
        ("wait", Some(tm.ttfb), WARN),
        ("download", Some(tm.download), GOOD),
    ]
    .into_iter()
    .filter_map(|(n, v, c)| v.map(|v| (n, v, c)))
    .collect();
    let total = tm.total().max(0.001);
    let label_w = 20usize;
    let bar_w = (area.width as usize).saturating_sub(label_w + 4).max(10);

    let mut lines = vec![];
    let mut offset = 0.0;
    for (name, ms, color) in &phases {
        let start = ((offset / total) * bar_w as f64).round() as usize;
        let len = ((ms / total) * bar_w as f64).round().max(1.0) as usize;
        lines.push(Line::from(vec![
            Span::styled(format!(" {name:<9}"), Style::default().fg(DIM)),
            Span::styled(format!("{:>8} ", format!("{ms:.1}ms")), Style::default().fg(TEXT)),
            Span::raw(" ".repeat(start)),
            Span::styled("█".repeat(len), Style::default().fg(*color)),
        ]));
        offset += ms;
    }
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<9}", "total"), Style::default().fg(DIM)),
        Span::styled(format!("{:>8} ", format!("{total:.1}ms")), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" {} transferred", human_bytes(r.body_bytes)),
            Style::default().fg(FAINT),
        ),
    ]));
    f.render_widget(Paragraph::new(lines).block(panel("timing")), area);
}

pub fn human_bytes(b: u64) -> String {
    match b {
        b if b < 1024 => format!("{b} B"),
        b if b < 1 << 20 => format!("{:.1} KB", b as f64 / 1024.0),
        b if b < 1 << 30 => format!("{:.1} MB", b as f64 / (1 << 20) as f64),
        b => format!("{:.2} GB", b as f64 / (1u64 << 30) as f64),
    }
}

fn draw_tls(f: &mut Frame, r: &Response, area: Rect) {
    let Some(tls) = &r.tls else {
        let lines = vec![Line::raw(""), Line::from(Span::styled(" plain http, no encryption", Style::default().fg(WARN)))];
        f.render_widget(Paragraph::new(lines).block(panel("tls")), area);
        return;
    };
    f.render_widget(Paragraph::new(tls_lines(tls)).wrap(Wrap { trim: false }).block(panel("tls")), area);
}

fn tls_lines(tls: &TlsInfo) -> Vec<Line<'static>> {
    let mut lines = vec![];
    match &tls.verify_error {
        None => lines.push(Line::from(Span::styled(" ✓ certificate chain trusted", Style::default().fg(GOOD)))),
        Some(e) => lines.push(Line::from(Span::styled(format!(" ✗ {e}"), Style::default().fg(BAD).add_modifier(Modifier::BOLD)))),
    }
    lines.push(kv("version", tls.version.clone(), if tls.version.contains("1.3") { GOOD } else { TEXT }, 9));
    lines.push(kv("cipher", tls.cipher.clone(), TEXT, 9));
    lines.push(kv("alpn", tls.alpn.clone().unwrap_or_else(|| "-".into()), TEXT, 9));
    if let Some(leaf) = tls.chain.first() {
        lines.push(Line::raw(""));
        lines.push(kv("subject", leaf.subject.clone(), TEXT, 9));
        lines.push(kv("issuer", leaf.issuer.clone(), TEXT, 9));
        let color = match leaf.days_left {
            d if d < 0 => BAD,
            d if d < 14 => BAD,
            d if d < 30 => WARN,
            _ => GOOD,
        };
        let expiry = if leaf.days_left < 0 {
            format!("EXPIRED {} days ago", -leaf.days_left)
        } else {
            format!("{} days left", leaf.days_left)
        };
        lines.push(kv("expires", expiry, color, 9));
        lines.push(kv("valid", format!("{} →", leaf.not_before), DIM, 9));
        lines.push(kv("", leaf.not_after.clone(), DIM, 9));
        lines.push(kv("key", leaf.key.clone(), TEXT, 9));
        let more = leaf.sans.len().saturating_sub(4);
        let mut sans = leaf.sans.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
        if more > 0 {
            sans.push_str(&format!(" +{more}"));
        }
        lines.push(kv("names", sans, TEXT, 9));
    }
    if tls.chain.len() > 1 {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(" chain", Style::default().fg(DIM))));
        for (i, c) in tls.chain.iter().enumerate() {
            lines.push(Line::from(vec![
                Span::styled(format!(" {}└ ", "  ".repeat(i)), Style::default().fg(FAINT)),
                Span::styled(c.subject.clone(), Style::default().fg(if i == 0 { TEXT } else { DIM })),
            ]));
        }
    }
    lines
}

fn draw_security(f: &mut Frame, r: &Response, area: Rect) {
    let present = SECURITY_HEADERS.iter().filter(|(h, _)| r.header(h).is_some()).count();
    let lines: Vec<Line> = SECURITY_HEADERS
        .iter()
        .map(|(h, label)| match r.header(h) {
            Some(v) => Line::from(vec![
                Span::styled(" ✓ ", Style::default().fg(GOOD)),
                Span::styled(format!("{label:<23}"), Style::default().fg(TEXT)),
                Span::styled(v.to_string(), Style::default().fg(FAINT)),
            ]),
            None => Line::from(vec![
                Span::styled(" ✗ ", Style::default().fg(BAD)),
                Span::styled(label.to_string(), Style::default().fg(DIM)),
            ]),
        })
        .collect();
    let title = format!("security headers {present}/{}", SECURITY_HEADERS.len());
    f.render_widget(Paragraph::new(lines).block(panel(&title)), area);
}

fn draw_headers(f: &mut Frame, app: &App, r: &Response, area: Rect) {
    let lines: Vec<Line> = r
        .headers
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!(" {k}: "), Style::default().fg(ACCENT)),
                Span::styled(v.clone(), Style::default().fg(TEXT)),
            ])
        })
        .collect();
    let max = (lines.len() as u16).saturating_sub(area.height.saturating_sub(2));
    let scroll = app.scroll[Tab::Http.index()].min(max);
    let title = format!("headers ({})", r.headers.len());
    f.render_widget(Paragraph::new(lines).scroll((scroll, 0)).block(panel(&title)), area);
}
