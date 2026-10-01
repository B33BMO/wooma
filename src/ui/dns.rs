use std::net::IpAddr;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::panel;
use super::theme::*;
use crate::app::App;
use crate::net::dns::{DnsQuery, QState};

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(q) = &app.dns else {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled("ask the internet a question", Style::default().fg(DIM))),
            Line::from(vec![
                Span::styled("press ", Style::default().fg(FAINT)),
                Span::styled("a", Style::default().fg(ACCENT2)),
                Span::styled(" and type a domain or ip  ·  ", Style::default().fg(FAINT)),
                Span::styled("s", Style::default().fg(ACCENT2)),
                Span::styled(format!(" resolver: {}", app.resolver.label()), Style::default().fg(FAINT)),
            ]),
        ])
        .alignment(Alignment::Center)
        .block(panel("dns"));
        f.render_widget(msg, area);
        return;
    };
    let q = q.lock().unwrap();

    let [info_area, body] = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(area);
    let [records_area, side] = Layout::horizontal([Constraint::Percentage(62), Constraint::Fill(1)]).areas(body);
    let [race_area, net_area] = Layout::vertical([Constraint::Length(8), Constraint::Fill(1)]).areas(side);

    draw_info(f, &q, info_area, t);
    draw_records(f, app, &q, records_area, t);
    draw_race(f, &q, race_area, t);
    draw_network(f, app, &q, net_area, t);
}

fn draw_info(f: &mut Frame, q: &DnsQuery, area: Rect, t: f32) {
    let total = q.sections.len();
    let done = total - q.sections.iter().filter(|s| matches!(s.state, QState::Pending)).count();
    let status = match q.finished {
        Some(fin) => Span::styled(
            format!("✓ done in {:.0} ms", fin.duration_since(q.started).as_secs_f64() * 1000.0),
            Style::default().fg(GOOD),
        ),
        None => Span::styled(format!("{} {done}/{total} answered", spinner(t)), Style::default().fg(ACCENT)),
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" ? ", Style::default().fg(ACCENT)),
            Span::styled(q.input.clone(), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  via {}", q.resolver.label()), Style::default().fg(DIM)),
        ]),
        Line::from(vec![Span::raw(" "), status]),
    ];
    f.render_widget(Paragraph::new(lines).block(panel("lookup")), area);
}

fn draw_records(f: &mut Frame, app: &App, q: &DnsQuery, area: Rect, t: f32) {
    let mut lines: Vec<Line> = Vec::new();
    for (i, sec) in q.sections.iter().enumerate() {
        let name = format!(" {:<6}", sec.rtype.to_string());
        let (head_color, timing) = match &sec.state {
            QState::Pending => (ACCENT, format!("{}", spinner(t + i as f32 * 0.1))),
            QState::Found { ms, .. } => (ACCENT2, format!("{ms:.0} ms")),
            QState::Empty { ms, .. } => (DIM, format!("{ms:.0} ms")),
            QState::Failed { ms, .. } => (BAD, format!("{ms:.0} ms")),
        };
        lines.push(Line::from(vec![
            Span::styled(name, Style::default().fg(head_color).add_modifier(Modifier::BOLD)),
            Span::styled(timing, Style::default().fg(FAINT)),
        ]));
        match &sec.state {
            QState::Pending => {}
            QState::Found { records, .. } => {
                // Long values (SPF, DKIM...) wrap with a hanging indent under the value column.
                let indent = 12;
                let width = (area.width as usize).saturating_sub(2 + indent).max(10);
                for r in records {
                    let chars: Vec<char> = r.value.chars().collect();
                    for (j, chunk) in chars.chunks(width).enumerate() {
                        let gutter = if j == 0 { format!("   {:>6}s  ", r.ttl) } else { " ".repeat(indent) };
                        lines.push(Line::from(vec![
                            Span::styled(gutter, Style::default().fg(FAINT)),
                            Span::styled(chunk.iter().collect::<String>(), Style::default().fg(TEXT)),
                        ]));
                    }
                }
            }
            QState::Empty { nxdomain: true, .. } => {
                lines.push(Line::from(Span::styled("   NXDOMAIN — name does not exist", Style::default().fg(BAD))));
            }
            QState::Empty { .. } => {
                lines.push(Line::from(Span::styled("   (no records)", Style::default().fg(FAINT))));
            }
            QState::Failed { msg, .. } => {
                lines.push(Line::from(Span::styled(format!("   {msg}"), Style::default().fg(BAD))));
            }
        }
        lines.push(Line::raw(""));
    }
    let max_scroll = (lines.len() as u16).saturating_sub(area.height.saturating_sub(2));
    let scroll = app.scroll[crate::app::Tab::Dns.index()].min(max_scroll);
    f.render_widget(
        Paragraph::new(lines).scroll((scroll, 0)).block(panel("records")),
        area,
    );
}

fn draw_race(f: &mut Frame, q: &DnsQuery, area: Rect, t: f32) {
    let inner_w = area.width.saturating_sub(2) as usize;
    let bar_w = inner_w.saturating_sub(30).max(4);
    let times: Vec<f64> = q.race.iter().filter_map(|r| r.result.as_ref()?.as_ref().ok().copied()).collect();
    let max = times.iter().copied().fold(1.0f64, f64::max);
    let best = times.iter().copied().fold(f64::INFINITY, f64::min);
    // Bars grow into place once a result lands, rather than snapping.
    let grow = ease_out(q.started.elapsed().as_secs_f32() / 0.6);

    let mut lines = vec![];
    for r in &q.race {
        let mut spans = vec![Span::styled(format!(" {:<19}", r.resolver.label()), Style::default().fg(DIM))];
        match &r.result {
            None => spans.push(Span::styled(spinner(t).to_string(), Style::default().fg(ACCENT))),
            Some(Err(_)) => spans.push(Span::styled("failed", Style::default().fg(BAD))),
            Some(Ok(ms)) => {
                let w = ((ms / max) * bar_w as f64 * grow as f64).round().max(1.0) as usize;
                spans.push(Span::styled("█".repeat(w), Style::default().fg(rtt_color(*ms))));
                spans.push(Span::styled(format!(" {ms:.0}ms"), Style::default().fg(TEXT)));
                if *ms == best && times.len() > 1 {
                    spans.push(Span::styled(" ★", Style::default().fg(WARN)));
                }
            }
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines).block(panel("resolver race")), area);
}

fn draw_network(f: &mut Frame, app: &App, q: &DnsQuery, area: Rect, t: f32) {
    // For a name, describe the first address it resolved to; for an ip, the ip itself.
    let ip: Option<IpAddr> = q.reverse_ip.or_else(|| {
        q.sections.iter().find_map(|s| match &s.state {
            QState::Found { records, .. } => records.iter().find_map(|r| r.value.parse().ok()),
            _ => None,
        })
    });
    let Some(ip) = ip else {
        f.render_widget(Paragraph::new("").block(panel("network")), area);
        return;
    };
    app.enricher.lookup(ip);
    let info = app.enricher.get(&ip).unwrap_or_default();
    let kv = |k: &str, v: Option<String>| {
        Line::from(vec![
            Span::styled(format!(" {k:<8}"), Style::default().fg(DIM)),
            match v {
                Some(v) => Span::styled(v, Style::default().fg(TEXT)),
                None if !info.done => Span::styled(spinner(t).to_string(), Style::default().fg(FAINT)),
                None => Span::styled("—", Style::default().fg(FAINT)),
            },
        ])
    };
    let lines = vec![
        kv("address", Some(ip.to_string())),
        kv("ptr", info.ptr.clone()),
        kv("asn", info.asn.map(|a| format!("AS{a}"))),
        kv("owner", info.as_name.clone()),
        kv("prefix", info.prefix.clone()),
        kv("country", info.country.clone()),
        kv("scope", Some(if info.private { "private".into() } else { "public".into() })),
    ];
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("network")), area);
}
