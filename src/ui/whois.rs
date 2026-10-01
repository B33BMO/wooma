use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::theme::*;
use super::{empty_hint, kv_wrap, panel};
use crate::app::{App, Tab};
use crate::net::whois::{days_from_civil, parse_date, today, WhoisLookup};

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(q) = &app.whois else {
        return empty_hint(f, area, "whois", "No lookup", "press a and enter a domain or ip");
    };
    let q = q.lock().unwrap();
    let [top, body] = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(area);
    let [summary, raw] = Layout::horizontal([Constraint::Percentage(42), Constraint::Fill(1)]).areas(body);
    draw_chain(f, &q, top, t);
    draw_summary(f, &q, summary, t);
    draw_raw(f, app, &q, raw);
}

fn draw_chain(f: &mut Frame, q: &WhoisLookup, area: Rect, t: f32) {
    let first = Line::from(vec![
        Span::styled(format!(" {}", q.input), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
        Span::styled(if q.is_ip { "  address" } else { "  domain" }, Style::default().fg(DIM)),
    ]);
    let mut chain = vec![Span::raw(" ")];
    for (i, hop) in q.hops.iter().enumerate() {
        if i > 0 {
            chain.push(Span::styled(" → ", Style::default().fg(FAINT)));
        }
        let color = if hop.text.is_ok() { TEXT } else { BAD };
        chain.push(Span::styled(hop.server.clone(), Style::default().fg(color)));
        chain.push(Span::styled(format!(" {:.0}ms", hop.ms), Style::default().fg(FAINT)));
    }
    if q.finished.is_none() {
        chain.push(Span::styled(format!(" → {}", spinner(t)), Style::default().fg(DIM)));
    }
    f.render_widget(Paragraph::new(vec![first, Line::from(chain)]).block(panel("whois")), area);
}

fn ymd(days: i64) -> String {
    let (y, rem) = (days / 365, days % 365);
    match (y, rem * 12 / 365) {
        (0, m) => format!("{m}mo {}d", rem % 30),
        (y, m) => format!("{y}y {m}mo"),
    }
}

fn draw_summary(f: &mut Frame, q: &WhoisLookup, area: Rect, t: f32) {
    let mut lines = vec![Line::raw("")];
    let now = today();

    if let Some(exp) = q.expires {
        let left = days_from_civil(exp) - now;
        let (color, label) = match left {
            l if l < 0 => (BAD, format!("EXPIRED {} days ago", -l)),
            l if l < 30 => (BAD, format!("expires in {l} days")),
            l if l < 90 => (WARN, format!("expires in {l} days")),
            l => (GOOD, format!("expires in {} ({l} days)", ymd(l))),
        };
        lines.push(Line::from(Span::styled(format!(" {label}"), Style::default().fg(color).add_modifier(Modifier::BOLD))));
        // How far through a year's registration we are; a full bar means plenty of runway.
        let w = area.width.saturating_sub(4) as usize;
        let mut m = meter((left.max(0) as f64 / 365.0).min(1.0), w, color);
        m.spans.insert(0, Span::raw(" "));
        lines.push(m);
    }
    if let Some(created) = q.created {
        let age = now - days_from_civil(created);
        lines.push(Line::from(Span::styled(format!(" registered {} ago", ymd(age.max(0))), Style::default().fg(DIM))));
    }
    if q.expires.is_some() || q.created.is_some() {
        lines.push(Line::raw(""));
    }

    if q.summary.is_empty() {
        let msg = if q.finished.is_none() { format!("{} querying", spinner(t)) } else { "no structured fields found".into() };
        lines.push(Line::from(Span::styled(format!(" {msg}"), Style::default().fg(DIM))));
    }
    for (k, v) in &q.summary {
        let color = match *k {
            "status" if v.contains("hold") => BAD,
            "dnssec" if v.to_ascii_lowercase().starts_with("signed") => GOOD,
            _ => TEXT,
        };
        // Dates read better without the time-of-day noise.
        let v = if matches!(*k, "created" | "updated" | "expires") && parse_date(v).is_some() {
            v.chars().take(10).collect()
        } else {
            v.clone()
        };
        lines.extend(kv_wrap(k, &v, color, 12, area.width.saturating_sub(2)));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("summary")), area);
}

fn draw_raw(f: &mut Frame, app: &App, q: &WhoisLookup, area: Rect) {
    let mut lines: Vec<Line> = vec![];
    // Most specific server first: that's usually the interesting one.
    for hop in q.hops.iter().rev() {
        lines.push(Line::from(Span::styled(
            format!("── {} ", hop.server),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        )));
        match &hop.text {
            Err(e) => lines.push(Line::from(Span::styled(e.clone(), Style::default().fg(BAD)))),
            Ok(text) => {
                for l in text.lines() {
                    lines.push(highlight(l));
                }
            }
        }
        lines.push(Line::raw(""));
    }
    let inner_h = area.height.saturating_sub(2);
    let max = (lines.len() as u16).saturating_sub(inner_h);
    let scroll = app.scroll[Tab::Whois.index()].min(max);
    let title = if max > 0 { format!("raw  {}/{}", scroll, max) } else { "raw".into() };
    f.render_widget(Paragraph::new(lines).scroll((scroll, 0)).block(panel(&title)), area);
}

fn highlight(l: &str) -> Line<'static> {
    if l.starts_with(['%', '#', '>']) || l.trim().is_empty() {
        return Line::from(Span::styled(l.to_string(), Style::default().fg(FAINT)));
    }
    match l.split_once(':') {
        Some((k, v)) if k.len() < 48 && !k.contains("//") => Line::from(vec![
            Span::styled(format!("{k}:"), Style::default().fg(ACCENT)),
            Span::styled(v.to_string(), Style::default().fg(TEXT)),
        ]),
        _ => Line::from(Span::styled(l.to_string(), Style::default().fg(DIM))),
    }
}
