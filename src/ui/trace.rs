use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use super::panel;
use super::theme::*;
use crate::app::App;
use crate::net::dns::HostInfo;
use crate::net::icmp::SockKind;
use crate::net::trace::{Hop, TraceState};

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(session) = &app.trace else {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled("no trace running", Style::default().fg(DIM))),
            Line::from(vec![
                Span::styled("press ", Style::default().fg(FAINT)),
                Span::styled("a", Style::default().fg(ACCENT2)),
                Span::styled(" and enter a host (try: github.com)", Style::default().fg(FAINT)),
            ]),
        ])
        .alignment(Alignment::Center)
        .block(panel("traceroute"));
        f.render_widget(msg, area);
        return;
    };

    let st = session.state.lock().unwrap();
    let [info_area, table_area, ribbon_area] =
        Layout::vertical([Constraint::Length(4), Constraint::Fill(1), Constraint::Length(6)]).areas(area);

    draw_info(f, app, &session.host, &st, info_area, t);
    draw_table(f, app, &st, table_area, t);
    draw_ribbon(f, &st, ribbon_area, t);
}

fn draw_info(f: &mut Frame, app: &App, host: &str, st: &TraceState, area: Rect, t: f32) {
    let mut spans = vec![
        Span::styled(" → ", Style::default().fg(ACCENT)),
        Span::styled(host.to_string(), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
    ];
    if let Some(ip) = st.ip {
        spans.push(Span::styled(format!("  {ip}"), Style::default().fg(DIM)));
        if let Some(info) = app.enricher.get(&ip) {
            if let Some(asn) = info.asn {
                spans.push(Span::styled(format!("  AS{asn}"), Style::default().fg(ACCENT2)));
            }
            if let Some(name) = info.as_name {
                spans.push(Span::styled(format!(" {name}"), Style::default().fg(DIM)));
            }
        }
    }
    let sep = || Span::styled("  ·  ", Style::default().fg(FAINT));
    let mut meta = vec![Span::raw(" ")];
    if let Some(e) = &st.error {
        meta.push(Span::styled(e.clone(), Style::default().fg(BAD)));
    } else {
        let status = match st.dest_ttl {
            Some(d) => Span::styled(format!("reached in {d} hops"), Style::default().fg(GOOD)),
            None if st.rounds > 3 => Span::styled("destination not answering yet", Style::default().fg(WARN)),
            None => Span::styled(format!("{} discovering", spinner(t)), Style::default().fg(ACCENT)),
        };
        meta.push(status);
        meta.push(sep());
        meta.push(Span::styled(format!("round {}", st.rounds), Style::default().fg(DIM)));
        meta.push(sep());
        meta.push(Span::styled(fmt_dur(st.started.elapsed().as_secs()), Style::default().fg(DIM)));
        meta.push(sep());
        meta.push(Span::styled(
            match st.sock_kind {
                Some(SockKind::Raw) => "raw icmp",
                Some(SockKind::Dgram) => "dgram icmp",
                None => "…",
            },
            Style::default().fg(DIM),
        ));
        if app.trace.as_ref().is_some_and(|s| s.paused.load(std::sync::atomic::Ordering::Relaxed)) {
            meta.push(sep());
            meta.push(Span::styled("paused", Style::default().fg(WARN)));
        }
    }
    f.render_widget(Paragraph::new(vec![Line::from(spans), Line::from(meta)]).block(panel("traceroute")), area);
}

fn hop_label(app: &App, hop: &Hop) -> (String, Option<HostInfo>) {
    let Some(ip) = hop.addrs.first() else { return ("???".into(), None) };
    let info = app.enricher.get(ip);
    let name = match (&info, app.show_ips) {
        (Some(HostInfo { ptr: Some(p), .. }), false) => p.clone(),
        _ => ip.to_string(),
    };
    let extra = if hop.addrs.len() > 1 { format!(" +{}", hop.addrs.len() - 1) } else { String::new() };
    (format!("{name}{extra}"), info)
}

fn draw_table(f: &mut Frame, app: &App, st: &TraceState, area: Rect, t: f32) {
    let hops = st.visible_hops();
    // Numeric columns + spacing are fixed; host, network and history share the rest.
    let flexible = area.width.saturating_sub(2 + 42 + 10);
    let spark_w = (flexible / 4).min(30) as usize;

    let header = Row::new(["  #", "host", "network", "loss", "snt", "last", "avg", "best", "wrst", "stdev", "history"])
        .style(Style::default().fg(DIM));
    let pulse = st.last_reply;
    let rows: Vec<Row> = hops
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let ttl = i + 1;
            let s = &hop.stats;
            let (label, info) = hop_label(app, hop);
            let is_dest = st.dest_ttl == Some(ttl as u8);

            // Flash the hop number when a reply just arrived from it.
            let flash = pulse
                .filter(|(pt, _)| *pt as usize == ttl)
                .map(|(_, at)| 1.0 - (at.elapsed().as_secs_f32() / 0.5).min(1.0))
                .unwrap_or(0.0);
            let num_color = if flash > 0.0 { scale(ACCENT, 0.6 + flash) } else { DIM };

            let host_style = if hop.addrs.is_empty() {
                Style::default().fg(FAINT)
            } else if is_dest {
                Style::default().fg(GOOD).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT)
            };
            let network = match &info {
                Some(i) if i.private => Span::styled("private", Style::default().fg(FAINT)),
                Some(HostInfo { asn: Some(asn), as_name, country, .. }) => {
                    let name = as_name.clone().unwrap_or_default();
                    let cc = country.clone().map(|c| format!("{c} ")).unwrap_or_default();
                    Span::styled(format!("{cc}AS{asn} {name}"), Style::default().fg(ACCENT2))
                }
                Some(HostInfo { done: false, .. }) => Span::styled(spinner(t).to_string(), Style::default().fg(FAINT)),
                _ => Span::raw(""),
            };
            let loss = s.loss_pct();
            let num = |v: Option<f64>| {
                let c = v.map(rtt_color).unwrap_or(FAINT);
                Cell::from(Line::from(Span::styled(fmt_ms(v), Style::default().fg(c))).right_aligned())
            };
            Row::new(vec![
                Cell::from(Line::from(Span::styled(format!("{ttl:>3}"), Style::default().fg(num_color)))),
                Cell::from(Span::styled(label, host_style)),
                Cell::from(network),
                Cell::from(
                    Line::from(Span::styled(
                        if s.sent == 0 { "—".into() } else { format!("{loss:.0}%") },
                        Style::default().fg(if s.sent == 0 { FAINT } else { loss_color(loss) }),
                    ))
                    .right_aligned(),
                ),
                Cell::from(Line::from(Span::styled(s.sent.to_string(), Style::default().fg(DIM))).right_aligned()),
                num(s.last),
                num(s.avg()),
                num(s.best()),
                num(s.worst()),
                Cell::from(Line::from(fmt_ms(s.stddev())).right_aligned().style(Style::default().fg(DIM))),
                Cell::from(sparkline(&s.history, spark_w)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(3),
        Constraint::Fill(3),
        Constraint::Fill(2),
        Constraint::Length(5),
        Constraint::Length(4),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(spark_w as u16),
    ];
    f.render_widget(Table::new(rows, widths).header(header).column_spacing(1).block(panel("hops")), area);
}

/// A horizontal map of the path with a packet bouncing out to the destination and back.
fn draw_ribbon(f: &mut Frame, st: &TraceState, area: Rect, t: f32) {
    let block = panel("path");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let hops = st.visible_hops();
    if hops.is_empty() || inner.width < 10 || inner.height < 3 {
        return;
    }
    let n = hops.len();
    let (x0, x1) = (inner.x + 3, inner.x + inner.width - 4);
    let span = (x1 - x0) as f32;
    let node_x = |i: usize| x0 + if n == 1 { 0 } else { (span * i as f32 / (n - 1) as f32).round() as u16 };
    let y = inner.y + 1;
    let buf = f.buffer_mut();

    buf.set_string(inner.x, y, "⌂", Style::default().fg(ACCENT));
    buf.set_string(inner.x + 1, y, "─".repeat((x0 - inner.x - 1) as usize), Style::default().fg(FAINT));
    buf.set_string(x0, y, "─".repeat((x1 - x0) as usize), Style::default().fg(FAINT));

    // The packet travels out and back along the path, with a fading trail.
    let cycle = 3.2;
    let phase = (t % cycle) / cycle;
    let pos = if phase < 0.5 { phase * 2.0 } else { 2.0 - phase * 2.0 };
    let head = inner.x as f32 + pos * (x1 - inner.x) as f32;
    let dir = if phase < 0.5 { -1.0 } else { 1.0 };
    for k in 0..6 {
        let x = head + dir * k as f32;
        if x >= inner.x as f32 && x < x1 as f32 {
            let c = scale(gradient(t * 0.3), 1.0 - k as f32 * 0.16);
            let ch = if k == 0 { "●" } else { "━" };
            buf.set_string(x.round() as u16, y, ch, Style::default().fg(c));
        }
    }

    let label_every = ((n as f32 * 4.0) / span).ceil().max(1.0) as usize;
    for (i, hop) in hops.iter().enumerate() {
        let x = node_x(i);
        let color = if hop.addrs.is_empty() {
            FAINT
        } else if hop.stats.sent == 0 {
            DIM
        } else {
            loss_color(hop.stats.loss_pct())
        };
        let near = (head - x as f32).abs() < 1.5;
        let ch = if hop.addrs.is_empty() { "○" } else { "◉" };
        let style = Style::default().fg(if near { scale(color, 1.5) } else { color });
        buf.set_string(x, y, ch, style);

        if i % label_every == 0 || i == n - 1 {
            buf.set_string(x, y + 1, format!("{}", i + 1), Style::default().fg(DIM));
            if let Some(avg) = hop.stats.avg() {
                let txt = format!("{avg:.0}");
                buf.set_string(x, y + 2, &txt, Style::default().fg(rtt_color(avg)));
            }
        }
    }

    let label_x = x1 + 1;
    let flag = if st.dest_ttl.is_some() { "⚑" } else { "?" };
    buf.set_string(label_x, y, flag, Style::default().fg(if st.dest_ttl.is_some() { GOOD } else { WARN }));
}
