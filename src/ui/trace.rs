use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use super::{empty_hint, error_panel, first_line, panel};
use super::theme::*;
use crate::app::App;
use crate::net::dns::HostInfo;
use crate::net::icmp::SockKind;
use crate::net::trace::{Hop, TraceState};

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(session) = &app.trace else {
        return empty_hint(f, area, "traceroute", "No trace running", "press a and enter a host, e.g. example.com");
    };

    let st = session.state.lock().unwrap();
    let [info_area, table_area] = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(area);

    draw_info(f, app, &session.host, &st, info_area, t);
    match &st.error {
        Some(e) => error_panel(f, e, table_area),
        None => draw_table(f, app, &st, table_area, t),
    }
}

fn draw_info(f: &mut Frame, app: &App, host: &str, st: &TraceState, area: Rect, t: f32) {
    let mut spans = vec![Span::styled(format!(" {host}"), Style::default().fg(TEXT).add_modifier(Modifier::BOLD))];
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
    let sep = || Span::styled("  |  ", Style::default().fg(FAINT));
    let mut meta = vec![Span::raw(" ")];
    if let Some(e) = &st.error {
        meta.push(Span::styled(first_line(e), Style::default().fg(BAD)));
    } else {
        let status = match st.dest_ttl {
            Some(d) => Span::styled(format!("reached in {d} hops"), Style::default().fg(GOOD)),
            None if st.rounds > 3 => Span::styled("destination not answering yet", Style::default().fg(WARN)),
            None => Span::styled(format!("{} discovering", spinner(t)), Style::default().fg(DIM)),
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
                None => "-",
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
    let Some(ip) = hop.addrs.first() else { return ("*".into(), None) };
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
    let rows: Vec<Row> = hops
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let ttl = i + 1;
            let s = &hop.stats;
            let (label, info) = hop_label(app, hop);
            let is_dest = st.dest_ttl == Some(ttl as u8);

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
                    Span::styled(format!("{cc}AS{asn} {name}"), Style::default().fg(DIM))
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
                Cell::from(Line::from(Span::styled(format!("{ttl:>3}"), Style::default().fg(DIM)))),
                Cell::from(Span::styled(label, host_style)),
                Cell::from(network),
                Cell::from(
                    Line::from(Span::styled(
                        if s.sent == 0 { "-".into() } else { format!("{loss:.0}%") },
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
