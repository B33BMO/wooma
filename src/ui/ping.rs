use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table};
use ratatui::Frame;

use super::panel;
use super::theme::*;
use crate::app::App;
use crate::net::icmp::SockKind;
use crate::net::ping::{PingState, Status};

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    if app.pings.is_empty() {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled("no targets yet", Style::default().fg(DIM))),
            Line::from(vec![
                Span::styled("press ", Style::default().fg(FAINT)),
                Span::styled("a", Style::default().fg(ACCENT2)),
                Span::styled(" to add one (try: 1.1.1.1 google.com)", Style::default().fg(FAINT)),
            ]),
        ])
        .alignment(Alignment::Center)
        .block(panel("ping"));
        f.render_widget(msg, area);
        return;
    }

    let list_h = (app.pings.len() as u16 + 3).min(area.height / 2).max(5);
    let [list_area, detail_area] = Layout::vertical([Constraint::Length(list_h), Constraint::Fill(1)]).areas(area);
    draw_list(f, app, list_area, t);

    if let Some(target) = app.pings.get(app.ping_sel) {
        let st = target.state.lock().unwrap();
        draw_detail(f, &target.host, &st, detail_area, t);
    }
}

fn status_cell(st: &PingState, t: f32) -> Span<'static> {
    match &st.status {
        Status::Resolving => Span::styled(spinner(t).to_string(), Style::default().fg(ACCENT)),
        Status::Up => {
            // Bright on each reply, then fades: a little heartbeat.
            let age = st.last_reply_at.map(|a| a.elapsed().as_secs_f32()).unwrap_or(9.0);
            let k = 0.45 + 0.55 * (1.0 - (age / 0.9).min(1.0));
            Span::styled("●", Style::default().fg(scale(GOOD, k)))
        }
        Status::Down => {
            let on = ((t * 2.0) as u32).is_multiple_of(2);
            Span::styled("●", Style::default().fg(if on { BAD } else { scale(BAD, 0.4) }))
        }
        Status::Error(_) => Span::styled("!", Style::default().fg(BAD).add_modifier(Modifier::BOLD)),
    }
}

fn draw_list(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let fixed: u16 = 1 + 22 + 16 + 7 + 7 + 6 + 7 + 7; // columns + spacing
    let spark_w = area.width.saturating_sub(fixed + 2).max(4) as usize;

    let header = Row::new(["", "target", "address", "last", "avg", "loss", "jitter", "history"])
        .style(Style::default().fg(DIM));
    let rows: Vec<Row> = app
        .pings
        .iter()
        .enumerate()
        .map(|(i, target)| {
            let st = target.state.lock().unwrap();
            let s = &st.stats;
            let paused = target.paused.load(std::sync::atomic::Ordering::Relaxed);
            let last = match s.last {
                Some(ms) => Span::styled(fmt_ms(Some(ms)), Style::default().fg(rtt_color(ms))),
                None if s.sent > 0 => Span::styled("lost", Style::default().fg(BAD)),
                None => Span::styled("—", Style::default().fg(FAINT)),
            };
            let history = match &st.status {
                Status::Error(e) => Line::from(Span::styled(e.clone(), Style::default().fg(BAD))),
                _ => sparkline(&s.history, spark_w),
            };
            let mut host_style = Style::default().fg(TEXT);
            if paused {
                host_style = host_style.fg(DIM).add_modifier(Modifier::ITALIC);
            }
            let row = Row::new(vec![
                Cell::from(status_cell(&st, t)),
                Cell::from(Span::styled(target.host.clone(), host_style)),
                Cell::from(Span::styled(
                    st.ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    Style::default().fg(DIM),
                )),
                Cell::from(Line::from(last).right_aligned()),
                Cell::from(Line::from(fmt_ms(s.avg())).right_aligned()),
                Cell::from(
                    Line::from(Span::styled(
                        format!("{:.1}%", s.loss_pct()),
                        Style::default().fg(loss_color(s.loss_pct())),
                    ))
                    .right_aligned(),
                ),
                Cell::from(Line::from(fmt_ms(s.jitter())).right_aligned()),
                Cell::from(history),
            ]);
            if i == app.ping_sel {
                row.style(Style::default().bg(SEL_BG))
            } else {
                row
            }
        })
        .collect();

    let widths = [
        Constraint::Length(1),
        Constraint::Length(22),
        Constraint::Length(16),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Fill(1),
    ];
    let table = Table::new(rows, widths).header(header).column_spacing(1).block(panel("targets"));
    f.render_widget(table, area);
}

fn draw_detail(f: &mut Frame, host: &str, st: &PingState, area: Rect, t: f32) {
    let [stats_area, right] = Layout::horizontal([Constraint::Length(30), Constraint::Fill(1)]).areas(area);
    let s = &st.stats;

    let (status_txt, status_color) = match &st.status {
        Status::Resolving => ("RESOLVING".to_string(), ACCENT),
        Status::Up => ("UP".to_string(), GOOD),
        Status::Down => ("DOWN".to_string(), BAD),
        Status::Error(_) => ("ERROR".to_string(), BAD),
    };
    let since = fmt_dur(st.status_since.elapsed().as_secs());
    let kv = |k: &str, v: String, c| {
        Line::from(vec![
            Span::styled(format!(" {k:<9}"), Style::default().fg(DIM)),
            Span::styled(v, Style::default().fg(c)),
        ])
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {status_txt}"), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" for {since}"), Style::default().fg(DIM)),
        ]),
        Line::raw(""),
        kv("address", st.ip.map(|i| i.to_string()).unwrap_or("…".into()), TEXT),
        kv("sent", s.sent.to_string(), TEXT),
        kv("received", s.recv.to_string(), TEXT),
        kv("loss", format!("{:.2}%", s.loss_pct()), loss_color(s.loss_pct())),
        Line::raw(""),
        kv("min", format!("{} ms", fmt_ms(s.best())), GOOD),
        kv("avg", format!("{} ms", fmt_ms(s.avg())), s.avg().map(rtt_color).unwrap_or(TEXT)),
        kv("max", format!("{} ms", fmt_ms(s.worst())), s.worst().map(rtt_color).unwrap_or(TEXT)),
        kv("stddev", format!("{} ms", fmt_ms(s.stddev())), TEXT),
        kv("jitter", format!("{} ms", fmt_ms(s.jitter())), TEXT),
        Line::raw(""),
        kv("flaps", st.flaps.to_string(), if st.flaps > 0 { WARN } else { TEXT }),
        kv(
            "socket",
            match st.sock_kind {
                Some(SockKind::Raw) => "raw icmp".into(),
                Some(SockKind::Dgram) => "dgram icmp".into(),
                None => "…".into(),
            },
            DIM,
        ),
    ];
    if let Status::Error(e) = &st.status {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(format!(" {e}"), Style::default().fg(BAD))));
    }
    f.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }).block(panel(host)),
        stats_area,
    );

    let [chart_area, timeline_area] = Layout::vertical([Constraint::Fill(1), Constraint::Length(4)]).areas(right);
    draw_chart(f, st, chart_area, t);
    draw_timeline(f, st, timeline_area);
}

fn draw_chart(f: &mut Frame, st: &PingState, area: Rect, t: f32) {
    let s = &st.stats;
    // Braille gives two points per cell horizontally.
    let n = ((area.width.saturating_sub(10)) as usize * 2).max(10);
    let skip = s.history.len().saturating_sub(n);
    // Newest sample sits at the right edge, so the chart scrolls leftward.
    let offset = n - (s.history.len() - skip);
    let window: Vec<(usize, Option<f64>)> =
        s.history.iter().skip(skip).copied().enumerate().map(|(i, v)| (i + offset, v)).collect();
    let max = window.iter().filter_map(|(_, v)| *v).fold(1.0f64, f64::max) * 1.25;

    let pts: Vec<(f64, f64)> = window.iter().filter_map(|(i, v)| v.map(|ms| (*i as f64, ms))).collect();
    let lost: Vec<(f64, f64)> = window.iter().filter(|(_, v)| v.is_none()).map(|(i, _)| (*i as f64, max * 0.97)).collect();
    let avg = s.avg().unwrap_or(0.0);
    let avg_line: Vec<(f64, f64)> = vec![(0.0, avg), (n as f64, avg)];

    let line_color = gradient(t * 0.15);
    let datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(FAINT))
            .data(&avg_line),
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(line_color))
            .data(&pts),
        Dataset::default().marker(Marker::Dot).style(Style::default().fg(BAD)).data(&lost),
    ];
    let label = |v: f64| Span::styled(format!("{v:.0}ms"), Style::default().fg(DIM));
    let chart = Chart::new(datasets)
        .block(panel("latency"))
        .x_axis(Axis::default().bounds([0.0, n as f64]).style(Style::default().fg(FAINT)))
        .y_axis(
            Axis::default()
                .bounds([0.0, max])
                .labels(vec![label(0.0), label(max / 2.0), label(max)])
                .style(Style::default().fg(FAINT)),
        );
    f.render_widget(chart, area);
}

/// One cell per probe, like a status-page uptime bar.
fn draw_timeline(f: &mut Frame, st: &PingState, area: Rect) {
    let w = area.width.saturating_sub(2) as usize;
    let s = &st.stats;
    let skip = s.history.len().saturating_sub(w);
    let mut spans: Vec<Span> = s
        .history
        .iter()
        .skip(skip)
        .map(|v| match v {
            Some(ms) => Span::styled("▆", Style::default().fg(rtt_color(*ms))),
            None => Span::styled("▆", Style::default().fg(BAD)),
        })
        .collect();
    let have = spans.len();
    if have < w {
        spans.insert(0, Span::styled("▆".repeat(w - have), Style::default().fg(SEL_BG)));
    }
    let uptime = if s.sent > 0 { 100.0 - s.loss_pct() } else { 100.0 };
    let caption = Line::from(vec![
        Span::styled(format!(" {} probes ", have), Style::default().fg(DIM)),
        Span::styled("· ", Style::default().fg(FAINT)),
        Span::styled(format!("{uptime:.2}% replied"), Style::default().fg(loss_color(100.0 - uptime))),
    ]);
    f.render_widget(Paragraph::new(vec![Line::from(spans), caption]).block(panel("timeline")), area);
}
