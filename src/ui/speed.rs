use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Chart, Dataset, GraphType, Paragraph};
use ratatui::Frame;

use super::panel;
use super::theme::*;
use crate::app::App;
use crate::net::speed::{bloat_grade, jitter, median, Phase, SpeedTest};

const DOWN: Color = ACCENT;
const UP: Color = Color::Rgb(255, 95, 175);

pub fn draw(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let Some(h) = &app.speed else {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled("how fast is your connection?", Style::default().fg(DIM))),
            Line::from(vec![
                Span::styled("press ", Style::default().fg(FAINT)),
                Span::styled("enter", Style::default().fg(ACCENT2)),
                Span::styled(" to run a ~25s test against cloudflare", Style::default().fg(FAINT)),
            ]),
        ])
        .alignment(Alignment::Center)
        .block(panel("speed"));
        f.render_widget(msg, area);
        return;
    };
    let s = h.state.lock().unwrap();
    let [top, cards, bottom] =
        Layout::vertical([Constraint::Length(4), Constraint::Length(9), Constraint::Fill(1)]).areas(area);
    let [down_card, up_card, lat_card] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1), Constraint::Fill(1)]).areas(cards);
    let [chart_area, bloat_area] = Layout::horizontal([Constraint::Fill(3), Constraint::Fill(2)]).areas(bottom);

    draw_phases(f, &s, top, t);
    let live = |p: Phase| (s.phase == p).then_some(s.current);
    draw_card(f, down_card, "download", s.down_mbps.or(live(Phase::Download)), "Mbps", DOWN, s.phase == Phase::Download, t);
    draw_card(f, up_card, "upload", s.up_mbps.or(live(Phase::Upload)), "Mbps", UP, s.phase == Phase::Upload, t);
    draw_card(f, lat_card, "latency", median(&s.idle), "ms idle", GOOD, s.phase == Phase::Latency, t);
    draw_chart(f, &s, chart_area);
    draw_bloat(f, &s, bloat_area);
}

fn draw_phases(f: &mut Frame, s: &SpeedTest, area: Rect, t: f32) {
    let order = [Phase::Meta, Phase::Latency, Phase::Download, Phase::Upload];
    let names = ["server", "latency", "download", "upload"];
    let cur = order.iter().position(|p| *p == s.phase).unwrap_or(order.len());
    let mut spans = vec![Span::raw(" ")];
    for (i, name) in names.iter().enumerate() {
        let (mark, color) = if i < cur || s.phase == Phase::Done {
            ('✓', GOOD)
        } else if i == cur {
            (spinner(t), ACCENT)
        } else {
            ('○', FAINT)
        };
        spans.push(Span::styled(format!("{mark} "), Style::default().fg(color)));
        spans.push(Span::styled(
            name.to_string(),
            Style::default().fg(if i == cur { TEXT } else { DIM }).add_modifier(if i == cur { Modifier::BOLD } else { Modifier::empty() }),
        ));
        if i + 1 < names.len() {
            spans.push(Span::styled("  ──  ", Style::default().fg(FAINT)));
        }
    }
    if s.phase == Phase::Done && s.error.is_none() {
        spans.push(Span::styled("   done · enter to run again", Style::default().fg(DIM)));
    }
    let meta = match (&s.error, &s.meta) {
        (Some(e), _) => Line::from(Span::styled(format!(" {e}"), Style::default().fg(BAD))),
        (None, Some(m)) => Line::from(vec![
            Span::styled(" cloudflare ", Style::default().fg(DIM)),
            Span::styled(m.colo.clone(), Style::default().fg(ACCENT2).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  ·  {}  ·  {}  ·  {}", m.isp, m.ip, m.location), Style::default().fg(DIM)),
        ]),
        (None, None) => Line::from(Span::styled(" speed.cloudflare.com", Style::default().fg(DIM))),
    };
    f.render_widget(Paragraph::new(vec![Line::from(spans), meta]).block(panel("speed test")), area);
}

#[allow(clippy::too_many_arguments)]
fn draw_card(f: &mut Frame, area: Rect, title: &str, value: Option<f64>, unit: &str, color: Color, active: bool, t: f32) {
    let text = match value {
        Some(v) if v >= 100.0 => format!("{v:.0}"),
        Some(v) => format!("{v:.1}"),
        None => "-".into(),
    };
    // The active card's number breathes through the gradient while measuring.
    let c = if active { gradient(t * 0.4) } else if value.is_some() { color } else { FAINT };
    let mut lines: Vec<Line> = vec![Line::raw("")];
    lines.extend(big_text(&text).into_iter().map(|r| Line::from(Span::styled(r, Style::default().fg(c)))));
    lines.push(Line::from(Span::styled(unit.to_string(), Style::default().fg(DIM))));
    let block = panel(title).border_style(Style::default().fg(if active { scale(c, 0.8) } else { FAINT }));
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center).block(block), area);
}

fn draw_chart(f: &mut Frame, s: &SpeedTest, area: Rect) {
    let down: Vec<(f64, f64)> = s.down_series.iter().enumerate().map(|(i, v)| (i as f64, *v)).collect();
    let up: Vec<(f64, f64)> = s.up_series.iter().enumerate().map(|(i, v)| (i as f64, *v)).collect();
    let max = s.down_series.iter().chain(&s.up_series).copied().fold(10.0f64, f64::max) * 1.15;
    let n = s.down_series.len().max(s.up_series.len()).max(50) as f64;
    let label = |v: f64| Span::styled(format!("{v:.0}"), Style::default().fg(DIM));
    let chart = Chart::new(vec![
        Dataset::default().name("down").marker(Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(DOWN)).data(&down),
        Dataset::default().name("up").marker(Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(UP)).data(&up),
    ])
    .block(panel("throughput · Mbps"))
    .x_axis(Axis::default().bounds([0.0, n]).style(Style::default().fg(FAINT)))
    .y_axis(Axis::default().bounds([0.0, max]).labels(vec![label(0.0), label(max / 2.0), label(max)]).style(Style::default().fg(FAINT)));
    f.render_widget(chart, area);
}

fn draw_bloat(f: &mut Frame, s: &SpeedTest, area: Rect) {
    let idle = median(&s.idle);
    let row = |label: &str, v: Option<f64>, extra: String| {
        Line::from(vec![
            Span::styled(format!(" {label:<15}"), Style::default().fg(DIM)),
            Span::styled(
                v.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into()),
                Style::default().fg(v.map(rtt_color).unwrap_or(FAINT)),
            ),
            Span::styled(extra, Style::default().fg(FAINT)),
        ])
    };
    let jit = jitter(&s.idle).map(|j| format!("  ±{j:.1} jitter")).unwrap_or_default();
    let mut lines = vec![
        Line::raw(""),
        row("idle", idle, jit),
        row("under download", median(&s.loaded_down), String::new()),
        row("under upload", median(&s.loaded_up), String::new()),
        Line::raw(""),
    ];
    let worst_loaded = [median(&s.loaded_down), median(&s.loaded_up)].into_iter().flatten().fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
    if let (Some(i), Some(l)) = (idle, worst_loaded) {
        let (grade, inc) = bloat_grade(i, l);
        let color = match grade {
            "A+" | "A" => GOOD,
            "B" => Color::Rgb(190, 235, 110),
            "C" => WARN,
            _ => BAD,
        };
        lines.push(Line::from(vec![
            Span::styled(" bufferbloat  ", Style::default().fg(DIM)),
            Span::styled(format!(" {grade} "), Style::default().fg(Color::Black).bg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  +{inc:.0} ms under load"), Style::default().fg(DIM)),
        ]));
    }
    if s.bytes_down + s.bytes_up > 0 {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!(" moved {} down · {} up", super::http::human_bytes(s.bytes_down), super::http::human_bytes(s.bytes_up)),
            Style::default().fg(FAINT),
        )));
    }
    f.render_widget(Paragraph::new(lines).block(panel("latency under load")), area);
}
