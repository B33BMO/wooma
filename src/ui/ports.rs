use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use super::theme::*;
use super::{empty_hint, panel};
use crate::app::{App, Tab};
use crate::net::ports::{service, PortState, Scan};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let Some(h) = &app.ports else {
        return empty_hint(f, area, "ports", "No scan", "press a and enter: host [top | all | 1-1024 | 22,80,443]");
    };
    let s = h.state.lock().unwrap();
    let [top, body] = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(area);
    let [table_area, grid_area] = Layout::horizontal([Constraint::Fill(3), Constraint::Fill(2)]).areas(body);
    draw_progress(f, &s, top);
    draw_open(f, app, &s, table_area);
    draw_grid(f, &s, grid_area);
}

fn draw_progress(f: &mut Frame, s: &Scan, area: Rect) {
    let mut first = vec![Span::styled(format!(" {}", s.host), Style::default().fg(TEXT).add_modifier(Modifier::BOLD))];
    if let Some(ip) = s.ip {
        first.push(Span::styled(format!("  {ip}"), Style::default().fg(DIM)));
    }
    first.push(Span::styled(format!("  {}, {} ports", s.spec, s.ports.len()), Style::default().fg(FAINT)));

    let second = if let Some(e) = &s.error {
        Line::from(Span::styled(format!(" {e}"), Style::default().fg(BAD)))
    } else {
        let total = s.ports.len().max(1);
        let frac = s.done as f64 / total as f64;
        let elapsed = s.finished.unwrap_or_else(std::time::Instant::now).duration_since(s.started).as_secs_f64();
        let bar_w = (area.width as usize / 3).max(10);
        let filled = (frac * bar_w as f64) as usize;
        let mut spans = vec![Span::raw(" ")];
        spans.push(Span::styled("━".repeat(filled), Style::default().fg(ACCENT)));
        spans.push(Span::styled("─".repeat(bar_w - filled), Style::default().fg(FAINT)));
        let open = s.count(|p| matches!(p, PortState::Open { .. }));
        let closed = s.count(|p| *p == PortState::Closed);
        let filtered = s.count(|p| *p == PortState::Filtered);
        spans.extend([
            Span::styled(format!(" {}/{} ", s.done, s.ports.len()), Style::default().fg(TEXT)),
            Span::styled(format!(" {open} open"), Style::default().fg(GOOD)),
            Span::styled(format!("  {closed} closed"), Style::default().fg(DIM)),
            Span::styled(format!("  {filtered} filtered"), Style::default().fg(FAINT)),
            Span::styled(
                format!("  |  {:.1}s, {:.0}/s", elapsed, s.done as f64 / elapsed.max(0.001)),
                Style::default().fg(FAINT),
            ),
        ]);
        Line::from(spans)
    };
    f.render_widget(Paragraph::new(vec![Line::from(first), second]).block(panel("port scan")), area);
}

fn draw_open(f: &mut Frame, app: &App, s: &Scan, area: Rect) {
    let mut open: Vec<(u16, f64, Option<String>)> = s
        .ports
        .iter()
        .zip(&s.states)
        .filter_map(|(p, st)| match st {
            PortState::Open { ms, banner } => Some((*p, *ms, banner.clone())),
            _ => None,
        })
        .collect();
    open.sort_by_key(|(p, _, _)| *p);

    if open.is_empty() {
        let msg = if s.finished.is_some() { "nothing open" } else { "scanning" };
        let p = Paragraph::new(vec![Line::raw(""), Line::from(Span::styled(format!(" {msg}"), Style::default().fg(DIM)))]);
        f.render_widget(p.block(panel("open")), area);
        return;
    }

    let rows: Vec<Row> = open
        .iter()
        .map(|(port, ms, banner)| {
            Row::new(vec![
                Cell::from(Line::from(Span::styled(format!("{port:>5}"), Style::default().fg(GOOD)))),
                Cell::from(Span::styled(service(*port), Style::default().fg(TEXT))),
                Cell::from(Line::from(Span::styled(fmt_ms(Some(*ms)), Style::default().fg(rtt_color(*ms)))).right_aligned()),
                Cell::from(Span::styled(banner.clone().unwrap_or_default(), Style::default().fg(DIM))),
            ])
        })
        .collect();
    let skip = (app.scroll[Tab::Ports.index()] as usize).min(rows.len().saturating_sub(1));
    let rows: Vec<Row> = rows.into_iter().skip(skip).collect();
    let header = Row::new([" port", "service", "  rtt", "banner"]).style(Style::default().fg(DIM));
    let widths = [Constraint::Length(5), Constraint::Length(12), Constraint::Length(6), Constraint::Fill(1)];
    let title = format!("open ({})", open.len());
    f.render_widget(Table::new(rows, widths).header(header).column_spacing(2).block(panel(&title)), area);
}

/// Every scanned port as a cell (or a bucket of ports when there are too many).
fn draw_grid(f: &mut Frame, s: &Scan, area: Rect) {
    let block = panel("map");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let n = s.ports.len();
    if n == 0 || inner.width < 2 || inner.height < 2 {
        return;
    }
    let cols = inner.width as usize;
    let cells = (cols * (inner.height as usize - 1)).max(1);
    let per = n.div_ceil(cells).max(1);
    let used = n.div_ceil(per);

    let rank = |st: &PortState| match st {
        PortState::Open { .. } => 3,
        PortState::Pending => 2,
        PortState::Closed => 1,
        PortState::Filtered => 0,
    };
    let buf = f.buffer_mut();
    for i in 0..used {
        let bucket = &s.states[i * per..((i + 1) * per).min(n)];
        let best = bucket.iter().max_by_key(|st| rank(st)).unwrap();
        let (ch, color) = match best {
            PortState::Open { .. } => ("■", GOOD),
            PortState::Pending => (" ", TEXT),
            PortState::Closed => ("▪", DIM),
            PortState::Filtered => ("·", FAINT),
        };
        let x = inner.x + (i % cols) as u16;
        let y = inner.y + (i / cols) as u16;
        buf.set_string(x, y, ch, Style::default().fg(color));
    }
    let legend = if per > 1 { format!("1 cell = {per} ports") } else { "1 cell = 1 port".into() };
    let y = inner.y + inner.height - 1;
    buf.set_string(inner.x, y, "■", Style::default().fg(GOOD));
    buf.set_string(inner.x + 1, y, " open ", Style::default().fg(DIM));
    buf.set_string(inner.x + 7, y, "▪", Style::default().fg(DIM));
    buf.set_string(inner.x + 8, y, " closed ", Style::default().fg(DIM));
    buf.set_string(inner.x + 16, y, "·", Style::default().fg(FAINT));
    buf.set_string(inner.x + 17, y, format!(" filtered  {legend}"), Style::default().fg(FAINT));
}
