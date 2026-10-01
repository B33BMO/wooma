mod dns;
mod http;
mod ip;
mod ping;
mod ports;
mod speed;
pub mod theme;
mod trace;
mod whois;

use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::{App, Tab};
use theme::*;

/// `t` is seconds since launch; it only drives the busy spinners.
pub fn draw(f: &mut Frame, app: &App, t: f32) {
    let [header, body, footer] =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1), Constraint::Length(1)]).areas(f.area());

    draw_header(f, app, header);
    match app.tab {
        Tab::Ping => ping::draw(f, app, body, t),
        Tab::Trace => trace::draw(f, app, body, t),
        Tab::Dns => dns::draw(f, app, body, t),
        Tab::Ip => ip::draw(f, app, body, t),
        Tab::Whois => whois::draw(f, app, body, t),
        Tab::Http => http::draw(f, app, body, t),
        Tab::Ports => ports::draw(f, app, body),
        Tab::Speed => speed::draw(f, app, body, t),
    }
    draw_footer(f, app, footer);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::styled(" wooma ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(" ")];
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let style = if *tab == app.tab {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::default().fg(DIM)
        };
        spans.push(Span::styled(format!(" {} {} ", i + 1, tab.title()), style));
        spans.push(Span::raw(" "));
    }
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(10)]).areas(Rect { height: 1, ..area });
    f.render_widget(Paragraph::new(Line::from(spans)), left);
    let version = Line::from(Span::styled(format!("v{} ", env!("CARGO_PKG_VERSION")), Style::default().fg(DIM)));
    f.render_widget(Paragraph::new(version.right_aligned()), right);

    let rule = Rect { y: area.y + 1, height: 1, ..area };
    f.render_widget(Paragraph::new(Span::styled("─".repeat(area.width as usize), Style::default().fg(FAINT))), rule);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if let Some(buf) = &app.input {
        let prompt = format!(" {}: ", app.prompt_label());
        let x = area.x + (prompt.chars().count() + buf.chars().count()) as u16;
        let line = Line::from(vec![
            Span::styled(prompt, Style::default().fg(ACCENT)),
            Span::styled(buf.clone(), Style::default().fg(TEXT)),
            Span::styled("   enter: ok  esc: cancel", Style::default().fg(DIM)),
        ]);
        f.render_widget(Paragraph::new(line), area);
        f.set_cursor_position(Position::new(x.min(area.right().saturating_sub(1)), area.y));
        return;
    }

    let keys: &[(&str, &str)] = match app.tab {
        Tab::Ping => &[("a", "add"), ("d", "remove"), ("↑↓", "select"), ("r", "reset"), ("space", "pause")],
        Tab::Trace => &[("a", "new trace"), ("n", "names/ips"), ("r", "reset"), ("space", "pause")],
        Tab::Dns => &[("a", "lookup"), ("s", "resolver"), ("r", "rerun"), ("↑↓", "scroll")],
        Tab::Ip => &[("a", "lookup"), ("r", "rerun")],
        Tab::Whois => &[("a", "lookup"), ("r", "rerun"), ("↑↓ pgup/dn", "scroll raw")],
        Tab::Http => &[("a", "url"), ("r", "rerun"), ("↑↓", "scroll headers")],
        Tab::Ports => &[("a", "scan"), ("r", "rerun"), ("↑↓", "scroll")],
        Tab::Speed => &[("enter", "start test")],
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, v) in keys.iter().chain([("tab", "switch"), ("q", "quit")].iter()) {
        spans.push(Span::styled(*k, Style::default().add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {v}   "), Style::default().fg(DIM)));
    }
    // A status message briefly takes over the right side of the footer.
    let flash = app.flash.as_ref().filter(|(_, at)| at.elapsed().as_secs_f32() < 2.5);
    let flash_w = flash.map(|(m, _)| m.chars().count() as u16 + 2).unwrap_or(0);
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(flash_w)]).areas(area);
    f.render_widget(Paragraph::new(Line::from(spans)), left);
    if let Some((msg, _)) = flash {
        let line = Line::from(Span::styled(format!("{msg} "), Style::default().fg(WARN)));
        f.render_widget(Paragraph::new(line.right_aligned()), right);
    }
}

pub fn panel(title: &str) -> Block<'static> {
    let block = Block::bordered().border_style(Style::default().fg(FAINT));
    if title.is_empty() {
        return block;
    }
    block.title(Span::styled(format!(" {title} "), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)))
}

/// A tool's error, full width; the first line is the headline, the rest detail.
pub fn error_panel(f: &mut Frame, msg: &str, area: Rect) {
    let mut lines = vec![Line::raw("")];
    for (i, l) in msg.lines().enumerate() {
        let style = if i == 0 { Style::default().fg(BAD).add_modifier(Modifier::BOLD) } else { Style::default().fg(TEXT) };
        lines.push(Line::from(Span::styled(format!(" {l}"), style)));
    }
    f.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }).block(panel("error")), area);
}

pub fn first_line(msg: &str) -> String {
    msg.lines().next().unwrap_or_default().to_string()
}

/// The placeholder shown before a tool has been run.
pub fn empty_hint(f: &mut Frame, area: Rect, title: &str, headline: &str, hint: &str) {
    let msg = Paragraph::new(vec![
        Line::raw(""),
        Line::from(Span::styled(headline.to_string(), Style::default().fg(TEXT))),
        Line::from(Span::styled(hint.to_string(), Style::default().fg(DIM))),
    ])
    .alignment(ratatui::layout::Alignment::Center)
    .block(panel(title));
    f.render_widget(msg, area);
}

/// A "  label   value" row with a fixed-width label column.
pub fn kv(label: &str, value: impl Into<String>, color: ratatui::style::Color, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {label:<width$}"), Style::default().fg(DIM)),
        Span::styled(value.into(), Style::default().fg(color)),
    ])
}

/// Like `kv`, but long values word-wrap with a hanging indent under the value column.
pub fn kv_wrap(label: &str, value: &str, color: ratatui::style::Color, label_w: usize, total_w: u16) -> Vec<Line<'static>> {
    let avail = (total_w as usize).saturating_sub(label_w + 3).max(8);
    let mut rows: Vec<String> = vec![String::new()];
    for word in value.split(' ') {
        let cur = rows.last_mut().unwrap();
        let need = if cur.is_empty() { word.chars().count() } else { cur.chars().count() + 1 + word.chars().count() };
        if need > avail && !cur.is_empty() {
            rows.push(String::new());
        }
        let cur = rows.last_mut().unwrap();
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
        // A single word longer than the line still has to break somewhere.
        while rows.last().unwrap().chars().count() > avail {
            let cur = rows.pop().unwrap();
            rows.push(cur.chars().take(avail).collect());
            rows.push(cur.chars().skip(avail).collect());
        }
    }
    rows.into_iter()
        .enumerate()
        .map(|(i, r)| kv(if i == 0 { label } else { "" }, r, color, label_w))
        .collect()
}
