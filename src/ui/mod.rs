mod dns;
mod http;
mod ip;
mod ping;
mod ports;
mod speed;
pub mod splash;
pub mod theme;
mod trace;
mod whois;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use crate::app::{App, Tab};
use theme::*;

pub fn draw(f: &mut Frame, app: &App) {
    let t = app.started.elapsed().as_secs_f32();
    if app.splash {
        splash::draw(f, t);
        return;
    }

    let [header, body, footer] =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1), Constraint::Length(1)]).areas(f.area());

    draw_header(f, app, header, t);
    match app.tab {
        Tab::Ping => ping::draw(f, app, body, t),
        Tab::Trace => trace::draw(f, app, body, t),
        Tab::Dns => dns::draw(f, app, body, t),
        Tab::Ip => ip::draw(f, app, body, t),
        Tab::Whois => whois::draw(f, app, body, t),
        Tab::Http => http::draw(f, app, body, t),
        Tab::Ports => ports::draw(f, app, body, t),
        Tab::Speed => speed::draw(f, app, body, t),
    }
    draw_footer(f, app, footer, t);
}

/// Where each tab label sits in the header, as (x offset, width).
fn tab_positions() -> Vec<(u16, u16)> {
    let mut x = 10; // after the logo
    Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, tab)| {
            let w = format!(" {} {} ", i + 1, tab.title()).chars().count() as u16;
            let pos = (x, w);
            x += w + 1;
            pos
        })
        .collect()
}

fn draw_header(f: &mut Frame, app: &App, area: Rect, t: f32) {
    let mut spans = vec![Span::raw(" ")];
    spans.push(Span::styled("◉ ", Style::default().fg(gradient(t * 0.4))));
    spans.extend(gradient_spans("wooma", t * 0.3, 0.08, true));
    spans.push(Span::raw("  "));
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let active = *tab == app.tab;
        let style = if active {
            Style::default().fg(TEXT).bg(SEL_BG).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(DIM)
        };
        spans.push(Span::styled(format!(" {}", i + 1), style.fg(if active { ACCENT } else { FAINT })));
        spans.push(Span::styled(format!(" {} ", tab.title()), style));
        spans.push(Span::raw(" "));
    }
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(12)]).areas(Rect { height: 1, ..area });
    f.render_widget(Paragraph::new(Line::from(spans)), left);

    let up = app.started.elapsed().as_secs();
    let right_line = Line::from(vec![
        Span::styled(format!("{} ", spinner(t)), Style::default().fg(scale(ACCENT, 0.7))),
        Span::styled(format!("up {} ", fmt_dur(up)), Style::default().fg(DIM)),
    ])
    .right_aligned();
    f.render_widget(Paragraph::new(right_line), right);

    // Underline slides from the previous tab to the new one.
    let pos = tab_positions();
    let to = pos[Tab::ALL.iter().position(|x| *x == app.tab).unwrap()];
    let from = pos[Tab::ALL.iter().position(|x| *x == app.prev_tab).unwrap()];
    let k = ease_out(app.tab_changed.elapsed().as_secs_f32() / 0.28);
    let x = from.0 as f32 + (to.0 as f32 - from.0 as f32) * k;
    let w = from.1 as f32 + (to.1 as f32 - from.1 as f32) * k;
    let rule = area.y + 1;
    let buf = f.buffer_mut();
    buf.set_string(area.x, rule, "─".repeat(area.width as usize), Style::default().fg(FAINT));
    let bar = "━".repeat(w.round() as usize);
    for (i, ch) in bar.chars().enumerate() {
        let cx = area.x + x.round() as u16 + i as u16;
        if cx < area.x + area.width {
            buf.set_string(cx, rule, ch.to_string(), Style::default().fg(gradient(t * 0.5 + i as f32 * 0.04)));
        }
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect, t: f32) {
    if let Some(buf) = &app.input {
        let cursor = if ((t * 2.5) as u32).is_multiple_of(2) { "▌" } else { " " };
        let line = Line::from(vec![
            Span::styled(" ❯ ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{}: ", app.prompt_label()), Style::default().fg(DIM)),
            Span::styled(buf.clone(), Style::default().fg(TEXT)),
            Span::styled(cursor, Style::default().fg(ACCENT)),
            Span::styled("   enter ok · esc cancel", Style::default().fg(FAINT)),
        ]);
        f.render_widget(Paragraph::new(line), area);
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
        spans.push(Span::styled(*k, Style::default().fg(ACCENT2)));
        spans.push(Span::styled(format!(" {v}  "), Style::default().fg(DIM)));
    }
    // A flash message briefly takes over the right side of the footer, then fades.
    let flash = app.flash.as_ref().filter(|(_, at)| at.elapsed().as_secs_f32() < 2.5);
    let flash_w = flash.map(|(m, _)| m.chars().count() as u16 + 2).unwrap_or(0);
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(flash_w)]).areas(area);
    f.render_widget(Paragraph::new(Line::from(spans)), left);
    if let Some((msg, at)) = flash {
        let fade = 1.0 - (at.elapsed().as_secs_f32() - 1.5).max(0.0);
        let line = Line::from(Span::styled(format!("{msg} "), Style::default().fg(scale(WARN, fade))));
        f.render_widget(Paragraph::new(line.right_aligned()), right);
    }
}

pub fn panel(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(FAINT))
        .title(Span::styled(format!(" {title} "), Style::default().fg(ACCENT2).add_modifier(Modifier::BOLD)))
}

/// The placeholder shown before a tool has been run.
pub fn empty_hint(f: &mut Frame, area: Rect, title: &str, headline: &str, hint: &str) {
    let msg = Paragraph::new(vec![
        Line::raw(""),
        Line::from(Span::styled(headline.to_string(), Style::default().fg(DIM))),
        Line::from(vec![
            Span::styled("press ", Style::default().fg(FAINT)),
            Span::styled("a", Style::default().fg(ACCENT2)),
            Span::styled(format!(" {hint}"), Style::default().fg(FAINT)),
        ]),
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
