use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::theme::*;

pub const LOGO: [&str; 6] = [
    "██╗    ██╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ",
    "██║    ██║██╔═══██╗██╔═══██╗████╗ ████║██╔══██╗",
    "██║ █╗ ██║██║   ██║██║   ██║██╔████╔██║███████║",
    "██║███╗██║██║   ██║██║   ██║██║╚██╔╝██║██╔══██║",
    "╚███╔███╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║",
    " ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝",
];

const TAGLINE: &str = "ping · trace · dns — packets go wooma";
pub const DURATION: f32 = 1.1;

pub fn draw(f: &mut Frame, t: f32) {
    let area = f.area();
    let [_, logo_area, _, tag_area, _, bar_area, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(LOGO.len() as u16),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);

    // Logo sweeps in column by column, then a bright shimmer passes over it.
    let width = LOGO[0].chars().count() as f32;
    let reveal = ease_out(t / 0.45) * (width + 8.0);
    let shimmer = (t - 0.45) * 110.0;
    let lines: Vec<Line> = LOGO
        .iter()
        .enumerate()
        .map(|(row, l)| {
            Line::from(
                l.chars()
                    .enumerate()
                    .map(|(col, ch)| {
                        // Rows lag slightly so the edge looks like a wave.
                        let edge = reveal - (row as f32 * 1.5);
                        let c = col as f32;
                        if c > edge {
                            return Span::raw(" ");
                        }
                        let fresh = (edge - c).min(6.0) / 6.0;
                        let mut color = gradient(c / width * 0.9 + row as f32 * 0.03 - t * 0.25);
                        color = scale(color, 0.4 + 0.6 * fresh);
                        if (c - shimmer).abs() < 3.0 {
                            color = scale(color, 1.6);
                        }
                        Span::styled(ch.to_string(), Style::default().fg(color))
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), logo_area);

    let typed = (((t - 0.2) * 90.0).max(0.0) as usize).min(TAGLINE.chars().count());
    let mut tag: Vec<Span> = vec![Span::styled(
        TAGLINE.chars().take(typed).collect::<String>(),
        Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
    )];
    if typed < TAGLINE.chars().count() && ((t * 4.0) as u32).is_multiple_of(2) {
        tag.push(Span::styled("▌", Style::default().fg(ACCENT)));
    }
    f.render_widget(Paragraph::new(Line::from(tag)).alignment(Alignment::Center), tag_area);

    let bar_w = 30usize;
    let filled = ((t / DURATION).clamp(0.0, 1.0) * bar_w as f32) as usize;
    let bar = Rect { x: bar_area.x + bar_area.width.saturating_sub(bar_w as u16) / 2, width: bar_w as u16, ..bar_area };
    let mut spans = gradient_spans(&"━".repeat(filled), -t * 0.5, 0.03, false);
    spans.push(Span::styled("━".repeat(bar_w - filled), Style::default().fg(FAINT)));
    f.render_widget(Paragraph::new(Line::from(spans)), bar);
}
