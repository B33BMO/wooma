use std::collections::VecDeque;

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

pub const DIM: Color = Color::Rgb(108, 112, 134);
pub const FAINT: Color = Color::Rgb(62, 64, 82);
pub const TEXT: Color = Color::Rgb(205, 214, 244);
pub const GOOD: Color = Color::Rgb(120, 230, 140);
pub const WARN: Color = Color::Rgb(250, 210, 100);
pub const BAD: Color = Color::Rgb(255, 95, 110);
pub const ACCENT: Color = Color::Rgb(0, 220, 255);
pub const ACCENT2: Color = Color::Rgb(190, 120, 255);
pub const SEL_BG: Color = Color::Rgb(38, 40, 58);

const STOPS: [(f32, f32, f32); 3] = [(0.0, 220.0, 255.0), (170.0, 120.0, 255.0), (255.0, 95.0, 175.0)];

/// Cyclic cyan → violet → pink gradient, `t` in any range.
pub fn gradient(t: f32) -> Color {
    let t = t.rem_euclid(1.0) * STOPS.len() as f32;
    let i = t as usize % STOPS.len();
    let f = t.fract();
    let (a, b) = (STOPS[i], STOPS[(i + 1) % STOPS.len()]);
    let lerp = |x: f32, y: f32| (x + (y - x) * f) as u8;
    Color::Rgb(lerp(a.0, b.0), lerp(a.1, b.1), lerp(a.2, b.2))
}

pub fn scale(c: Color, k: f32) -> Color {
    match c {
        Color::Rgb(r, g, b) => {
            let f = |v: u8| (v as f32 * k).clamp(0.0, 255.0) as u8;
            Color::Rgb(f(r), f(g), f(b))
        }
        other => other,
    }
}

/// Text painted with a flowing gradient; `phase` animates it.
pub fn gradient_spans(text: &str, phase: f32, spread: f32, bold: bool) -> Vec<Span<'static>> {
    text.chars()
        .enumerate()
        .map(|(i, ch)| {
            let mut s = Style::default().fg(gradient(phase + i as f32 * spread));
            if bold {
                s = s.add_modifier(Modifier::BOLD);
            }
            Span::styled(ch.to_string(), s)
        })
        .collect()
}

pub fn rtt_color(ms: f64) -> Color {
    match ms {
        m if m < 30.0 => GOOD,
        m if m < 80.0 => Color::Rgb(190, 235, 110),
        m if m < 150.0 => WARN,
        m if m < 300.0 => Color::Rgb(255, 150, 80),
        _ => BAD,
    }
}

pub fn loss_color(pct: f64) -> Color {
    match pct {
        p if p <= 0.0 => GOOD,
        p if p < 5.0 => WARN,
        p if p < 30.0 => Color::Rgb(255, 150, 80),
        _ => BAD,
    }
}

pub fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(ms) if ms >= 100.0 => format!("{ms:.0}"),
        Some(ms) => format!("{ms:.1}"),
        None => "—".into(),
    }
}

pub fn fmt_dur(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{:02}s", s / 60, s % 60),
        s if s < 86400 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{:02}h", s / 86400, (s % 86400) / 3600),
    }
}

const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// An inline sparkline of the most recent `width` samples, colored by latency.
pub fn sparkline(history: &VecDeque<Option<f64>>, width: usize) -> Line<'static> {
    let skip = history.len().saturating_sub(width);
    let window: Vec<Option<f64>> = history.iter().skip(skip).copied().collect();
    // Scale from a floor below the window's minimum so stable links still show texture.
    let max = window.iter().flatten().fold(1.0f64, |m, v| m.max(*v));
    let lo = window.iter().flatten().fold(max, |m, v| m.min(*v)) * 0.6;
    let mut spans: Vec<Span> = window
        .iter()
        .map(|s| match s {
            Some(ms) => {
                let idx = (((ms - lo) / (max - lo).max(0.001)) * 7.0).round().clamp(0.0, 7.0) as usize;
                Span::styled(BLOCKS[idx].to_string(), Style::default().fg(rtt_color(*ms)))
            }
            None => Span::styled("×", Style::default().fg(BAD)),
        })
        .collect();
    if window.len() < width {
        spans.insert(0, Span::styled("·".repeat(width - window.len()), Style::default().fg(FAINT)));
    }
    Line::from(spans)
}

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn spinner(secs: f32) -> char {
    SPINNER[(secs * 12.0) as usize % SPINNER.len()]
}

pub fn ease_out(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// A chunky 3x5 font for headline numbers.
fn glyph(c: char) -> [&'static str; 5] {
    match c {
        '0' => ["███", "█ █", "█ █", "█ █", "███"],
        '1' => ["██ ", " █ ", " █ ", " █ ", "███"],
        '2' => ["███", "  █", "███", "█  ", "███"],
        '3' => ["███", "  █", "███", "  █", "███"],
        '4' => ["█ █", "█ █", "███", "  █", "  █"],
        '5' => ["███", "█  ", "███", "  █", "███"],
        '6' => ["███", "█  ", "███", "█ █", "███"],
        '7' => ["███", "  █", "  █", "  █", "  █"],
        '8' => ["███", "█ █", "███", "█ █", "███"],
        '9' => ["███", "█ █", "███", "  █", "███"],
        '.' => [" ", " ", " ", " ", "█"],
        '%' => ["█ █", "  █", " █ ", "█  ", "█ █"],
        '-' => ["   ", "   ", "███", "   ", "   "],
        _ => ["   ", "   ", "   ", "   ", "   "],
    }
}

pub fn big_text(s: &str) -> [String; 5] {
    let mut rows: [String; 5] = Default::default();
    for (i, c) in s.chars().enumerate() {
        for (r, row) in rows.iter_mut().enumerate() {
            if i > 0 {
                row.push(' ');
            }
            row.push_str(glyph(c)[r]);
        }
    }
    rows
}

/// A horizontal meter, `frac` in 0..=1, using eighth-blocks for a smooth edge.
pub fn meter(frac: f64, width: usize, color: Color) -> Line<'static> {
    const EIGHTHS: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let cells = frac.clamp(0.0, 1.0) * width as f64;
    let full = cells.floor() as usize;
    let rem = ((cells - full as f64) * 8.0) as usize;
    let mut s = "█".repeat(full);
    if full < width {
        s.push(EIGHTHS[rem]);
    }
    let pad = width.saturating_sub(s.chars().count());
    Line::from(vec![
        Span::styled(s, Style::default().fg(color)),
        Span::styled("·".repeat(pad), Style::default().fg(FAINT)),
    ])
}
