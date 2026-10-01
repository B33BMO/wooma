use std::collections::VecDeque;

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

// Named ANSI colors so the UI follows the user's terminal theme (dark or light).
pub const TEXT: Color = Color::Reset;
pub const DIM: Color = Color::DarkGray;
pub const FAINT: Color = Color::DarkGray;
pub const GOOD: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const BAD: Color = Color::Red;
pub const ACCENT: Color = Color::Cyan;
pub const ACCENT2: Color = Color::Blue;

pub fn rtt_color(ms: f64) -> Color {
    match ms {
        m if m < 80.0 => GOOD,
        m if m < 200.0 => WARN,
        _ => BAD,
    }
}

pub fn loss_color(pct: f64) -> Color {
    match pct {
        p if p <= 0.0 => GOOD,
        p if p < 5.0 => WARN,
        _ => BAD,
    }
}

pub fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(ms) if ms >= 100.0 => format!("{ms:.0}"),
        Some(ms) => format!("{ms:.1}"),
        None => "-".into(),
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
        spans.insert(0, Span::styled(" ".repeat(width - window.len()), Style::default()));
    }
    Line::from(spans)
}

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn spinner(secs: f32) -> char {
    SPINNER[(secs * 10.0) as usize % SPINNER.len()]
}

/// A horizontal meter, `frac` in 0..=1.
pub fn meter(frac: f64, width: usize, color: Color) -> Line<'static> {
    let full = (frac.clamp(0.0, 1.0) * width as f64).round() as usize;
    Line::from(vec![
        Span::styled("━".repeat(full), Style::default().fg(color)),
        Span::styled("─".repeat(width - full), Style::default().fg(FAINT)),
    ])
}
