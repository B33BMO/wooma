use std::collections::VecDeque;

pub const HISTORY: usize = 600;

/// Rolling round-trip statistics. `None` samples are lost probes.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub sent: u64,
    pub recv: u64,
    pub last: Option<f64>,
    pub min: f64,
    pub max: f64,
    sum: f64,
    sum_sq: f64,
    jitter_sum: f64,
    jitter_n: u64,
    pub history: VecDeque<Option<f64>>,
}

impl Stats {
    pub fn push(&mut self, rtt_ms: Option<f64>) {
        self.sent += 1;
        if let Some(ms) = rtt_ms {
            if self.recv == 0 || ms < self.min {
                self.min = ms;
            }
            if ms > self.max {
                self.max = ms;
            }
            if let Some(prev) = self.history.iter().rev().flatten().next() {
                self.jitter_sum += (ms - prev).abs();
                self.jitter_n += 1;
            }
            self.recv += 1;
            self.sum += ms;
            self.sum_sq += ms * ms;
        }
        self.last = rtt_ms;
        self.history.push_back(rtt_ms);
        if self.history.len() > HISTORY {
            self.history.pop_front();
        }
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.recv) as f64 * 100.0 / self.sent as f64
        }
    }

    pub fn avg(&self) -> Option<f64> {
        (self.recv > 0).then(|| self.sum / self.recv as f64)
    }

    pub fn stddev(&self) -> Option<f64> {
        let avg = self.avg()?;
        Some((self.sum_sq / self.recv as f64 - avg * avg).max(0.0).sqrt())
    }

    pub fn jitter(&self) -> Option<f64> {
        (self.jitter_n > 0).then(|| self.jitter_sum / self.jitter_n as f64)
    }

    pub fn best(&self) -> Option<f64> {
        (self.recv > 0).then_some(self.min)
    }

    pub fn worst(&self) -> Option<f64> {
        (self.recv > 0).then_some(self.max)
    }

    /// Number of consecutive lost probes at the tail of the history.
    pub fn lost_streak(&self) -> usize {
        self.history.iter().rev().take_while(|s| s.is_none()).count()
    }
}
