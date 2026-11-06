//! Current-measurement statistics for `cedar meter` and the web UI's meter
//! page, fed with [`Sample`]s from a KM003C measurement block
//! ([`AdcSample`], ~100 Hz) or a TC66 reading ([`Measurement`], ~2 Hz).
//!
//! Low-power limits such as the USB 2.0 suspend current (2.5 mA) apply to
//! the average over a window (1 s for suspend), not to single readings, so the
//! meter keeps a rolling window average of the readings and the worst window
//! seen so far, plus the running mean, spread and extremes.
//!
//! The KM003C also reports its own 1 s block average, presumably computed
//! from its full internal sample rate; the worst of those is tracked as a
//! cross-check, and a limit fails if either worst exceeds it. Every figure has
//! a zero offset subtracted: measure it with nothing attached and pass it
//! back in.
//!
//! Times are supplied by the caller (µs on any monotonic clock): neither
//! meter timestamps its readings, and the CLI and the browser use different
//! clocks.

use std::collections::VecDeque;
use std::fmt::Write as _;

use crate::km003c::AdcSample;
use crate::tc66::Measurement;

/// One reading from any supported meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub vbus_uv: i32,
    pub ibus_ua: i32,
    /// The meter's own 1 s block average, if it reports one (KM003C only).
    pub ibus_avg_ua: Option<i32>,
}

impl From<AdcSample> for Sample {
    fn from(s: AdcSample) -> Self {
        Sample {
            vbus_uv: s.vbus_uv,
            ibus_ua: s.ibus_ua,
            ibus_avg_ua: Some(s.ibus_avg_ua),
        }
    }
}

impl From<&Measurement> for Sample {
    fn from(m: &Measurement) -> Self {
        Sample {
            vbus_uv: m.vbus_uv,
            ibus_ua: m.ibus_ua,
            ibus_avg_ua: None,
        }
    }
}

/// The default averaging window: the USB suspend current is averaged over 1 s.
pub const DEFAULT_WINDOW_US: u64 = 1_000_000;

/// Running statistics over a stream of current readings.
#[derive(Debug, Clone)]
pub struct Meter {
    window_us: u64,
    offset_ua: f64,
    start_us: Option<u64>,
    /// Raw readings (µA) inside the current window, with their time.
    window: VecDeque<(u64, i32)>,
    window_sum: i64,
    // Offset-corrected running statistics (Welford), in µA.
    n: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
    /// Largest |window average| (µA) and the elapsed time (µs) it ended at.
    worst: Option<(f64, u64)>,
    /// Largest |meter 1 s average| (µA) among those computed since the start.
    worst_meter: Option<f64>,
    /// Whether the meter's average has changed since the first reading, i.e.
    /// now covers a second that began after the start.
    meter_avg_fresh: bool,
    last: Option<(u64, Sample)>,
}

/// How the worst window compares with a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No full window measured yet.
    Pending,
    Pass,
    Fail,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pending => "pending",
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
        }
    }
}

/// A snapshot of the meter's figures. Currents are in µA with the offset
/// subtracted; signs follow the KM003C (negative when power flows from the
/// male to the female port).
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub elapsed_s: f64,
    pub samples: u64,
    /// Readings per second since the start.
    pub rate_hz: f64,
    pub vbus_v: f64,
    pub ibus_ua: f64,
    /// The meter's own 1 s average (updates once a second), if it reports one.
    pub meter_avg_ua: Option<f64>,
    /// Average over the window ending now; `None` until a full window has
    /// been measured.
    pub window_ua: Option<f64>,
    pub mean_ua: f64,
    pub std_ua: f64,
    pub min_ua: f64,
    pub max_ua: f64,
    /// Largest window average magnitude, and when (elapsed s) it ended.
    pub worst_ua: Option<f64>,
    pub worst_at_s: Option<f64>,
    /// Largest magnitude of the meter's own 1 s averages since the start.
    pub worst_meter_ua: Option<f64>,
    pub offset_ua: f64,
    pub window_s: f64,
}

impl Meter {
    /// A meter averaging over `window_us` that subtracts `offset_ua` from
    /// every reading.
    pub fn new(window_us: u64, offset_ua: f64) -> Self {
        Meter {
            window_us: window_us.max(1),
            offset_ua,
            start_us: None,
            window: VecDeque::new(),
            window_sum: 0,
            n: 0,
            mean: 0.0,
            m2: 0.0,
            min: 0.0,
            max: 0.0,
            worst: None,
            worst_meter: None,
            meter_avg_fresh: false,
            last: None,
        }
    }

    pub fn offset_ua(&self) -> f64 {
        self.offset_ua
    }

    pub fn window_us(&self) -> u64 {
        self.window_us
    }

    /// Discard all statistics, keeping the window and offset.
    pub fn reset(&mut self) {
        *self = Meter::new(self.window_us, self.offset_ua);
    }

    /// Change the zero offset; statistics restart.
    pub fn set_offset(&mut self, offset_ua: f64) {
        self.offset_ua = offset_ua;
        self.reset();
    }

    /// Change the averaging window; statistics restart.
    pub fn set_window(&mut self, window_us: u64) {
        self.window_us = window_us.max(1);
        self.reset();
    }

    /// Take the mean measured so far as the new zero (on top of the current
    /// offset) and restart. Returns the new offset, or `None` (and changes
    /// nothing) if there are no readings yet.
    pub fn zero(&mut self) -> Option<f64> {
        if self.n == 0 {
            return None;
        }
        self.set_offset(self.offset_ua + self.mean);
        Some(self.offset_ua)
    }

    /// Add a reading taken at `t_us`.
    pub fn push(&mut self, t_us: u64, s: impl Into<Sample>) {
        let s: Sample = s.into();
        let start = *self.start_us.get_or_insert(t_us);
        self.window.push_back((t_us, s.ibus_ua));
        self.window_sum += s.ibus_ua as i64;
        while let Some(&(t, v)) = self.window.front() {
            if t + self.window_us <= t_us {
                self.window.pop_front();
                self.window_sum -= v as i64;
            } else {
                break;
            }
        }

        let x = s.ibus_ua as f64 - self.offset_ua;
        self.n += 1;
        if self.n == 1 {
            self.min = x;
            self.max = x;
        } else {
            self.min = self.min.min(x);
            self.max = self.max.max(x);
        }
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (x - self.mean);

        if let Some(avg) = self.window_avg(t_us) {
            if self.worst.map_or(true, |(w, _)| avg.abs() > w) {
                self.worst = Some((avg.abs(), t_us - start));
            }
        }

        // The meter's average at the start covers a second before it.
        if let Some((_, prev)) = self.last {
            self.meter_avg_fresh |= prev.ibus_avg_ua != s.ibus_avg_ua;
        }
        if let (true, Some(avg)) = (self.meter_avg_fresh, s.ibus_avg_ua) {
            let avg = (avg as f64 - self.offset_ua).abs();
            self.worst_meter = Some(self.worst_meter.map_or(avg, |w| w.max(avg)));
        }
        self.last = Some((t_us, s));
    }

    /// The window average at `now_us`, once a whole window has elapsed.
    fn window_avg(&self, now_us: u64) -> Option<f64> {
        let start = self.start_us?;
        if now_us.saturating_sub(start) < self.window_us || self.window.is_empty() {
            return None;
        }
        Some(self.window_sum as f64 / self.window.len() as f64 - self.offset_ua)
    }

    /// Compare the worst averages with `limit_ua` (a magnitude): fail if
    /// either cedar's window or the meter's own 1 s average exceeded it.
    pub fn verdict(&self, limit_ua: f64) -> Verdict {
        let ours = self.worst.map(|(w, _)| w);
        if ours
            .into_iter()
            .chain(self.worst_meter)
            .any(|w| w >= limit_ua)
        {
            return Verdict::Fail;
        }
        match ours {
            None => Verdict::Pending,
            Some(_) => Verdict::Pass,
        }
    }

    /// The current figures, or `None` before the first reading.
    pub fn reading(&self) -> Option<Reading> {
        let (t, s) = self.last?;
        let start = self.start_us?;
        let elapsed_us = t - start;
        let elapsed_s = elapsed_us as f64 / 1e6;
        Some(Reading {
            elapsed_s,
            samples: self.n,
            rate_hz: if elapsed_us > 0 {
                (self.n - 1) as f64 / elapsed_s
            } else {
                0.0
            },
            vbus_v: s.vbus_uv as f64 / 1e6,
            ibus_ua: s.ibus_ua as f64 - self.offset_ua,
            meter_avg_ua: s.ibus_avg_ua.map(|a| a as f64 - self.offset_ua),
            window_ua: self.window_avg(t),
            mean_ua: self.mean,
            std_ua: if self.n > 1 {
                (self.m2 / (self.n - 1) as f64).sqrt()
            } else {
                0.0
            },
            min_ua: self.min,
            max_ua: self.max,
            worst_ua: self.worst.map(|(w, _)| w),
            worst_at_s: self.worst.map(|(_, at)| at as f64 / 1e6),
            worst_meter_ua: self.worst_meter,
            offset_ua: self.offset_ua,
            window_s: self.window_us as f64 / 1e6,
        })
    }
}

impl Reading {
    /// The reading as a JSON object (for the web UI).
    pub fn json(&self) -> String {
        let opt = |v: Option<f64>| v.map_or("null".to_string(), |v| format!("{v:.1}"));
        format!(
            concat!(
                "{{\"elapsed\":{:.3},\"samples\":{},\"rate\":{:.1},\"vbus\":{:.6},",
                "\"ibus\":{:.1},\"meterAvg\":{},\"window\":{},",
                "\"mean\":{:.1},\"std\":{:.1},\"min\":{:.1},\"max\":{:.1},",
                "\"worst\":{},\"worstAt\":{},\"worstMeter\":{},",
                "\"offset\":{:.1},\"windowS\":{}}}"
            ),
            self.elapsed_s,
            self.samples,
            self.rate_hz,
            self.vbus_v,
            self.ibus_ua,
            opt(self.meter_avg_ua),
            opt(self.window_ua),
            self.mean_ua,
            self.std_ua,
            self.min_ua,
            self.max_ua,
            opt(self.worst_ua),
            self.worst_at_s
                .map_or("null".to_string(), |v| format!("{v:.3}")),
            opt(self.worst_meter_ua),
            self.offset_ua,
            self.window_s,
        )
    }

    /// The live status lines for the CLI.
    pub fn status_lines(&self, limit_ua: Option<f64>, verdict: Verdict) -> Vec<String> {
        let w = fmt_secs(self.window_s);
        vec![
            format!(
                "  now: {}   {w} avg: {}{}   VBUS {:.3} V",
                ma(self.ibus_ua),
                self.window_ua.map_or("(filling)".to_string(), ma),
                self.meter_avg_ua
                    .map_or(String::new(), |a| format!("   meter 1 s avg: {}", ma(a))),
                self.vbus_v,
            ),
            format!(
                "  mean: {}   std dev: {}   min: {}   max: {}",
                ma(self.mean_ua),
                ma(self.std_ua),
                ma(self.min_ua),
                ma(self.max_ua),
            ),
            format!(
                "  worst {w} avg: {}{}{}",
                self.worst_ua.map_or("(filling)".to_string(), ma),
                self.worst_at_s
                    .map_or(String::new(), |t| format!(" at {t:.1} s")),
                match (self.meter_avg_ua, self.worst_meter_ua) {
                    (None, _) => String::new(),
                    (Some(_), w) => format!(
                        "   worst meter 1 s avg: {}",
                        w.map_or("(waiting)".to_string(), ma)
                    ),
                },
            ),
            format!(
                "  {}   offset: {}   {} readings, {:.0}/s, {:.0} s",
                match limit_ua {
                    Some(l) => format!("limit {}: {}", ma(l), verdict_text(verdict)),
                    None => "no limit set".to_string(),
                },
                ma(self.offset_ua),
                self.samples,
                self.rate_hz,
                self.elapsed_s,
            ),
        ]
    }

    /// The end-of-run summary for the CLI.
    pub fn summary(&self, limit_ua: Option<f64>, verdict: Verdict) -> String {
        let w = fmt_secs(self.window_s);
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} readings over {:.1} s ({:.0}/s), VBUS {:.3} V",
            self.samples, self.elapsed_s, self.rate_hz, self.vbus_v
        );
        let _ = writeln!(
            out,
            "  mean {}   std dev {}   min {}   max {}",
            ma(self.mean_ua),
            ma(self.std_ua),
            ma(self.min_ua),
            ma(self.max_ua)
        );
        match self.worst_ua {
            Some(worst) => {
                let _ = writeln!(out, "  worst {w} average {}", ma(worst));
            }
            None => {
                let _ = writeln!(out, "  worst {w} average: run was shorter than {w}");
            }
        }
        if let Some(worst) = self.worst_meter_ua {
            let _ = writeln!(out, "  worst meter 1 s average {}", ma(worst));
        }
        if self.offset_ua != 0.0 {
            let _ = writeln!(out, "  (offset {} subtracted)", ma(self.offset_ua));
        }
        if let Some(l) = limit_ua {
            let _ = writeln!(out, "Limit {}: {}", ma(l), verdict_text(verdict));
        }
        out
    }
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::Pending => "waiting for a full window",
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
    }
}

/// Format µA as mA with µA resolution.
pub fn ma(ua: f64) -> String {
    format!("{:.3} mA", ua / 1000.0)
}

fn fmt_secs(s: f64) -> String {
    if s.fract() == 0.0 {
        format!("{s:.0} s")
    } else {
        format!("{s} s")
    }
}

/// Parse a current such as `2.5mA`, `2500uA`, `2500µA` or `0.0025A`. A bare
/// number is taken as mA. Returns µA.
pub fn parse_current(s: &str) -> Result<f64, String> {
    let t = s.trim();
    let lower = t.to_ascii_lowercase();
    let (num, scale) = if let Some(n) = lower.strip_suffix("ma") {
        (n, 1e3)
    } else if let Some(n) = lower.strip_suffix("ua") {
        (n, 1.0)
    } else if let Some(n) = t.strip_suffix("µA").or_else(|| t.strip_suffix("μA")) {
        (n, 1.0)
    } else if let Some(n) = lower.strip_suffix('a') {
        (n, 1e6)
    } else {
        (lower.as_str(), 1e3)
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid current {s:?} (try 2.5mA, 2500uA or 0.0025A)"))?;
    if !v.is_finite() {
        return Err(format!("invalid current {s:?}"));
    }
    Ok(v * scale)
}

/// Header of the per-reading CSV log.
pub const CSV_HEADER: &str = "time_s,vbus_v,ibus_ma,ibus_corrected_ma,meter_avg_ma\n";

/// One CSV row for a reading taken `elapsed_us` after the start; `offset_ua`
/// is subtracted in the corrected column. `meter_avg_ma` is empty for meters
/// without their own average.
pub fn csv_row(elapsed_us: u64, s: impl Into<Sample>, offset_ua: f64) -> String {
    let s: Sample = s.into();
    format!(
        "{:.6},{:.6},{:.3},{:.3},{}\n",
        elapsed_us as f64 / 1e6,
        s.vbus_uv as f64 / 1e6,
        s.ibus_ua as f64 / 1000.0,
        (s.ibus_ua as f64 - offset_ua) / 1000.0,
        s.ibus_avg_ua
            .map_or(String::new(), |a| format!("{:.3}", a as f64 / 1000.0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ibus_ua: i32) -> AdcSample {
        AdcSample {
            vbus_uv: 5_000_000,
            ibus_ua,
            vbus_avg_uv: 5_000_000,
            ibus_avg_ua: ibus_ua,
        }
    }

    #[test]
    fn parses_currents() {
        assert_eq!(parse_current("2.5mA"), Ok(2500.0));
        assert_eq!(parse_current("2.5 ma"), Ok(2500.0));
        assert_eq!(parse_current("2500uA"), Ok(2500.0));
        assert_eq!(parse_current("2500µA"), Ok(2500.0));
        assert_eq!(parse_current("0.0025A"), Ok(2500.0));
        assert_eq!(parse_current("2.5"), Ok(2500.0));
        assert_eq!(parse_current("-0.12mA"), Ok(-120.0));
        assert!(parse_current("lots").is_err());
        assert!(parse_current("NaN").is_err());
    }

    #[test]
    fn window_average_and_worst() {
        let mut m = Meter::new(1_000_000, 0.0);
        // 100 Hz: 1 mA for 2 s, then a 0.5 s burst at 4 mA, then 1 mA again.
        for i in 0..400u64 {
            let t = i * 10_000;
            let ua = if (200..250).contains(&i) { 4000 } else { 1000 };
            // The meter's own average stays at 1 mA throughout.
            m.push(
                t,
                AdcSample {
                    ibus_avg_ua: 1000,
                    ..sample(ua)
                },
            );
            if i == 50 {
                assert_eq!(m.reading().unwrap().window_ua, None);
                assert_eq!(m.verdict(2500.0), Verdict::Pending);
            }
        }
        let r = m.reading().unwrap();
        assert_eq!(r.samples, 400);
        assert!((r.rate_hz - 100.0).abs() < 0.01);
        // The worst 1 s window holds the whole burst: 50 × 4 mA + 50 × 1 mA.
        assert!((r.worst_ua.unwrap() - 2500.0).abs() < 1.0, "{r:?}");
        assert!((r.window_ua.unwrap() - 1000.0).abs() < 1e-9);
        assert_eq!(r.max_ua, 4000.0);
        assert_eq!(r.min_ua, 1000.0);
        assert_eq!(m.verdict(2600.0), Verdict::Pass);
        assert_eq!(m.verdict(2400.0), Verdict::Fail);
    }

    #[test]
    fn offset_and_zero() {
        let mut m = Meter::new(1_000_000, 0.0);
        for i in 0..10u64 {
            m.push(i * 10_000, sample(if i % 2 == 0 { 300 } else { 500 }));
        }
        assert_eq!(m.zero(), Some(400.0));
        assert!(m.reading().is_none());
        m.push(0, sample(2400));
        let r = m.reading().unwrap();
        assert_eq!(r.ibus_ua, 2000.0);
        assert_eq!(r.offset_ua, 400.0);

        // Negative currents (power flowing the other way) count by magnitude.
        let mut m = Meter::new(100_000, 0.0);
        for i in 0..20u64 {
            m.push(i * 10_000, sample(-3000));
        }
        assert_eq!(m.verdict(2500.0), Verdict::Fail);
        assert!(m.reading().unwrap().json().contains("\"worst\":3000.0"));
    }

    #[test]
    fn meter_average_fails_the_limit_too() {
        let mut m = Meter::new(1_000_000, 0.0);
        // The meter's first average predates the start and is ignored; a
        // later one above the limit fails even though cedar's readings
        // (which might miss short spikes) stay low.
        for i in 0..200u64 {
            let avg = match i {
                0..=49 => 9000,
                50..=149 => 1000,
                _ => 2600,
            };
            m.push(
                i * 10_000,
                AdcSample {
                    ibus_avg_ua: avg,
                    ..sample(1000)
                },
            );
            if i == 120 {
                assert_eq!(m.verdict(2500.0), Verdict::Pass);
            }
        }
        assert_eq!(m.reading().unwrap().worst_meter_ua, Some(2600.0));
        assert_eq!(m.verdict(2500.0), Verdict::Fail);
    }
}
