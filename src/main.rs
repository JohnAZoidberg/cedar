//! cedar — a command-line capture tool for the Cypress / Infineon CY4500
//! EZ-PD Protocol Analyzer.
//!
//! It starts a capture on the analyzer, streams USB-PD packets and (optionally)
//! the oscilloscope trace, and on Ctrl+C writes the result to a `.ccgx3` or
//! `.csv` file compatible with the original EZ-PD Protocol Analyzer utility.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use cedar::capture;
use cedar::km003c;
use cedar::protocol::Decoder;
use cedar::report;
use cedar::tc66;
use cedar::writer;

#[derive(Parser)]
#[command(name = "cedar", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record a capture until Ctrl+C, then write it to a file.
    Record {
        /// Output file. The extension (.ccgx3 or .csv) selects the format
        /// unless --format is given.
        output: PathBuf,

        /// Output format. Defaults to the output file's extension.
        #[arg(long, value_enum)]
        format: Option<Format>,

        /// Do not capture the oscilloscope (VBUS/CC/current) trace.
        #[arg(long)]
        no_scope: bool,

        /// Also save the KM003C's raw poll responses (one hex line each) to
        /// this file, for debugging and test fixtures.
        #[arg(long, value_name = "FILE")]
        raw: Option<PathBuf>,

        /// Which analyzer to record from. Defaults to whichever is attached
        /// (the CY4500 if both are).
        #[arg(long, value_enum)]
        analyzer: Option<AnalyzerKind>,
    },

    /// Re-decode existing .ccgx3 capture(s) into an HTML report.
    Report {
        /// Capture files to include (each becomes a section in the report).
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output HTML file. Defaults to the input name with a .html extension
        /// (or report.html for multiple inputs).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Print a plain-text decode of existing .ccgx3 capture(s).
    Dump {
        /// Capture files to dump.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Only print packets annotated with a session event.
        #[arg(long)]
        events: bool,

        /// Interleave VBUS/CC level transitions from the scope trace.
        #[arg(long)]
        scope: bool,
    },

    /// Measure current until Ctrl+C with a rolling window average (e.g. for
    /// USB suspend current), using a POWER-Z KM003C (1 µA steps, ~100
    /// readings/s) or a TC66 (10 µA steps, ~2 readings/s).
    Meter {
        /// Which meter to use. Defaults to the KM003C if one is attached,
        /// otherwise a TC66.
        #[arg(long, value_enum)]
        device: Option<MeterKind>,

        /// Pass/fail limit for the worst window average, e.g. 2.5mA, 2500uA
        /// or 0.0025A (a bare number is mA).
        #[arg(long, value_parser = parse_current)]
        limit: Option<f64>,

        /// Averaging window in seconds.
        #[arg(long, default_value_t = 1.0, value_parser = parse_window)]
        window: f64,

        /// Zero offset to subtract from every reading (same units as
        /// --limit). Measure it by running with nothing attached: it is the
        /// mean of that run.
        #[arg(long, value_parser = parse_current, allow_hyphen_values = true, default_value = "0")]
        offset: f64,

        /// Stop after this many seconds instead of waiting for Ctrl+C.
        #[arg(long)]
        duration: Option<f64>,

        /// Also save every reading to this CSV file.
        #[arg(long, value_name = "FILE")]
        csv: Option<PathBuf>,
    },

    /// List attached analyzers and meters (CY4500, POWER-Z KM003C, TC66).
    List,

    /// Print the analyzer's firmware version.
    Version,
}

#[derive(Copy, Clone, ValueEnum)]
enum AnalyzerKind {
    /// Cypress / Infineon CY4500 EZ-PD Protocol Analyzer.
    Cy4500,
    /// ChargerLab POWER-Z KM003C.
    Km003c,
}

#[derive(Copy, Clone, ValueEnum)]
enum MeterKind {
    /// ChargerLab POWER-Z KM003C.
    Km003c,
    /// RuiDeng TC66 / TC66C USB-C meter.
    Tc66,
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    /// Native analyzer format (packets + scope trace) in a ZIP.
    Ccgx3,
    /// Comma-separated packet list.
    Csv,
    /// Self-contained HTML report (VBUS chart + decoded packet table).
    Html,
    /// Write both a .ccgx3 and a .csv next to each other.
    Both,
    /// Write .ccgx3, .csv and .html next to each other.
    All,
}

fn main() {
    env_logger::init();
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::List => list_devices(),
        Command::Version => print_version(),
        Command::Report { inputs, output } => report_captures(&inputs, output),
        Command::Dump {
            inputs,
            events,
            scope,
        } => dump_captures(&inputs, events, scope),
        Command::Meter {
            device,
            limit,
            window,
            offset,
            duration,
            csv,
        } => meter(device, limit, window, offset, duration, csv.as_deref()),
        Command::Record {
            output,
            format,
            no_scope,
            analyzer,
            raw,
        } => record(&output, format, !no_scope, analyzer, raw.as_deref()),
    }
}

fn report_captures(inputs: &[PathBuf], output: Option<PathBuf>) -> Result<()> {
    // Read each capture into owned packet/scope lists, then borrow into datasets.
    let mut loaded = Vec::new();
    for input in inputs {
        let (packets, scope) = cedar::reader::read_ccgx3(input)?;
        let label = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("capture")
            .to_string();
        loaded.push((label, packets, scope));
    }
    let datasets: Vec<report::Dataset> = loaded
        .iter()
        .map(|(label, packets, scope)| report::Dataset {
            label: label.clone(),
            packets,
            scope,
        })
        .collect();

    let out = output.unwrap_or_else(|| match inputs {
        [single] => single.with_extension("html"),
        _ => PathBuf::from("report.html"),
    });
    report::write_html(&out, &datasets)?;
    println!("Wrote {} ({} capture(s))", out.display(), datasets.len());
    Ok(())
}

fn dump_captures(inputs: &[PathBuf], events_only: bool, scope: bool) -> Result<()> {
    let opts = cedar::dump::Options { events_only, scope };
    for (i, input) in inputs.iter().enumerate() {
        let (packets, samples) = cedar::reader::read_ccgx3(input)?;
        if inputs.len() > 1 {
            if i > 0 {
                println!();
            }
            println!("== {} ==", input.display());
        }
        print!("{}", cedar::dump::dump(&packets, &samples, opts));
    }
    Ok(())
}

/// An attached analyzer picked for a capture.
enum Picked {
    Cy4500(rusb::Device<rusb::GlobalContext>),
    Km003c(rusb::Device<rusb::GlobalContext>),
}

fn pick_analyzer(kind: Option<AnalyzerKind>) -> Result<Picked> {
    match kind {
        Some(AnalyzerKind::Cy4500) => Ok(Picked::Cy4500(capture::find_device()?)),
        Some(AnalyzerKind::Km003c) => km003c::find_device()?.map(Picked::Km003c).ok_or_else(|| {
            anyhow::anyhow!(
                "No POWER-Z KM003C found (looking for {:#06x}:{:#06x}).",
                km003c::VID,
                km003c::PID
            )
        }),
        None => match capture::find_device() {
            Ok(dev) => Ok(Picked::Cy4500(dev)),
            Err(cy_err) => match km003c::find_device()? {
                Some(dev) => Ok(Picked::Km003c(dev)),
                None => Err(cy_err.context(format!(
                    "no POWER-Z KM003C found either ({:#06x}:{:#06x})",
                    km003c::VID,
                    km003c::PID
                ))),
            },
        },
    }
}

fn list_devices() -> Result<()> {
    capture::list_devices()?;
    let km = km003c::describe_devices()?;
    if km.is_empty() {
        println!("No POWER-Z KM003C found.");
    }
    for line in km {
        println!("{line}");
    }
    let tc = tc66::describe_devices()?;
    if tc.is_empty() {
        println!("No TC66 found.");
    }
    for line in tc {
        println!("{line}");
    }
    Ok(())
}

fn print_version() -> Result<()> {
    if let Picked::Km003c(dev) = pick_analyzer(None)? {
        let desc = dev.device_descriptor()?;
        let v = desc.device_version();
        println!(
            "POWER-Z KM003C (USB bcdDevice {}.{:02}); firmware version readout is not supported",
            v.major(),
            v.minor() * 10 + v.sub_minor()
        );
        return Ok(());
    }
    let dev = capture::find_device()?;
    let analyzer = capture::Analyzer::open(&dev)?;
    let v = analyzer.version()?;
    println!(
        "Firmware version: {}.{}.{}.{} (raw {:02x} {:02x} {:02x} {:02x})",
        v[0], v[1], v[2], v[3], v[0], v[1], v[2], v[3]
    );
    Ok(())
}

fn record(
    output: &Path,
    format: Option<Format>,
    capture_scope: bool,
    analyzer: Option<AnalyzerKind>,
    raw: Option<&Path>,
) -> Result<()> {
    let format = match format {
        Some(f) => f,
        None => match output.extension().and_then(|e| e.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("ccgx3") => Format::Ccgx3,
            Some(ext) if ext.eq_ignore_ascii_case("csv") => Format::Csv,
            Some(ext) if ext.eq_ignore_ascii_case("html") => Format::Html,
            _ => bail!(
                "cannot infer format from '{}'; pass --format ccgx3|csv|html|both|all",
                output.display()
            ),
        },
    };

    let picked = pick_analyzer(analyzer)?;
    if raw.is_some() && matches!(picked, Picked::Cy4500(_)) {
        bail!("--raw is only supported for the POWER-Z KM003C");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::Relaxed);
    })
    .context("setting Ctrl+C handler")?;

    let mut decoder = Decoder::new();
    match picked {
        Picked::Cy4500(dev) => {
            let analyzer = capture::Analyzer::open(&dev)?;
            println!("Recording from CY4500. Press Ctrl+C to stop and save.");
            analyzer.capture(&mut decoder, capture_scope, &stop)?;
        }
        Picked::Km003c(dev) => {
            let meter = km003c::Km003c::open(&dev)?;
            let mut raw_file = match raw {
                Some(path) => Some(std::io::BufWriter::new(
                    std::fs::File::create(path)
                        .with_context(|| format!("creating {}", path.display()))?,
                )),
                None => None,
            };
            println!("Recording from POWER-Z KM003C. Press Ctrl+C to stop and save.");
            let captured = meter.capture(
                &mut decoder,
                &stop,
                raw_file.as_mut().map(|f| f as &mut dyn std::io::Write),
            );
            if let Some(mut f) = raw_file {
                std::io::Write::flush(&mut f)?;
            }
            captured?;
            // The KM003C's levels come with every PD poll; drop them if unwanted.
            if !capture_scope {
                decoder.scope.clear();
            }
        }
    }

    write_outputs(output, format, &decoder)?;
    Ok(())
}

fn parse_current(s: &str) -> Result<f64, String> {
    cedar::meter::parse_current(s)
}

fn parse_window(s: &str) -> Result<f64, String> {
    match s.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.01 => Ok(v),
        _ => Err(format!("invalid window {s:?} (seconds, at least 0.01)")),
    }
}

/// The meter `cedar meter` reads from.
enum MeterSource {
    Km003c(km003c::Km003c),
    Tc66 {
        meter: tc66::Tc66,
        filter: tc66::RefreshFilter,
        epoch: std::time::Instant,
    },
}

impl MeterSource {
    fn open(kind: Option<MeterKind>) -> Result<Self> {
        let no_km003c = || {
            anyhow::anyhow!(
                "No POWER-Z KM003C found (looking for {:#06x}:{:#06x}).",
                km003c::VID,
                km003c::PID
            )
        };
        let no_tc66 = || {
            anyhow::anyhow!(
                "No TC66 found (looking for a serial port on {:#06x}:{:#06x}).",
                tc66::VID,
                tc66::PID
            )
        };
        let open_km003c = |dev| -> Result<Self> {
            let km = km003c::Km003c::open(&dev)?;
            km.connect()?;
            Ok(MeterSource::Km003c(km))
        };
        let open_tc66 = |port: String| -> Result<Self> {
            Ok(MeterSource::Tc66 {
                meter: tc66::Tc66::open(&port)?,
                filter: tc66::RefreshFilter::new(),
                epoch: std::time::Instant::now(),
            })
        };
        match kind {
            Some(MeterKind::Km003c) => open_km003c(km003c::find_device()?.ok_or_else(no_km003c)?),
            Some(MeterKind::Tc66) => open_tc66(tc66::find_port()?.ok_or_else(no_tc66)?),
            None => {
                if let Some(dev) = km003c::find_device()? {
                    open_km003c(dev)
                } else if let Some(port) = tc66::find_port()? {
                    open_tc66(port)
                } else {
                    bail!(
                        "No meter found: neither a POWER-Z KM003C ({:#06x}:{:#06x}) nor a TC66 ({:#06x}:{:#06x}).",
                        km003c::VID,
                        km003c::PID,
                        tc66::VID,
                        tc66::PID
                    )
                }
            }
        }
    }

    fn name(&self) -> String {
        match self {
            MeterSource::Km003c(_) => "POWER-Z KM003C".to_string(),
            MeterSource::Tc66 { meter, .. } => format!("TC66 on {}", meter.port_name()),
        }
    }

    /// Pause between polls.
    fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(match self {
            MeterSource::Km003c(_) => km003c::POLL_INTERVAL_MS,
            MeterSource::Tc66 { .. } => tc66::POLL_INTERVAL_MS,
        })
    }

    /// Poll the meter: the next reading, or `None` if it has not refreshed
    /// since the last one.
    fn poll(&mut self) -> Result<Option<cedar::meter::Sample>> {
        match self {
            MeterSource::Km003c(km) => Ok(Some(km.poll_adc()?.into())),
            MeterSource::Tc66 {
                meter,
                filter,
                epoch,
            } => {
                let m = meter.measure()?;
                let t_us = epoch.elapsed().as_micros() as u64;
                Ok(filter.is_new(&m, t_us).then(|| (&m).into()))
            }
        }
    }
}

fn meter(
    device: Option<MeterKind>,
    limit: Option<f64>,
    window_s: f64,
    offset_ua: f64,
    duration: Option<f64>,
    csv: Option<&Path>,
) -> Result<()> {
    use cedar::meter::{Meter, CSV_HEADER};
    use std::io::{IsTerminal, Write};
    use std::time::{Duration, Instant};

    let mut source = MeterSource::open(device)?;

    let mut csv_file = match csv {
        Some(path) => {
            let mut f = std::io::BufWriter::new(
                std::fs::File::create(path)
                    .with_context(|| format!("creating {}", path.display()))?,
            );
            f.write_all(CSV_HEADER.as_bytes())?;
            Some(f)
        }
        None => None,
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || stop_handler.store(true, Ordering::Relaxed))
        .context("setting Ctrl+C handler")?;

    println!(
        "Measuring with {}. {}",
        source.name(),
        match duration {
            Some(d) => format!("Stopping after {d} s (or Ctrl+C)."),
            None => "Press Ctrl+C to stop.".to_string(),
        }
    );
    if matches!(source, MeterSource::Tc66 { .. }) && window_s < 5.0 {
        println!(
            "Note: the TC66 refreshes about twice a second in 10 µA steps, so a {window_s} s \
             window averages only ~{:.0} reading(s) and can miss short spikes.",
            (window_s * 1000.0 / tc66::UPDATE_INTERVAL_MS as f64).max(1.0)
        );
    }
    let mut meter = Meter::new((window_s * 1e6).round() as u64, offset_ua);
    let start = Instant::now();
    let tty = std::io::stderr().is_terminal();
    let mut last_draw: Option<Instant> = None;
    let mut drawn_lines = 0usize;
    let draw = |meter: &Meter, drawn_lines: &mut usize| {
        let Some(r) = meter.reading() else { return };
        let verdict = meter.verdict(limit.unwrap_or(f64::INFINITY));
        let lines = r.status_lines(limit, verdict);
        let mut err = std::io::stderr();
        if tty {
            if *drawn_lines > 0 {
                let _ = write!(err, "\x1b[{}A", drawn_lines);
            }
            for line in &lines {
                let _ = write!(err, "\r\x1b[2K{line}\n");
            }
            *drawn_lines = lines.len();
        } else {
            let _ = writeln!(err, "{}", lines[0].trim_start());
        }
        let _ = err.flush();
    };

    let result = (|| -> Result<()> {
        while !stop.load(Ordering::Relaxed) {
            if duration.is_some_and(|d| start.elapsed().as_secs_f64() >= d) {
                break;
            }
            if let Some(sample) = source.poll()? {
                let t_us = start.elapsed().as_micros() as u64;
                meter.push(t_us, sample);
                if let Some(f) = csv_file.as_mut() {
                    f.write_all(cedar::meter::csv_row(t_us, sample, offset_ua).as_bytes())?;
                }
            }
            let interval = if tty {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(2)
            };
            if last_draw.map_or(true, |t| t.elapsed() >= interval) {
                last_draw = Some(Instant::now());
                draw(&meter, &mut drawn_lines);
            }
            std::thread::sleep(source.poll_interval());
        }
        Ok(())
    })();
    if let Some(mut f) = csv_file {
        f.flush()?;
    }
    result?;

    let Some(r) = meter.reading() else {
        bail!("no readings taken");
    };
    let verdict = meter.verdict(limit.unwrap_or(f64::INFINITY));
    if tty {
        draw(&meter, &mut drawn_lines);
    }
    println!();
    print!("{}", r.summary(limit, verdict));
    // A small mean with no offset set looks like a zero-load run.
    if offset_ua == 0.0 && r.mean_ua.abs() < 5000.0 {
        println!(
            "If nothing was attached, this was the zero offset: pass --offset {:.3}mA to subtract it.",
            r.mean_ua / 1000.0
        );
    }
    if let Some(path) = csv {
        println!("Wrote {}", path.display());
    }
    Ok(())
}

fn write_outputs(output: &Path, format: Format, decoder: &Decoder) -> Result<()> {
    let html_label = output
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture")
        .to_string();
    match format {
        Format::Ccgx3 => {
            writer::write_ccgx3(output, &decoder.packets, &decoder.scope)?;
            println!("Wrote {}", output.display());
        }
        Format::Csv => {
            writer::write_csv(output, &decoder.packets)?;
            println!("Wrote {}", output.display());
        }
        Format::Html => {
            let ds = vec![report::Dataset {
                label: html_label,
                packets: &decoder.packets,
                scope: &decoder.scope,
            }];
            report::write_html(output, &ds)?;
            println!("Wrote {}", output.display());
        }
        Format::Both => {
            let ccgx3 = output.with_extension("ccgx3");
            let csv = output.with_extension("csv");
            writer::write_ccgx3(&ccgx3, &decoder.packets, &decoder.scope)?;
            writer::write_csv(&csv, &decoder.packets)?;
            println!("Wrote {} and {}", ccgx3.display(), csv.display());
        }
        Format::All => {
            let ccgx3 = output.with_extension("ccgx3");
            let csv = output.with_extension("csv");
            let html = output.with_extension("html");
            writer::write_ccgx3(&ccgx3, &decoder.packets, &decoder.scope)?;
            writer::write_csv(&csv, &decoder.packets)?;
            let ds = vec![report::Dataset {
                label: html_label,
                packets: &decoder.packets,
                scope: &decoder.scope,
            }];
            report::write_html(&html, &ds)?;
            println!(
                "Wrote {}, {} and {}",
                ccgx3.display(),
                csv.display(),
                html.display()
            );
        }
    }
    Ok(())
}
