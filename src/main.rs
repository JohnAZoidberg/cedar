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
use cedar::protocol::Decoder;
use cedar::report;
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

    /// List attached CY4500 analyzers.
    List,

    /// Print the analyzer's firmware version.
    Version,
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
        Command::List => capture::list_devices(),
        Command::Version => print_version(),
        Command::Report { inputs, output } => report_captures(&inputs, output),
        Command::Record {
            output,
            format,
            no_scope,
        } => record(&output, format, !no_scope),
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

fn print_version() -> Result<()> {
    let dev = capture::find_device()?;
    let analyzer = capture::Analyzer::open(&dev)?;
    let v = analyzer.version()?;
    println!(
        "Firmware version: {}.{}.{}.{} (raw {:02x} {:02x} {:02x} {:02x})",
        v[0], v[1], v[2], v[3], v[0], v[1], v[2], v[3]
    );
    Ok(())
}

fn record(output: &Path, format: Option<Format>, capture_scope: bool) -> Result<()> {
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

    let dev = capture::find_device()?;
    let analyzer = capture::Analyzer::open(&dev)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::Relaxed);
    })
    .context("setting Ctrl+C handler")?;

    println!("Recording. Press Ctrl+C to stop and save.");
    let mut decoder = Decoder::new();
    analyzer.capture(&mut decoder, capture_scope, &stop)?;

    write_outputs(output, format, &decoder)?;
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
