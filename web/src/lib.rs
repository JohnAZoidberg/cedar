//! WebAssembly bindings for the cedar web UI.
//!
//! The browser owns the USB I/O (WebUSB is promise-based and has no read
//! timeouts, so the transfer loops live in JavaScript); everything else — the
//! CY4500 record decoder, the KM003C request framing and event conversion,
//! session analysis, `.ccgx3`/`.csv`/HTML output and the text dump — is the
//! same Rust code the command-line tool runs.

use std::fmt::Write as _;

use cedar::km003c::{self, Command, Converter};
use cedar::meter::{self, Meter};
use cedar::pd_session::{analyze, Session};
use cedar::protocol::{self, Decoder, GraphSample, Packet};
use cedar::{dump, reader, report, writer};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn console_warn(s: &str);
}

#[wasm_bindgen(start)]
fn start() {
    std::panic::set_hook(Box::new(|info| console_error(&info.to_string())));
}

/// Most recent packet rows returned by one [`Capture::live_json`] call; the
/// live view only shows the tail of a capture.
const MAX_LIVE_ROWS: usize = 500;

/// USB identifiers and endpoints for both analyzers, as JSON, so the
/// JavaScript transport has a single source of truth.
#[wasm_bindgen(js_name = deviceInfo)]
pub fn device_info() -> String {
    format!(
        concat!(
            "{{\"cy4500\":{{\"vid\":{},\"pid\":{},\"pidFirmware\":{},\"epOut\":{},",
            "\"epData\":{},\"epScope\":{},\"epResp\":{},\"maxRead\":{},\"maxScopeRead\":{}}},",
            "\"km003c\":{{\"vid\":{},\"pid\":{},\"interface\":{},\"epOut\":{},\"epIn\":{},",
            "\"pollMs\":{}}}}}"
        ),
        protocol::VID,
        protocol::PID,
        protocol::PID_NO_WINUSB,
        protocol::EP_OUT_CMD,
        protocol::EP_IN_CC_DATA & 0x7f,
        protocol::EP_IN_MEASURE & 0x7f,
        protocol::EP_IN_CMD_RESP & 0x7f,
        protocol::MAX_READ_SIZE,
        protocol::MAX_SCOPE_READ_SIZE,
        km003c::VID,
        km003c::PID,
        km003c::INTERFACE,
        km003c::EP_OUT,
        km003c::EP_IN & 0x7f,
        km003c::POLL_INTERVAL_MS,
    )
}

/// CY4500 `START` command.
#[wasm_bindgen(js_name = cy4500CmdStart)]
pub fn cy4500_cmd_start() -> Vec<u8> {
    protocol::cmd_start().to_vec()
}

/// CY4500 `STOP` command.
#[wasm_bindgen(js_name = cy4500CmdStop)]
pub fn cy4500_cmd_stop() -> Vec<u8> {
    protocol::cmd_stop().to_vec()
}

/// CY4500 `GET_VERSION` command (4-byte answer on the response endpoint).
#[wasm_bindgen(js_name = cy4500CmdVersion)]
pub fn cy4500_cmd_version() -> Vec<u8> {
    protocol::cmd_get_version().to_vec()
}

fn km003c_command(name: &str) -> Result<Command, JsError> {
    Ok(match name {
        "connect" => Command::Connect,
        "monitorOn" => Command::PdMonitorOn,
        "monitorOff" => Command::PdMonitorOff,
        "poll" => Command::PollPd,
        "adc" => Command::PollAdc,
        _ => return Err(JsError::new(&format!("unknown KM003C command {name:?}"))),
    })
}

fn js_err(e: anyhow::Error) -> JsError {
    JsError::new(&format!("{e:#}"))
}

/// Request bytes for KM003C command `name` (`connect`, `monitorOn`,
/// `monitorOff`, `poll`, `adc`) with transaction id `id`.
#[wasm_bindgen(js_name = km003cRequest)]
pub fn km003c_request(name: &str, id: u8) -> Result<Vec<u8>, JsError> {
    Ok(km003c_command(name)?.header(id).to_vec())
}

/// Whether `resp` is a whole response to command `name`.
#[wasm_bindgen(js_name = km003cComplete)]
pub fn km003c_complete(name: &str, resp: &[u8]) -> Result<bool, JsError> {
    km003c_command(name)?
        .response_complete(resp)
        .map_err(js_err)
}

/// Throw if a complete response to command `name` reports a failure.
#[wasm_bindgen(js_name = km003cCheck)]
pub fn km003c_check(name: &str, resp: &[u8]) -> Result<(), JsError> {
    km003c_command(name)?.check_response(resp).map_err(js_err)
}

/// A capture being recorded, or one loaded from a `.ccgx3` file.
#[wasm_bindgen]
pub struct Capture {
    decoder: Decoder,
    converter: Converter,
    /// KM003C poll responses that carried PD events, one hex line each (the
    /// CLI's `--raw` format).
    raw: String,
    /// Session analysis of the first `analyzed` packets.
    session: Session,
    analyzed: usize,
}

impl Default for Capture {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl Capture {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Capture {
        Capture {
            decoder: Decoder::new(),
            converter: Converter::new(),
            raw: String::new(),
            session: Session::default(),
            analyzed: 0,
        }
    }

    /// Load a `.ccgx3` file.
    #[wasm_bindgen(js_name = fromCcgx3)]
    pub fn from_ccgx3(bytes: &[u8]) -> Result<Capture, JsError> {
        let (packets, scope) = reader::read_ccgx3_bytes(bytes).map_err(js_err)?;
        let mut c = Capture::new();
        c.decoder.packets = packets;
        c.decoder.scope = scope;
        Ok(c)
    }

    /// Feed one transfer from the CY4500 CC data endpoint.
    #[wasm_bindgen(js_name = feedCy4500Pd)]
    pub fn feed_cy4500_pd(&mut self, data: &[u8]) {
        self.decoder.feed_pd(data);
    }

    /// Feed one transfer from the CY4500 oscilloscope endpoint.
    #[wasm_bindgen(js_name = feedCy4500Scope)]
    pub fn feed_cy4500_scope(&mut self, data: &[u8]) {
        self.decoder.feed_scope(data);
    }

    /// Feed one complete KM003C `poll` response. A response that cannot be
    /// framed throws; a malformed event payload is logged and skipped, as in
    /// the CLI.
    #[wasm_bindgen(js_name = feedKm003c)]
    pub fn feed_km003c(&mut self, resp: &[u8]) -> Result<(), JsError> {
        let payload = km003c::pd_payload(resp).map_err(js_err)?;
        if payload.len() > km003c::PD_STATUS_SIZE {
            for b in resp {
                let _ = write!(self.raw, "{b:02x}");
            }
            self.raw.push('\n');
        }
        match km003c::parse_pd_payload(payload) {
            Ok((status, events)) => self.converter.feed(&mut self.decoder, &status, &events),
            Err(e) => console_warn(&format!("skipping malformed KM003C PD payload: {e:#}")),
        }
        Ok(())
    }

    /// Discard the oscilloscope trace (the KM003C reports levels with every
    /// poll; this honours "don't record levels").
    #[wasm_bindgen(js_name = clearScope)]
    pub fn clear_scope(&mut self) {
        self.decoder.scope.clear();
    }

    #[wasm_bindgen(getter, js_name = packetCount)]
    pub fn packet_count(&self) -> usize {
        self.decoder.packets.len()
    }

    #[wasm_bindgen(getter, js_name = scopeCount)]
    pub fn scope_count(&self) -> usize {
        self.decoder.scope.len()
    }

    /// Live state as JSON: counts, latest levels, session summary, the most
    /// recent real PD message, and packet rows from index `from` on (at most
    /// the last [`MAX_LIVE_ROWS`]).
    #[wasm_bindgen(js_name = liveJson)]
    pub fn live_json(&mut self, from: usize) -> String {
        let packets = &self.decoder.packets;
        if packets.len() != self.analyzed {
            self.session = analyze(packets);
            self.analyzed = packets.len();
        }
        let s = &self.session.summary;

        let mut out = String::new();
        let _ = write!(
            out,
            "{{\"packets\":{},\"scope\":{}",
            packets.len(),
            self.decoder.scope.len()
        );
        out.push_str(",\"levels\":");
        push_levels(&mut out, self.decoder.scope.last());
        for (k, v) in [
            ("contract", &s.contract),
            ("cable", &s.cable),
            ("partner", &s.partner),
            ("display", &s.display),
        ] {
            let _ = write!(out, ",\"{k}\":");
            push_opt_str(&mut out, v.as_deref());
        }

        out.push_str(",\"last\":");
        match packets.iter().rposition(is_real_message) {
            Some(i) => push_row(&mut out, i, &packets[i], None),
            None => out.push_str("null"),
        }

        out.push_str(",\"rows\":[");
        let from = from.max(packets.len().saturating_sub(MAX_LIVE_ROWS));
        for (n, i) in (from..packets.len()).enumerate() {
            if n > 0 {
                out.push(',');
            }
            let event = self.session.events.get(i).and_then(|e| e.as_ref());
            push_row(
                &mut out,
                i,
                &packets[i],
                event.map(|e| format!("{} {}", e.emoji, e.text)),
            );
        }
        out.push_str("]}");
        out
    }

    /// The capture as a `.ccgx3` file. `unix_secs` names the folder inside the
    /// archive, as the original utility does.
    pub fn ccgx3(&self, unix_secs: f64) -> Result<Vec<u8>, JsError> {
        writer::ccgx3_bytes(
            &self.decoder.packets,
            &self.decoder.scope,
            unix_secs.max(0.0) as u64,
        )
        .map_err(js_err)
    }

    /// The capture as the original utility's CSV export.
    pub fn csv(&self) -> String {
        let mut buf = Vec::new();
        writer::write_csv_to(&mut buf, &self.decoder.packets).expect("writing to a Vec");
        String::from_utf8(buf).expect("CSV is UTF-8")
    }

    /// Plain-text decode, as `cedar dump`.
    pub fn dump(&self, events_only: bool, scope: bool) -> String {
        dump::dump(
            &self.decoder.packets,
            &self.decoder.scope,
            dump::Options { events_only, scope },
        )
    }

    /// KM003C poll responses with PD events, one hex line each (as `cedar
    /// record --raw`). Empty for CY4500 captures.
    #[wasm_bindgen(js_name = rawLog)]
    pub fn raw_log(&self) -> String {
        self.raw.clone()
    }
}

/// Parse a current such as `2.5mA` or `2500uA` (a bare number is mA) to µA.
#[wasm_bindgen(js_name = parseCurrent)]
pub fn parse_current(s: &str) -> Result<f64, JsError> {
    meter::parse_current(s).map_err(|e| JsError::new(&e))
}

/// KM003C current measurement, as `cedar meter`: feed it `adc` responses and
/// read back the windowed statistics. Every reading is also kept as a CSV row.
#[wasm_bindgen(js_name = CurrentMeter)]
pub struct CurrentMeter {
    meter: Meter,
    /// Time of the first reading since the last reset, in ms.
    start_ms: Option<f64>,
    csv: String,
}

#[wasm_bindgen(js_class = CurrentMeter)]
impl CurrentMeter {
    /// A meter averaging over `window_s` seconds that subtracts `offset_ua`.
    #[wasm_bindgen(constructor)]
    pub fn new(window_s: f64, offset_ua: f64) -> CurrentMeter {
        CurrentMeter {
            meter: Meter::new(window_us(window_s), offset_ua),
            start_ms: None,
            csv: String::new(),
        }
    }

    /// Feed one complete `adc` response read at `t_ms` (any monotonic clock,
    /// e.g. `performance.now()`).
    pub fn feed(&mut self, resp: &[u8], t_ms: f64) -> Result<(), JsError> {
        let sample = km003c::adc_sample(resp).map_err(js_err)?;
        let start = *self.start_ms.get_or_insert(t_ms);
        let t_us = ((t_ms - start).max(0.0) * 1000.0).round() as u64;
        self.meter.push(t_us, sample);
        self.csv
            .push_str(&meter::csv_row(t_us, &sample, self.meter.offset_ua()));
        Ok(())
    }

    /// The current figures as JSON (µA, see `cedar::meter::Reading`), or
    /// `null` before the first reading.
    #[wasm_bindgen(js_name = readingJson)]
    pub fn reading_json(&self) -> String {
        self.meter
            .reading()
            .map_or("null".to_string(), |r| r.json())
    }

    /// `pending`, `pass` or `fail` against `limit_ua`.
    pub fn verdict(&self, limit_ua: f64) -> String {
        self.meter.verdict(limit_ua).as_str().to_string()
    }

    /// Take the mean so far as the zero and restart; returns the new offset
    /// in µA, or `undefined` if there were no readings.
    pub fn zero(&mut self) -> Option<f64> {
        let z = self.meter.zero();
        if z.is_some() {
            self.restart();
        }
        z
    }

    #[wasm_bindgen(getter)]
    pub fn offset(&self) -> f64 {
        self.meter.offset_ua()
    }

    #[wasm_bindgen(js_name = setOffset)]
    pub fn set_offset(&mut self, offset_ua: f64) {
        self.meter.set_offset(offset_ua);
        self.restart();
    }

    #[wasm_bindgen(js_name = setWindow)]
    pub fn set_window(&mut self, window_s: f64) {
        self.meter.set_window(window_us(window_s));
        self.restart();
    }

    /// Discard the statistics and the CSV log.
    pub fn reset(&mut self) {
        self.meter.reset();
        self.restart();
    }

    /// Every reading since the last reset, as `cedar meter --csv` writes.
    pub fn csv(&self) -> String {
        format!("{}{}", meter::CSV_HEADER, self.csv)
    }

    fn restart(&mut self) {
        self.start_ms = None;
        self.csv.clear();
    }
}

fn window_us(window_s: f64) -> u64 {
    if window_s.is_finite() && window_s > 0.0 {
        (window_s * 1e6).round() as u64
    } else {
        meter::DEFAULT_WINDOW_US
    }
}

/// Builds one HTML report from several captures, like `cedar report a b`.
#[wasm_bindgen]
#[derive(Default)]
pub struct Report {
    datasets: Vec<(String, Vec<Packet>, Vec<GraphSample>)>,
}

#[wasm_bindgen]
impl Report {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Report {
        Report::default()
    }

    /// Add a capture as a section titled `label`.
    pub fn add(&mut self, label: String, capture: &Capture) {
        self.datasets.push((
            label,
            capture.decoder.packets.clone(),
            capture.decoder.scope.clone(),
        ));
    }

    /// Render the self-contained report page. `unix_secs` is shown as the
    /// generation time.
    pub fn html(&self, unix_secs: f64) -> String {
        let datasets: Vec<report::Dataset> = self
            .datasets
            .iter()
            .map(|(label, packets, scope)| report::Dataset {
                label: label.clone(),
                packets,
                scope,
            })
            .collect();
        report::render_html(&datasets, &writer::utc_stamp_at(unix_secs.max(0.0) as u64))
    }
}

fn push_levels(out: &mut String, s: Option<&GraphSample>) {
    match s {
        Some(s) => {
            let _ = write!(
                out,
                "{{\"vbus\":{},\"ibus\":{},\"cc1\":{},\"cc2\":{}}}",
                s.volt, s.amp, s.cc1, s.cc2
            );
        }
        None => out.push_str("null"),
    }
}

fn push_row(out: &mut String, i: usize, p: &Packet, event: Option<String>) {
    let _ = write!(out, "{{\"i\":{i}");
    for (k, v) in [
        ("ok", &p.ok),
        ("sop", &p.sop),
        ("msg", &p.msg),
        ("vbus", &p.vbus),
        ("t", &p.s_time),
        ("data", &p.data),
    ] {
        let _ = write!(out, ",\"{k}\":");
        push_str(out, v);
    }
    if let Some(e) = event {
        out.push_str(",\"event\":");
        push_str(out, &e);
    }
    out.push('}');
}

/// Whether a packet is a real PD message rather than an attach/detach marker,
/// GoodCRC or reserved placeholder (mirrors the CLI's live status line).
fn is_real_message(p: &Packet) -> bool {
    if p.ok == "VBUS_UP" || p.ok == "VBUS_DN" {
        return false;
    }
    let m = &p.msg;
    m != "GOODCRC"
        && !m.starts_with("C_RSVD")
        && !m.starts_with("D_RSVD")
        && !m.starts_with("E_RSVD")
}

fn push_opt_str(out: &mut String, s: Option<&str>) {
    match s {
        Some(s) => push_str(out, s),
        None => out.push_str("null"),
    }
}

/// Append a JSON string literal.
fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
