//! HTML report output. Embeds the same self-contained page the reference
//! `parse_ccgx3.py --html` produces (a VBUS-over-time chart plus a filterable,
//! expandable packet table with full PD decode), rendered from data captured by
//! cedar.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::pd_decode::{decode_capture, Detail};
use crate::pd_session::{analyze, Event};
use crate::protocol::Packet;
use crate::writer::utc_stamp;

const TEMPLATE: &str = include_str!("report_template.html");

/// A named capture to include in the report.
pub struct Dataset<'a> {
    pub label: String,
    pub packets: &'a [Packet],
}

/// Write an HTML report covering one or more captures.
pub fn write_html(path: &Path, datasets: &[Dataset]) -> Result<()> {
    let mut json = String::from("[");
    for (i, ds) in datasets.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write_dataset(&mut json, ds);
    }
    json.push(']');
    // Keep the embedded JSON from prematurely closing the <script> element.
    let json = json.replace("</", "<\\/");

    let html = TEMPLATE
        .replace("__DATA__", &json)
        .replace("__STAMP__", &utc_stamp());
    fs::write(path, html).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_dataset(out: &mut String, ds: &Dataset) {
    let session = analyze(ds.packets);
    let decoded = decode_capture(ds.packets);

    out.push_str("{\"label\":");
    push_json_str(out, &ds.label);
    out.push_str(",\"summary\":");
    write_summary(out, &session.summary);
    out.push_str(",\"pkts\":[");
    for (i, (p, dec)) in ds.packets.iter().zip(&decoded).enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_packet(out, p, dec.as_deref(), session.events[i].as_ref());
    }
    out.push_str("]}");
}

fn write_summary(out: &mut String, s: &crate::pd_session::Summary) {
    out.push('{');
    let fields = [
        ("cable", s.cable.as_deref()),
        ("partner", s.partner.as_deref()),
        ("contract", s.contract.as_deref()),
    ];
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(out, k);
        out.push(':');
        match v {
            Some(v) => push_json_str(out, v),
            None => out.push_str("null"),
        }
    }
    out.push('}');
}

fn write_packet(out: &mut String, p: &Packet, dec: Option<&[Detail]>, event: Option<&Event>) {
    out.push('{');
    let fields = [
        ("sno", p.sno.as_str()),
        ("ok", p.ok.as_str()),
        ("sop", p.sop.as_str()),
        ("msg", p.msg.as_str()),
        ("dRole", p.d_role.as_str()),
        ("pRole", p.p_role.as_str()),
        ("rev", p.rev.as_str()),
        ("data", p.data.as_str()),
        ("vbus", p.vbus.as_str()),
        ("sTime", p.s_time.as_str()),
        ("eTime", p.e_time.as_str()),
        ("duration", p.duration.as_str()),
        ("delta", p.delta.as_deref().unwrap_or("")),
        ("count", p.count.as_str()),
    ];
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(out, k);
        out.push(':');
        push_json_str(out, v);
    }
    if let Some(e) = event {
        out.push_str(",\"event\":");
        push_json_str(out, &format!("{} {}", e.emoji, e.text));
    }
    if let Some(details) = dec {
        if !details.is_empty() {
            out.push_str(",\"dec\":");
            write_details(out, details);
        }
    }
    out.push('}');
}

/// Serialize a decode tree to a compact JSON array string
/// (`[{"n":..,"v":..,"s":[..]},..]`), matching the reference report format.
pub fn details_to_json(details: &[Detail]) -> String {
    let mut s = String::new();
    write_details(&mut s, details);
    s
}

fn write_details(out: &mut String, details: &[Detail]) {
    out.push('[');
    for (i, det) in details.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"n\":");
        push_json_str(out, &det.n);
        out.push_str(",\"v\":");
        push_json_str(out, &det.v);
        out.push_str(",\"s\":");
        write_details(out, &det.s);
        out.push('}');
    }
    out.push(']');
}

/// Append a JSON-escaped string literal (including surrounding quotes).
fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
