//! Plain-text dump of a capture for reading in a terminal or diffing: the
//! session summary, then one line per packet (time, SOP, message, roles, VBUS,
//! data words, VDM summary, session event), optionally interleaved with the
//! VBUS/CC level transitions seen in the oscilloscope trace.

use std::fmt::Write;

use crate::pd_decode::{parse_data_words, vdm_summary};
use crate::pd_session::{analyze, Event};
use crate::protocol::{GraphSample, Packet};

/// What to include in the dump.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Only print packets that carry a session event.
    pub events_only: bool,
    /// Interleave VBUS/CC transitions from the scope trace.
    pub scope: bool,
}

/// Samples a new CC/VBUS level must persist for before it is reported, so BMC
/// traffic on CC and brief ripple on VBUS do not show up as transitions.
const DEBOUNCE: usize = 8;

/// Render the dump of one capture.
pub fn dump(packets: &[Packet], scope: &[GraphSample], opts: Options) -> String {
    let session = analyze(packets);
    let mut out = String::new();

    let s = &session.summary;
    let _ = writeln!(out, "SUMMARY");
    for (name, v) in [
        ("cable", &s.cable),
        ("partner", &s.partner),
        ("manufacturer", &s.manufacturer),
        ("display", &s.display),
        ("contract", &s.contract),
    ] {
        let _ = writeln!(out, "  {name:<13} {}", v.as_deref().unwrap_or("-"));
    }
    let _ = writeln!(
        out,
        "  {:<13} {} packets, {} scope samples",
        "size",
        packets.len(),
        scope.len()
    );
    if let (Some(first), Some(last)) = (scope.first(), scope.last()) {
        let _ = writeln!(
            out,
            "  {:<13} {} .. {}",
            "scope span",
            fmt_time(first.time_stamp),
            fmt_time(last.time_stamp)
        );
    }
    let _ = writeln!(out);

    let mut lines: Vec<(i64, String)> = Vec::new();
    for (p, ev) in packets.iter().zip(&session.events) {
        if opts.events_only && ev.is_none() {
            continue;
        }
        let t = p.s_time.replace(',', "").parse::<i64>().unwrap_or(0);
        lines.push((t, packet_line(t, p, ev.as_ref())));
    }
    if opts.scope {
        lines.extend(scope_transitions(scope));
    }
    // Stable sort keeps packet order for equal timestamps.
    lines.sort_by_key(|(t, _)| *t);
    for (_, l) in lines {
        let _ = writeln!(out, "{l}");
    }
    out
}

fn packet_line(t: i64, p: &Packet, ev: Option<&Event>) -> String {
    let mut l = format!(
        "{}  #{:<5} {:<9} {:<22} {:>3}/{:<3} {:>6} mV  {}",
        fmt_time(t),
        p.sno,
        p.sop,
        if p.ok == "OK" {
            p.msg.clone()
        } else {
            p.ok.clone()
        },
        p.p_role,
        p.d_role,
        p.vbus,
        p.data,
    );
    if let Some(v) = parse_data_words(&p.data)
        .filter(|_| p.msg == "VENDOR_DEFINED")
        .and_then(|w| vdm_summary(&w))
    {
        let _ = write!(l, "  [{v}]");
    }
    if let Some(e) = ev {
        let _ = write!(l, "  {} {}", e.emoji, e.text);
    }
    l
}

/// Seconds with microsecond resolution.
fn fmt_time(us: i64) -> String {
    format!("{:>10.6}s", us as f64 / 1e6)
}

/// Coarse VBUS level, in the vSafe0V / vSafe5V terms of the Type-C spec.
fn vbus_level(mv: i16) -> &'static str {
    match mv {
        ..=800 => "vSafe0V",
        801..=3999 => "between",
        _ => "present",
    }
}

/// Coarse CC level as seen with Rp on the source and Rd on the sink.
fn cc_level(mv: i16) -> &'static str {
    match mv {
        ..=199 => "open/Ra",
        200..=659 => "Rd·Default",
        660..=1229 => "Rd·1.5A",
        1230..=2179 => "Rd·3A",
        _ => "Rp-open",
    }
}

/// Debounced level transitions of VBUS, CC1 and CC2.
fn scope_transitions(scope: &[GraphSample]) -> Vec<(i64, String)> {
    type Probe = (
        &'static str,
        fn(&GraphSample) -> i16,
        fn(i16) -> &'static str,
    );
    let probes: [Probe; 3] = [
        ("VBUS", |s| s.volt, vbus_level),
        ("CC1", |s| s.cc1, cc_level),
        ("CC2", |s| s.cc2, cc_level),
    ];
    let mut out = Vec::new();
    for (name, get, level) in probes {
        let Some(first) = scope.first() else { break };
        let mut cur = level(get(first));
        out.push((
            first.time_stamp,
            scope_line(first.time_stamp, name, None, cur, get(first)),
        ));
        let mut i = 0;
        while i < scope.len() {
            let l = level(get(&scope[i]));
            if l != cur {
                let run = scope[i..]
                    .iter()
                    .take(DEBOUNCE)
                    .take_while(|s| level(get(s)) == l)
                    .count();
                if run == DEBOUNCE || i + run == scope.len() {
                    let s = &scope[i];
                    out.push((
                        s.time_stamp,
                        scope_line(s.time_stamp, name, Some(cur), l, get(s)),
                    ));
                    cur = l;
                }
            }
            i += 1;
        }
    }
    out
}

fn scope_line(t: i64, name: &str, from: Option<&str>, to: &str, mv: i16) -> String {
    match from {
        Some(f) => format!("{}  ~ {name:<4} {f} -> {to} ({mv} mV)", fmt_time(t)),
        None => format!("{}  ~ {name:<4} {to} ({mv} mV) at start", fmt_time(t)),
    }
}
