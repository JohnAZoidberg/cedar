//! Session-level analysis of a capture: derive the negotiated PD contract, the
//! attached cable's capabilities, and the port partner's identity by walking
//! the packet stream, and emit a per-packet event annotation on the packets
//! where something significant happens (attach/detach, cable/partner
//! discovered, contract established/changed/dropped, resets, EPR entry).
//!
//! Both the live capture display and the HTML report consume this.

use crate::pd_decode::{bit, bits, parse_data_words, parse_leading_hex, pin_letters};
use crate::protocol::Packet;

/// A significant transition, annotating one packet.
#[derive(Debug, Clone)]
pub struct Event {
    pub emoji: &'static str,
    pub text: String,
}

/// High-level summary of a whole capture.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub cable: Option<String>,
    pub partner: Option<String>,
    /// Vendor from a MANUFACTURER_INFO response (often the local device, which
    /// can differ from the Discover-Identity partner).
    pub manufacturer: Option<String>,
    /// DisplayPort alt-mode state, if entered (pin assignment + HPD).
    pub display: Option<String>,
    /// The current contract, or the last one seen with a "(dropped)" note.
    pub contract: Option<String>,
}

/// Result of analysing a capture: a per-packet event list (aligned to the
/// packet slice, mostly `None`) and the overall summary.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub events: Vec<Option<Event>>,
    pub summary: Summary,
}

const PRODUCT_TYPE_UFP: [&str; 8] = [
    "UNDEFINED",
    "PDUSB_HUB",
    "PDUSB_PERIPHERAL",
    "PSD",
    "RSVD4",
    "AMA",
    "VPD",
    "RSVD7",
];
const PRODUCT_TYPE_DFP: [&str; 8] = [
    "RSVD0",
    "PDUSB_HUB",
    "PDUSB_HOST",
    "POWER_BRICK",
    "ALTERNATE_MODE_CONTROLLER",
    "RSVD5",
    "RSVD6",
    "RSVD7",
];
const CABLE_MAX_VOLT: [&str; 4] = ["20 V", "30 V", "40 V", "50 V"];
const CABLE_SS: [&str; 8] = [
    "USB 2.0",
    "USB 3.2 Gen1",
    "USB 3.2 Gen1/Gen2",
    "USB4 Gen3",
    "USB4 Gen4",
    "USB ?",
    "USB ?",
    "USB ?",
];

fn volts(mv: u32, decimals: bool) -> String {
    if !decimals && mv % 1000 == 0 {
        format!("{} V", mv / 1000)
    } else {
        format!("{:.1} V", mv as f64 / 1000.0)
    }
}

fn amps(ma: u32, decimals: bool) -> String {
    if !decimals && ma % 1000 == 0 {
        format!("{} A", ma / 1000)
    } else {
        format!("{:.1} A", ma as f64 / 1000.0)
    }
}

/// A source PDO remembered from `SOURCE_CAPABILITIES`, for resolving requests.
#[derive(Clone, Copy)]
struct Pdo {
    supply: u32,
    volt_mv: u32,
}

#[derive(Default)]
struct State {
    offered: Vec<Pdo>, // by 1-based position: offered[pos - 1]
    pending: Option<String>,
    active: Option<String>,
    last: Option<String>,
    epr_active: bool,
    cable: Option<String>,
    partner: Option<String>,
    manufacturer: Option<String>,
    dp_entered: bool,
    dp_pin: Option<String>,
    dp_hpd: Option<bool>,
    dp_discovered: bool,            // a DisplayPort Discover Modes ACK was seen
    dp_discover_idx: Option<usize>, // packet index of that ACK
}

/// Analyse a capture. `events[i]` corresponds to `packets[i]`.
pub fn analyze(packets: &[Packet]) -> Session {
    let mut st = State::default();
    let mut events: Vec<Option<Event>> = Vec::with_capacity(packets.len());

    for (i, p) in packets.iter().enumerate() {
        // Fall back to leading-header words for extended messages (whose `data`
        // string ends in a "N bytes ..." description) when pktData is present.
        let words = parse_data_words(&p.data).or_else(|| {
            (!p.pkt_data.is_empty())
                .then(|| parse_leading_hex(&p.data))
                .flatten()
        });
        let ev = step(&mut st, p, i, words.as_deref());
        events.push(ev);
    }

    // DisplayPort was offered but never entered — annotate the Discover Modes
    // ACK packet so the failure is visible in the timeline.
    if st.dp_discovered && !st.dp_entered {
        if let Some(idx) = st.dp_discover_idx {
            if events[idx].is_none() {
                events[idx] = Some(ev("🖥️", "DisplayPort discovered but not entered"));
            }
        }
    }

    let contract = st
        .active
        .clone()
        .or_else(|| st.last.map(|c| format!("{c} (dropped)")));
    let display = if st.dp_entered {
        let mut s = "DisplayPort".to_string();
        if let Some(pin) = &st.dp_pin {
            s.push_str(&format!(" — pin {pin}"));
        }
        if let Some(hpd) = st.dp_hpd {
            s.push_str(&format!(", HPD {}", if hpd { "high" } else { "low" }));
        }
        Some(s)
    } else if st.dp_discovered {
        // The display advertised DisplayPort but the port never entered it —
        // often because the cable can't carry it (e.g. a USB 2.0 cable).
        Some("advertised by display but not entered".to_string())
    } else {
        None
    };

    Session {
        events,
        summary: Summary {
            cable: st.cable,
            partner: st.partner,
            manufacturer: st.manufacturer,
            display,
            contract,
        },
    }
}

fn step(st: &mut State, p: &Packet, idx: usize, words: Option<&[u32]>) -> Option<Event> {
    // VBUS attach/detach events carry no PD message.
    match p.ok.as_str() {
        "VBUS_UP" => return Some(ev("🟢", "Attach (VBUS up)")),
        "VBUS_DN" => {
            let dropped = st.active.take().is_some();
            return Some(ev(
                "🔴",
                if dropped {
                    "Detach — contract dropped"
                } else {
                    "Detach (VBUS down)"
                },
            ));
        }
        _ => {}
    }

    if p.sop == "HARD_RESET" {
        st.active = None;
        return Some(ev("💥", "Hard Reset"));
    }

    let words = words?;
    let is_sop = p.sop == "SOP";

    match p.msg.as_str() {
        "SOURCE_CAPABILITIES" if is_sop => {
            st.offered = parse_source_caps(words);
            None
        }
        "REQUEST" if is_sop => {
            st.pending = Some(describe_request(st, words));
            None
        }
        "PS_RDY" if is_sop => {
            let pending = st.pending.take()?;
            let full = if st.epr_active {
                format!("{pending}, EPR")
            } else {
                pending
            };
            let changed = st.active.as_deref().is_some_and(|a| a != full);
            st.active = Some(full.clone());
            st.last = Some(full.clone());
            Some(ev(
                "⚡",
                if changed {
                    format!("Contract changed → {full}")
                } else {
                    format!("Contract: {full}")
                },
            ))
        }
        "REJECT" if is_sop => {
            st.pending = None;
            Some(ev("🚫", "Request rejected"))
        }
        "WAIT" if is_sop => Some(ev("⏳", "Wait")),
        "SOFT_RESET" if is_sop => Some(ev("🔄", "Soft Reset")),
        "EPR_MODE" if is_sop && words.len() > 1 => {
            let action = bits(words[1], 31, 24);
            match action {
                3 => {
                    st.epr_active = true;
                    Some(ev("🔋", "EPR mode entered"))
                }
                5 => {
                    st.epr_active = false;
                    Some(ev("🔋", "EPR mode exited"))
                }
                _ => None,
            }
        }
        "VENDOR_DEFINED" => vdm_event(st, p, idx, words),
        "ENTER_USB" if words.len() > 1 => {
            let mode = match bits(words[1], 30, 28) {
                0 => "USB 2.0",
                1 => "USB 3.2",
                2 => "USB4",
                _ => "USB",
            };
            Some(ev("🔗", format!("Enter USB: {mode}")))
        }
        "MANUFACTURER_INFO" => {
            let mfr = manufacturer_string(&p.pkt_data)?;
            if st.manufacturer.is_some() {
                return None;
            }
            st.manufacturer = Some(mfr.clone());
            Some(ev("🏭", format!("Manufacturer: {mfr}")))
        }
        _ => None,
    }
}

/// Extract the manufacturer string from a MANUFACTURER_INFO record's `pktData`
/// (VID at offset 22, PID at 24, then a NUL-terminated string from 26).
fn manufacturer_string(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 27 {
        return None;
    }
    let ext_hdr = u16::from_le_bytes([pkt[20], pkt[21]]);
    let data_bytes = (ext_hdr & 0x1ff) as usize;
    let end = (22 + data_bytes).min(pkt.len());
    if end <= 26 {
        return None;
    }
    let bytes: &[u8] = pkt[26..end].split(|&b| b == 0).next().unwrap_or(&[]);
    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn parse_source_caps(words: &[u32]) -> Vec<Pdo> {
    words[1..]
        .iter()
        .map(|&w| {
            let supply = bits(w, 31, 30);
            let volt_mv = match supply {
                0 => bits(w, 19, 10) * 50, // fixed
                2 => bits(w, 29, 20) * 50, // variable (max voltage)
                _ => 0,                    // battery / APDO
            };
            Pdo { supply, volt_mv }
        })
        .collect()
}

fn describe_request(st: &State, words: &[u32]) -> String {
    if words.len() < 2 {
        return "unknown".to_string();
    }
    let rdo = words[1];
    let pos = bits(rdo, 30, 28) as usize;
    let pdo = pos.checked_sub(1).and_then(|i| st.offered.get(i)).copied();
    match pdo.map(|p| p.supply) {
        Some(3) => {
            // PPS/AVS: the RDO carries the requested output voltage/current.
            let mv = bits(rdo, 19, 9) * 20;
            let ma = bits(rdo, 6, 0) * 50;
            format!("{} @ {} (PPS PDO {pos})", volts(mv, true), amps(ma, true))
        }
        Some(supply) => {
            let p = pdo.unwrap();
            let op_ma = bits(rdo, 19, 10) * 10;
            let kind = if supply == 2 { "Variable" } else { "Fixed" };
            format!(
                "{} @ {} ({kind} PDO {pos})",
                volts(p.volt_mv, false),
                amps(op_ma, false)
            )
        }
        None => format!("PDO {pos}"),
    }
}

/// Dispatch a VENDOR_DEFINED (structured VDM) message to the relevant event:
/// alternate-mode entry, DisplayPort configuration, or Discover Identity.
fn vdm_event(st: &mut State, p: &Packet, idx: usize, words: &[u32]) -> Option<Event> {
    if words.len() < 2 {
        return None;
    }
    let vdm = words[1];
    if bit(vdm, 15) == 0 {
        return None; // unstructured VDM
    }
    let svid = bits(vdm, 31, 16);
    let cmd = bits(vdm, 4, 0);
    let ctype = bits(vdm, 7, 6);

    // Track DisplayPort alt-mode state for the summary.
    if svid == 0xFF01 {
        match cmd {
            3 if ctype == 1 => {
                st.dp_discovered = true; // Discover Modes ACK (DP offered)
                st.dp_discover_idx = Some(idx);
            }
            4 if ctype == 1 => st.dp_entered = true, // Enter Mode ACK
            17 if words.len() > 2 => {
                let pins = bits(words[2], 15, 8);
                if pins != 0 {
                    st.dp_pin = Some(pin_letters(pins)); // DP Configure pin assignment
                }
            }
            6 | 16 if words.len() > 2 => st.dp_hpd = Some(bit(words[2], 7) != 0), // DP Status/Attention
            _ => {}
        }
    }

    // Enter Mode ACK — an alternate mode was entered.
    if cmd == 4 && ctype == 1 {
        return Some(ev(
            "🖥️",
            format!("{} alt mode entered", alt_mode_name(svid)),
        ));
    }
    // DisplayPort Configure ACK — the pin assignment / config was applied.
    if cmd == 17 && svid == 0xFF01 && ctype == 1 {
        return Some(ev("🖥️", "DisplayPort configured"));
    }
    // Discover Identity ACK — cable / partner identity.
    discover_identity(st, p, words)
}

fn alt_mode_name(svid: u32) -> String {
    match svid {
        0xFF01 => "DisplayPort".to_string(),
        0x8087 => "Thunderbolt".to_string(),
        s => format!("SVID {s:#06x}"),
    }
}

fn discover_identity(st: &mut State, p: &Packet, words: &[u32]) -> Option<Event> {
    if words.len() < 3 {
        return None;
    }
    let vdm = words[1];
    let structured = bit(vdm, 15) != 0;
    let svid = bits(vdm, 31, 16);
    let cmd = bits(vdm, 4, 0);
    let ctype = bits(vdm, 7, 6);
    if !structured || svid != 0xFF00 || cmd != 1 || ctype != 1 {
        return None; // only Discover Identity ACK
    }
    let id_hdr = words[2];
    let vid = bits(id_hdr, 15, 0);

    if p.sop == "SOP_PRIME" {
        if st.cable.is_some() {
            return None;
        }
        let ptype = bits(id_hdr, 29, 27); // 3 = passive, 4 = active
        let kind = match ptype {
            3 => "Passive",
            4 => "Active",
            _ => "Unknown",
        };
        let mut parts: Vec<String> = Vec::new();
        if words.len() > 5 {
            let vdo = words[5];
            let cur = match bits(vdo, 6, 5) {
                1 => Some("3 A"),
                2 => Some("5 A"),
                _ => None,
            };
            if let Some(c) = cur {
                parts.push(c.to_string());
            }
            parts.push(CABLE_MAX_VOLT[bits(vdo, 10, 9) as usize].to_string());
            if bit(vdo, 17) != 0 {
                parts.push("EPR-capable".to_string());
            }
            parts.push(CABLE_SS[bits(vdo, 2, 0) as usize].to_string());
        }
        let summary = format!("{kind} cable — {} (VID {:#06x})", parts.join(", "), vid);
        st.cable = Some(summary.clone());
        return Some(ev("🔌", format!("Cable: {summary}")));
    }

    if p.sop == "SOP" {
        if st.partner.is_some() {
            return None;
        }
        let ufp = PRODUCT_TYPE_UFP[bits(id_hdr, 29, 27) as usize];
        let dfp = PRODUCT_TYPE_DFP[bits(id_hdr, 25, 23) as usize];
        let role = if ufp != "UNDEFINED" {
            ufp
        } else if !dfp.starts_with("RSVD") {
            dfp
        } else {
            "device"
        };
        let pid = words.get(4).map(|w| bits(*w, 31, 16)).unwrap_or(0);
        let summary = format!("{role} (VID {vid:#06x} PID {pid:#06x})");
        st.partner = Some(summary.clone());
        return Some(ev("🏷️", format!("Partner: {summary}")));
    }

    None
}

fn ev(emoji: &'static str, text: impl Into<String>) -> Event {
    Event {
        emoji,
        text: text.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(sop: &str, msg: &str, ok: &str, data: &str) -> Packet {
        Packet {
            sno: String::new(),
            ok: ok.to_string(),
            sop: sop.to_string(),
            msg: msg.to_string(),
            id: String::new(),
            d_role: String::new(),
            p_role: String::new(),
            count: String::new(),
            rev: String::new(),
            duration: String::new(),
            delta: None,
            vbus: String::new(),
            data: data.to_string(),
            s_time: "0".to_string(),
            e_time: String::new(),
            pkt_data: Vec::new(),
        }
    }

    #[test]
    fn derives_cable_from_discover_identity_ack() {
        // Real SOP' Discover Identity ACK from a Framework EPR cable capture.
        let p = pkt(
            "SOP_PRIME",
            "VENDOR_DEFINED",
            "OK",
            "0x518F 0xFF00A041 0x18000000 0x0 0x0 0xA6640",
        );
        let s = analyze(std::slice::from_ref(&p));
        assert_eq!(
            s.summary.cable.as_deref(),
            Some("Passive cable — 5 A, 50 V, EPR-capable, USB 2.0 (VID 0x0000)")
        );
    }

    #[test]
    fn derives_contract_from_caps_request_psrdy() {
        // Real SOURCE_CAPABILITIES / REQUEST (PDO 5 = 20 V) / PS_RDY sequence.
        let pkts = [
            pkt(
                "SOP",
                "SOURCE_CAPABILITIES",
                "OK",
                "0x71A1 0xA81912C 0x2D12C 0x3C12C 0x4B12C 0x641F4 0xE004B1F4 0xC1A43264",
            ),
            pkt("SOP", "REQUEST", "OK", "0x1082 0x52C7D1F4"),
            pkt("SOP", "PS_RDY", "OK", "0x5A6"),
        ];
        let s = analyze(&pkts);
        assert_eq!(
            s.summary.contract.as_deref(),
            Some("20 V @ 5 A (Fixed PDO 5)")
        );
        // The contract event lands on the PS_RDY packet.
        assert!(s.events[2]
            .as_ref()
            .is_some_and(|e| e.text.contains("Contract: 20 V @ 5 A")));
    }

    #[test]
    fn detach_drops_contract() {
        let pkts = [
            pkt(
                "SOP",
                "SOURCE_CAPABILITIES",
                "OK",
                "0x71A1 0xA81912C 0x2D12C 0x3C12C 0x4B12C 0x641F4 0xE004B1F4 0xC1A43264",
            ),
            pkt("SOP", "REQUEST", "OK", "0x1082 0x52C7D1F4"),
            pkt("SOP", "PS_RDY", "OK", "0x5A6"),
            pkt("SOP", "C_RSVD0", "VBUS_DN", "0x0"),
        ];
        let s = analyze(&pkts);
        assert_eq!(
            s.summary.contract.as_deref(),
            Some("20 V @ 5 A (Fixed PDO 5) (dropped)")
        );
    }

    #[test]
    fn dp_entered_summarizes_pin_and_hpd() {
        // Enter Mode (DP) ACK, DP Configure (DP) with pin D (bit 3 -> 0x08 << 8),
        // DP Status (DP) with HPD high (bit 7).
        let pkts = [
            pkt("SOP", "VENDOR_DEFINED", "OK", "0x1DAF 0xFF018043 0x140045"), // Discover Modes ACK
            pkt("SOP", "VENDOR_DEFINED", "OK", "0x1FAF 0xFF018044"),          // Enter Mode ACK
            pkt("SOP", "VENDOR_DEFINED", "OK", "0x21AF 0xFF018051 0x800"),    // DP Configure, pin D
            pkt("SOP", "VENDOR_DEFINED", "OK", "0x23AF 0xFF018050 0x80"),     // DP Status, HPD high
        ];
        let s = analyze(&pkts);
        assert_eq!(
            s.summary.display.as_deref(),
            Some("DisplayPort — pin D, HPD high")
        );
    }

    #[test]
    fn dp_discovered_but_not_entered() {
        // DisplayPort modes are discovered but never entered (e.g. a cable that
        // can't carry DP) — surfaced in the summary and as an event.
        let pkts = [
            pkt("SOP", "VENDOR_DEFINED", "OK", "0x1DAF 0xFF018043 0x140045"), // Discover Modes ACK
            pkt("SOP", "SOURCE_CAPABILITIES", "OK", "0x11A1 0x2701912C"),
        ];
        let s = analyze(&pkts);
        assert_eq!(
            s.summary.display.as_deref(),
            Some("advertised by display but not entered")
        );
        assert!(s.events[0]
            .as_ref()
            .is_some_and(|e| e.text == "DisplayPort discovered but not entered"));
    }
}
