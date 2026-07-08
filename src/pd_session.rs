//! Session-level analysis of a capture: derive the negotiated PD contract, the
//! attached cable's capabilities, and the port partner's identity by walking
//! the packet stream, and emit a per-packet event annotation on the packets
//! where something significant happens (attach/detach, cable/partner
//! discovered, contract established/changed/dropped, resets, EPR entry).
//!
//! Both the live capture display and the HTML report consume this.

use crate::pd_decode::{bit, bits, parse_data_words};
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
    "USB ?",
    "USB ?",
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
}

/// Analyse a capture. `events[i]` corresponds to `packets[i]`.
pub fn analyze(packets: &[Packet]) -> Session {
    let mut st = State::default();
    let mut events: Vec<Option<Event>> = Vec::with_capacity(packets.len());

    for p in packets {
        let words = parse_data_words(&p.data);
        let ev = step(&mut st, p, words.as_deref());
        events.push(ev);
    }

    let contract = st
        .active
        .clone()
        .or_else(|| st.last.map(|c| format!("{c} (dropped)")));
    Session {
        events,
        summary: Summary {
            cable: st.cable,
            partner: st.partner,
            contract,
        },
    }
}

fn step(st: &mut State, p: &Packet, words: Option<&[u32]>) -> Option<Event> {
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
        "VENDOR_DEFINED" => discover_identity(st, p, words),
        _ => None,
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
}
