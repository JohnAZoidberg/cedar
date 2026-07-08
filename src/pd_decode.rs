//! USB Power Delivery message decoder.
//!
//! Ported from the Infineon/Cypress EZ-PD Protocol Analyzer's `PDParser`
//! (decompiled from v3.1.0) via the reference `pd_decode.py`, with the same
//! spec-alignment fixes. It works from a packet's `data` hex words (header plus
//! objects, as stored in `.ccgx3` and CSV captures), so no raw byte capture is
//! needed.
//!
//! Each decoded field is a [`Detail`] `{ n: name, v: value, s: sub-fields }`.
//! [`decode_capture`] decodes a whole packet list, tracking
//! `SOURCE_CAPABILITIES` so `REQUEST`/`EPR_REQUEST` RDOs are interpreted against
//! the right PDO type.

use crate::protocol::Packet;

/// One node in a packet's decode tree.
#[derive(Debug, Clone)]
pub struct Detail {
    pub n: String,
    pub v: String,
    pub s: Vec<Detail>,
}

fn d(n: &str, v: impl Into<String>) -> Detail {
    Detail {
        n: n.to_string(),
        v: v.into(),
        s: Vec::new(),
    }
}

fn ds(n: &str, v: impl Into<String>, s: Vec<Detail>) -> Detail {
    Detail {
        n: n.to_string(),
        v: v.into(),
        s,
    }
}

const YESNO: [&str; 2] = ["No", "Yes"];

const CTRL_MSG_TYPE: [&str; 32] = [
    "C_RSVD0",
    "GOODCRC",
    "GOTOMIN",
    "ACCEPT",
    "REJECT",
    "PING",
    "PS_RDY",
    "GET_SOURCE_CAP",
    "GET_SINK_CAP",
    "DR_SWAP",
    "PR_SWAP",
    "VCONN_SWAP",
    "WAIT",
    "SOFT_RESET",
    "DATA_RESET",
    "DATA_RESET_COMPLETE",
    "NOT_SUPPORTED",
    "GET_SOURCE_CAP_EXTENDED",
    "GET_STATUS",
    "FR_SWAP",
    "GET_PPS_STATUS",
    "GET_COUNTRY_CODES",
    "GET_SINK_CAP_EXTENDED",
    "GET_SOURCE_INFO",
    "GET_REVISION",
    "C_RSVD25",
    "C_RSVD26",
    "C_RSVD27",
    "C_RSVD28",
    "C_RSVD29",
    "C_RSVD30",
    "C_RSVD31",
];
const DATA_MSG_TYPE: [&str; 32] = [
    "D_RSVD0",
    "SOURCE_CAPABILITIES",
    "REQUEST",
    "BIST",
    "SINK_CAPABILITIES",
    "BATTERY_STATUS",
    "ALERT",
    "GET_COUNTRY_INFO",
    "ENTER_USB",
    "EPR_REQUEST",
    "EPR_MODE",
    "SOURCE_INFO",
    "REVISION",
    "D_RSVD13",
    "D_RSVD14",
    "VENDOR_DEFINED",
    "D_RSVD16",
    "D_RSVD17",
    "D_RSVD18",
    "D_RSVD19",
    "D_RSVD20",
    "D_RSVD21",
    "D_RSVD22",
    "D_RSVD23",
    "D_RSVD24",
    "D_RSVD25",
    "D_RSVD26",
    "D_RSVD27",
    "D_RSVD28",
    "D_RSVD29",
    "D_RSVD30",
    "D_RSVD31",
];
const EXTD_MSG_TYPE: [&str; 32] = [
    "E_RSVD0",
    "SOURCE_CAPABILITIES_EXTENDED",
    "STATUS",
    "GET_BATTERY_CAP",
    "GET_BATTERY_STATUS",
    "BATTERY_CAPABILITIES",
    "GET_MANUFACTURER_INFO",
    "MANUFACTURER_INFO",
    "SECURITY_REQUEST",
    "SECURITY_RESPONSE",
    "FIRMWARE_UPDATE_REQUEST",
    "FIRMWARE_UPDATE_RESPONSE",
    "PPS_STATUS",
    "COUNTRY_INFO",
    "COUNTRY_CODES",
    "SINK_CAPABILITIES_EXTENDED",
    "EXTENDED_CONTROL_MSG",
    "EPR_SOURCE_CAPABILITIES",
    "EPR_SINK_CAPABILITIES",
    "E_RSVD19",
    "E_RSVD20",
    "E_RSVD21",
    "E_RSVD22",
    "E_RSVD23",
    "E_RSVD24",
    "E_RSVD25",
    "E_RSVD26",
    "E_RSVD27",
    "E_RSVD28",
    "E_RSVD29",
    "E_RSVD30",
    "E_RSVD31",
];

const SUPPLY_TYPE: [&str; 4] = ["FIXED_SUPPLY", "BATTERY_SUPPLY", "VARIABLE_SUPPLY", "APDO"];
const SPEC_REV: [&str; 4] = ["v1", "v2", "v3", "RSVD"];
const PORT_POWER_ROLE: [&str; 2] = ["SNK", "SRC"];
const PORT_DATA_ROLE: [&str; 2] = ["UFP", "DFP"];
const SRC_PEAK_CURRENT: [&str; 4] = [
    "PEAK_EQ_IOC",
    "PEAK_EQ_110_IOC_10ms",
    "PEAK_EQ_125_IOC_10ms",
    "PEAK_EQ_150_IOC_10ms",
];
const SINK_FR_SWAP: [&str; 4] = [
    "FAST_SWAP_NOT_SUPPORTED",
    "CUR_DEF_USB",
    "CUR_1_5A",
    "CUR_3A",
];
const BATT_CHARGING: [&str; 4] = ["CHARGING", "DISCHARGING", "IDLE", "RSVD3"];
const BIST_MODE: [&str; 16] = [
    "RSVD0",
    "RSVD1",
    "RSVD2",
    "RSVD3",
    "RSVD4",
    "BIST_CARRIER_MODE",
    "RSVD6",
    "RSVD7",
    "BIST_TEST_DATA",
    "BIST_SHARED_TEST_MODE_ENTRY",
    "BIST_SHARED_TEST_MODE_EXIT",
    "RSVD11",
    "RSVD12",
    "RSVD13",
    "RSVD14",
    "RSVD15",
];
const VDM_TYPE: [&str; 2] = ["UNSTRUCTURED", "STRUCTURED"];
const SVDM_CMD: [&str; 32] = [
    "RSVD",
    "DISCOVER_IDENTITY",
    "DISCOVER_SVID",
    "DISCOVER_MODES",
    "ENTER_MODE",
    "EXIT_MODE",
    "ATTENTION",
    "RSVD7",
    "RSVD8",
    "RSVD9",
    "RSVD10",
    "RSVD11",
    "RSVD12",
    "RSVD13",
    "RSVD14",
    "RSVD15",
    "DP_STATUS_UPDATE",
    "DP_CONFIGURE",
    "RSVD18",
    "RSVD19",
    "RSVD20",
    "RSVD21",
    "RSVD22",
    "RSVD23",
    "RSVD24",
    "RSVD25",
    "RSVD26",
    "RSVD27",
    "RSVD28",
    "RSVD29",
    "RSVD30",
    "RSVD31",
];
const SVDM_CMD_TYPE: [&str; 4] = ["REQ", "ACK", "NAK", "BUSY"];
const SVDM_VERSION: [&str; 4] = ["VER_1_0", "VER_2_0", "RSVD2", "RSVD3"];
const ID_PRODUCT_TYPE_UFP: [&str; 8] = [
    "UNDEFINED",
    "PDUSB_HUB",
    "PDUSB_PERIPHERAL",
    "PSD",
    "RSVD4",
    "AMA",
    "VPD",
    "RSVD7",
];
const ID_PRODUCT_TYPE_DFP: [&str; 8] = [
    "RSVD0",
    "PDUSB_HUB",
    "PDUSB_HOST",
    "POWER_BRICK",
    "ALTERNATE_MODE_CONTROLLER",
    "RSVD5",
    "RSVD6",
    "RSVD7",
];
const ID_PRODUCT_TYPE_CABLE: [&str; 8] = [
    "RSVD0",
    "RSVD1",
    "RSVD2",
    "PASSIVE_CABLE",
    "ACTIVE_CABLE",
    "RSVD5",
    "RSVD6",
    "RSVD7",
];
const ID_CONNECTOR_TYPE: [&str; 4] = ["RSVD0", "RSVD1", "TYPE_C_RECEPTACLE", "TYPE_C_PLUG"];
const CABLE_TC_PLUG_REV2: [&str; 4] = ["USB_TYPEA", "USB_TYPEB", "USB_TYPEC", "CAPTIVE"];
const CABLE_TC_PLUG_REV3: [&str; 4] = ["RSVD0", "RSVD1", "USB_TYPEC", "CAPTIVE"];
const CABLE_LATENCY_PASSIVE: [&str; 16] = [
    "RSVD0",
    "LATENCY_10ns",
    "LATENCY_10_20ns",
    "LATENCY_20_30ns",
    "LATENCY_30_40ns",
    "LATENCY_40_50ns",
    "LATENCY_50_60ns",
    "LATENCY_60_70ns",
    "LATENCY_MORE_THAN_70ns",
    "RSVD9",
    "RSVD10",
    "RSVD11",
    "RSVD12",
    "RSVD13",
    "RSVD14",
    "RSVD15",
];
const CABLE_LATENCY_ACTIVE: [&str; 16] = [
    "RSVD0",
    "LATENCY_10ns",
    "LATENCY_10_20ns",
    "LATENCY_20_30ns",
    "LATENCY_30_40ns",
    "LATENCY_40_50ns",
    "LATENCY_50_60ns",
    "LATENCY_60_70ns",
    "LATENCY_1000ns",
    "LATENCY_2000ns",
    "LATENCY_3000ns",
    "RSVD11",
    "RSVD12",
    "RSVD13",
    "RSVD14",
    "RSVD15",
];
const CABLE_PASSIVE_TERM: [&str; 4] = ["VCONN_NOT_REQ", "VCONN_REQ", "RSVD2", "RSVD3"];
const CABLE_ACTIVE_TERM: [&str; 4] = [
    "RSVD0",
    "RSVD1",
    "ONE_END_ACTIVE_ONE_PASSIVE_VCONN_REQ",
    "BOTH_END_ACTIVE_VCONN_REQ",
];
const CABLE_MAX_VOLT: [&str; 4] = ["VOLT_20V", "VOLT_30V", "VOLT_40V", "VOLT_50V"];
const CABLE_VBUS_CUR: [&str; 4] = ["RSVD0", "CUR_3A", "CUR_5A", "RSVD3"];
const CABLE_SS_SUPPORT: [&str; 8] = [
    "USB2_0_ONLY",
    "USB_3_1_GEN1",
    "USB_3_1_GEN1_GEN2",
    "RSVD3",
    "RSVD4",
    "RSVD5",
    "RSVD6",
    "RSVD7",
];
const AMA_VCONN_POWER: [&str; 8] = [
    "POWER_1W",
    "POWER_1_5W",
    "POWER_2W",
    "POWER_3W",
    "POWER_4W",
    "POWER_5W",
    "POWER_6W",
    "RSVD7",
];
const AMA_SS_SUPPORT: [&str; 8] = [
    "USB2_0_ONLY",
    "USB_3_1_GEN1",
    "USB_3_1_GEN1_GEN2",
    "BILLBOARD_ONLY",
    "RSVD4",
    "RSVD5",
    "RSVD6",
    "RSVD7",
];
const DP_STATUS_CONN: [&str; 4] = [
    "DISABLED",
    "DFP_D_CONNECTED",
    "UFP_D_CONNECTED",
    "BOTH_UFP_D_DFP_D_CONNECTED",
];
const DP_PORT_CAP: [&str; 4] = [
    "RSVD",
    "UFP_D_CAPABLE",
    "DFP_D_CAPABLE",
    "BOTH_UFP_D_DFP_D_CAPABLE",
];
const DP_RECEPTACLE: [&str; 2] = ["DP_PLUG", "DP_RECEPTACLE"];
const DP_SIGNALLING: [&str; 16] = [
    "SIGNALLING_UNSPECIFIED",
    "DP_V1_3",
    "GEN2",
    "RSVD3",
    "RSVD4",
    "RSVD5",
    "RSVD6",
    "RSVD7",
    "RSVD8",
    "RSVD9",
    "RSVD10",
    "RSVD11",
    "RSVD12",
    "RSVD13",
    "RSVD14",
    "RSVD15",
];
const DP_CONFIG_SELECT: [&str; 4] = ["USB", "SET_UFP_U_AS_DFP_D", "SET_UFP_U_AS_UFP_D", "RSVD3"];
const PPS_OMF: [&str; 2] = ["CONSTANT_VOLTAGE", "CURRENT_FOLDBACK"];
const STATUS_TEMP: [&str; 4] = ["NOT_SUPPORTED", "NORMAL", "WARNING", "OVER_TEMPERATURE"];
const STATUS_DCAC: [&str; 2] = ["DC", "AC"];

fn svid_name(svid: u32) -> Option<&'static str> {
    match svid {
        0xFF00 => Some("PD SID"),
        0xFF01 => Some("DP VID"),
        0x8087 => Some("INTEL VID"),
        0x04B4 => Some("CY VID"),
        _ => None,
    }
}

fn ext_ctrl_msg(t: u32) -> &'static str {
    match t {
        1 => "EPR_Get_Source_Cap",
        2 => "EPR_Get_Sink_Cap",
        3 => "EPR_KeepAlive",
        4 => "EPR_KeepAlive_Ack",
        _ => "Reserved",
    }
}

/// Extract bits `[hi:lo]` inclusive.
pub(crate) fn bits(v: u32, hi: u32, lo: u32) -> u32 {
    (v >> lo) & ((1u64 << (hi - lo + 1)) as u32).wrapping_sub(1)
}

/// Extract a single bit.
pub(crate) fn bit(v: u32, b: u32) -> u32 {
    (v >> b) & 1
}

fn hx(v: u32) -> String {
    format!("0x{v:x}")
}

fn hxd(v: u32) -> String {
    format!("0x{v:x} ({v})")
}

fn yn(b: u32) -> &'static str {
    YESNO[(b & 1) as usize]
}

/// `'0x71A1 0xA81912C ...'` -> `[0x71A1, 0xA81912C, ...]`; `None` if empty or
/// unparseable.
pub(crate) fn parse_data_words(data: &str) -> Option<Vec<u32>> {
    let mut words = Vec::new();
    for tok in data.split_whitespace() {
        let hexpart = tok
            .strip_prefix("0x")
            .or_else(|| tok.strip_prefix("0X"))
            .unwrap_or(tok);
        match u64::from_str_radix(hexpart, 16) {
            Ok(v) => words.push(v as u32),
            Err(_) => return None,
        }
    }
    if words.is_empty() {
        None
    } else {
        Some(words)
    }
}

/// Rebuild the analyzer's byte layout: header at 16, objects at 20.
fn pkt_bytes(words: &[u32]) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b.extend_from_slice(&((words[0] & 0xFFFF) as u16).to_le_bytes());
    b.extend_from_slice(&[0, 0]);
    for w in &words[1..] {
        b.extend_from_slice(&w.to_le_bytes());
    }
    b.extend(std::iter::repeat(0u8).take(64));
    b
}

fn u8_at(pkt: &[u8], i: usize) -> u32 {
    pkt[i] as u32
}
fn u16_at(pkt: &[u8], i: usize) -> u32 {
    u16::from_le_bytes([pkt[i], pkt[i + 1]]) as u32
}
fn u32_at(pkt: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([pkt[i], pkt[i + 1], pkt[i + 2], pkt[i + 3]])
}

// ---------------------------------------------------------------- headers

fn hdr_common(hdr: u32, rev: u32, count: u32, is_ext: bool) -> &'static str {
    let msg = if rev <= 1 {
        bits(hdr, 3, 0)
    } else {
        bits(hdr, 4, 0)
    } as usize;
    if is_ext {
        EXTD_MSG_TYPE[msg]
    } else if count == 0 {
        CTRL_MSG_TYPE[msg]
    } else {
        DATA_MSG_TYPE[msg]
    }
}

fn decode_msg_header(hdr: u32, is_sop: bool, rev: u32, is_ext: bool) -> Detail {
    let count = bits(hdr, 14, 12);
    let which = if is_sop { "SOP" } else { "SOP PRIME" };
    let mut subs = Vec::new();
    let title;
    if rev <= 1 {
        title = format!("MESSAGE HEADER REVISION 2 {which}");
        subs.push(d("Reserved", hx(bit(hdr, 15))));
    } else {
        title = format!("MESSAGE HEADER REVISION 3 {which}");
        subs.push(d("Extended", yn(bit(hdr, 15))));
    }
    subs.push(d("Data objects", count.to_string()));
    subs.push(d("Message id", bits(hdr, 11, 9).to_string()));
    if is_sop {
        subs.push(d("Power role", PORT_POWER_ROLE[bit(hdr, 8) as usize]));
    } else {
        subs.push(d("Cable plug", yn(bit(hdr, 8))));
    }
    subs.push(d(
        "Specification revision",
        SPEC_REV[bits(hdr, 7, 6) as usize],
    ));
    if is_sop {
        subs.push(d("Data role", PORT_DATA_ROLE[bit(hdr, 5) as usize]));
    } else if rev >= 2 {
        subs.push(d("Reserved", hx(bit(hdr, 5))));
    }
    if rev <= 1 {
        subs.push(d("Reserved", hx(bit(hdr, 4))));
    }
    subs.push(d("Message type", hdr_common(hdr, rev, count, is_ext)));
    ds(&title, hx(hdr), subs)
}

fn decode_ext_header(ext: u32) -> Detail {
    ds(
        "EXTENDED MESSAGE HEADER",
        hx(ext),
        vec![
            d("Chunked", yn(bit(ext, 15))),
            d("Chunk number", bits(ext, 14, 11).to_string()),
            d("Request chunk", yn(bit(ext, 10))),
            d("Reserved", hx(bit(ext, 9))),
            d("Data size", hxd(bits(ext, 8, 0))),
        ],
    )
}

// ---------------------------------------------------------------- PDOs

fn fixed_src_pdo(pdo: u32, first: bool, rev: u32) -> Detail {
    let cur = bits(pdo, 9, 0) * 10;
    let volt = bits(pdo, 19, 10) * 50;
    let mut subs = vec![d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize])];
    let title;
    if first {
        title = format!(
            "FIXED 5V SOURCE PDO REVISION {}->{} mV, {} mA",
            if rev <= 1 { 2 } else { 3 },
            volt,
            cur
        );
        subs.push(d("Dual role power", yn(bit(pdo, 29))));
        subs.push(d("USB suspend support", yn(bit(pdo, 28))));
        subs.push(d("Unconstrained power", yn(bit(pdo, 27))));
        subs.push(d("USB communications capable", yn(bit(pdo, 26))));
        subs.push(d("Dual role data", yn(bit(pdo, 25))));
        if rev <= 1 {
            subs.push(d("Reserved", hx(bits(pdo, 24, 22))));
        } else {
            subs.push(d("Unchunked support", yn(bit(pdo, 24))));
            subs.push(d("EPR mode capable", yn(bit(pdo, 23))));
            subs.push(d("Reserved", hx(bit(pdo, 22))));
        }
    } else {
        title = format!("FIXED SUPPLY PDO - SOURCE ->{volt} mV, {cur} mA");
        subs.push(d("Reserved", hx(bits(pdo, 29, 22))));
    }
    subs.push(d(
        "Peak current",
        SRC_PEAK_CURRENT[bits(pdo, 21, 20) as usize],
    ));
    subs.push(d(
        "Voltage in 50mV units",
        format!("{} ({} mV)", hx(bits(pdo, 19, 10)), volt),
    ));
    subs.push(d(
        "Maximum current in 10mA units",
        format!("{} ({} mA)", hx(bits(pdo, 9, 0)), cur),
    ));
    ds(&title, hx(pdo), subs)
}

fn fixed_sink_pdo(pdo: u32, first: bool, rev: u32) -> Detail {
    let volt = bits(pdo, 19, 10) * 50;
    let cur = bits(pdo, 9, 0) * 10;
    let mut subs = vec![d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize])];
    let title;
    if first {
        title = format!(
            "FIXED 5V SINK PDO REVISION {}",
            if rev <= 1 { 2 } else { 3 }
        );
        subs.push(d("Dual role power", yn(bit(pdo, 29))));
        subs.push(d("Higher capability", yn(bit(pdo, 28))));
        subs.push(d("Unconstrained power", yn(bit(pdo, 27))));
        subs.push(d("USB communications capable", yn(bit(pdo, 26))));
        subs.push(d("Dual role data", yn(bit(pdo, 25))));
        if rev <= 1 {
            subs.push(d("Reserved", hx(bits(pdo, 24, 20))));
        } else {
            subs.push(d(
                "Fast role swap request",
                SINK_FR_SWAP[bits(pdo, 24, 23) as usize],
            ));
            subs.push(d("Reserved", hx(bits(pdo, 22, 20))));
        }
    } else {
        title = "FIXED SINK PDO".to_string();
        subs.push(d("Reserved", hx(bits(pdo, 29, 20))));
    }
    subs.push(d(
        "Voltage in 50mV units",
        format!("{} ({} mV)", hx(bits(pdo, 19, 10)), volt),
    ));
    subs.push(d(
        "Maximum current in 10mA units",
        format!("{} ({} mA)", hx(bits(pdo, 9, 0)), cur),
    ));
    ds(&title, hx(pdo), subs)
}

fn variable_pdo(pdo: u32, sink: bool) -> Detail {
    let vmax = bits(pdo, 29, 20) * 50;
    let vmin = bits(pdo, 19, 10) * 50;
    let cur = bits(pdo, 9, 0) * 10;
    ds(
        if sink {
            "VARIABLE SINK PDO"
        } else {
            "VARIABLE SUPPLY PDO - SOURCE"
        },
        hx(pdo),
        vec![
            d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize]),
            d(
                "Maximum voltage in 50mV units",
                format!("{} ({} mV)", hx(bits(pdo, 29, 20)), vmax),
            ),
            d(
                "Minimum voltage in 50mV units",
                format!("{} ({} mV)", hx(bits(pdo, 19, 10)), vmin),
            ),
            d(
                if sink {
                    "Operational current in 10mA units"
                } else {
                    "Maximum current in 10mA units"
                },
                format!("{} ({} mA)", hx(bits(pdo, 9, 0)), cur),
            ),
        ],
    )
}

fn battery_pdo(pdo: u32, sink: bool) -> Detail {
    let vmax = bits(pdo, 29, 20) * 50;
    let vmin = bits(pdo, 19, 10) * 50;
    let power = bits(pdo, 9, 0) * 250;
    ds(
        if sink {
            "BATTERY SINK PDO"
        } else {
            "BATTERY SUPPLY PDO - SOURCE"
        },
        hx(pdo),
        vec![
            d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize]),
            d(
                "Maximum voltage in 50mV units",
                format!("{} ({} mV)", hx(bits(pdo, 29, 20)), vmax),
            ),
            d(
                "Minimum voltage in 50mV units",
                format!("{} ({} mV)", hx(bits(pdo, 19, 10)), vmin),
            ),
            d(
                if sink {
                    "Operational power in 250mW units"
                } else {
                    "Maximum power in 250mW units"
                },
                format!("{} ({} mW)", hx(bits(pdo, 9, 0)), power),
            ),
        ],
    )
}

fn apdo(pdo: u32, sink: bool) -> Detail {
    let apdo_type = bits(pdo, 29, 28);
    let role = if sink { "SINK" } else { "SOURCE" };
    if apdo_type == 1 {
        return ds(
            &format!("EPR ADJUSTABLE VOLTAGE SUPPLY APDO - {role}"),
            hx(pdo),
            vec![
                d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize]),
                d("APDO type", "EPR_AVS"),
                d("Peak current", SRC_PEAK_CURRENT[bits(pdo, 27, 26) as usize]),
                d(
                    "Maximum voltage in 100mV increments",
                    format!("{} ({} mV)", hx(bits(pdo, 25, 17)), bits(pdo, 25, 17) * 100),
                ),
                d("Reserved", hx(bit(pdo, 16))),
                d(
                    "Minimum voltage in 100mV increments",
                    format!("{} ({} mV)", hx(bits(pdo, 15, 8)), bits(pdo, 15, 8) * 100),
                ),
                d(
                    "PDP in 1W increments",
                    format!("{} ({} W)", hx(bits(pdo, 7, 0)), bits(pdo, 7, 0)),
                ),
            ],
        );
    }
    if apdo_type == 2 {
        return ds(
            &format!("SPR ADJUSTABLE VOLTAGE SUPPLY APDO - {role}"),
            hx(pdo),
            vec![
                d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize]),
                d("APDO type", "SPR_AVS"),
                d("Peak current", SRC_PEAK_CURRENT[bits(pdo, 27, 26) as usize]),
                d("Reserved", hx(bits(pdo, 25, 20))),
                d(
                    "Maximum current 15V in 10mA increments",
                    format!("{} ({} mA)", hx(bits(pdo, 19, 10)), bits(pdo, 19, 10) * 10),
                ),
                d(
                    "Maximum current 20V in 10mA increments",
                    format!("{} ({} mA)", hx(bits(pdo, 9, 0)), bits(pdo, 9, 0) * 10),
                ),
            ],
        );
    }
    let apdo_name = ["PPS", "EPR_AVS", "SPR_AVS", "RSVD3"][apdo_type as usize];
    ds(
        &format!("PROGRAMMABLE POWER SUPPLY APDO - {role}"),
        hx(pdo),
        vec![
            d("Supply", SUPPLY_TYPE[bits(pdo, 31, 30) as usize]),
            d("APDO type", apdo_name),
            d("Reserved", hx(bits(pdo, 27, 25))),
            d(
                "Maximum voltage in 100mV increments",
                format!("{} ({} mV)", hx(bits(pdo, 24, 17)), bits(pdo, 24, 17) * 100),
            ),
            d("Reserved", hx(bit(pdo, 16))),
            d(
                "Minimum voltage in 100mV increments",
                format!("{} ({} mV)", hx(bits(pdo, 15, 8)), bits(pdo, 15, 8) * 100),
            ),
            d("Reserved", hx(bit(pdo, 7))),
            d(
                "Maximum current in 50mA increments",
                format!("{} ({} mA)", hx(bits(pdo, 6, 0)), bits(pdo, 6, 0) * 50),
            ),
        ],
    )
}

fn decode_pdo(pdo: u32, index: usize, rev: u32, sink: bool) -> Detail {
    let supply = bits(pdo, 31, 30);
    match supply {
        0 => {
            if sink {
                fixed_sink_pdo(pdo, index == 0, rev)
            } else {
                fixed_src_pdo(pdo, index == 0, rev)
            }
        }
        1 => battery_pdo(pdo, sink),
        2 => variable_pdo(pdo, sink),
        _ => apdo(pdo, sink),
    }
}

// ---------------------------------------------------------------- RDOs

fn fixed_var_rdo(rdo: u32, rev: u32) -> Detail {
    let give_back = bit(rdo, 27);
    let mut subs = Vec::new();
    let title;
    if rev <= 1 {
        title = "FIXED VARIABLE RDO REVISION 2";
        subs.push(d("Reserved", hx(bit(rdo, 31))));
    } else {
        title = "FIXED VARIABLE RDO REVISION 3";
        subs.push(d("EPR PDO requested", yn(bit(rdo, 31))));
    }
    subs.push(d("Object position", bits(rdo, 30, 28).to_string()));
    subs.push(d("GiveBack flag", yn(give_back)));
    subs.push(d("Capability mismatch", yn(bit(rdo, 26))));
    subs.push(d("USB communications capable", yn(bit(rdo, 25))));
    subs.push(d("No USB suspend", yn(bit(rdo, 24))));
    if rev <= 1 {
        subs.push(d("Reserved", hx(bits(rdo, 23, 20))));
    } else {
        subs.push(d("Unchunked extended messages supported", yn(bit(rdo, 23))));
        subs.push(d("EPR mode capable", yn(bit(rdo, 22))));
        subs.push(d("Reserved", hx(bits(rdo, 21, 20))));
    }
    let op = bits(rdo, 19, 10) * 10;
    let mx = bits(rdo, 9, 0) * 10;
    subs.push(d(
        "Operating current in 10mA units",
        format!("{} ({} mA)", hx(bits(rdo, 19, 10)), op),
    ));
    subs.push(d(
        if give_back != 0 {
            "Minimum operating current in 10mA units"
        } else {
            "Maximum operating current in 10mA units"
        },
        format!("{} ({} mA)", hx(bits(rdo, 9, 0)), mx),
    ));
    ds(title, hx(rdo), subs)
}

fn battery_rdo(rdo: u32, rev: u32) -> Detail {
    let give_back = bit(rdo, 27);
    let title = format!("BATTERY RDO REVISION {}", if rev <= 1 { 2 } else { 3 });
    let mut subs = vec![
        d("Reserved", hx(bit(rdo, 31))),
        d("Object position", bits(rdo, 30, 28).to_string()),
        d("GiveBack flag", yn(give_back)),
        d("Capability mismatch", yn(bit(rdo, 26))),
        d("USB communications capable", yn(bit(rdo, 25))),
        d("No USB suspend", yn(bit(rdo, 24))),
    ];
    if rev <= 1 {
        subs.push(d("Reserved", hx(bits(rdo, 23, 20))));
    } else {
        subs.push(d("Unchunked extended messages supported", yn(bit(rdo, 23))));
        subs.push(d("Reserved", hx(bits(rdo, 22, 20))));
    }
    subs.push(d(
        "Operating power in 250mW",
        format!("{} ({} mW)", hx(bits(rdo, 19, 10)), bits(rdo, 19, 10) * 250),
    ));
    subs.push(d(
        if give_back != 0 {
            "Minimum operating power in 250mW"
        } else {
            "Maximum operating power in 250mW"
        },
        format!("{} ({} mW)", hx(bits(rdo, 9, 0)), bits(rdo, 9, 0) * 250),
    ));
    ds(&title, hx(rdo), subs)
}

fn pps_rdo(rdo: u32) -> Detail {
    ds(
        "PROGRAMMABLE POWER SUPPLY RDO",
        hx(rdo),
        vec![
            d("Reserved", hx(bit(rdo, 31))),
            d("Object position", bits(rdo, 30, 28).to_string()),
            d("Reserved", hx(bit(rdo, 27))),
            d("Capability mismatch", yn(bit(rdo, 26))),
            d("USB communications capable", yn(bit(rdo, 25))),
            d("No USB suspend", yn(bit(rdo, 24))),
            d("Unchunked extended messages supported", yn(bit(rdo, 23))),
            d("Reserved", hx(bits(rdo, 22, 20))),
            d(
                "Output voltage in 20mV units",
                format!("{} ({} mV)", hx(bits(rdo, 19, 9)), bits(rdo, 19, 9) * 20),
            ),
            d("Reserved", hx(bits(rdo, 8, 7))),
            d(
                "Operating current in 50mA units",
                format!("{} ({} mA)", hx(bits(rdo, 6, 0)), bits(rdo, 6, 0) * 50),
            ),
        ],
    )
}

fn decode_rdo(rdo: u32, rev: u32, supply_type: u32) -> Detail {
    match supply_type {
        0 | 2 => fixed_var_rdo(rdo, rev),
        1 => battery_rdo(rdo, rev),
        _ => pps_rdo(rdo),
    }
}

// ---------------------------------------------------------------- other data messages

fn bist(words: &[u32]) -> Vec<Detail> {
    let mut out = vec![ds(
        "BIST OBJECT 1",
        hx(words[1]),
        vec![
            d("Bist mode", BIST_MODE[bits(words[1], 31, 28) as usize]),
            d("Reserved", hxd(bits(words[1], 27, 0))),
        ],
    )];
    for (i, w) in words[2..].iter().enumerate() {
        out.push(d(&format!("BIST OBJECT {}", i + 2), hx(*w)));
    }
    out
}

fn battery_status(ado: u32) -> Detail {
    let present = bit(ado, 9);
    let mut subs = vec![
        d(
            "Battery present capacity",
            format!("{} ({} WH)", hx(bits(ado, 31, 16)), bits(ado, 31, 16) * 10),
        ),
        d("Reserved", hx(bits(ado, 15, 12))),
    ];
    if present != 0 {
        subs.push(d(
            "Battery charging status",
            BATT_CHARGING[bits(ado, 11, 10) as usize],
        ));
    } else {
        subs.push(d("Reserved", hx(bits(ado, 11, 10))));
    }
    subs.push(d("Battery present", yn(present)));
    subs.push(d("Invalid battery reference", yn(bit(ado, 8))));
    subs.push(d("Reserved", hx(bits(ado, 7, 0))));
    ds("BATTERY STATUS", hx(ado), subs)
}

fn alert(ado: u32) -> Detail {
    ds(
        "ALERT ADO",
        hx(ado),
        vec![
            d("Reserved", hx(bit(ado, 31))),
            d("OVP", yn(bit(ado, 30))),
            d("Source input change", yn(bit(ado, 29))),
            d("Operating condition change", yn(bit(ado, 28))),
            d("OTP", yn(bit(ado, 27))),
            d("OCP", yn(bit(ado, 26))),
            d("Battery status change", yn(bit(ado, 25))),
            d("Reserved", hx(bit(ado, 24))),
            d("Fixed batteries", format!("0b{:04b}", bits(ado, 23, 20))),
            d(
                "Hot swappable batteries",
                format!("0b{:04b}", bits(ado, 19, 16)),
            ),
            d("Reserved", hx(bits(ado, 15, 0))),
        ],
    )
}

fn get_country_info(w: u32) -> Detail {
    ds(
        "GET COUNTRY INFO",
        hx(w),
        vec![
            d(
                "First character of Alpha-2 country code",
                hxd(bits(w, 31, 24)),
            ),
            d(
                "Second character of Alpha-2 country code",
                hxd(bits(w, 23, 16)),
            ),
            d("Reserved", hx(bits(w, 15, 0))),
        ],
    )
}

fn enter_usb(w: u32) -> Detail {
    let usb_mode = match bits(w, 30, 28) {
        0 => "USB 2.0",
        1 => "USB 3.2",
        2 => "USB4",
        _ => "Reserved",
    };
    let speed = match bits(w, 23, 21) {
        0 => "[USB 2.0] only, no SuperSpeed support",
        1 => "[USB 3.2] Gen1",
        2 => "[USB 3.2] Gen2 and [USB4] Gen2",
        3 => "[USB4] Gen3",
        _ => "Reserved",
    };
    let cable_type = [
        "Passive",
        "Active Re-timer",
        "Active Re-driver",
        "Optically Isolated",
    ][(bits(w, 20, 19) & 3) as usize];
    let cable_cur = ["VBUS is not supported", "Reserved", "3A", "5A"][bits(w, 18, 17) as usize];
    ds(
        "ENTER USB",
        hx(w),
        vec![
            d("Reserved", hx(bit(w, 31))),
            d("USB mode", usb_mode),
            d("Reserved", hx(bit(w, 27))),
            d(
                "USB4 DRD",
                format!(
                    "{} of operating as a [USB4] Device",
                    ["Not capable", "Capable"][bit(w, 26) as usize]
                ),
            ),
            d(
                "USB3 DRD",
                format!(
                    "{} of operating as a [USB 3.2] Device",
                    ["Not capable", "Capable"][bit(w, 25) as usize]
                ),
            ),
            d("Reserved", hx(bit(w, 24))),
            d("Cable speed", speed),
            d("Cable type", cable_type),
            d("Cable current", cable_cur),
            d(
                "PCIe support",
                if bit(w, 16) != 0 {
                    "[USB4] PCIe tunneling supported by the host"
                } else {
                    "Not Supported"
                },
            ),
            d(
                "DP support",
                if bit(w, 15) != 0 {
                    "[USB4] DP tunneling supported by the host"
                } else {
                    "Not Supported"
                },
            ),
            d(
                "TBT support",
                if bit(w, 14) != 0 {
                    "[TBT3] is supported by the host's USB4 Connection Manager"
                } else {
                    "Not Supported"
                },
            ),
            d(
                "Host present",
                if bit(w, 13) != 0 {
                    "Connected to a Host"
                } else {
                    "Not Connected"
                },
            ),
            d("Reserved", hx(bits(w, 12, 0))),
        ],
    )
}

fn epr_mode(w: u32) -> Detail {
    let action = bits(w, 31, 24);
    let action_name = match action {
        1 => Some("Enter"),
        2 => Some("Enter Acknowledged"),
        3 => Some("Enter Succeeded"),
        4 => Some("Enter Failed"),
        5 => Some("Exit"),
        _ => None,
    };
    let mut subs = vec![match action_name {
        Some(name) => d("Action", name),
        None => d("Reserved", "0"),
    }];
    let data = bits(w, 23, 16);
    if action == 4 {
        let fail = match data {
            0 => "Unknown cause".to_string(),
            1 => "Cable not EPR capable".to_string(),
            2 => "Source failed to become VCONN source".to_string(),
            3 => "EPR Mode Capable bit not set in RDO".to_string(),
            4 => "Source unable to enter EPR Mode at this time".to_string(),
            5 => "EPR Mode Capable bit not set in PDO".to_string(),
            _ => format!("Reserved {}", hx(data)),
        };
        subs.push(d("Data", fail));
    } else if action_name.is_some() {
        subs.push(d("Data", hx(data)));
    }
    subs.push(d("Reserved", hx(bits(w, 15, 0))));
    ds("EPR MODE", hx(w), subs)
}

fn source_info(w: u32) -> Detail {
    ds(
        "SOURCE INFO",
        hx(w),
        vec![
            d(
                "PortType",
                if bit(w, 31) != 0 {
                    "Assured Capacity port"
                } else {
                    "Shared Capacity port"
                },
            ),
            d("Reserved", hx(bits(w, 30, 24))),
            d(
                "Port maximum PDP",
                format!("{} ({} W)", hx(bits(w, 23, 16)), bits(w, 23, 16)),
            ),
            d(
                "Port present PDP",
                format!("{} ({} W)", hx(bits(w, 15, 8)), bits(w, 15, 8)),
            ),
            d(
                "Port reported PDP",
                format!("{} ({} W)", hx(bits(w, 7, 0)), bits(w, 7, 0)),
            ),
        ],
    )
}

fn revision(w: u32) -> Detail {
    ds(
        "Revision Message",
        hx(w),
        vec![
            d("Revision major", hx(bits(w, 31, 28))),
            d("Revision minor", hx(bits(w, 27, 24))),
            d("Version major", hx(bits(w, 23, 20))),
            d("Version minor", hx(bits(w, 19, 16))),
            d("Reserved", hx(bits(w, 15, 0))),
        ],
    )
}

// ---------------------------------------------------------------- VDMs

fn struct_vdm_hdr(w: u32) -> Detail {
    let cmd = bits(w, 4, 0) as usize;
    let ctype = bits(w, 7, 6) as usize;
    let svid = bits(w, 31, 16);
    let svid_nm = svid_name(svid).unwrap_or("Unknown VID");
    ds(
        &format!(
            "STRUCTURED VDM HEADER-{} {}",
            SVDM_CMD[cmd].to_lowercase(),
            SVDM_CMD_TYPE[ctype].to_lowercase()
        ),
        hx(w),
        vec![
            d("SVID", format!("{} ({})", hx(svid), svid_nm)),
            d("VDM type", VDM_TYPE[bit(w, 15) as usize]),
            d(
                "Structured VDM version",
                SVDM_VERSION[bits(w, 14, 13) as usize],
            ),
            d("Reserved", hx(bits(w, 12, 11))),
            d("Object position", bits(w, 10, 8).to_string()),
            d("Command type", SVDM_CMD_TYPE[ctype]),
            d("Reserved", hx(bit(w, 5))),
            d("Command", SVDM_CMD[cmd]),
        ],
    )
}

fn unstruct_vdm_hdr(w: u32) -> Detail {
    ds(
        "UNSTRUCTURED VDM HEADER",
        hx(w),
        vec![
            d("Vendor id", hxd(bits(w, 31, 16))),
            d("VDM type", VDM_TYPE[bit(w, 15) as usize]),
            d("Vendor use", hxd(bits(w, 14, 0))),
        ],
    )
}

/// Returns (detail, product-type-UFP name).
fn id_header_vdo(w: u32, rev: u32, is_sop: bool) -> (Detail, &'static str) {
    let ptype_ufp = if is_sop {
        ID_PRODUCT_TYPE_UFP[bits(w, 29, 27) as usize]
    } else {
        ID_PRODUCT_TYPE_CABLE[bits(w, 29, 27) as usize]
    };
    let mut subs = vec![
        d("USB host", yn(bit(w, 31))),
        d("USB device", yn(bit(w, 30))),
        d(
            if is_sop {
                "Product type UFP"
            } else {
                "Product type (cable plug)"
            },
            ptype_ufp,
        ),
        d("Modal operation supported", yn(bit(w, 26))),
    ];
    let title;
    if rev <= 1 {
        title = "ID HEADER VDO REVISION 2";
        subs.push(d("Reserved", hx(bits(w, 25, 16))));
    } else {
        title = "ID HEADER VDO REVISION 3";
        subs.push(d(
            "Product type DFP",
            ID_PRODUCT_TYPE_DFP[bits(w, 25, 23) as usize],
        ));
        subs.push(d(
            "Connector type",
            ID_CONNECTOR_TYPE[bits(w, 22, 21) as usize],
        ));
        subs.push(d("Reserved", hx(bits(w, 20, 16))));
    }
    subs.push(d("USB vendor id", hxd(bits(w, 15, 0))));
    (ds(title, hx(w), subs), ptype_ufp)
}

fn product_vdo(w: u32) -> Detail {
    ds(
        "PRODUCT VDO",
        hx(w),
        vec![
            d("PID", hxd(bits(w, 31, 16))),
            d("bcdDevice", hxd(bits(w, 15, 0))),
        ],
    )
}

fn passive_cable_vdo(w: u32, rev: u32) -> Detail {
    let mut subs = vec![
        d("HW version", hx(bits(w, 31, 28))),
        d("FW version", hx(bits(w, 27, 24))),
    ];
    let title;
    if rev <= 1 {
        title = "PASSIVE CABLE VDO REVISION 2";
        subs.push(d("Reserved", hx(bits(w, 23, 20))));
        subs.push(d(
            "USB Type-C plug to Type-A/B/C/Captive",
            CABLE_TC_PLUG_REV2[bits(w, 19, 18) as usize],
        ));
        subs.push(d("Reserved", hx(bit(w, 17))));
        subs.push(d(
            "Cable latency",
            CABLE_LATENCY_PASSIVE[bits(w, 16, 13) as usize],
        ));
        subs.push(d(
            "Cable term type",
            CABLE_PASSIVE_TERM[bits(w, 12, 11) as usize],
        ));
        subs.push(d("SSTX1 configurable", yn(bit(w, 10))));
        subs.push(d("SSTX2 configurable", yn(bit(w, 9))));
        subs.push(d("SSRX1 configurable", yn(bit(w, 8))));
        subs.push(d("SSRX2 configurable", yn(bit(w, 7))));
        subs.push(d(
            "VBUS current handling capability",
            CABLE_VBUS_CUR[bits(w, 6, 5) as usize],
        ));
        subs.push(d("VBUS through cable", yn(bit(w, 4))));
        subs.push(d("Reserved", hx(bit(w, 3))));
        subs.push(d(
            "USB SuperSpeed signaling support",
            CABLE_SS_SUPPORT[bits(w, 2, 0) as usize],
        ));
    } else {
        title = "PASSIVE CABLE VDO REVISION 3";
        subs.push(d("VDO version", hx(bits(w, 23, 21))));
        subs.push(d("Reserved", hx(bit(w, 20))));
        subs.push(d(
            "USB Type-C plug to Type-C/Captive",
            CABLE_TC_PLUG_REV3[bits(w, 19, 18) as usize],
        ));
        subs.push(d(
            "EPR mode capable",
            if bit(w, 17) != 0 {
                "Cable is EPR mode capable"
            } else {
                "Cable is not EPR mode capable"
            },
        ));
        subs.push(d(
            "Cable latency",
            CABLE_LATENCY_PASSIVE[bits(w, 16, 13) as usize],
        ));
        subs.push(d(
            "Cable termination type",
            CABLE_PASSIVE_TERM[bits(w, 12, 11) as usize],
        ));
        subs.push(d(
            "Maximum VBUS voltage",
            CABLE_MAX_VOLT[bits(w, 10, 9) as usize],
        ));
        subs.push(d("Reserved", hx(bits(w, 8, 7))));
        subs.push(d(
            "VBUS current handling capability",
            CABLE_VBUS_CUR[bits(w, 6, 5) as usize],
        ));
        subs.push(d("Reserved", hx(bits(w, 4, 3))));
        subs.push(d(
            "USB highest speed",
            CABLE_SS_SUPPORT[bits(w, 2, 0) as usize],
        ));
    }
    ds(title, hx(w), subs)
}

fn active_cable_vdo(w: u32, rev: u32) -> Detail {
    let mut subs = vec![
        d("HW version", hx(bits(w, 31, 28))),
        d("FW version", hx(bits(w, 27, 24))),
    ];
    let title;
    if rev <= 1 {
        title = "ACTIVE CABLE VDO REVISION 2";
        subs.push(d("Reserved", hx(bits(w, 23, 20))));
        subs.push(d(
            "USB Type-C plug to Type-A/B/C/Captive",
            CABLE_TC_PLUG_REV2[bits(w, 19, 18) as usize],
        ));
        subs.push(d("Reserved", hx(bit(w, 17))));
        subs.push(d(
            "Cable latency",
            CABLE_LATENCY_ACTIVE[bits(w, 16, 13) as usize],
        ));
        subs.push(d(
            "Cable termination type",
            CABLE_ACTIVE_TERM[bits(w, 12, 11) as usize],
        ));
        subs.push(d("SSTX1 configurable", yn(bit(w, 10))));
        subs.push(d("SSTX2 configurable", yn(bit(w, 9))));
        subs.push(d("SSRX1 configurable", yn(bit(w, 8))));
        subs.push(d("SSRX2 configurable", yn(bit(w, 7))));
    } else {
        title = "ACTIVE CABLE VDO REVISION 3";
        subs.push(d("VDO version", hx(bits(w, 23, 21))));
        subs.push(d("Reserved", hx(bit(w, 20))));
        subs.push(d(
            "Connector type",
            CABLE_TC_PLUG_REV3[bits(w, 19, 18) as usize],
        ));
        subs.push(d(
            "EPR mode capable",
            if bit(w, 17) != 0 {
                "Cable is EPR mode capable"
            } else {
                "Cable is not EPR mode capable"
            },
        ));
        subs.push(d(
            "Cable latency",
            CABLE_LATENCY_ACTIVE[bits(w, 16, 13) as usize],
        ));
        subs.push(d(
            "Cable termination type",
            CABLE_ACTIVE_TERM[bits(w, 12, 11) as usize],
        ));
        subs.push(d(
            "Maximum VBUS voltage",
            CABLE_MAX_VOLT[bits(w, 10, 9) as usize],
        ));
        subs.push(d("SBU connections supported", yn((bit(w, 8) == 0) as u32)));
        subs.push(d(
            "SBU type",
            if bit(w, 7) != 0 { "Active" } else { "Passive" },
        ));
    }
    subs.push(d(
        "VBUS current handling capability",
        CABLE_VBUS_CUR[bits(w, 6, 5) as usize],
    ));
    subs.push(d("VBUS through cable", yn(bit(w, 4))));
    subs.push(d("SOP\" controller present", yn(bit(w, 3))));
    subs.push(d(
        if rev >= 2 {
            "USB highest speed"
        } else {
            "USB SuperSpeed signaling support"
        },
        CABLE_SS_SUPPORT[bits(w, 2, 0) as usize],
    ));
    ds(title, hx(w), subs)
}

fn ama_vdo(w: u32, rev: u32) -> Detail {
    let mut subs = vec![
        d("HW version", hx(bits(w, 31, 28))),
        d("FW version", hx(bits(w, 27, 24))),
    ];
    let title;
    if rev <= 1 {
        title = "AMA VDO REVISION 2";
        subs.push(d("Reserved", hx(bits(w, 23, 12))));
        subs.push(d("SSTX1 configurable", yn(bit(w, 11))));
        subs.push(d("SSTX2 configurable", yn(bit(w, 10))));
        subs.push(d("SSRX1 configurable", yn(bit(w, 9))));
        subs.push(d("SSRX2 configurable", yn(bit(w, 8))));
    } else {
        title = "AMA VDO REVISION 3";
        subs.push(d("VDO version", hx(bits(w, 23, 21))));
        subs.push(d("Reserved", hx(bits(w, 20, 8))));
    }
    subs.push(d("VCONN power", AMA_VCONN_POWER[bits(w, 7, 5) as usize]));
    subs.push(d("VCONN required", yn(bit(w, 4))));
    subs.push(d("VBUS required", yn(bit(w, 3))));
    subs.push(d(
        if rev >= 2 {
            "USB highest speed"
        } else {
            "USB SuperSpeed signaling support"
        },
        AMA_SS_SUPPORT[bits(w, 2, 0) as usize],
    ));
    ds(title, hx(w), subs)
}

fn ufp1_vdo(w: u32) -> Detail {
    let ver = match bits(w, 31, 29) {
        1 => "1.1",
        2 => "1.2",
        _ => "Reserved",
    };
    let conn = match bits(w, 23, 22) {
        2 => "Receptacle",
        3 => "Captive Plug",
        _ => "Reserved",
    };
    let speed = match bits(w, 2, 0) {
        0 => "[USB 2.0] only, no SuperSpeed",
        1 => "[USB 3.2] Gen1",
        2 => "[USB 3.2]/[USB4] Gen2",
        3 => "[USB4] Gen3",
        _ => "Reserved",
    };
    ds(
        "UFP 1 VDO",
        hx(w),
        vec![
            d("UFP VDO Version", ver),
            d("Reserved", hx(bit(w, 28))),
            d(
                "[USB 4] Device capability",
                ["Not capable", "Capable"][bit(w, 27) as usize],
            ),
            d(
                "[USB 3.2] Device capability",
                ["Not capable", "Capable"][bit(w, 26) as usize],
            ),
            d(
                "[USB 2.0] Device capability(Billboard only)",
                ["Not capable", "Capable"][bit(w, 25) as usize],
            ),
            d(
                "[USB 2.0] Device capability",
                ["Not capable", "Capable"][bit(w, 24) as usize],
            ),
            d("USB Type-C connector type", conn),
            d("Reserved", hx(bits(w, 21, 6))),
            d(
                "Alternate Modes not reconfigured on [USB Type-C 2.0]",
                ["Not supported", "Supported"][bit(w, 5) as usize],
            ),
            d(
                "Alternate Modes reconfigured on [USB Type-C 2.0] except for [TBT3]",
                ["Not supported", "Supported"][bit(w, 4) as usize],
            ),
            d(
                "[TBT3] Alternate Mode",
                ["Not supported", "Supported"][bit(w, 3) as usize],
            ),
            d("USB highest speed", speed),
        ],
    )
}

fn ufp2_vdo(w: u32) -> Detail {
    ds(
        "UFP 2 VDO",
        hx(w),
        vec![
            d("Reserved", hx(bits(w, 31, 30))),
            d(
                "USB4 Min power",
                format!("{} ({} W)", hx(bits(w, 29, 23)), bits(w, 29, 23)),
            ),
            d(
                "USB4 Max power",
                format!("{} ({} W)", hx(bits(w, 22, 16)), bits(w, 22, 16)),
            ),
            d("Reserved", hx(bits(w, 15, 14))),
            d(
                "USB3 Min power",
                format!("{} ({} W)", hx(bits(w, 13, 7)), bits(w, 13, 7)),
            ),
            d(
                "USB3 Max power",
                format!("{} ({} W)", hx(bits(w, 6, 0)), bits(w, 6, 0)),
            ),
        ],
    )
}

fn dfp_vdo(w: u32) -> Detail {
    let ver = match bits(w, 31, 29) {
        1 => "1.1",
        _ => "Reserved",
    };
    let conn = match bits(w, 23, 22) {
        2 => "Receptacle",
        3 => "Captive Plug",
        _ => "Reserved",
    };
    ds(
        "DFP VDO",
        hx(w),
        vec![
            d("DFP VDO Version", ver),
            d("Reserved", hx(bits(w, 28, 27))),
            d(
                "[USB4] Host capability",
                ["Not capable", "Capable"][bit(w, 26) as usize],
            ),
            d(
                "[USB 3.2] Host capability",
                ["Not capable", "Capable"][bit(w, 25) as usize],
            ),
            d(
                "[USB 2.0] Host capability",
                ["Not capable", "Capable"][bit(w, 24) as usize],
            ),
            d("USB Type-C connector type", conn),
            d("Reserved", hx(bits(w, 21, 5))),
            d("Port number", hx(bits(w, 4, 0))),
        ],
    )
}

fn pin_assignments(v: u32, none_label: &str) -> String {
    let mut s = hx(v);
    if v == 0 {
        s.push(' ');
        s.push_str(none_label);
    }
    for (bit_idx, name) in "ABCDEF".chars().enumerate() {
        if v & (1 << bit_idx) != 0 {
            s.push_str(", ");
            s.push(name);
        }
    }
    s
}

fn dp_status(w: u32) -> Detail {
    let hpd = ["HPD_LOW", "HPD_HIGH"][bit(w, 7) as usize];
    let irq = ["IRQ_CLEAR", "IRQ_SET"][bit(w, 8) as usize];
    ds(
        &format!(
            "DisplayPort STATUS-{}-{}",
            hpd.to_lowercase(),
            irq.to_lowercase()
        ),
        hx(w),
        vec![
            d("Reserved", hx(bits(w, 31, 9))),
            d("IRQ_HPD", irq),
            d("HPD state", hpd),
            d("Exit DisplayPort mode request", yn(bit(w, 6))),
            d("USB configuration request", yn(bit(w, 5))),
            d("Multi-function preferred", yn(bit(w, 4))),
            d("Enabled", yn(bit(w, 3))),
            d("Power low", yn(bit(w, 2))),
            d(
                "DFP_D/UFP_D connected",
                DP_STATUS_CONN[bits(w, 1, 0) as usize],
            ),
        ],
    )
}

fn dp_modes(w: u32) -> Detail {
    ds(
        "DisplayPort MODES",
        hx(w),
        vec![
            d("Reserved", hx(bits(w, 31, 24))),
            d(
                "UFP_D pin assignment",
                pin_assignments(bits(w, 23, 16), "Not supported"),
            ),
            d(
                "DFP_D pin assignment",
                pin_assignments(bits(w, 15, 8), "Not supported"),
            ),
            d("USB2 signaling not used", yn(bit(w, 7))),
            d("Receptacle indication", DP_RECEPTACLE[bit(w, 6) as usize]),
            d("Signaling", DP_SIGNALLING[bits(w, 5, 2) as usize]),
            d("Port capability", DP_PORT_CAP[bits(w, 1, 0) as usize]),
        ],
    )
}

fn dp_configure(w: u32) -> Detail {
    ds(
        "DisplayPort CONFIGURE",
        hx(w),
        vec![
            d("Reserved", hx(bits(w, 31, 16))),
            d(
                "UFP_U with DFP_D pin assignment",
                pin_assignments(bits(w, 15, 8), "Deselect"),
            ),
            d("Reserved", hx(bits(w, 7, 6))),
            d("Signaling", DP_SIGNALLING[bits(w, 5, 2) as usize]),
            d(
                "Select configuration",
                DP_CONFIG_SELECT[bits(w, 1, 0) as usize],
            ),
        ],
    )
}

fn generic_objects(words: &[u32], start: usize, label: &str) -> Vec<Detail> {
    words[start.min(words.len())..]
        .iter()
        .enumerate()
        .map(|(i, w)| d(&format!("{} {}", label, i + start + 1), hx(*w)))
        .collect()
}

fn decode_vdm(words: &[u32], sop: &str, rev: u32) -> Vec<Detail> {
    let vdm_hdr = words[1];
    if bit(vdm_hdr, 15) == 0 {
        let mut out = vec![unstruct_vdm_hdr(vdm_hdr)];
        out.extend(generic_objects(words, 2, "DATA OBJECT"));
        return out;
    }
    let svid = bits(vdm_hdr, 31, 16);
    let cmd = bits(vdm_hdr, 4, 0);
    let ctype = bits(vdm_hdr, 7, 6);
    let mut out = vec![struct_vdm_hdr(vdm_hdr)];
    let vdos = &words[2..];
    if cmd == 1 && svid == 0xFF00 && ctype == 1 {
        // Discover Identity ACK
        let is_sop = sop == "SOP";
        let mut idx = 0usize;
        let mut ptype = "";
        let mut ptype_dfp = "";
        if idx < vdos.len() {
            let (id_hdr, pt) = id_header_vdo(vdos[idx], rev, is_sop);
            ptype = pt;
            ptype_dfp = if rev >= 2 {
                ID_PRODUCT_TYPE_DFP[bits(vdos[idx], 25, 23) as usize]
            } else {
                ""
            };
            out.push(id_hdr);
            idx += 1;
        }
        if idx < vdos.len() {
            out.push(d("CERT STAT VDO", hx(vdos[idx])));
            idx += 1;
        }
        if idx < vdos.len() {
            out.push(product_vdo(vdos[idx]));
            idx += 1;
        }
        let dfp_types = ["PDUSB_HUB", "PDUSB_HOST", "POWER_BRICK"];
        if idx < vdos.len() {
            let w = vdos[idx];
            if ptype == "PASSIVE_CABLE" {
                out.push(passive_cable_vdo(w, rev));
                idx += 1;
            } else if ptype == "ACTIVE_CABLE" {
                out.push(active_cable_vdo(w, rev));
                idx += 1;
            } else if ptype == "AMA" {
                out.push(ama_vdo(w, rev));
                idx += 1;
            } else if ptype == "PDUSB_HUB" || ptype == "PDUSB_PERIPHERAL" {
                out.push(ufp1_vdo(w));
                idx += 1;
            } else if dfp_types.contains(&ptype_dfp) {
                out.push(dfp_vdo(w));
                idx += 1;
            }
        }
        if idx < vdos.len() {
            let w = vdos[idx];
            if ptype == "PDUSB_HUB" || ptype == "PDUSB_PERIPHERAL" {
                out.push(ufp2_vdo(w));
                idx += 1;
            } else if ptype == "AMA" && dfp_types.contains(&ptype_dfp) {
                out.push(dfp_vdo(w));
                idx += 1;
            }
        }
        if idx < vdos.len() && dfp_types.contains(&ptype_dfp) {
            out.push(dfp_vdo(vdos[idx]));
            idx += 1;
        }
        out.extend(generic_objects(words, 2 + idx, "DATA OBJECT"));
    } else if cmd == 2 && ctype == 1 {
        // Discover SVIDs ACK
        for (i, w) in vdos.iter().enumerate() {
            for sv in [bits(*w, 31, 16), bits(*w, 15, 0)] {
                if sv != 0 {
                    match svid_name(sv) {
                        Some(name) => out.push(d("SVID", format!("{} ({})", hx(sv), name))),
                        None => out.push(d("SVID", hx(sv))),
                    }
                }
            }
            if bits(*w, 31, 16) == 0 && bits(*w, 15, 0) == 0 {
                out.push(d(&format!("DATA OBJECT {}", i + 2), hx(*w)));
            }
        }
    } else if cmd == 3 && svid == 0xFF01 && ctype == 1 {
        // DP Discover Modes ACK
        for w in vdos {
            out.push(dp_modes(*w));
        }
    } else if cmd == 6 && svid == 0xFF01 && !vdos.is_empty() {
        // DP Attention
        out.push(dp_status(vdos[0]));
        out.extend(generic_objects(words, 3, "DATA OBJECT"));
    } else if cmd == 16 && svid == 0xFF01 && (ctype == 0 || ctype == 1) && !vdos.is_empty() {
        out.push(dp_status(vdos[0]));
        out.extend(generic_objects(words, 3, "DATA OBJECT"));
    } else if cmd == 17 && svid == 0xFF01 && ctype == 0 && !vdos.is_empty() {
        out.push(dp_configure(vdos[0]));
        out.extend(generic_objects(words, 3, "DATA OBJECT"));
    } else {
        out.extend(generic_objects(words, 2, "DATA OBJECT"));
    }
    out
}

// ---------------------------------------------------------------- extended messages

fn peak_current(name: &str, v: u32) -> Detail {
    ds(
        name,
        hx(v),
        vec![
            d("VBUS voltage droop", yn(bit(v, 15))),
            d(
                "Duty cycle",
                format!("{} ({} %)", hx(bits(v, 14, 11)), bits(v, 14, 11) * 5),
            ),
            d(
                "Overload period",
                format!("{} ({} ms)", hx(bits(v, 10, 5)), bits(v, 10, 5) * 20),
            ),
            d(
                "Percent overload",
                format!("{} ({} %)", hx(bits(v, 4, 0)), bits(v, 4, 0) * 10),
            ),
        ],
    )
}

fn source_cap_extended(pkt: &[u8]) -> Vec<Detail> {
    vec![
        d("VID", hx(u16_at(pkt, 22))),
        d("PID", hx(u16_at(pkt, 24))),
        d("XID", hx(u32_at(pkt, 26))),
        d("FW Version", hx(u8_at(pkt, 30))),
        d("HW Version", hx(u8_at(pkt, 31))),
        ds(
            "Voltage Regulation",
            hx(u8_at(pkt, 32)),
            vec![
                d("Reserved", hx(bits(u8_at(pkt, 32), 7, 3))),
                d(
                    "IoC",
                    ["Percent_25", "Percent_90"][bit(u8_at(pkt, 32), 2) as usize],
                ),
                d(
                    "Load step",
                    [
                        "LOAD_STEP_150mA_per_us",
                        "LOAD_STEP_500mA_per_us",
                        "RSVD2",
                        "RSVD3",
                    ][bits(u8_at(pkt, 32), 1, 0) as usize],
                ),
            ],
        ),
        d(
            "Holdup Time",
            if u8_at(pkt, 33) == 0 {
                "Not Supported".to_string()
            } else {
                hx(u8_at(pkt, 33))
            },
        ),
        ds(
            "Compliance",
            hx(u8_at(pkt, 34)),
            vec![
                d("PS2 compliant", yn(bit(u8_at(pkt, 34), 2))),
                d("PS1 compliant", yn(bit(u8_at(pkt, 34), 1))),
                d("LPS compliant", yn(bit(u8_at(pkt, 34), 0))),
            ],
        ),
        ds(
            "Touch Current",
            hx(u8_at(pkt, 35)),
            vec![
                d("Ground pin for Earth", yn(bit(u8_at(pkt, 35), 2))),
                d("Ground pin supported", yn(bit(u8_at(pkt, 35), 1))),
                d("Low touch current EPS", yn(bit(u8_at(pkt, 35), 0))),
            ],
        ),
        peak_current("Peak Current 1", u16_at(pkt, 36)),
        peak_current("Peak Current 2", u16_at(pkt, 38)),
        peak_current("Peak Current 3", u16_at(pkt, 40)),
        d(
            "Touch Temp",
            match u8_at(pkt, 42) {
                0 => "IEC 60950-1".to_string(),
                1 => "IEC 62368-1 TS1".to_string(),
                2 => "IEC 62368-1 TS2".to_string(),
                v => hx(v),
            },
        ),
        ds(
            "Source Inputs",
            hx(u8_at(pkt, 43)),
            vec![
                d("Internal battery present", yn(bit(u8_at(pkt, 43), 2))),
                d("Unconstrained", yn(bit(u8_at(pkt, 43), 1))),
                d("External supply present", yn(bit(u8_at(pkt, 43), 0))),
            ],
        ),
        ds(
            "Number of Batteries",
            hx(u8_at(pkt, 44)),
            vec![
                d(
                    "Hot swappable batteries",
                    bits(u8_at(pkt, 44), 7, 4).to_string(),
                ),
                d("Fixed batteries", bits(u8_at(pkt, 44), 3, 0).to_string()),
            ],
        ),
        ds(
            "Source PDP",
            hx(u8_at(pkt, 45)),
            vec![d(
                "Rated PDP",
                format!(
                    "{} ({} Watts)",
                    hx(bits(u8_at(pkt, 45), 6, 0)),
                    bits(u8_at(pkt, 45), 6, 0)
                ),
            )],
        ),
        ds(
            "EPR Source PDP",
            hx(u8_at(pkt, 46)),
            vec![d(
                "Rated PDP",
                format!("{} ({} Watts)", hx(u8_at(pkt, 46)), u8_at(pkt, 46)),
            )],
        ),
    ]
}

fn status(pkt: &[u8]) -> Vec<Detail> {
    let temp = u8_at(pkt, 22);
    vec![
        d(
            "Internal Temp",
            if temp == 0 {
                "Not Supported".to_string()
            } else if temp == 1 {
                "< 2C".to_string()
            } else {
                format!("{temp} C")
            },
        ),
        ds(
            "Present Input",
            hx(u8_at(pkt, 23)),
            vec![
                d(
                    "Internal power from non-Battery",
                    yn(bit(u8_at(pkt, 23), 4)),
                ),
                d("Internal power from Battery", yn(bit(u8_at(pkt, 23), 3))),
                d(
                    "External power AC/DC",
                    STATUS_DCAC[bit(u8_at(pkt, 23), 2) as usize],
                ),
                d("External power", yn(bit(u8_at(pkt, 23), 1))),
            ],
        ),
        d("Present Battery Input", hx(u8_at(pkt, 24))),
        ds(
            "Event Flags",
            hx(u8_at(pkt, 25)),
            vec![
                d("CF mode", yn(bit(u8_at(pkt, 25), 4))),
                d("OVP", yn(bit(u8_at(pkt, 25), 3))),
                d("OTP", yn(bit(u8_at(pkt, 25), 2))),
                d("OCP", yn(bit(u8_at(pkt, 25), 1))),
            ],
        ),
        ds(
            "Temperature Status",
            hx(u8_at(pkt, 26)),
            vec![d(
                "Status",
                STATUS_TEMP[bits(u8_at(pkt, 26), 2, 1) as usize],
            )],
        ),
        ds(
            "Power Status",
            hx(u8_at(pkt, 27)),
            vec![
                d(
                    "Source power limited due to temperature",
                    yn(bit(u8_at(pkt, 27), 5)),
                ),
                d(
                    "Source power limited due to event flags",
                    yn(bit(u8_at(pkt, 27), 4)),
                ),
                d(
                    "Source power limited due to insufficient external power",
                    yn(bit(u8_at(pkt, 27), 3)),
                ),
                d(
                    "Source power limited due to insufficient power",
                    yn(bit(u8_at(pkt, 27), 2)),
                ),
                d(
                    "Source power limited due to cable supported current",
                    yn(bit(u8_at(pkt, 27), 1)),
                ),
            ],
        ),
    ]
}

fn pps_status(pkt: &[u8]) -> Vec<Detail> {
    let v = u16_at(pkt, 22);
    let i = u8_at(pkt, 24);
    let flags = u8_at(pkt, 25);
    vec![
        d(
            "Output Voltage",
            if v == 0xFFFF {
                "Not Supported".to_string()
            } else {
                format!("{} ({} mV)", hx(v), v * 20)
            },
        ),
        d(
            "Output Current",
            if i == 0xFF {
                "Not Supported".to_string()
            } else {
                format!("{} ({} mA)", hx(i), i * 50)
            },
        ),
        ds(
            "Real Time Flags",
            hx(flags),
            vec![
                d("Operating mode", PPS_OMF[bit(flags, 3) as usize]),
                d(
                    "Present temperature",
                    STATUS_TEMP[bits(flags, 2, 1) as usize],
                ),
            ],
        ),
    ]
}

fn manufacturer_info(pkt: &[u8], nwords: usize) -> Vec<Detail> {
    let end = (20 + nwords * 4).min(pkt.len());
    let slice = &pkt[26.min(pkt.len())..end];
    let text_bytes: &[u8] = slice.split(|&b| b == 0).next().unwrap_or(&[]);
    let text = String::from_utf8_lossy(text_bytes).to_string();
    vec![
        d("VID", hx(u16_at(pkt, 22))),
        d("PID", hx(u16_at(pkt, 24))),
        d("Manufacturer String", text),
    ]
}

fn battery_caps(pkt: &[u8]) -> Vec<Detail> {
    fn wh(v: u32) -> String {
        if v == 0 {
            "Battery not present".to_string()
        } else if v == 0xFFFF {
            "Unknown".to_string()
        } else {
            format!("{} ({} WH)", hx(v), v * 10)
        }
    }
    vec![
        d("VID", hx(u16_at(pkt, 22))),
        d("PID", hx(u16_at(pkt, 24))),
        d("Battery Design Capacity", wh(u16_at(pkt, 26))),
        d("Battery Last Full Charge Capacity", wh(u16_at(pkt, 28))),
        ds(
            "Battery Type",
            hx(u8_at(pkt, 30)),
            vec![d("Invalid battery reference", yn(bit(u8_at(pkt, 30), 0)))],
        ),
    ]
}

fn decode_extended(msg: usize, words: &[u32], pkt: &[u8], rev: u32) -> Vec<Detail> {
    let count = words.len() - 1;
    let mut out = vec![decode_ext_header(u16_at(pkt, 20))];
    match msg {
        1 => out.extend(source_cap_extended(pkt)),
        2 => out.extend(status(pkt)),
        3 => out.push(d("Battery Cap Ref", u8_at(pkt, 22).to_string())),
        4 => out.push(d("Battery Status Ref", u8_at(pkt, 22).to_string())),
        5 => out.extend(battery_caps(pkt)),
        6 => {
            out.push(d(
                "Manufacturer Info Target",
                match u8_at(pkt, 22) {
                    0 => "Port/Cable Plug".to_string(),
                    1 => "Battery".to_string(),
                    v => v.to_string(),
                },
            ));
            out.push(d("Manufacturer Info Ref", u8_at(pkt, 23).to_string()));
        }
        7 => out.extend(manufacturer_info(pkt, count)),
        12 => out.extend(pps_status(pkt)),
        15 => {
            // SKEDB shares the leading VID/PID/XID/FW/HW layout with SCEDB.
            let sce = source_cap_extended(pkt);
            out.extend(sce.into_iter().take(5));
            out.extend(generic_objects(words, 2, "SKEDB DATA OBJECT"));
        }
        16 => {
            let t = u8_at(pkt, 22);
            out.push(ds(
                "Extended Control Message Type",
                hx(t),
                vec![d("Message type", ext_ctrl_msg(t))],
            ));
            out.push(d("Data", hx(u8_at(pkt, 23))));
        }
        17 => {
            for i in 0..count {
                if 22 + i * 4 + 4 <= pkt.len() {
                    out.push(decode_pdo(u32_at(pkt, 22 + i * 4), i, rev, false));
                }
            }
        }
        18 => {
            for i in 0..count {
                if 22 + i * 4 + 4 <= pkt.len() {
                    out.push(decode_pdo(u32_at(pkt, 22 + i * 4), i, rev, true));
                }
            }
        }
        _ => out.extend(generic_objects(
            words,
            1,
            &format!("{} DATA OBJECT", EXTD_MSG_TYPE[msg]),
        )),
    }
    out
}

// ---------------------------------------------------------------- entry points

/// Decode one packet's data words. Returns `None` for reset/invalid SOP or
/// empty input, matching the reference `decode_words`.
pub fn decode_words<F>(words: &[u32], sop: &str, supply_lookup: F) -> Option<Vec<Detail>>
where
    F: Fn(usize) -> u32,
{
    if sop == "HARD_RESET" || sop == "CABLE_RESET" || sop == "INVALID" || words.is_empty() {
        return None;
    }
    let hdr = words[0];
    let rev = bits(hdr, 7, 6);
    let count = bits(hdr, 14, 12);
    let is_ext = bit(hdr, 15) != 0 && rev >= 2;
    let msg = (if rev <= 1 {
        bits(hdr, 3, 0)
    } else {
        bits(hdr, 4, 0)
    }) as usize;
    let is_sop = sop == "SOP";
    let mut out = vec![decode_msg_header(hdr, is_sop, rev, is_ext)];
    if is_ext {
        out.extend(decode_extended(msg, words, &pkt_bytes(words), rev));
        return Some(out);
    }
    if count == 0 || words.len() < 2 {
        return Some(out);
    }
    match msg {
        1 => {
            for (i, w) in words[1..(count as usize + 1).min(words.len())]
                .iter()
                .enumerate()
            {
                out.push(decode_pdo(*w, i, rev, false));
            }
        }
        2 => {
            let pos = bits(words[1], 30, 28) as usize;
            let st = supply_lookup(pos);
            out.push(decode_rdo(words[1], rev, st));
        }
        3 => out.extend(bist(words)),
        4 => {
            for (i, w) in words[1..(count as usize + 1).min(words.len())]
                .iter()
                .enumerate()
            {
                out.push(decode_pdo(*w, i, rev, true));
            }
        }
        5 => out.push(battery_status(words[1])),
        6 => out.push(alert(words[1])),
        7 => out.push(get_country_info(words[1])),
        8 => out.push(enter_usb(words[1])),
        9 => {
            let pos = bits(words[1], 30, 28) as usize;
            let st = supply_lookup(pos);
            out.push(decode_rdo(words[1], 2, st));
            out.extend(generic_objects(words, 2, "DATA OBJECT"));
        }
        10 => out.push(epr_mode(words[1])),
        11 => out.push(source_info(words[1])),
        12 => out.push(revision(words[1])),
        15 => out.extend(decode_vdm(words, sop, rev)),
        _ => out.extend(generic_objects(words, 1, "DATA OBJECT")),
    }
    Some(out)
}

/// Decode a whole capture, tracking `SOURCE_CAPABILITIES` so RDOs decode
/// against the offered PDO supply type. Returns one entry per packet, `None`
/// where there is nothing to decode (VBUS events, resets).
pub fn decode_capture(packets: &[Packet]) -> Vec<Option<Vec<Detail>>> {
    // (sTime, supply types indexed by 1-based object position).
    let mut src_caps: Vec<(i64, [u32; 8])> = Vec::new();

    let num = |s: &str| -> i64 { s.replace(',', "").parse().unwrap_or(0) };

    let mut results = Vec::with_capacity(packets.len());
    for p in packets {
        let words = match parse_data_words(&p.data) {
            Some(w) => w,
            None => {
                results.push(None);
                continue;
            }
        };
        if words[0] == 0 && (p.msg == "C_RSVD0" || p.msg.is_empty()) {
            results.push(None);
            continue;
        }
        let t = num(&p.s_time);

        let lookup = |pos: usize| -> u32 {
            for (st, types) in src_caps.iter().rev() {
                if *st < t {
                    return if pos < types.len() { types[pos] } else { 0 };
                }
            }
            0
        };

        results.push(decode_words(&words, &p.sop, lookup));

        let hdr = words[0];
        let rev = bits(hdr, 7, 6);
        let msg = if rev <= 1 {
            bits(hdr, 3, 0)
        } else {
            bits(hdr, 4, 0)
        };
        let count = bits(hdr, 14, 12);
        if p.sop == "SOP" && bit(hdr, 15) == 0 && count > 0 && msg == 1 {
            let mut types = [0u32; 8];
            for (i, w) in words[1..(count as usize + 1).min(words.len())]
                .iter()
                .enumerate()
            {
                if i + 1 < 8 {
                    types[i + 1] = bits(*w, 31, 30);
                }
            }
            src_caps.push((t, types));
        }
    }
    results
}
