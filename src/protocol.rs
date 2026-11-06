//! Decoding of the CY4500 wire format.
//!
//! The device streams two kinds of records over separate bulk IN endpoints:
//! 64-byte USB-PD packet records (endpoint `0x81`) and 64-byte oscilloscope
//! sample records (endpoint `0x83`). The logic here mirrors the Java reference
//! implementation (`EZPDUtil.getData`, `EZPDUtil.readData` and
//! `ScopeCollecter.run`) so that captures are bit-for-bit equivalent to those
//! produced by the original EZ-PD Protocol Analyzer utility.

// USB identifiers.
pub const VID: u16 = 0x04b4;
pub const PID: u16 = 0xf67e;
/// Product ID the device exposes while its WinUSB firmware is missing; it can
/// only be updated, not used for capture.
pub const PID_NO_WINUSB: u16 = 0x0078;

// Endpoints (interface 0).
pub const EP_OUT_CMD: u8 = 0x02;
pub const EP_IN_CC_DATA: u8 = 0x81;
pub const EP_IN_MEASURE: u8 = 0x83;
pub const EP_IN_CMD_RESP: u8 = 0x84;

pub const MAX_READ_SIZE: usize = 65535;
pub const MAX_SCOPE_READ_SIZE: usize = 13000;

/// A single 64-byte record on the wire; assembled records may be longer.
pub const RECORD_SIZE: usize = 64;
/// Bytes of a record that precede the packet data objects.
const NON_DATA_SIZE: usize = 20;
/// Data bytes carried by a continuation record of a chunked message.
const CONT_DATA_SIZE: usize = 44;

/// The device counts timestamps in a 32-bit register; the reference code adds
/// this value (not 2^32) on every wrap, so we replicate it exactly.
const TIMESTAMP_RECEIVED_MAX: u64 = 0xFFFF_FFFF;
/// Sentinel timestamp the reference scope decoder discards.
const SCOPE_TS_SENTINEL: u64 = 2_913_774_506;

// Command opcodes (first byte of an OUT transfer on EP 0x02).
const CMD_START: u8 = 16;
const CMD_STOP: u8 = 3;
const CMD_GET_VERSION: u8 = 4;
const CMD_TERMINATION: u8 = 7;

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

const SOP_TYPE: [&str; 8] = [
    "SOP",
    "SOP_PRIME",
    "SOP_DPRIME",
    "SOP_P_DBG",
    "SOP_DP_DBG",
    "HARD_RESET",
    "CABLE_RESET",
    "INVALID",
];

const SPEC_REV: [&str; 4] = ["v1", "v2", "v3", "RSVD"];

const VOLT_PKT_EVT: [&str; 7] = [
    "NONE", "VBUS_DN", "VBUS_UP", "CC_DEF", "CC_1_5A", "CC_3A", "DETACH",
];

const PKT_TYPE_VOLT: u32 = 1;

/// Build the 8-byte `START` command. The reference utility always sends a
/// config value of 4.
pub fn cmd_start() -> [u8; 8] {
    let mut cmd = [0u8; 8];
    cmd[0] = CMD_START;
    cmd[4..8].copy_from_slice(&4u32.to_le_bytes());
    cmd
}

pub fn cmd_stop() -> [u8; 4] {
    [CMD_STOP, 0, 0, 0]
}

pub fn cmd_get_version() -> [u8; 4] {
    [CMD_GET_VERSION, 0, 0, 0]
}

/// A termination the analyzer can put on a CC line, in parallel with
/// whatever the two ports present. The values were worked out on hardware
/// (a laptop host advertising 1.5 A, a USB 2 device); the firmware sends no
/// response to the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Termination {
    /// No termination of its own: plain pass-through. The power-on default.
    None = 0,
    /// Pull-up (Rp). With a source on the line, CC rises above the
    /// attach window, so the source sees a detach and turns VBUS off.
    Rp = 1,
    /// Low-value pull-down (Ra, the VCONN load).
    Ra = 2,
    /// Sink pull-down (Rd).
    Rd = 3,
}

/// Build the `TERMINATION` command. The setting sticks until it is changed,
/// across captures and after the host releases the analyzer.
pub fn cmd_termination(cc1: Termination, cc2: Termination) -> [u8; 12] {
    let mut cmd = [0u8; 12];
    cmd[0] = CMD_TERMINATION;
    cmd[4] = cc1 as u8;
    cmd[8] = cc2 as u8;
    cmd
}

fn u32_le(buf: &[u8], idx: usize) -> u32 {
    u32::from_le_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]])
}

fn u16_le(buf: &[u8], idx: usize) -> u16 {
    u16::from_le_bytes([buf[idx], buf[idx + 1]])
}

fn round_up(num: usize, divisor: usize) -> usize {
    num.div_ceil(divisor)
}

/// Format an integer with US-style thousands separators, matching Java's
/// `NumberFormat.getNumberInstance(Locale.US)`.
fn group_us(mut n: i64) -> String {
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::new();
    let len = bytes.len();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// One decoded USB-PD packet, mirroring the fields of the Java `USBPacketData`
/// model that end up in a `.ccgx3` / `.csv` capture.
#[derive(Debug, Clone)]
pub struct Packet {
    pub sno: String,
    pub ok: String,
    pub sop: String,
    pub msg: String,
    pub id: String,
    pub d_role: String,
    pub p_role: String,
    pub count: String,
    pub rev: String,
    pub duration: String,
    pub delta: Option<String>,
    pub vbus: String,
    pub data: String,
    pub s_time: String,
    pub e_time: String,
    pub pkt_data: Vec<u8>,
}

/// One decoded oscilloscope sample, mirroring the Java `GraphData` model.
#[derive(Debug, Clone, Copy)]
pub struct GraphSample {
    pub cc1: i16,
    pub cc2: i16,
    pub amp: i16,
    pub volt: i16,
    pub time_stamp: i64,
}

/// One oscilloscope sample as the analyzer sends it, before the reference
/// tool's conversion. [`GraphSample`] keeps only the magnitude of the current,
/// truncated to whole mA (one ADC count is about 2.8 mA); a meter averaging
/// many samples needs the sign and the fraction, which this keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeRecord {
    /// Device time in µs. 32 bits, so it wraps after about 71 minutes.
    pub time_stamp: u32,
    pub vbus: u16,
    pub cc1: u16,
    pub cc2: u16,
    /// Current ADC count, 2048 at zero.
    pub amp: u16,
}

impl ScopeRecord {
    pub fn vbus_mv(&self) -> f64 {
        f64::from(self.vbus) * 3296.0 * 11.0 / 4096.0
    }

    pub fn cc1_mv(&self) -> f64 {
        f64::from(self.cc1) * 3296.0 / 4096.0
    }

    pub fn cc2_mv(&self) -> f64 {
        f64::from(self.cc2) * 3296.0 / 4096.0
    }

    /// Signed current in mA, unrounded.
    pub fn current_ma(&self) -> f64 {
        (f64::from(self.amp) - 2048.0) * 100.0 / 36.0
    }
}

/// The scope samples in one transfer from [`EP_IN_MEASURE`]: up to five per
/// 64-byte record, skipping empty slots and the sentinel the reference
/// discards. Timestamps are left as sent (not de-wrapped).
pub fn scope_records(input: &[u8]) -> Vec<ScopeRecord> {
    let length = input.len() / RECORD_SIZE * RECORD_SIZE;
    let mut out = Vec::with_capacity(length / RECORD_SIZE * 5);
    for i in (0..length).step_by(RECORD_SIZE) {
        for j in 0..5usize {
            let s = i + j * 12;
            let ts = u32_le(input, s);
            if ts == 0 || u64::from(ts) == SCOPE_TS_SENTINEL {
                continue;
            }
            out.push(ScopeRecord {
                time_stamp: ts,
                vbus: u16_le(input, s + 4),
                cc1: u16_le(input, s + 6),
                cc2: u16_le(input, s + 8),
                amp: u16_le(input, s + 10),
            });
        }
    }
    out
}

/// Stateful decoder that reconstructs packets and scope samples from the raw
/// bulk transfers. The state (timestamp wrap accumulators, residual chunk
/// queue, running delta) is exactly what the reference implementation keeps.
#[derive(Default)]
pub struct Decoder {
    pub packets: Vec<Packet>,
    pub scope: Vec<GraphSample>,

    // Packet timestamp de-wrapping.
    prev_start: u64,
    prev_end: u64,
    add_factor: u64,
    add_factor_end: u64,
    // Last stored packet's calculated end time, for the delta column.
    prev_pkt_end: Option<i64>,

    // Partial chunked messages carried over between reads.
    residual: Vec<[u8; RECORD_SIZE]>,

    // Scope timestamp de-wrapping.
    prev_graph_ts: u64,
    add_factor_graph: u64,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode a single, already-assembled packet record and append it,
    /// advancing timestamp/delta state. Useful for validating the decoder
    /// against reference captures where only assembled `pktData` is available.
    pub fn decode_assembled(&mut self, pkt: &[u8]) {
        let p = self.decode_packet(pkt);
        self.packets.push(p);
    }

    /// Feed a raw transfer read from `EP_IN_CC_DATA`.
    pub fn feed_pd(&mut self, input: &[u8]) {
        // Prepend any residual records left over from a previous read.
        let mut data: Vec<u8> = Vec::with_capacity(self.residual.len() * RECORD_SIZE + input.len());
        for rec in self.residual.drain(..) {
            data.extend_from_slice(&rec);
        }
        data.extend_from_slice(input);

        let pkt_count = data.len() / RECORD_SIZE;
        let mut i = 0usize;
        while i < pkt_count {
            let base = i * RECORD_SIZE;
            let hdr = u32_le(&data, base + 16);
            let extd_hdr = u16_le(&data, base + 20);

            if get_field_extended(hdr) && !get_field_is_chunked(extd_hdr) && chunk_no(hdr) == 0 {
                let extd_bytes = extended_count(extd_hdr) as usize;
                let p_count = round_up(extd_bytes + 2, CONT_DATA_SIZE);
                if p_count <= 1 {
                    let end = base + NON_DATA_SIZE + extd_bytes + 2;
                    if end <= data.len() {
                        let pkt = self.decode_packet(&data[base..end]);
                        self.packets.push(pkt);
                    }
                } else if i + p_count <= pkt_count {
                    // All continuation records are present: assemble them.
                    let mut assembled: Vec<u8> = Vec::new();
                    for k in 0..p_count {
                        let rec_base = (i + k) * RECORD_SIZE;
                        if k == 0 {
                            assembled.extend_from_slice(&data[rec_base..rec_base + RECORD_SIZE]);
                        } else {
                            let start = rec_base + NON_DATA_SIZE;
                            assembled.extend_from_slice(&data[start..start + CONT_DATA_SIZE]);
                        }
                    }
                    let end = (NON_DATA_SIZE + extd_bytes + 2).min(assembled.len());
                    let pkt = self.decode_packet(&assembled[..end]);
                    self.packets.push(pkt);
                    i += p_count - 1;
                } else {
                    // Not all records have arrived yet: stash them for the
                    // next read.
                    while i < pkt_count {
                        let rec_base = i * RECORD_SIZE;
                        let mut rec = [0u8; RECORD_SIZE];
                        rec.copy_from_slice(&data[rec_base..rec_base + RECORD_SIZE]);
                        self.residual.push(rec);
                        i += 1;
                    }
                    break;
                }
            } else {
                let end = base + NON_DATA_SIZE + msg_count(hdr) as usize * 4;
                if end <= data.len() {
                    let pkt = self.decode_packet(&data[base..end]);
                    self.packets.push(pkt);
                }
            }
            i += 1;
        }
    }

    /// Decode a single (already assembled) packet record. Mirrors
    /// `EZPDUtil.getData`.
    fn decode_packet(&mut self, pkt: &[u8]) -> Packet {
        let sno = u32_le(pkt, 0) as u64;
        let vbus_raw = u32_le(pkt, 4) as u64;
        let start_time = u32_le(pkt, 8) as u64;
        let end_time = u32_le(pkt, 12) as u64;
        let hdr = u32_le(pkt, 16);

        if start_time < self.prev_start {
            self.add_factor += TIMESTAMP_RECEIVED_MAX;
        }
        let s_calc = start_time + self.add_factor;
        self.prev_start = start_time;

        if end_time < self.prev_end {
            self.add_factor_end += TIMESTAMP_RECEIVED_MAX;
        }
        let e_calc = end_time + self.add_factor_end;
        self.prev_end = end_time;

        let delta = self.prev_pkt_end.map(|prev| group_us(s_calc as i64 - prev));
        self.prev_pkt_end = Some(e_calc as i64);

        let duration = group_us(end_time as i64 - start_time as i64);
        let vbus = group_us((vbus_raw * 3296 * 11 / 4096) as i64);

        let mut ok = if get_field_ok(hdr) {
            "OK".to_string()
        } else {
            let mut s = "ER".to_string();
            if get_field_crc_error(hdr) {
                s.push_str("_CRC");
            }
            if get_field_eop_error(hdr) {
                s.push_str("_EOP");
            }
            s
        };
        if pkt_type(hdr) == PKT_TYPE_VOLT {
            if let Some(evt) = VOLT_PKT_EVT.get(sno as usize) {
                ok = evt.to_string();
            }
        }

        let sop_idx = sop_type(hdr) as usize;
        let sop = SOP_TYPE[sop_idx].to_string();

        // Data column.
        let mut dstr = format!("0x{:X}", u16_le(pkt, 16));
        if get_field_extended(hdr) && pkt.len() < 22 {
            // No extended header: the KM003C reports only the 2-byte message
            // header of extended messages.
            dstr.push_str(" (payload not captured)");
        } else if get_field_extended(hdr) {
            let extd_hdr = u16_le(pkt, 20);
            let byte_count = extended_count(extd_hdr);
            dstr.push_str(&format!(" 0x{:X}", extd_hdr));
            dstr.push_str(&format!(" {byte_count} bytes"));
            if get_field_is_chunked(extd_hdr) {
                dstr.push_str(&format!(" Chunk {}", extended_chunk_no(extd_hdr)));
                dstr.push_str(if is_request_chunk(extd_hdr) {
                    " req"
                } else {
                    " resp"
                });
            } else {
                dstr.push_str(" Unchunked");
            }
        } else {
            let count = msg_count(hdr);
            for k in 0..count as usize {
                let off = 20 + k * 4;
                if off + 4 <= pkt.len() {
                    dstr.push_str(&format!(" 0x{:X}", u32_le(pkt, off)));
                }
            }
        }

        Packet {
            sno: sno.to_string(),
            ok,
            sop,
            msg: msg_type_name(hdr).to_string(),
            id: msg_id(hdr).to_string(),
            d_role: data_role(hdr, sop_idx),
            p_role: power_role(hdr, sop_idx),
            count: msg_count(hdr).to_string(),
            rev: SPEC_REV[spec_rev(hdr) as usize].to_string(),
            duration,
            delta,
            vbus,
            data: dstr,
            s_time: s_calc.to_string(),
            e_time: e_calc.to_string(),
            pkt_data: pkt.to_vec(),
        }
    }

    /// Feed a raw transfer read from `EP_IN_MEASURE`. Mirrors
    /// `ScopeCollecter.run`.
    pub fn feed_scope(&mut self, input: &[u8]) {
        for r in scope_records(input) {
            let ts = u64::from(r.time_stamp);
            if ts < self.prev_graph_ts {
                self.add_factor_graph += TIMESTAMP_RECEIVED_MAX;
            }
            let ts_calc = (ts + self.add_factor_graph) as i64;
            self.prev_graph_ts = ts;

            let cur = r.amp as i32;
            let cur = if cur < 2048 {
                (2048 - cur) * 100 / 36
            } else {
                (cur - 2048) * 100 / 36
            };
            let vbus = r.vbus as i32 * 3296 * 11 / 4096;
            let cc1 = r.cc1 as i32 * 3296 / 4096;
            let cc2 = r.cc2 as i32 * 3296 / 4096;

            let sample = GraphSample {
                cc1: cc1 as i16,
                cc2: cc2 as i16,
                amp: cur as i16,
                volt: vbus as i16,
                time_stamp: ts_calc,
            };
            if self.scope.is_empty() {
                self.scope.push(GraphSample {
                    cc1: 0,
                    cc2: 0,
                    amp: 0,
                    volt: 0,
                    time_stamp: sample.time_stamp - 2,
                });
                self.scope.push(GraphSample {
                    time_stamp: sample.time_stamp - 1,
                    ..sample
                });
            }
            self.scope.push(sample);
        }
    }
}

// --- PD header field accessors (mirror `PDUtils`) ---

fn get_field_ok(hdr: u32) -> bool {
    (hdr >> 31) != 0
}
fn get_field_crc_error(hdr: u32) -> bool {
    (hdr >> 30) & 1 != 0
}
fn get_field_eop_error(hdr: u32) -> bool {
    (hdr >> 29) & 1 != 0
}
fn pkt_type(hdr: u32) -> u32 {
    (hdr >> 26) & 3
}
fn chunk_no(hdr: u32) -> u32 {
    (hdr >> 20) & 0x3f
}
fn sop_type(hdr: u32) -> u32 {
    (hdr >> 16) & 0xf
}
fn get_field_extended(hdr: u32) -> bool {
    (hdr >> 15) & 1 != 0
}
fn msg_count(hdr: u32) -> u32 {
    (hdr >> 12) & 7
}
fn msg_id(hdr: u32) -> u32 {
    (hdr >> 9) & 7
}
fn spec_rev(hdr: u32) -> u32 {
    (hdr >> 6) & 3
}

fn power_role(hdr: u32, sop_idx: usize) -> String {
    let val = ((hdr >> 8) & 1) as usize;
    if sop_idx == 0 {
        ["SNK", "SRC"][val].to_string()
    } else {
        ["DFP_UFP", "CBL_PLUG"][val].to_string()
    }
}

fn data_role(hdr: u32, sop_idx: usize) -> String {
    let val = ((hdr >> 5) & 1) as usize;
    if sop_idx == 0 {
        ["UFP", "DFP"][val].to_string()
    } else if val == 0 {
        "RSVD".to_string()
    } else {
        "ERR".to_string()
    }
}

fn msg_type_name(hdr: u32) -> &'static str {
    let val = (hdr & 0x1f) as usize;
    if !get_field_extended(hdr) {
        if msg_count(hdr) == 0 {
            CTRL_MSG_TYPE[val]
        } else {
            DATA_MSG_TYPE[val]
        }
    } else {
        EXTD_MSG_TYPE[val]
    }
}

fn extended_count(ext_hdr: u16) -> u16 {
    ext_hdr & 0x1ff
}
fn extended_chunk_no(ext_hdr: u16) -> u16 {
    (ext_hdr >> 11) & 0xf
}
fn get_field_is_chunked(ext_hdr: u16) -> bool {
    (ext_hdr >> 15) != 0
}
fn is_request_chunk(ext_hdr: u16) -> bool {
    (ext_hdr >> 10) & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_command_layout() {
        assert_eq!(
            cmd_termination(Termination::Rp, Termination::Rd),
            [7, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0]
        );
        assert_eq!(
            cmd_termination(Termination::None, Termination::None),
            [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn group_matches_java_numberformat() {
        assert_eq!(group_us(743), "743");
        assert_eq!(group_us(32225), "32,225");
        assert_eq!(group_us(6649), "6,649");
        assert_eq!(group_us(0), "0");
        assert_eq!(group_us(-1234567), "-1,234,567");
    }

    #[test]
    fn scope_records_keep_sign_and_fraction() {
        // Two samples in slots 0 and 2 of one record; slot 1 empty, slot 3
        // the sentinel.
        let mut rec = [0u8; RECORD_SIZE];
        let put = |rec: &mut [u8; RECORD_SIZE], slot: usize, ts: u32, amp: u16| {
            let s = slot * 12;
            rec[s..s + 4].copy_from_slice(&ts.to_le_bytes());
            rec[s + 4..s + 6].copy_from_slice(&565u16.to_le_bytes()); // ~5 V
            rec[s + 10..s + 12].copy_from_slice(&amp.to_le_bytes());
        };
        put(&mut rec, 0, 1000, 2050);
        put(&mut rec, 2, 2000, 2047);
        put(&mut rec, 3, SCOPE_TS_SENTINEL as u32, 2100);
        let got = scope_records(&rec);
        assert_eq!(got.len(), 2);
        assert!((got[0].current_ma() - 200.0 / 36.0).abs() < 1e-9);
        assert!((got[1].current_ma() + 100.0 / 36.0).abs() < 1e-9);
        assert!((got[0].vbus_mv() - 5001.2).abs() < 0.1);

        // The reference conversion still stores whole-mA magnitudes.
        let mut dec = Decoder::new();
        dec.feed_scope(&rec);
        let amps: Vec<i16> = dec.scope.iter().map(|g| g.amp).collect();
        assert_eq!(amps, [0, 5, 5, 2]);
    }

    #[test]
    fn decodes_reference_vbus_down_packet() {
        // Record captured from a real .ccgx3: sno=1, vbus raw=0x54, header
        // 0x04000000 -> VOLT_PKT, event index 1 = VBUS_DN. Records are 64 bytes
        // on the wire; only the first 20 carry a control packet.
        let mut pkt = [0u8; RECORD_SIZE];
        pkt[..20].copy_from_slice(&[
            0x01, 0x00, 0x00, 0x00, // sno
            0x54, 0x00, 0x00, 0x00, // vbus raw
            0x30, 0x74, 0x40, 0x00, // start time
            0x30, 0x74, 0x40, 0x00, // end time
            0x00, 0x00, 0x00, 0x04, // header
        ]);
        let mut dec = Decoder::new();
        dec.feed_pd(&pkt);
        assert_eq!(dec.packets.len(), 1);
        let p = &dec.packets[0];
        assert_eq!(p.sno, "1");
        assert_eq!(p.ok, "VBUS_DN");
        assert_eq!(p.sop, "SOP");
        assert_eq!(p.msg, "C_RSVD0");
        assert_eq!(p.d_role, "UFP");
        assert_eq!(p.p_role, "SNK");
        assert_eq!(p.vbus, "743");
        assert_eq!(p.data, "0x0");
        assert_eq!(p.rev, "v1");
        assert_eq!(p.pkt_data.len(), 20);
    }
}
