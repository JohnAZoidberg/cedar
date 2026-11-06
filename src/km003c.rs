//! Capture backend for the ChargerLab POWER-Z KM003C (USB `5fc9:0063`).
//!
//! The KM003C is a USB-C power meter that can also sniff USB-PD traffic. It is
//! request/response driven: the host sends 4-byte commands on the vendor bulk
//! interface and polls for queued PD events. Protocol details follow the
//! reverse-engineering work in <https://github.com/okhsunrog/km003c-rs>.
//!
//! Captured events are converted into CY4500-format packet records and fed to
//! the regular [`Decoder`], so everything downstream (the `.ccgx3`/`.csv`
//! writers, HTML report, `dump`, session analysis) works unchanged and the
//! resulting `.ccgx3` files open in the original EZ-PD utility.
//!
//! Only the vendor bulk interface (0) is used. The HID interface answers ADC
//! requests, but enabling the PD monitor or polling PD data over it wedged or
//! rebooted the meter in testing.

use anyhow::{anyhow, bail, Result};

use crate::protocol::{Decoder, GraphSample};

#[cfg(feature = "cli")]
mod usb;
#[cfg(feature = "cli")]
pub use usb::{describe_devices, find_device, Km003c};

pub const VID: u16 = 0x5fc9;
pub const PID: u16 = 0x0063;

/// The vendor bulk interface and its endpoints.
pub const INTERFACE: u8 = 0;
pub const EP_OUT: u8 = 0x01;
pub const EP_IN: u8 = 0x81;

// Packet types (low 7 bits of the first header byte).
const CMD_CONNECT: u8 = 0x02;
const CMD_ACCEPT: u8 = 0x05;
const CMD_GET_DATA: u8 = 0x0c;
const CMD_PD_MONITOR_ON: u8 = 0x10;
const CMD_PD_MONITOR_OFF: u8 = 0x11;
const PUT_DATA: u8 = 0x41;

/// GetData attribute selecting the PD status block plus queued PD events.
const ATT_PD_PACKET: u16 = 0x10;

/// Size of the measurement block that starts every PD payload.
pub const PD_STATUS_SIZE: usize = 12;
/// Size of an event header in the PD payload.
const PD_EVENT_HEADER_SIZE: usize = 6;
/// Event marker for connection/status events (not PD wire messages).
const PD_EVENT_CONNECTION: u8 = 0x45;

/// Pause between PD polls, in ms. The meter queues events between polls;
/// ~10 ms keeps the queue short without hogging the bus.
pub const POLL_INTERVAL_MS: u64 = 10;

/// The requests a capture sends. Each is one 4-byte header on [`EP_OUT`],
/// answered on [`EP_IN`] by a response echoing its transaction id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    PdMonitorOn,
    PdMonitorOff,
    /// GetData for the PD status block plus queued PD events.
    PollPd,
}

impl Command {
    /// The request bytes for transaction `id`.
    pub fn header(self, id: u8) -> [u8; 4] {
        match self {
            Command::Connect => ctrl_header(CMD_CONNECT, id, 0),
            Command::PdMonitorOn => ctrl_header(CMD_PD_MONITOR_ON, id, 1),
            Command::PdMonitorOff => ctrl_header(CMD_PD_MONITOR_OFF, id, 0),
            Command::PollPd => ctrl_header(CMD_GET_DATA, id, ATT_PD_PACKET),
        }
    }

    /// A short name for error messages.
    pub fn what(self) -> &'static str {
        match self {
            Command::Connect => "connect",
            Command::PdMonitorOn => "PD monitor enable",
            Command::PdMonitorOff => "PD monitor disable",
            Command::PollPd => "PD poll",
        }
    }

    /// Whether `resp` (the bytes received so far for this transaction) is a
    /// whole response.
    pub fn response_complete(self, resp: &[u8]) -> Result<bool> {
        match self {
            Command::PollPd => Ok(matches!(
                put_data_payload(resp, ATT_PD_PACKET)?,
                Framed::Complete(_)
            )),
            _ => Ok(resp.len() >= 4),
        }
    }

    /// Check a complete response: control commands must be accepted.
    pub fn check_response(self, resp: &[u8]) -> Result<()> {
        if self != Command::PollPd && resp[0] & 0x7f != CMD_ACCEPT {
            bail!(
                "KM003C rejected {} (response type {:#04x})",
                self.what(),
                resp[0] & 0x7f
            );
        }
        Ok(())
    }
}

/// The PD payload of a complete [`Command::PollPd`] response.
pub fn pd_payload(resp: &[u8]) -> Result<&[u8]> {
    match put_data_payload(resp, ATT_PD_PACKET)? {
        Framed::Complete(Some(payload)) => Ok(payload),
        Framed::Complete(None) => bail!("KM003C response carried no PD data"),
        Framed::Incomplete => bail!("KM003C response is incomplete"),
    }
}

// CY4500 record conventions (see `protocol.rs`).
const CY_HDR_OK: u32 = 1 << 31;
const CY_PKT_TYPE_VOLT: u32 = 1 << 26;
const CY_VOLT_VBUS_DN: u32 = 1;
const CY_VOLT_VBUS_UP: u32 = 2;

/// Build a 4-byte control header: type (7 bits), transaction id, attribute
/// (15 bits at bit 17).
pub fn ctrl_header(packet_type: u8, id: u8, attribute: u16) -> [u8; 4] {
    let word =
        (packet_type as u32 & 0x7f) | ((id as u32) << 8) | ((attribute as u32 & 0x7fff) << 17);
    word.to_le_bytes()
}

/// The measurement block at the start of every PD payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdStatus {
    pub timestamp_ms: u32,
    pub vbus_mv: u16,
    /// Signed: negative when power flows from the male to the female port.
    pub ibus_ma: i16,
    pub cc1_mv: u16,
    pub cc2_mv: u16,
}

/// One entry of the PD event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdEvent {
    Connect {
        timestamp_ms: u32,
    },
    Disconnect {
        timestamp_ms: u32,
    },
    /// Unrecognized connection/status event code.
    Other {
        timestamp_ms: u32,
        code: u8,
    },
    /// A PD wire message: 2-byte header followed by data objects or an
    /// extended header and payload. `sop` is 0 = SOP, 1 = SOP', 2 = SOP''.
    Message {
        timestamp_ms: u32,
        sop: u8,
        wire: Vec<u8>,
    },
}

/// Outcome of trying to frame a (possibly partial) PutData response.
#[derive(Debug, PartialEq, Eq)]
pub enum Framed<'a> {
    /// More bytes are needed.
    Incomplete,
    /// The payload of the logical packet with the requested attribute, or
    /// `None` if the response carried no such packet.
    Complete(Option<&'a [u8]>),
}

/// Walk the logical packets of a PutData response and return the payload with
/// the given attribute. Each logical packet starts with a 4-byte extended
/// header: attribute (15 bits), next (1), chunk (6), size (10).
pub fn put_data_payload(buf: &[u8], attribute: u16) -> Result<Framed<'_>> {
    if buf.len() < 4 {
        return Ok(Framed::Incomplete);
    }
    if buf[0] & 0x7f != PUT_DATA {
        bail!(
            "expected PutData response, got packet type {:#04x}",
            buf[0] & 0x7f
        );
    }
    let mut off = 4;
    let mut found = None;
    loop {
        if buf.len() < off + 4 {
            return Ok(Framed::Incomplete);
        }
        let ext = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let attr = (ext & 0x7fff) as u16;
        let next = ext & (1 << 15) != 0;
        let size = (ext >> 22) as usize;
        off += 4;
        if buf.len() < off + size {
            return Ok(Framed::Incomplete);
        }
        if attr == attribute && found.is_none() {
            found = Some(&buf[off..off + size]);
        }
        off += size;
        if !next {
            return Ok(Framed::Complete(found));
        }
    }
}

/// Parse a PD payload: the 12-byte status block followed by queued events.
pub fn parse_pd_payload(p: &[u8]) -> Result<(PdStatus, Vec<PdEvent>)> {
    if p.len() < PD_STATUS_SIZE {
        bail!("PD payload too short: {} bytes", p.len());
    }
    let u16_at = |i: usize| u16::from_le_bytes([p[i], p[i + 1]]);
    let status = PdStatus {
        timestamp_ms: u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
        vbus_mv: u16_at(4),
        ibus_ma: u16_at(6) as i16,
        cc1_mv: u16_at(8),
        cc2_mv: u16_at(10),
    };

    let mut events = Vec::new();
    let mut off = PD_STATUS_SIZE;
    while off < p.len() {
        if p.len() - off < PD_EVENT_HEADER_SIZE {
            bail!("truncated PD event header at offset {off}");
        }
        let marker = p[off];
        if marker == PD_EVENT_CONNECTION {
            // 24-bit timestamp, one reserved byte, event code.
            let ts24 = u32::from_le_bytes([p[off + 1], p[off + 2], p[off + 3], 0]);
            let timestamp_ms = extend_ts24(ts24, status.timestamp_ms);
            let code = p[off + 5];
            events.push(match code {
                0x21 | 0x11 => PdEvent::Connect { timestamp_ms },
                0x22 | 0x12 => PdEvent::Disconnect { timestamp_ms },
                _ => PdEvent::Other { timestamp_ms, code },
            });
            off += PD_EVENT_HEADER_SIZE;
            continue;
        }

        let timestamp_ms = u32::from_le_bytes([p[off + 1], p[off + 2], p[off + 3], p[off + 4]]);
        let sop = p[off + 5];
        let wire_len = ((marker & 0x3f) as usize)
            .checked_sub(5)
            .ok_or_else(|| anyhow!("invalid PD event size marker {marker:#04x} at offset {off}"))?;
        off += PD_EVENT_HEADER_SIZE;
        if p.len() - off < wire_len {
            bail!("truncated PD message at offset {off}: need {wire_len} bytes");
        }
        events.push(PdEvent::Message {
            timestamp_ms,
            sop,
            wire: p[off..off + wire_len].to_vec(),
        });
        off += wire_len;
    }
    Ok((status, events))
}

/// Connection events carry only 24 timestamp bits; take the upper bits from
/// the status block's 32-bit timestamp (which is never older than the event).
fn extend_ts24(ts24: u32, reference: u32) -> u32 {
    let mut full = (reference & !0x00ff_ffff) | ts24;
    if full > reference && reference >= 0x0100_0000 {
        full -= 0x0100_0000;
    }
    full
}

/// Whether a wire message is as long as its PD header says. Extended
/// messages only need their extended header; chunks are padded, so they may
/// be longer than the data size.
fn wire_len_consistent(wire: &[u8]) -> bool {
    let hdr = u16::from_le_bytes([wire[0], wire[1]]);
    let objects = ((hdr >> 12) & 7) as usize;
    if hdr & 0x8000 != 0 {
        wire.len() >= 4
    } else {
        wire.len() == 2 + objects * 4
    }
}

/// Approximate on-the-wire duration of a PD message in µs: preamble (64 bits),
/// SOP (20), 4b5b-coded header+payload and CRC (10 bits per byte), EOP (5), at
/// 300 kbit/s.
fn wire_duration_us(wire_len: usize) -> u64 {
    let bits = 64 + 20 + (wire_len as u64 + 4) * 10 + 5;
    bits * 10 / 3
}

/// Convert millivolts to the CY4500's VBUS ADC counts (inverse of
/// `raw * 3296 * 11 / 4096`), rounding up so the round trip lands on or just
/// below the original value.
fn mv_to_cy_raw(mv: u16) -> u32 {
    (mv as u32 * 4096).div_ceil(3296 * 11)
}

/// Turns KM003C PD payloads into CY4500 packet records and scope samples.
///
/// The KM003C timestamps events with 1 ms resolution. Records need
/// monotonically increasing µs start/end times (the decoder treats a backwards
/// step as a 32-bit wrap), so messages that share a millisecond are laid out
/// back to back using their estimated wire duration.
#[derive(Default)]
pub struct Converter {
    sno: u32,
    last_vbus_mv: Option<u16>,
    last_end_us: u64,
    last_scope_us: Option<i64>,
}

impl Converter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one parsed PD payload, appending packets and a scope sample.
    pub fn feed(&mut self, decoder: &mut Decoder, status: &PdStatus, events: &[PdEvent]) {
        // Events were queued before this status block was sampled, so use the
        // previous poll's VBUS for them.
        let vbus_mv = self.last_vbus_mv.unwrap_or(status.vbus_mv);
        for event in events {
            self.feed_event(decoder, event, vbus_mv);
        }
        self.last_vbus_mv = Some(status.vbus_mv);

        let ts = status.timestamp_ms as i64 * 1000;
        if !matches!(self.last_scope_us, Some(last) if ts <= last) {
            decoder.scope.push(GraphSample {
                cc1: clamp_i16(status.cc1_mv as i64),
                cc2: clamp_i16(status.cc2_mv as i64),
                // The CY4500 reports current magnitude only.
                amp: clamp_i16((status.ibus_ma as i64).abs()),
                volt: clamp_i16(status.vbus_mv as i64),
                time_stamp: ts,
            });
            self.last_scope_us = Some(ts);
        }
    }

    fn feed_event(&mut self, decoder: &mut Decoder, event: &PdEvent, vbus_mv: u16) {
        match event {
            PdEvent::Connect { timestamp_ms } => {
                self.push_volt(decoder, *timestamp_ms, CY_VOLT_VBUS_UP, vbus_mv)
            }
            PdEvent::Disconnect { timestamp_ms } => {
                self.push_volt(decoder, *timestamp_ms, CY_VOLT_VBUS_DN, vbus_mv)
            }
            PdEvent::Other { code, .. } => log::debug!("ignoring KM003C status event {code:#04x}"),
            PdEvent::Message {
                timestamp_ms,
                sop,
                wire,
            } => {
                if wire.len() < 2 {
                    log::debug!("ignoring KM003C PD event with {} wire bytes", wire.len());
                    return;
                }
                if *sop > 2 {
                    log::debug!("KM003C PD event with unknown SOP code {sop}");
                }
                if !wire_len_consistent(wire) {
                    log::debug!("KM003C PD message length does not match its header: {wire:02x?}");
                }
                let (start, end) = self.place(*timestamp_ms, wire_duration_us(wire.len()));
                self.sno = self.sno.wrapping_add(1);
                let pd_header = u16::from_le_bytes([wire[0], wire[1]]) as u32;
                let hdr = CY_HDR_OK | ((*sop as u32 & 0xf) << 16) | pd_header;

                let mut rec = Vec::with_capacity(20 + wire.len() - 2);
                rec.extend_from_slice(&self.sno.to_le_bytes());
                rec.extend_from_slice(&mv_to_cy_raw(vbus_mv).to_le_bytes());
                rec.extend_from_slice(&(start as u32).to_le_bytes());
                rec.extend_from_slice(&(end as u32).to_le_bytes());
                rec.extend_from_slice(&hdr.to_le_bytes());
                rec.extend_from_slice(&wire[2..]);
                decoder.decode_assembled(&rec);
            }
        }
    }

    /// A CY4500 "volt packet": attach/detach marker whose `sno` field is the
    /// event index.
    fn push_volt(&mut self, decoder: &mut Decoder, timestamp_ms: u32, event: u32, vbus_mv: u16) {
        let (start, _) = self.place(timestamp_ms, 0);
        let mut rec = Vec::with_capacity(20);
        rec.extend_from_slice(&event.to_le_bytes());
        rec.extend_from_slice(&mv_to_cy_raw(vbus_mv).to_le_bytes());
        rec.extend_from_slice(&(start as u32).to_le_bytes());
        rec.extend_from_slice(&(start as u32).to_le_bytes());
        rec.extend_from_slice(&CY_PKT_TYPE_VOLT.to_le_bytes());
        decoder.decode_assembled(&rec);
    }

    /// Pick start/end µs times: the event's millisecond timestamp, pushed past
    /// the previous record's end if they overlap.
    fn place(&mut self, timestamp_ms: u32, duration_us: u64) -> (u64, u64) {
        let start = (timestamp_ms as u64 * 1000).max(self.last_end_us);
        let end = start + duration_us;
        self.last_end_us = end;
        (start, end)
    }
}

fn clamp_i16(v: i64) -> i16 {
    v.clamp(i16::MIN as i64, i16::MAX as i64) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn header_encoding() {
        assert_eq!(ctrl_header(CMD_GET_DATA, 1, 0x1), [0x0c, 0x01, 0x02, 0x00]);
        assert_eq!(
            ctrl_header(CMD_GET_DATA, 5, ATT_PD_PACKET),
            [0x0c, 0x05, 0x20, 0x00]
        );
        assert_eq!(
            ctrl_header(CMD_PD_MONITOR_ON, 3, 1),
            [0x10, 0x03, 0x02, 0x00]
        );
    }

    #[test]
    fn frames_partial_and_complete_responses() {
        let resp = hex("410480001000000365f30000f64bd3f400008106");
        for n in 0..resp.len() {
            assert_eq!(
                put_data_payload(&resp[..n], ATT_PD_PACKET).unwrap(),
                Framed::Incomplete
            );
        }
        let Framed::Complete(Some(p)) = put_data_payload(&resp, ATT_PD_PACKET).unwrap() else {
            panic!("expected payload");
        };
        let (st, events) = parse_pd_payload(p).unwrap();
        assert_eq!(
            st,
            PdStatus {
                timestamp_ms: 0xf365,
                vbus_mv: 19446,
                ibus_ma: -2861,
                cc1_mv: 0,
                cc2_mv: 1665
            }
        );
        assert!(events.is_empty());
    }

    #[test]
    fn parses_connect_and_messages() {
        // Source_Capabilities, GoodCRC, Request from a Framework 60 W adapter,
        // then a connect event.
        let p = hex(concat!(
            "92290200ba13feff0100ef01",
            "9b8c29020000a1512c91010a2cd102002cb104002c4106003c21a4c9",
            "878c290200004100",
            "8b912902000082102cb1c442",
            "45cb27020021",
        ));
        let (_, events) = parse_pd_payload(&p).unwrap();
        assert_eq!(events.len(), 4);
        match &events[0] {
            PdEvent::Message {
                sop,
                wire,
                timestamp_ms,
            } => {
                assert_eq!(*sop, 0);
                assert_eq!(*timestamp_ms, 0x02298c);
                assert_eq!(wire.len(), 22);
                assert_eq!(&wire[..2], &[0xa1, 0x51]);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            events[3],
            PdEvent::Connect {
                timestamp_ms: 0x0227cb
            }
        );

        // A message cut short is an error, not a silent drop.
        assert!(parse_pd_payload(&p[..p.len() - 8]).is_err());
    }

    #[test]
    fn extends_24_bit_timestamps() {
        assert_eq!(extend_ts24(0x0227cb, 0x022992), 0x0227cb);
        assert_eq!(extend_ts24(0xfffff0, 0x0100_0010), 0x00ff_fff0);
        assert_eq!(extend_ts24(0x000005, 0x0100_0010), 0x0100_0005);
    }

    #[test]
    fn vbus_round_trips_through_cy_counts() {
        for mv in [0u16, 5050, 9000, 15000, 19446, 20000, 28000] {
            let back = (mv_to_cy_raw(mv) * 3296 * 11 / 4096) as i64;
            assert!((back - mv as i64).abs() <= 9, "{mv} -> {back}");
        }
    }
}
