//! Support for the RuiDeng TC66 / TC66C USB-C power meter (USB `28e9:018a`).
//!
//! The TC66 is a USB CDC-ACM serial device driven by 5-byte ASCII commands.
//! `getva` returns the live measurements as 192 bytes encrypted with AES-256
//! in ECB mode under a fixed key (the one published by community tools such as
//! rd-usb). Decrypted, they are three 64-byte blocks tagged `pac1`, `pac2` and
//! `pac3`, each ending in a CRC-16/MODBUS over its first 60 bytes (stored as a
//! little-endian u32). All fields are little-endian u32.
//!
//! The meter refreshes its readings about twice a second and measures VBUS in
//! 100 µV and current in 10 µA steps (magnitude only). It cannot see USB-PD
//! traffic or CC, so cedar uses it only as a current meter.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes256;
use anyhow::{bail, Result};

#[cfg(feature = "devices")]
mod serial;
#[cfg(feature = "devices")]
pub use serial::{describe_devices, find_port, Tc66};

pub const VID: u16 = 0x28e9;
pub const PID: u16 = 0x018a;

/// Request the live measurements (a [`RESPONSE_SIZE`]-byte encrypted reply).
pub const CMD_GETVA: &[u8] = b"getva";
/// Ask which mode the meter runs in: answered with `firm` (normal firmware)
/// or `boot` (bootloader).
pub const CMD_QUERY: &[u8] = b"query";

/// Size of a `getva` reply.
pub const RESPONSE_SIZE: usize = 192;

/// The meter refreshes its readings about this often, in ms.
pub const UPDATE_INTERVAL_MS: u64 = 500;

/// Pause between polls, in ms: several per refresh, so readings are timed to
/// about 0.1 s.
pub const POLL_INTERVAL_MS: u64 = 100;

/// After this long without a change, a repeated reading counts as new.
const STALE_US: u64 = UPDATE_INTERVAL_MS * 3 / 2 * 1000;

const KEY: [u8; 32] = [
    0x58, 0x21, 0xfa, 0x56, 0x01, 0xb2, 0xf0, 0x26, 0x87, 0xff, 0x12, 0x04, 0x62, 0x2a, 0x4f, 0xb0,
    0x86, 0xf4, 0x02, 0x60, 0x81, 0x6f, 0x9a, 0x0b, 0xa7, 0xf1, 0x06, 0x61, 0x9a, 0xb8, 0x72, 0x88,
];

const BLOCK: usize = 64;
const TAGS: [&[u8; 4]; 3] = [b"pac1", b"pac2", b"pac3"];

/// One decoded `getva` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// Product name, e.g. `TC66`.
    pub product: String,
    /// Firmware version, e.g. `1.14`.
    pub firmware: String,
    pub serial: u32,
    /// How many times the meter has been powered on.
    pub runs: u32,
    pub vbus_uv: i32,
    /// Current magnitude: the TC66 does not report direction.
    pub ibus_ua: i32,
    pub power_uw: i32,
    /// Load resistance as computed by the meter, in mΩ.
    pub resistance_mohm: u32,
    /// The meter's two energy accumulators: (mAh, mWh).
    pub groups: [(u32, u32); 2],
    pub temperature_c: i32,
    pub dp_mv: u32,
    pub dm_mv: u32,
}

/// Picks the meter's refreshes out of repeated polls.
///
/// The TC66 repeats its reading between refreshes and carries no counter, so
/// a reading counts as new when it differs from the last one passed on, or
/// once a refresh has surely gone by since (so a steady load still fills the
/// averaging window, without counting each poll as a reading).
#[derive(Debug, Clone, Default)]
pub struct RefreshFilter {
    last: Option<((i32, i32, i32), u64)>,
}

impl RefreshFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `m`, polled at `t_us` (µs on any monotonic clock), is a new
    /// reading. If so, it becomes the one later polls are compared with.
    pub fn is_new(&mut self, m: &Measurement, t_us: u64) -> bool {
        let key = (m.vbus_uv, m.ibus_ua, m.power_uw);
        let new = match self.last {
            None => true,
            Some((last, at)) => last != key || t_us.saturating_sub(at) >= STALE_US,
        };
        if new {
            self.last = Some((key, t_us));
        }
        new
    }
}

/// Decrypt a `getva` reply in place and check its block tags and CRCs.
pub fn decrypt(resp: &[u8]) -> Result<[u8; RESPONSE_SIZE]> {
    let Ok(mut buf) = <[u8; RESPONSE_SIZE]>::try_from(resp) else {
        bail!(
            "TC66 reply is {} bytes, expected {RESPONSE_SIZE}",
            resp.len()
        );
    };
    let cipher = Aes256::new(GenericArray::from_slice(&KEY));
    for chunk in buf.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    for (i, tag) in TAGS.iter().enumerate() {
        let block = &buf[i * BLOCK..(i + 1) * BLOCK];
        if &block[..4] != *tag {
            bail!("TC66 reply block {i} is not tagged {:?}", tag_str(tag));
        }
        let stored = u32_at(block, 60);
        let crc = crc16_modbus(&block[..60]) as u32;
        if stored != crc {
            bail!(
                "TC66 reply block {} CRC mismatch (stored {stored:#06x}, computed {crc:#06x})",
                tag_str(tag)
            );
        }
    }
    Ok(buf)
}

/// Decrypt and decode a `getva` reply.
pub fn parse(resp: &[u8]) -> Result<Measurement> {
    let p = decrypt(resp)?;
    let u = |o: usize| u32_at(&p, o);
    // Raw values fit an i32 by a wide margin (VBUS ≤ ~25 V, I ≤ ~5 A).
    let scaled = |o: usize, k: u32| u(o).saturating_mul(k).min(i32::MAX as u32) as i32;
    let temp = u(92) as i32;
    Ok(Measurement {
        product: ascii(&p[4..8]),
        firmware: ascii(&p[8..12]),
        serial: u(12),
        runs: u(44),
        vbus_uv: scaled(48, 100),
        ibus_ua: scaled(52, 10),
        power_uw: scaled(56, 100),
        resistance_mohm: u(68).saturating_mul(100),
        groups: [(u(72), u(76)), (u(80), u(84))],
        temperature_c: if u(88) != 0 { -temp } else { temp },
        dp_mv: u(96).saturating_mul(10),
        dm_mv: u(100).saturating_mul(10),
    })
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn ascii(b: &[u8]) -> String {
    b.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| if c.is_ascii_graphic() { c as char } else { '?' })
        .collect()
}

fn tag_str(tag: &[u8; 4]) -> &str {
    std::str::from_utf8(tag).unwrap_or("?")
}

/// CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF).
fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    /// Build an encrypted reply from plaintext field values.
    fn reply(fields: &[(usize, u32)]) -> Vec<u8> {
        let mut p = [0u8; RESPONSE_SIZE];
        for (i, tag) in TAGS.iter().enumerate() {
            p[i * BLOCK..i * BLOCK + 4].copy_from_slice(*tag);
        }
        p[4..8].copy_from_slice(b"TC66");
        p[8..12].copy_from_slice(b"1.14");
        for &(o, v) in fields {
            p[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        for i in 0..3 {
            let crc = crc16_modbus(&p[i * BLOCK..i * BLOCK + 60]) as u32;
            p[i * BLOCK + 60..i * BLOCK + 64].copy_from_slice(&crc.to_le_bytes());
        }
        let cipher = Aes256::new(GenericArray::from_slice(&KEY));
        for chunk in p.chunks_exact_mut(16) {
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        }
        p.to_vec()
    }

    #[test]
    fn crc_check_value() {
        assert_eq!(crc16_modbus(b"123456789"), 0x4b37);
    }

    #[test]
    fn decodes_fields() {
        let r = reply(&[
            (12, 16115),
            (44, 486),
            (48, 51198), // 5.1198 V
            (52, 2521),  // 25.21 mA
            (56, 1288),  // 0.1288 W
            (68, 2030),  // 203.0 Ω
            (72, 4),
            (76, 24),
            (88, 1),
            (92, 5),
            (96, 60),
            (100, 3),
        ]);
        let m = parse(&r).unwrap();
        assert_eq!(m.product, "TC66");
        assert_eq!(m.firmware, "1.14");
        assert_eq!(m.serial, 16115);
        assert_eq!(m.runs, 486);
        assert_eq!(m.vbus_uv, 5_119_800);
        assert_eq!(m.ibus_ua, 25_210);
        assert_eq!(m.power_uw, 128_800);
        assert_eq!(m.resistance_mohm, 203_000);
        assert_eq!(m.groups, [(4, 24), (0, 0)]);
        assert_eq!(m.temperature_c, -5);
        assert_eq!((m.dp_mv, m.dm_mv), (600, 30));
    }

    /// A `getva` reply read from a real TC66 (firmware 1.14) with no load,
    /// its input unpowered.
    #[test]
    fn decodes_real_reply() {
        let hex = include_str!("../tests/fixtures/tc66-getva.hex").trim();
        let resp: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let m = parse(&resp).unwrap();
        assert_eq!(m.product, "TC66");
        assert_eq!(m.firmware, "1.14");
        assert_eq!(m.serial, 16115);
        assert_eq!(m.runs, 487);
        assert_eq!(m.vbus_uv, 10_300);
        assert_eq!((m.ibus_ua, m.power_uw), (0, 0));
        assert_eq!(m.resistance_mohm, 9_999_900);
        assert_eq!(m.groups, [(8, 43), (0, 0)]);
        assert_eq!(m.temperature_c, 22);
        assert_eq!((m.dp_mv, m.dm_mv), (2130, 2800));
    }

    #[test]
    fn refresh_filter() {
        let mut m = parse(&reply(&[(48, 50000), (52, 1000)])).unwrap();
        let mut f = RefreshFilter::new();
        assert!(f.is_new(&m, 0));
        assert!(!f.is_new(&m, 100_000));
        assert!(!f.is_new(&m, 700_000));
        // A repeat counts once a refresh has surely gone by...
        assert!(f.is_new(&m, 750_000));
        assert!(!f.is_new(&m, 850_000));
        // ...and a change counts at once.
        m.ibus_ua += 10;
        assert!(f.is_new(&m, 900_000));
        assert!(!f.is_new(&m, 1_000_000));
    }

    #[test]
    fn rejects_bad_replies() {
        let mut r = reply(&[(48, 50000)]);
        assert!(parse(&r[..100]).is_err());
        r[70] ^= 1; // corrupts pac2 after decryption
        let err = parse(&r).unwrap_err().to_string();
        assert!(err.contains("pac2"), "{err}");
    }
}
