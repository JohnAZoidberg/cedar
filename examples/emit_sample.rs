//! Generate a small synthetic capture and write it to `.ccgx3` + `.csv`.
//! Used to validate the file writers without a physical device:
//!
//!     cargo run --example emit_sample -- /tmp/sample.ccgx3

use std::path::PathBuf;

use cedar::protocol::Decoder;
use cedar::writer;

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sample.ccgx3"));

    let mut dec = Decoder::new();

    // A VOLT_PKT (VBUS_UP), a GoodCRC control message, and a SOURCE_CAPABILITIES
    // data message with 7 objects — enough to exercise the common paths.
    dec.feed_pd(&record(1, 0x54, 0x1000, 0x1000, 0x0400_0000, &[])); // sno index 2 = VBUS_UP if type volt
    dec.feed_pd(&record(2, 0x640, 0x2000, 0x2005, 0x8001_0001, &[])); // GoodCRC-ish
    dec.feed_pd(&record(
        3,
        0x640,
        0x3000,
        0x3050,
        // header low16: extended=0, count=7, msg_type=1 (SOURCE_CAPABILITIES),
        // spec_rev v3, roles set; upper bits ok + SOP.
        0x8000_0000 | (7 << 12) | (2 << 6) | (1 << 8) | (1 << 5) | 1,
        &[0x2701_2c91, 0x0002_d12c, 0x0003_c12c, 0, 0, 0, 0],
    ));

    // A couple of scope records.
    dec.feed_scope(&scope_record(&[(100, 0x600, 0x800, 0x0, 0x820)]));

    writer::write_ccgx3(&out, &dec.packets, &dec.scope).expect("write ccgx3");
    let csv = out.with_extension("csv");
    writer::write_csv(&csv, &dec.packets).expect("write csv");
    println!(
        "wrote {} ({} packets, {} scope) and {}",
        out.display(),
        dec.packets.len(),
        dec.scope.len(),
        csv.display()
    );
}

/// Build one 64-byte PD record.
fn record(sno: u32, vbus: u32, stime: u32, etime: u32, hdr: u32, objs: &[u32]) -> [u8; 64] {
    let mut r = [0u8; 64];
    r[0..4].copy_from_slice(&sno.to_le_bytes());
    r[4..8].copy_from_slice(&vbus.to_le_bytes());
    r[8..12].copy_from_slice(&stime.to_le_bytes());
    r[12..16].copy_from_slice(&etime.to_le_bytes());
    r[16..20].copy_from_slice(&hdr.to_le_bytes());
    for (i, o) in objs.iter().enumerate().take(11) {
        r[20 + i * 4..24 + i * 4].copy_from_slice(&o.to_le_bytes());
    }
    r
}

/// Build one 64-byte scope record from up to five (ts, vbus, cc1, cc2, cur)
/// samples.
fn scope_record(samples: &[(u32, u16, u16, u16, u16)]) -> [u8; 64] {
    let mut r = [0u8; 64];
    for (j, (ts, vbus, cc1, cc2, cur)) in samples.iter().enumerate().take(5) {
        let s = j * 12;
        r[s..s + 4].copy_from_slice(&ts.to_le_bytes());
        r[s + 4..s + 6].copy_from_slice(&vbus.to_le_bytes());
        r[s + 6..s + 8].copy_from_slice(&cc1.to_le_bytes());
        r[s + 8..s + 10].copy_from_slice(&cc2.to_le_bytes());
        r[s + 10..s + 12].copy_from_slice(&cur.to_le_bytes());
    }
    r
}
