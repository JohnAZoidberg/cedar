//! Build an HTML report from a fixture `.expected.tsv`, for exercising the
//! report writer with a packet-rich capture without a device.
//!
//!     cargo run --example emit_report -- tests/fixtures/NAME.expected.tsv out.html

use std::fs;
use std::path::Path;

use cedar::protocol::Packet;
use cedar::report::{write_html, Dataset};

fn main() {
    let tsv = std::env::args().nth(1).expect("tsv path");
    let out = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "report.html".into());
    let text = fs::read_to_string(&tsv).expect("read tsv");
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split('\t').collect();
    let col = |f: &[String], name: &str| f[header.iter().position(|h| *h == name).unwrap()].clone();

    let mut packets = Vec::new();
    for line in lines {
        let f: Vec<String> = line.split('\t').map(|s| s.to_string()).collect();
        let delta = col(&f, "delta");
        packets.push(Packet {
            sno: col(&f, "sno"),
            ok: col(&f, "ok"),
            sop: col(&f, "sop"),
            msg: col(&f, "msg"),
            id: col(&f, "id"),
            d_role: col(&f, "dRole"),
            p_role: col(&f, "pRole"),
            count: col(&f, "count"),
            rev: col(&f, "rev"),
            duration: col(&f, "duration"),
            delta: if delta.is_empty() { None } else { Some(delta) },
            vbus: col(&f, "vbus"),
            data: col(&f, "data"),
            s_time: col(&f, "sTime"),
            e_time: col(&f, "eTime"),
            pkt_data: Vec::new(),
        });
    }

    // If a sibling `.bin` (length-prefixed pktData records) exists, attach it so
    // extended-message payloads decode fully.
    let bin_path = Path::new(&tsv).with_extension("").with_extension("bin");
    if let Ok(bin) = fs::read(&bin_path) {
        let mut off = 0;
        let mut idx = 0;
        while off + 4 <= bin.len() && idx < packets.len() {
            let len =
                u32::from_le_bytes([bin[off], bin[off + 1], bin[off + 2], bin[off + 3]]) as usize;
            off += 4;
            packets[idx].pkt_data = bin[off..off + len].to_vec();
            off += len;
            idx += 1;
        }
        eprintln!("attached pktData from {}", bin_path.display());
    }

    let label = Path::new(&tsv)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture")
        .to_string();
    let ds = vec![Dataset {
        label,
        packets: &packets,
        scope: &[], // fixtures carry no scope trace
    }];
    write_html(Path::new(&out), &ds).expect("write html");
    println!("wrote {out} ({} packets)", packets.len());
}
