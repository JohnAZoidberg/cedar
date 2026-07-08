//! Golden tests: decode the raw `pktData` records extracted from real captures
//! made by the original EZ-PD Protocol Analyzer utility, and assert our decoder
//! reproduces the exact field values the original tool stored.
//!
//! Each fixture is a pair:
//! * `<name>.bin` — packet records, each a `u32` little-endian length followed
//!   by that many bytes of `pktData`.
//! * `<name>.expected.tsv` — the original tool's decoded fields, one row per
//!   packet (header row first), tab-separated.
//!
//! Fixtures are generated from `.ccgx3` files; see `tests/fixtures/README.md`.

use std::fs;
use std::path::Path;

use cedar::pd_decode::decode_capture;
use cedar::protocol::{Decoder, Packet};
use cedar::report::details_to_json;

/// The columns stored in the expected file, in order.
const COLUMNS: &[&str] = &[
    "sno", "ok", "sop", "msg", "id", "dRole", "pRole", "count", "rev", "duration", "delta", "vbus",
    "data", "sTime", "eTime",
];

fn split_records(bin: &[u8]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut off = 0;
    while off + 4 <= bin.len() {
        let len = u32::from_le_bytes([bin[off], bin[off + 1], bin[off + 2], bin[off + 3]]) as usize;
        off += 4;
        assert!(off + len <= bin.len(), "truncated fixture record");
        records.push(bin[off..off + len].to_vec());
        off += len;
    }
    records
}

/// Split the tab-separated expected file. No field contains a tab, so a plain
/// split is sufficient.
fn parse_tsv(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|line| line.split('\t').map(|s| s.to_string()).collect())
        .collect()
}

fn field<'a>(row: &'a [String], name: &str) -> &'a str {
    let idx = COLUMNS.iter().position(|c| c == &name).unwrap();
    &row[idx]
}

fn check_fixture(name: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let bin = fs::read(dir.join(format!("{name}.bin"))).expect("read .bin fixture");
    let tsv = fs::read_to_string(dir.join(format!("{name}.expected.tsv"))).expect("read .tsv");

    let records = split_records(&bin);
    let rows = parse_tsv(&tsv);
    let expected = &rows[1..]; // skip header
    assert_eq!(
        records.len(),
        expected.len(),
        "{name}: record count mismatch"
    );

    let mut dec = Decoder::new();
    for rec in &records {
        dec.decode_assembled(rec);
    }
    assert_eq!(dec.packets.len(), expected.len());

    for (i, (got, exp)) in dec.packets.iter().zip(expected).enumerate() {
        let ctx = format!("{name} packet #{i}");
        assert_eq!(got.sno, field(exp, "sno"), "{ctx}: sno");
        assert_eq!(got.ok, field(exp, "ok"), "{ctx}: ok");
        assert_eq!(got.sop, field(exp, "sop"), "{ctx}: sop");
        assert_eq!(got.msg, field(exp, "msg"), "{ctx}: msg");
        assert_eq!(got.id, field(exp, "id"), "{ctx}: id");
        assert_eq!(got.d_role, field(exp, "dRole"), "{ctx}: dRole");
        assert_eq!(got.p_role, field(exp, "pRole"), "{ctx}: pRole");
        assert_eq!(got.count, field(exp, "count"), "{ctx}: count");
        assert_eq!(got.rev, field(exp, "rev"), "{ctx}: rev");
        assert_eq!(got.duration, field(exp, "duration"), "{ctx}: duration");
        assert_eq!(
            got.delta.as_deref().unwrap_or(""),
            field(exp, "delta"),
            "{ctx}: delta"
        );
        assert_eq!(got.vbus, field(exp, "vbus"), "{ctx}: vbus");
        assert_eq!(got.data, field(exp, "data"), "{ctx}: data");
        assert_eq!(got.s_time, field(exp, "sTime"), "{ctx}: sTime");
        assert_eq!(got.e_time, field(exp, "eTime"), "{ctx}: eTime");
    }
}

/// Build a `Packet` carrying only the fields the PD decoder reads.
fn packet_for_decode(exp: &[String]) -> Packet {
    let get = |name: &str| field(exp, name).to_string();
    Packet {
        sno: String::new(),
        ok: String::new(),
        sop: get("sop"),
        msg: get("msg"),
        id: String::new(),
        d_role: String::new(),
        p_role: String::new(),
        count: String::new(),
        rev: String::new(),
        duration: String::new(),
        delta: None,
        vbus: String::new(),
        data: get("data"),
        s_time: get("sTime"),
        e_time: String::new(),
        pkt_data: Vec::new(),
    }
}

/// Check the PD message decoder against the reference `pd_decode.py` output
/// (`<name>.decode.json`: one line per packet, `null` or a compact JSON tree).
fn check_decode(name: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let json_path = dir.join(format!("{name}.decode.json"));
    if !json_path.exists() {
        return;
    }
    let tsv = fs::read_to_string(dir.join(format!("{name}.expected.tsv"))).expect("read .tsv");
    let expected = fs::read_to_string(&json_path).expect("read .decode.json");

    let rows = parse_tsv(&tsv);
    let packets: Vec<Packet> = rows[1..].iter().map(|r| packet_for_decode(r)).collect();
    let decoded = decode_capture(&packets);

    let expected_lines: Vec<&str> = expected.lines().collect();
    assert_eq!(
        decoded.len(),
        expected_lines.len(),
        "{name}: decode line count mismatch"
    );
    for (i, (got, exp)) in decoded.iter().zip(&expected_lines).enumerate() {
        let got_json = match got {
            None => "null".to_string(),
            Some(details) => details_to_json(details),
        };
        assert_eq!(&got_json, exp, "{name}: decode mismatch at packet #{i}");
    }
}

/// Discover and check every fixture in the directory.
#[test]
fn all_reference_captures_decode_identically() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let f = e.file_name().into_string().ok()?;
            f.strip_suffix(".bin").map(|s| s.to_string())
        })
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no fixtures found");
    for name in names {
        check_fixture(&name);
        check_decode(&name);
    }
}
