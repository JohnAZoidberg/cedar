//! Decode every packet in a fixture `.expected.tsv` and print one JSON line per
//! packet (`null` if nothing to decode). Used to cross-check the Rust decoder
//! against the reference Python `pd_decode`.
//!
//!     cargo run --example dump_decode -- tests/fixtures/NAME.expected.tsv

use std::fs;

use cedar::pd_decode::decode_capture;
use cedar::protocol::Packet;
use cedar::report::details_to_json;

fn main() {
    let path = std::env::args().nth(1).expect("tsv path");
    let text = fs::read_to_string(&path).expect("read tsv");
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split('\t').collect();
    let idx = |name: &str| header.iter().position(|h| *h == name).unwrap();
    let (i_sop, i_msg, i_data, i_stime) = (idx("sop"), idx("msg"), idx("data"), idx("sTime"));

    let mut packets = Vec::new();
    for line in lines {
        let f: Vec<&str> = line.split('\t').collect();
        packets.push(mk_packet(f[i_sop], f[i_msg], f[i_data], f[i_stime]));
    }

    for dec in decode_capture(&packets) {
        match dec {
            None => println!("null"),
            Some(details) => println!("{}", details_to_json(&details)),
        }
    }
}

fn mk_packet(sop: &str, msg: &str, data: &str, s_time: &str) -> Packet {
    Packet {
        sno: String::new(),
        ok: String::new(),
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
        s_time: s_time.to_string(),
        e_time: String::new(),
        pkt_data: Vec::new(),
    }
}
