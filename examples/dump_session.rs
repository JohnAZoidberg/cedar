//! Print the session summary and event timeline for a fixture `.expected.tsv`.
//!
//!     cargo run --example dump_session -- tests/fixtures/NAME.expected.tsv

use std::fs;

use cedar::pd_session::analyze;
use cedar::protocol::Packet;

fn main() {
    let path = std::env::args().nth(1).expect("tsv path");
    let text = fs::read_to_string(&path).expect("read tsv");
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split('\t').collect();
    let col = |f: &[String], name: &str| f[header.iter().position(|h| *h == name).unwrap()].clone();

    let mut packets = Vec::new();
    for line in lines {
        let f: Vec<String> = line.split('\t').map(|s| s.to_string()).collect();
        packets.push(Packet {
            sno: col(&f, "sno"),
            ok: col(&f, "ok"),
            sop: col(&f, "sop"),
            msg: col(&f, "msg"),
            id: String::new(),
            d_role: String::new(),
            p_role: String::new(),
            count: String::new(),
            rev: String::new(),
            duration: String::new(),
            delta: None,
            vbus: col(&f, "vbus"),
            data: col(&f, "data"),
            s_time: col(&f, "sTime"),
            e_time: String::new(),
            pkt_data: Vec::new(),
        });
    }

    let session = analyze(&packets);
    println!("SUMMARY");
    println!("  cable:    {:?}", session.summary.cable);
    println!("  partner:  {:?}", session.summary.partner);
    println!("  contract: {:?}", session.summary.contract);
    println!("\nEVENTS");
    for (i, ev) in session.events.iter().enumerate() {
        if let Some(e) = ev {
            println!("  #{i:<4} {} {}", e.emoji, e.text);
        }
    }
}
