//! Replay real POWER-Z KM003C poll responses through the KM003C converter and
//! the regular CY4500 decoder / session analysis.

use std::fs;
use std::path::Path;

use cedar::km003c::{parse_pd_payload, put_data_payload, Converter, Framed};
use cedar::pd_session::analyze;
use cedar::protocol::Decoder;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn replay(name: &str) -> Decoder {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = fs::read_to_string(&path).unwrap();
    let mut decoder = Decoder::new();
    let mut conv = Converter::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let resp = hex(line.trim());
        let Framed::Complete(Some(payload)) = put_data_payload(&resp, 0x10).unwrap() else {
            panic!("incomplete response: {line}");
        };
        let (status, events) = parse_pd_payload(payload).unwrap();
        conv.feed(&mut decoder, &status, &events);
    }
    decoder
}

#[test]
fn framework_60w_adapter_negotiation() {
    let dec = replay("km003c-framework-60w.txt");

    // Two plug-ins: each starts with a VBUS_UP marker and offers capabilities.
    let attaches = dec.packets.iter().filter(|p| p.ok == "VBUS_UP").count();
    let detaches = dec.packets.iter().filter(|p| p.ok == "VBUS_DN").count();
    assert_eq!((attaches, detaches), (4, 3));

    let caps: Vec<_> = dec
        .packets
        .iter()
        .filter(|p| p.msg == "SOURCE_CAPABILITIES")
        .collect();
    assert_eq!(caps.len(), 2);
    for p in &caps {
        assert_eq!(p.sop, "SOP");
        assert_eq!(p.p_role, "SRC");
        assert_eq!(p.count, "5");
    }
    assert!(dec.packets.iter().any(|p| p.msg == "REQUEST"));
    assert!(dec.packets.iter().any(|p| p.msg == "PS_RDY"));
    // The source probes the cable with Discover Identity on SOP'.
    assert!(dec
        .packets
        .iter()
        .any(|p| p.sop == "SOP_PRIME" && p.msg == "VENDOR_DEFINED"));

    // Start/end times must be monotonic, or the decoder would see a wrap.
    let times: Vec<i64> = dec
        .packets
        .iter()
        .map(|p| p.s_time.parse().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "{times:?}");

    // Every poll contributes one scope sample.
    assert!(dec.scope.len() > 20);

    let session = analyze(&dec.packets);
    let contract = session.summary.contract.expect("a contract");
    assert!(contract.starts_with("20 V @ 3 A"), "{contract}");
}

/// A message with the Extended bit set but no extended header (seen live from
/// an Apple display) must not crash the decoder, PD decode, session analysis
/// or dump.
#[test]
fn truncated_extended_message_does_not_panic() {
    use cedar::km003c::{PdEvent, PdStatus};

    let status = PdStatus {
        timestamp_ms: 1000,
        vbus_mv: 20000,
        ibus_ma: 0,
        cc1_mv: 0,
        cc2_mv: 900,
    };
    let mut dec = Decoder::new();
    let mut conv = Converter::new();
    let events: Vec<PdEvent> = [
        vec![0x81, 0x90],             // extended, header only
        vec![0x81, 0x90, 0x05],       // extended, one stray byte
        vec![0x8f, 0x90, 0x02, 0x80], // extended, header + ext header
        vec![0xa1, 0x51],             // Source_Capabilities claiming 5 objects, none present
    ]
    .into_iter()
    .map(|wire| PdEvent::Message {
        timestamp_ms: 999,
        sop: 0,
        wire,
    })
    .collect();
    conv.feed(&mut dec, &status, &events);
    assert_eq!(dec.packets.len(), 4);

    let _ = cedar::pd_decode::decode_capture(&dec.packets);
    let _ = analyze(&dec.packets);
    let opts = cedar::dump::Options {
        events_only: false,
        scope: true,
    };
    let _ = cedar::dump::dump(&dec.packets, &dec.scope, opts);
    let path = std::env::temp_dir().join(format!("cedar-km003c-trunc-{}.html", std::process::id()));
    cedar::report::write_html(
        &path,
        &[cedar::report::Dataset {
            label: "t".into(),
            packets: &dec.packets,
            scope: &dec.scope,
        }],
    )
    .unwrap();
    let _ = std::fs::remove_file(path);
}

#[test]
fn apple_display_thunderbolt_and_pr_swap() {
    let dec = replay("km003c-apple-display.txt");
    let session = analyze(&dec.packets);
    let s = &session.summary;

    assert_eq!(
        s.cable.as_deref(),
        Some("Passive cable — 5 A, 50 V, EPR-capable, USB4 Gen4 (VID 0x2b1d)")
    );
    assert_eq!(s.partner.as_deref(), Some("AMA (VID 0x05ac PID 0x7900)"));
    let contract = s.contract.as_deref().unwrap();
    assert!(contract.starts_with("20 V @ 4.7 A"), "{contract}");

    assert!(dec.packets.iter().any(|p| p.msg == "PR_SWAP"));
    assert!(session
        .events
        .iter()
        .flatten()
        .any(|e| e.text.contains("Thunderbolt alt mode entered")));

    // The KM003C drops extended-message payloads; say so instead of
    // pretending the message was empty.
    let ext: Vec<_> = dec
        .packets
        .iter()
        .filter(|p| p.msg == "MANUFACTURER_INFO")
        .collect();
    assert_eq!(ext.len(), 1);
    assert!(
        ext[0].data.ends_with("(payload not captured)"),
        "{}",
        ext[0].data
    );
}
