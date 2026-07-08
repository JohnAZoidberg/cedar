//! A minimal writer for the Java Object Serialization Stream Protocol.
//!
//! The `.ccgx3` format stores its two payloads as Java-serialized objects: an
//! `ArrayList<USBPacketData>` (`ezpd_last.part`) and an `ArrayList<GraphData>`
//! (`ezpd_scope.scope`). Rather than pull in a JVM, we emit the exact stream
//! `java.io.ObjectOutputStream` would produce for those two classes, including
//! the handle/back-reference table so the descriptors and repeated strings are
//! written once. The output is read back correctly by both the original
//! analyzer utility and `javaobj`/`ObjectInputStream`.

use std::collections::HashMap;

use crate::protocol::{GraphSample, Packet};

// Stream grammar constants (see the Java Object Serialization Specification).
const STREAM_MAGIC: u16 = 0xaced;
const STREAM_VERSION: u16 = 5;
const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_ENDBLOCKDATA: u8 = 0x78;
const TC_BLOCKDATA: u8 = 0x77;
const BASE_WIRE_HANDLE: u32 = 0x7e0000;

const SC_WRITE_METHOD: u8 = 0x01;
const SC_SERIALIZABLE: u8 = 0x02;

// serialVersionUIDs of the classes we emit, taken from the reference captures.
const SUID_ARRAYLIST: i64 = 0x7881_D21D_99C7_619Du64 as i64;
const SUID_USBPACKETDATA: i64 = 1;
const SUID_UUID: i64 = 0xBC99_03F7_986D_852Fu64 as i64;
const SUID_BYTE_ARRAY: i64 = 0xACF3_17F8_0608_54E0u64 as i64;
const SUID_GRAPHDATA: i64 = 1;

const CLASS_ARRAYLIST: &str = "java.util.ArrayList";
const CLASS_USBPACKETDATA: &str = "com.cypress.ezpdanalyzer.ui.model.USBPacketData";
const CLASS_GRAPHDATA: &str = "com.cypress.ezpdanalyzer.ui.model.GraphData";
const CLASS_UUID: &str = "java.util.UUID";
const CLASS_BYTE_ARRAY: &str = "[B";

/// A single field in a class descriptor: the type code, name, and (for object
/// or array fields) the type signature string.
struct Field {
    type_code: u8,
    name: &'static str,
    signature: Option<&'static str>,
}

fn f(type_code: u8, name: &'static str, signature: Option<&'static str>) -> Field {
    Field {
        type_code,
        name,
        signature,
    }
}

struct Serializer {
    buf: Vec<u8>,
    next_handle: u32,
    strings: HashMap<String, u32>,
    classes: HashMap<&'static str, u32>,
    uuid_state: u64,
}

impl Serializer {
    fn new() -> Self {
        let mut s = Serializer {
            buf: Vec::new(),
            next_handle: BASE_WIRE_HANDLE,
            strings: HashMap::new(),
            classes: HashMap::new(),
            // Fixed seed: the UUIDs only serve as opaque row identifiers, so a
            // deterministic sequence keeps captures reproducible.
            uuid_state: 0x9e37_79b9_7f4a_7c15,
        };
        s.buf.extend_from_slice(&STREAM_MAGIC.to_be_bytes());
        s.buf.extend_from_slice(&STREAM_VERSION.to_be_bytes());
        s
    }

    fn assign_handle(&mut self) -> u32 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a length-prefixed (modified) UTF-8 string body, without a type tag.
    fn utf(&mut self, s: &str) {
        self.u16(s.len() as u16);
        self.buf.extend_from_slice(s.as_bytes());
    }

    fn reference(&mut self, handle: u32) {
        self.u8(TC_REFERENCE);
        self.buf.extend_from_slice(&handle.to_be_bytes());
    }

    /// Write a string as a new `TC_STRING` (assigning a handle) or a
    /// back-reference to a previously written identical string.
    fn write_string(&mut self, s: &str) {
        if let Some(&h) = self.strings.get(s) {
            self.reference(h);
            return;
        }
        self.u8(TC_STRING);
        self.utf(s);
        let h = self.assign_handle();
        self.strings.insert(s.to_string(), h);
    }

    /// Write a class descriptor with no superclass, back-referencing it if
    /// already emitted.
    fn write_class_desc(&mut self, name: &'static str, suid: i64, flags: u8, fields: &[Field]) {
        if let Some(&h) = self.classes.get(name) {
            self.reference(h);
            return;
        }
        self.u8(TC_CLASSDESC);
        self.utf(name);
        self.i64(suid);
        self.u8(flags);
        self.u16(fields.len() as u16);
        let h = self.assign_handle();
        self.classes.insert(name, h);
        for field in fields {
            self.u8(field.type_code);
            self.utf(field.name);
            if let Some(sig) = field.signature {
                self.write_string(sig);
            }
        }
        self.u8(TC_ENDBLOCKDATA);
        self.u8(TC_NULL); // no superclass
    }

    fn arraylist_desc(&mut self) {
        self.write_class_desc(
            CLASS_ARRAYLIST,
            SUID_ARRAYLIST,
            SC_WRITE_METHOD | SC_SERIALIZABLE,
            &[f(b'I', "size", None)],
        );
    }

    /// Write an empty `java.util.ArrayList` object.
    fn write_empty_arraylist(&mut self) {
        self.u8(TC_OBJECT);
        self.arraylist_desc();
        self.assign_handle();
        self.i32(0); // size field
        self.u8(TC_BLOCKDATA);
        self.u8(4);
        self.i32(0); // capacity
        self.u8(TC_ENDBLOCKDATA);
    }

    /// Emit the next deterministic UUID as a `java.util.UUID` object.
    fn write_uuid(&mut self) {
        // splitmix64 for two 64-bit halves.
        let most = self.next_splitmix();
        let least = self.next_splitmix();
        // Shape the bits like a version-4 UUID (cosmetic only).
        let most = (most & !0x0000_0000_0000_f000) | 0x0000_0000_0000_4000;
        let least = (least & !0xc000_0000_0000_0000) | 0x8000_0000_0000_0000;

        self.u8(TC_OBJECT);
        self.write_class_desc(
            CLASS_UUID,
            SUID_UUID,
            SC_SERIALIZABLE,
            &[f(b'J', "leastSigBits", None), f(b'J', "mostSigBits", None)],
        );
        self.assign_handle();
        self.i64(least as i64);
        self.i64(most as i64);
    }

    fn next_splitmix(&mut self) -> u64 {
        self.uuid_state = self.uuid_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.uuid_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn write_byte_array(&mut self, bytes: &[u8]) {
        self.u8(TC_ARRAY);
        self.write_class_desc(CLASS_BYTE_ARRAY, SUID_BYTE_ARRAY, SC_SERIALIZABLE, &[]);
        self.assign_handle();
        self.i32(bytes.len() as i32);
        self.buf.extend_from_slice(bytes);
    }

    fn usbpacketdata_desc(&mut self) {
        const STR: &str = "Ljava/lang/String;";
        const LIST: &str = "Ljava/util/ArrayList;";
        let fields = [
            f(b'Z', "isMarked", None),
            f(b'I', "markerCount", None),
            f(
                b'L',
                "bg",
                Some("Lcom/cypress/ezpdanalyzer/ui/util/BGColor;"),
            ),
            f(b'L', "count", Some(STR)),
            f(b'L', "dRole", Some(STR)),
            f(b'L', "data", Some(STR)),
            f(b'L', "delta", Some(STR)),
            f(b'L', "duration", Some(STR)),
            f(b'L', "eTime", Some(STR)),
            f(b'L', "id", Some(STR)),
            f(b'L', "msg", Some(STR)),
            f(b'L', "ok", Some(STR)),
            f(b'L', "pRole", Some(STR)),
            f(b'L', "packetDetails", Some(LIST)),
            f(b'L', "payloads", Some(LIST)),
            f(b'[', "pktData", Some("[B")),
            f(b'L', "rev", Some(STR)),
            f(b'L', "sTime", Some(STR)),
            f(b'L', "sno", Some(STR)),
            f(b'L', "sop", Some(STR)),
            f(b'L', "subPackets", Some(LIST)),
            f(b'L', "uniqueId", Some("Ljava/util/UUID;")),
            f(b'L', "vbus", Some(STR)),
        ];
        self.write_class_desc(
            CLASS_USBPACKETDATA,
            SUID_USBPACKETDATA,
            SC_SERIALIZABLE,
            &fields,
        );
    }

    /// Write a String field value that may be null.
    fn write_opt_string(&mut self, s: Option<&str>) {
        match s {
            Some(v) => self.write_string(v),
            None => self.u8(TC_NULL),
        }
    }

    fn write_packet(&mut self, p: &Packet) {
        self.u8(TC_OBJECT);
        self.usbpacketdata_desc();
        self.assign_handle();
        // Field values in the class descriptor's declared order.
        self.u8(0); // isMarked = false
        self.i32(0); // markerCount
        self.u8(TC_NULL); // bg
        self.write_string(&p.count);
        self.write_string(&p.d_role);
        self.write_string(&p.data);
        self.write_opt_string(p.delta.as_deref());
        self.write_string(&p.duration);
        self.write_string(&p.e_time);
        self.write_string(&p.id);
        self.write_string(&p.msg);
        self.write_string(&p.ok);
        self.write_string(&p.p_role);
        self.write_empty_arraylist(); // packetDetails
        self.write_empty_arraylist(); // payloads
        self.write_byte_array(&p.pkt_data);
        self.write_string(&p.rev);
        self.write_string(&p.s_time);
        self.write_string(&p.sno);
        self.write_string(&p.sop);
        self.write_empty_arraylist(); // subPackets
        self.write_uuid();
        self.write_string(&p.vbus);
    }

    fn write_graph(&mut self, g: &GraphSample) {
        self.u8(TC_OBJECT);
        self.write_class_desc(
            CLASS_GRAPHDATA,
            SUID_GRAPHDATA,
            SC_SERIALIZABLE,
            &[
                f(b'S', "amp", None),
                f(b'S', "cc1", None),
                f(b'S', "cc2", None),
                f(b'J', "timeStamp", None),
                f(b'S', "volt", None),
            ],
        );
        self.assign_handle();
        self.u16(g.amp as u16);
        self.u16(g.cc1 as u16);
        self.u16(g.cc2 as u16);
        self.i64(g.time_stamp);
        self.u16(g.volt as u16);
    }

    /// Write an `ArrayList` wrapper around a sequence of elements.
    fn write_list<T>(&mut self, items: &[T], mut write_elem: impl FnMut(&mut Self, &T)) {
        self.u8(TC_OBJECT);
        self.arraylist_desc();
        self.assign_handle();
        self.i32(items.len() as i32); // size field
        self.u8(TC_BLOCKDATA);
        self.u8(4);
        self.i32(items.len() as i32); // capacity
        for item in items {
            write_elem(self, item);
        }
        self.u8(TC_ENDBLOCKDATA);
    }
}

/// Serialize the packet list into the `ezpd_last.part` byte stream.
pub fn serialize_packets(packets: &[Packet]) -> Vec<u8> {
    let mut s = Serializer::new();
    s.write_list(packets, |s, p| s.write_packet(p));
    s.buf
}

/// Serialize the scope sample list into the `ezpd_scope.scope` byte stream.
pub fn serialize_scope(scope: &[GraphSample]) -> Vec<u8> {
    let mut s = Serializer::new();
    s.write_list(scope, |s, g| s.write_graph(g));
    s.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suid_constants_have_expected_bytes() {
        assert_eq!(SUID_ARRAYLIST as u64, 0x7881D21D99C7619D);
        assert_eq!(SUID_UUID as u64, 0xBC9903F7986D852F);
        assert_eq!(SUID_BYTE_ARRAY as u64, 0xACF317F8060854E0);
    }

    #[test]
    fn empty_packet_stream_has_header() {
        let out = serialize_packets(&[]);
        assert_eq!(&out[..4], &[0xac, 0xed, 0x00, 0x05]);
    }
}
