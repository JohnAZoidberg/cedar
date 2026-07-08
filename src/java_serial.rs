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

// ---------------------------------------------------------------- reader

use anyhow::{bail, Result};

/// A slot in the deserialization handle table.
#[derive(Clone)]
enum Handle {
    Str(String),
    Class(ClassDesc),
    Other,
}

/// Minimal class descriptor: name plus (type-code, field-name) pairs.
#[derive(Clone)]
struct ClassDesc {
    name: String,
    fields: Vec<(u8, String)>,
}

/// A decoded field value we care about (strings and byte arrays); everything
/// else is consumed but discarded.
enum Val {
    Null,
    Str(String),
    Bytes(Vec<u8>),
    Other,
}

/// A cursor over a Java `ObjectOutputStream` byte stream, tracking the handle
/// table so back-references resolve. Only the subset of the grammar used by the
/// analyzer's captures is implemented.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    handles: Vec<Handle>,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let mut r = Reader {
            data,
            pos: 0,
            handles: Vec::new(),
        };
        if r.u16()? != STREAM_MAGIC || r.u16()? != STREAM_VERSION {
            bail!("not a Java serialization stream");
        }
        Ok(r)
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(eof)?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }
    fn i32(&mut self) -> Result<i32> {
        let mut v = 0i32;
        for _ in 0..4 {
            v = (v << 8) | self.u8()? as i32;
        }
        Ok(v)
    }
    fn i64(&mut self) -> Result<i64> {
        let mut v = 0i64;
        for _ in 0..8 {
            v = (v << 8) | self.u8()? as i64;
        }
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        let end = self.pos.checked_add(n).ok_or_else(eof)?;
        let s = self.data.get(self.pos..end).ok_or_else(eof)?.to_vec();
        self.pos = end;
        Ok(s)
    }
    fn utf(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        Ok(String::from_utf8_lossy(&self.take(n)?).into_owned())
    }
    fn expect(&mut self, tc: u8) -> Result<()> {
        let got = self.u8()?;
        if got != tc {
            bail!(
                "expected tag {tc:#x}, got {got:#x} at offset {}",
                self.pos - 1
            );
        }
        Ok(())
    }
    fn ref_index(&mut self) -> Result<usize> {
        let h = self.i32()? as u32;
        Ok((h.wrapping_sub(BASE_WIRE_HANDLE)) as usize)
    }

    /// Read a class descriptor (new, a back-reference, or null).
    fn class_desc(&mut self) -> Result<ClassDesc> {
        match self.u8()? {
            TC_NULL => Ok(ClassDesc {
                name: String::new(),
                fields: Vec::new(),
            }),
            TC_REFERENCE => {
                let h = self.ref_index()?;
                match self.handles.get(h) {
                    Some(Handle::Class(c)) => Ok(c.clone()),
                    _ => bail!("bad class reference"),
                }
            }
            TC_CLASSDESC => {
                let name = self.utf()?;
                let _suid = self.i64()?;
                let _flags = self.u8()?;
                let nfields = self.u16()?;
                let idx = self.handles.len();
                self.handles.push(Handle::Other); // reserve class handle
                let mut fields = Vec::with_capacity(nfields as usize);
                for _ in 0..nfields {
                    let tc = self.u8()?;
                    let fname = self.utf()?;
                    if tc == b'L' || tc == b'[' {
                        self.read_string()?; // field type signature (consumes a handle)
                    }
                    fields.push((tc, fname));
                }
                self.expect(TC_ENDBLOCKDATA)?;
                let cd = ClassDesc { name, fields };
                self.handles[idx] = Handle::Class(cd.clone());
                self.class_desc()?; // superclass (TC_NULL in our data)
                Ok(cd)
            }
            other => bail!("expected class descriptor, got tag {other:#x}"),
        }
    }

    fn read_string(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            TC_NULL => Ok(None),
            TC_STRING => {
                let s = self.utf()?;
                self.handles.push(Handle::Str(s.clone()));
                Ok(Some(s))
            }
            TC_REFERENCE => {
                let h = self.ref_index()?;
                match self.handles.get(h) {
                    Some(Handle::Str(s)) => Ok(Some(s.clone())),
                    _ => bail!("bad string reference"),
                }
            }
            other => bail!("expected string, got tag {other:#x}"),
        }
    }

    /// Read one object/array field value (the `L`/`[` field types).
    fn read_value(&mut self) -> Result<Val> {
        match self.u8()? {
            TC_NULL => Ok(Val::Null),
            TC_STRING => {
                let s = self.utf()?;
                self.handles.push(Handle::Str(s.clone()));
                Ok(Val::Str(s))
            }
            TC_REFERENCE => {
                let h = self.ref_index()?;
                match self.handles.get(h) {
                    Some(Handle::Str(s)) => Ok(Val::Str(s.clone())),
                    _ => Ok(Val::Other),
                }
            }
            TC_ARRAY => {
                let _cd = self.class_desc()?;
                self.handles.push(Handle::Other);
                let len = self.i32()? as usize;
                Ok(Val::Bytes(self.take(len)?))
            }
            TC_OBJECT => {
                let cd = self.class_desc()?;
                self.handles.push(Handle::Other);
                match cd.name.as_str() {
                    "java.util.ArrayList" => {
                        let size = self.i32()?;
                        self.expect(TC_BLOCKDATA)?;
                        let _blen = self.u8()?;
                        let _cap = self.i32()?;
                        for _ in 0..size {
                            self.read_value()?; // nested elements (empty in our data)
                        }
                        self.expect(TC_ENDBLOCKDATA)?;
                        Ok(Val::Other)
                    }
                    _ => {
                        // Generic object: consume its declared fields.
                        for (tc, _) in cd.fields.clone() {
                            self.read_field(tc)?;
                        }
                        Ok(Val::Other)
                    }
                }
            }
            other => bail!("unexpected value tag {other:#x}"),
        }
    }

    /// Consume a single field value of the given type code.
    fn read_field(&mut self, tc: u8) -> Result<Val> {
        match tc {
            b'Z' | b'B' => {
                self.u8()?;
                Ok(Val::Other)
            }
            b'C' | b'S' => {
                self.u16()?;
                Ok(Val::Other)
            }
            b'I' | b'F' => {
                self.i32()?;
                Ok(Val::Other)
            }
            b'J' | b'D' => {
                self.i64()?;
                Ok(Val::Other)
            }
            b'L' | b'[' => self.read_value(),
            other => bail!("unknown field type {other}"),
        }
    }

    /// Read the `TC_OBJECT` ArrayList wrapper and its elements via `elem`.
    fn read_list<T>(&mut self, mut elem: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        self.expect(TC_OBJECT)?;
        let _cd = self.class_desc()?; // java.util.ArrayList
        self.handles.push(Handle::Other);
        let size = self.i32()?;
        self.expect(TC_BLOCKDATA)?;
        let _blen = self.u8()?;
        let _cap = self.i32()?;
        let mut out = Vec::with_capacity(size.max(0) as usize);
        for _ in 0..size {
            out.push(elem(self)?);
        }
        self.expect(TC_ENDBLOCKDATA)?;
        Ok(out)
    }

    /// Read one object, returning its object fields as a name→value map.
    fn read_object_fields(&mut self) -> Result<HashMap<String, Val>> {
        self.expect(TC_OBJECT)?;
        let cd = self.class_desc()?;
        self.handles.push(Handle::Other);
        let mut map = HashMap::new();
        for (tc, name) in cd.fields.clone() {
            let v = self.read_field(tc)?;
            if matches!(tc, b'L' | b'[') {
                map.insert(name, v);
            }
        }
        Ok(map)
    }

    /// Read one object, returning its primitive fields as a name→i64 map.
    fn read_object_prims(&mut self) -> Result<HashMap<String, i64>> {
        self.expect(TC_OBJECT)?;
        let cd = self.class_desc()?;
        self.handles.push(Handle::Other);
        let mut map = HashMap::new();
        for (tc, name) in cd.fields.clone() {
            let v = match tc {
                b'Z' | b'B' => self.u8()? as i64,
                b'C' | b'S' => self.u16()? as i16 as i64,
                b'I' => self.i32()? as i64,
                b'J' => self.i64()?,
                b'L' | b'[' => {
                    self.read_value()?;
                    continue;
                }
                other => bail!("unknown field type {other}"),
            };
            map.insert(name, v);
        }
        Ok(map)
    }
}

fn eof() -> anyhow::Error {
    anyhow::anyhow!("unexpected end of serialized stream")
}

/// Deserialize `ezpd_last.part` into packets.
pub fn read_packets(bytes: &[u8]) -> Result<Vec<Packet>> {
    let mut r = Reader::new(bytes)?;
    r.read_list(|r| {
        let f = r.read_object_fields()?;
        let s = |k: &str| match f.get(k) {
            Some(Val::Str(v)) => v.clone(),
            _ => String::new(),
        };
        let delta = match f.get("delta") {
            Some(Val::Str(v)) => Some(v.clone()),
            _ => None,
        };
        let pkt_data = match f.get("pktData") {
            Some(Val::Bytes(b)) => b.clone(),
            _ => Vec::new(),
        };
        Ok(Packet {
            sno: s("sno"),
            ok: s("ok"),
            sop: s("sop"),
            msg: s("msg"),
            id: s("id"),
            d_role: s("dRole"),
            p_role: s("pRole"),
            count: s("count"),
            rev: s("rev"),
            duration: s("duration"),
            delta,
            vbus: s("vbus"),
            data: s("data"),
            s_time: s("sTime"),
            e_time: s("eTime"),
            pkt_data,
        })
    })
}

/// Deserialize `ezpd_scope.scope` into scope samples.
pub fn read_scope(bytes: &[u8]) -> Result<Vec<GraphSample>> {
    let mut r = Reader::new(bytes)?;
    r.read_list(|r| {
        let p = r.read_object_prims()?;
        let g = |k: &str| p.get(k).copied().unwrap_or(0);
        Ok(GraphSample {
            cc1: g("cc1") as i16,
            cc2: g("cc2") as i16,
            amp: g("amp") as i16,
            volt: g("volt") as i16,
            time_stamp: g("timeStamp"),
        })
    })
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

    #[test]
    fn packets_round_trip() {
        let pkts = vec![
            Packet {
                sno: "1".into(),
                ok: "VBUS_UP".into(),
                sop: "SOP".into(),
                msg: "C_RSVD0".into(),
                id: "0".into(),
                d_role: "UFP".into(),
                p_role: "SNK".into(),
                count: "0".into(),
                rev: "v1".into(),
                duration: "0".into(),
                delta: None,
                vbus: "5,000".into(),
                data: "0x0".into(),
                s_time: "26".into(),
                e_time: "26".into(),
                pkt_data: vec![1, 2, 3, 4, 5, 6],
            },
            Packet {
                sno: "3".into(),
                ok: "OK".into(),
                sop: "SOP".into(),
                msg: "SOURCE_CAPABILITIES".into(),
                id: "1".into(),
                d_role: "DFP".into(),
                p_role: "SRC".into(),
                count: "7".into(),
                rev: "v3".into(),
                duration: "1,376".into(),
                delta: Some("7,190".into()),
                vbus: "19,800".into(),
                data: "0x71A1 0xA81912C".into(),
                s_time: "1000".into(),
                e_time: "2376".into(),
                pkt_data: (0..48).collect(),
            },
        ];
        let bytes = serialize_packets(&pkts);
        let back = read_packets(&bytes).unwrap();
        assert_eq!(back.len(), pkts.len());
        for (a, b) in pkts.iter().zip(&back) {
            assert_eq!(a.sno, b.sno);
            assert_eq!(a.ok, b.ok);
            assert_eq!(a.msg, b.msg);
            assert_eq!(a.data, b.data);
            assert_eq!(a.vbus, b.vbus);
            assert_eq!(a.delta, b.delta);
            assert_eq!(a.s_time, b.s_time);
            assert_eq!(a.e_time, b.e_time);
            assert_eq!(a.pkt_data, b.pkt_data);
        }
    }

    #[test]
    fn scope_round_trip() {
        let scope = vec![
            GraphSample {
                cc1: 1657,
                cc2: 0,
                amp: 250,
                volt: 19800,
                time_stamp: 876,
            },
            GraphSample {
                cc1: -5,
                cc2: 3,
                amp: 1208,
                volt: 19600,
                time_stamp: 5_995_974,
            },
        ];
        let bytes = serialize_scope(&scope);
        let back = read_scope(&bytes).unwrap();
        assert_eq!(back.len(), scope.len());
        for (a, b) in scope.iter().zip(&back) {
            assert_eq!(a.cc1, b.cc1);
            assert_eq!(a.cc2, b.cc2);
            assert_eq!(a.amp, b.amp);
            assert_eq!(a.volt, b.volt);
            assert_eq!(a.time_stamp, b.time_stamp);
        }
    }
}
