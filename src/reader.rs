//! Reading `.ccgx3` capture files (the inverse of `writer::write_ccgx3`):
//! unzip and deserialize the packet and scope lists so a capture can be
//! re-decoded (e.g. into an HTML report).

use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result};
use zip::ZipArchive;

use crate::java_serial::{read_packets, read_scope};
use crate::protocol::{GraphSample, Packet};

/// Read a `.ccgx3` file into its packet and scope lists. Scope may be empty if
/// the capture was taken with the trace disabled.
pub fn read_ccgx3(path: &Path) -> Result<(Vec<Packet>, Vec<GraphSample>)> {
    let bytes = std::fs::read(path).with_context(|| format!("opening {}", path.display()))?;
    read_ccgx3_bytes(&bytes).with_context(|| format!("reading {}", path.display()))
}

/// Read an in-memory `.ccgx3` file (see [`read_ccgx3`]).
pub fn read_ccgx3_bytes(bytes: &[u8]) -> Result<(Vec<Packet>, Vec<GraphSample>)> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).context("not a .ccgx3 (ZIP) file")?;

    let mut part: Option<Vec<u8>> = None;
    let mut scope: Option<Vec<u8>> = None;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if name.ends_with("ezpd_last.part") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            part = Some(buf);
        } else if name.ends_with("ezpd_scope.scope") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            scope = Some(buf);
        }
    }

    let part = part.context("no ezpd_last.part in archive")?;
    let packets = read_packets(&part).context("decoding packet list")?;
    let scope = match scope {
        Some(bytes) => read_scope(&bytes).unwrap_or_default(),
        None => Vec::new(),
    };
    Ok((packets, scope))
}
