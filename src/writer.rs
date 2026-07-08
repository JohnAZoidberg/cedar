//! Writing captures to `.ccgx3` and `.csv`, matching the original utility.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::java_serial::{serialize_packets, serialize_scope};
use crate::protocol::{GraphSample, Packet};

/// Write a `.ccgx3` file: a ZIP holding the Java-serialized packet list
/// (`ezpd_last.part`) and scope list (`ezpd_scope.scope`) inside a
/// timestamp-named folder, exactly as the original "Save" action produces.
pub fn write_ccgx3(path: &Path, packets: &[Packet], scope: &[GraphSample]) -> Result<()> {
    let folder = timestamp_folder();
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut zip = ZipWriter::new(BufWriter::new(file));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.add_directory(format!("{folder}/"), options)?;

    zip.start_file(format!("{folder}/ezpd_last.part"), options)?;
    zip.write_all(&serialize_packets(packets))?;

    zip.start_file(format!("{folder}/ezpd_scope.scope"), options)?;
    zip.write_all(&serialize_scope(scope))?;

    zip.finish()?;
    Ok(())
}

/// Write a `.csv` file with the same columns and formatting as the original
/// utility's Excel/CSV export.
pub fn write_csv(path: &Path, packets: &[Packet]) -> Result<()> {
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    writeln!(
        w,
        "Sno,Ok,SOP,Message,Msg Id,Data Role,Power Role,Obj Count,Rev,Duration,Delta,Vbus(V),Data,Start Time,End Time"
    )?;
    for p in packets {
        let duration = p.duration.replace(',', "");
        let delta = p.delta.as_deref().unwrap_or("").replace(',', "");
        let vbus = p.vbus.replace(',', "");
        let data = csv_data_column(p);
        // Note: the original export writes the start time into the End Time
        // column too; we reproduce that behaviour so captures diff cleanly
        // against the reference utility. The correct end time is preserved in
        // the .ccgx3 file.
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            p.sno,
            p.ok,
            p.sop,
            p.msg,
            p.id,
            p.d_role,
            p.p_role,
            p.count,
            p.rev,
            duration,
            delta,
            vbus,
            data,
            p.s_time,
            p.s_time,
        )?;
    }
    w.flush()?;
    Ok(())
}

/// Reproduce the Data-column formatting from the reference export: extended
/// messages are shown as `0x<hdr> 0x<exthdr>` followed by their raw payload
/// bytes; everything else is passed through unchanged.
fn csv_data_column(p: &Packet) -> String {
    if !p.data.contains("bytes") {
        return p.data.clone();
    }
    let tokens: Vec<&str> = p.data.split(' ').collect();
    let mut out = String::new();
    if let Some(t) = tokens.first() {
        out.push_str(t);
    }
    if let Some(t) = tokens.get(1) {
        out.push(' ');
        out.push_str(t);
    }
    for byte in p.pkt_data.iter().skip(22) {
        out.push_str(&format!(" 0x{byte:02X}"));
    }
    out
}

/// Build a `YYYY_MM_DD_HH_MM_SS` folder name from the current UTC time, the
/// same shape the reference utility uses for its per-capture log directory.
fn timestamp_folder() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day, hour, min, sec) = civil_from_unix(secs);
    format!("{year:04}_{month:02}_{day:02}_{hour:02}_{min:02}_{sec:02}")
}

/// Current UTC time formatted as `YYYY-MM-DD HH:MM`, for report timestamps.
pub(crate) fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day, hour, min, _sec) = civil_from_unix(secs);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}")
}

/// Convert a Unix timestamp (UTC) to civil calendar fields using Howard
/// Hinnant's `civil_from_days` algorithm.
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_unix_matches_known_dates() {
        // 2026-07-08 14:11:00 UTC = 1783778 ... verify a known epoch.
        // 1609459200 = 2021-01-01 00:00:00 UTC
        assert_eq!(civil_from_unix(1609459200), (2021, 1, 1, 0, 0, 0));
        // 0 = 1970-01-01 00:00:00 UTC
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
    }
}
