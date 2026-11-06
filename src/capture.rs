//! Talking to the CY4500 over USB: device discovery, start/stop, and the
//! capture read loop.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use rusb::{Device, DeviceHandle, GlobalContext};

use crate::pd_session::{analyze, Summary};
use crate::protocol::{
    cmd_get_version, cmd_start, cmd_stop, Decoder, GraphSample, EP_IN_CC_DATA, EP_IN_CMD_RESP,
    EP_IN_MEASURE, EP_OUT_CMD, MAX_READ_SIZE, MAX_SCOPE_READ_SIZE, PID, PID_NO_WINUSB, VID,
};

const CMD_TIMEOUT: Duration = Duration::from_millis(1000);
/// Short read timeout so Ctrl+C is handled promptly between transfers.
const READ_TIMEOUT: Duration = Duration::from_millis(200);
const IDLE_SLEEP: Duration = Duration::from_millis(5);
/// How often the live status display is redrawn on a terminal.
const STATUS_INTERVAL: Duration = Duration::from_millis(100);

/// A claimed CY4500 ready for capture.
pub struct Analyzer {
    handle: DeviceHandle<GlobalContext>,
}

/// Find the first attached CY4500 analyzer, if any.
pub fn find_device() -> Result<Device<GlobalContext>> {
    let mut needs_firmware = false;
    for dev in rusb::devices()?.iter() {
        let desc = match dev.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if desc.vendor_id() != VID {
            continue;
        }
        if desc.product_id() == PID {
            return Ok(dev);
        }
        if desc.product_id() == PID_NO_WINUSB {
            needs_firmware = true;
        }
    }
    if needs_firmware {
        bail!(
            "Found a CY4500 in firmware-update mode (PID {PID_NO_WINUSB:#06x}). \
             Use the original utility to flash its capture firmware first."
        );
    }
    Err(anyhow!(
        "No CY4500 EZ-PD Analyzer found (looking for {VID:#06x}:{PID:#06x})."
    ))
}

/// Print all attached analyzers.
pub fn list_devices() -> Result<()> {
    let mut found = 0;
    for dev in rusb::devices()?.iter() {
        let desc = match dev.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if desc.vendor_id() == VID
            && (desc.product_id() == PID || desc.product_id() == PID_NO_WINUSB)
        {
            found += 1;
            let mode = if desc.product_id() == PID_NO_WINUSB {
                " (firmware-update mode)"
            } else {
                ""
            };
            println!(
                "CY4500 EZ-PD Analyzer at bus {:03} device {:03} [{:04x}:{:04x}]{}",
                dev.bus_number(),
                dev.address(),
                desc.vendor_id(),
                desc.product_id(),
                mode
            );
        }
    }
    if found == 0 {
        println!("No CY4500 EZ-PD Analyzer found.");
    }
    Ok(())
}

/// The Linux usbfs device node for a device, e.g. `/dev/bus/usb/003/009`.
#[cfg(target_os = "linux")]
fn usb_node_path(dev: &Device<GlobalContext>) -> String {
    format!("/dev/bus/usb/{:03}/{:03}", dev.bus_number(), dev.address())
}

/// Build a helpful error for a failed `open`, naming the device node to fix on
/// Linux.
#[cfg(target_os = "linux")]
fn open_error(dev: &Device<GlobalContext>, e: rusb::Error) -> anyhow::Error {
    let node = usb_node_path(dev);
    if matches!(e, rusb::Error::Access) {
        anyhow!(
            "permission denied opening {node}.\n\
             Grant access with either:\n  \
             sudo chmod 666 {node}          (temporary, until the analyzer is replugged)\n\
             or install the bundled udev rule for a permanent fix:\n  \
             sudo cp contrib/99-cy4500.rules /etc/udev/rules.d/ && \
             sudo udevadm control --reload-rules && sudo udevadm trigger\n  \
             (then replug the analyzer)"
        )
    } else {
        anyhow!("failed to open device at {node}: {e}")
    }
}

#[cfg(not(target_os = "linux"))]
fn open_error(_dev: &Device<GlobalContext>, e: rusb::Error) -> anyhow::Error {
    anyhow!("failed to open device: {e}")
}

impl Analyzer {
    /// Open and claim interface 0 of the given device.
    pub fn open(dev: &Device<GlobalContext>) -> Result<Self> {
        let handle = dev.open().map_err(|e| open_error(dev, e))?;
        // Best-effort: let libusb reattach any kernel driver on release.
        let _ = handle.set_auto_detach_kernel_driver(true);
        handle
            .claim_interface(0)
            .map_err(|e| anyhow!("failed to claim interface 0: {e}"))?;
        Ok(Analyzer { handle })
    }

    /// Read the 4-byte firmware version.
    pub fn version(&self) -> Result<[u8; 4]> {
        self.handle
            .write_bulk(EP_OUT_CMD, &cmd_get_version(), CMD_TIMEOUT)?;
        let mut buf = [0u8; 4];
        let n = self
            .handle
            .read_bulk(EP_IN_CMD_RESP, &mut buf, CMD_TIMEOUT)?;
        if n != 4 {
            bail!("unexpected version response length: {n}");
        }
        Ok(buf)
    }

    fn start(&self) -> Result<()> {
        self.handle
            .write_bulk(EP_OUT_CMD, &cmd_start(), CMD_TIMEOUT)?;
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.handle
            .write_bulk(EP_OUT_CMD, &cmd_stop(), CMD_TIMEOUT)?;
        Ok(())
    }

    /// Run the capture loop until `stop` is set, decoding into `decoder`.
    pub fn capture(
        &self,
        decoder: &mut Decoder,
        capture_scope: bool,
        stop: &Arc<AtomicBool>,
    ) -> Result<()> {
        self.start()?;

        let mut data_buf = vec![0u8; MAX_READ_SIZE];
        let mut scope_buf = vec![0u8; MAX_SCOPE_READ_SIZE];
        let mut status = Status::new(capture_scope);

        while !stop.load(Ordering::Relaxed) {
            match self
                .handle
                .read_bulk(EP_IN_CC_DATA, &mut data_buf, READ_TIMEOUT)
            {
                Ok(size) if size > 8 => {
                    decoder.feed_pd(&data_buf[..size]);
                    status.tick(decoder, false);
                    continue;
                }
                Ok(_) => {}
                Err(rusb::Error::Timeout) => {}
                Err(e) => {
                    status.interrupt();
                    eprintln!("read error on data endpoint: {e}");
                }
            }

            if capture_scope {
                scope_buf.iter_mut().for_each(|b| *b = 0);
                match self
                    .handle
                    .read_bulk(EP_IN_MEASURE, &mut scope_buf, READ_TIMEOUT)
                {
                    Ok(size) if size > 8 => {
                        decoder.feed_scope(&scope_buf[..size]);
                        status.tick(decoder, false);
                        continue;
                    }
                    Ok(_) => {}
                    Err(rusb::Error::Timeout) => {}
                    Err(e) => {
                        status.interrupt();
                        eprintln!("read error on measure endpoint: {e}");
                    }
                }
            }

            status.tick(decoder, false);
            std::thread::sleep(IDLE_SLEEP);
        }

        status.tick(decoder, true);
        // Tell the device to stop streaming; ignore errors during teardown.
        let _ = self.stop();
        Ok(())
    }
}

/// A live, in-place status display shown while capturing. On a terminal it
/// redraws three lines: running counts, the most recent PD message, and the
/// latest voltage/current levels. When output is not a terminal it prints a
/// periodic single-line summary instead.
pub(crate) struct Status {
    start: Instant,
    last_draw: Option<Instant>,
    tty: bool,
    drawn: bool,
    lines: usize,
    capture_scope: bool,
    packets_seen: usize,
    last_msg: Option<(String, String, i64)>, // message, SOP, VBUS in mV
    summary: Summary,
}

impl Status {
    pub(crate) fn new(capture_scope: bool) -> Self {
        Status {
            start: Instant::now(),
            last_draw: None,
            tty: std::io::stderr().is_terminal(),
            drawn: false,
            lines: 0,
            capture_scope,
            packets_seen: 0,
            last_msg: None,
            summary: Summary::default(),
        }
    }

    /// Note new packets and, subject to throttling (or `force`), redraw.
    pub(crate) fn tick(&mut self, decoder: &Decoder, force: bool) {
        if decoder.packets.len() != self.packets_seen {
            for p in &decoder.packets[self.packets_seen..] {
                if is_real_message(p) {
                    self.last_msg = Some((p.msg.clone(), p.sop.clone(), parse_mv(&p.vbus)));
                }
            }
            self.packets_seen = decoder.packets.len();
            // Re-derive contract/cable only when new packets have arrived.
            self.summary = analyze(&decoder.packets).summary;
        }

        let now = Instant::now();
        let interval = if self.tty {
            STATUS_INTERVAL
        } else {
            Duration::from_secs(2)
        };
        if !force {
            if let Some(last) = self.last_draw {
                if now.duration_since(last) < interval {
                    return;
                }
            }
        }
        self.last_draw = Some(now);
        self.render(decoder);
    }

    /// Called before printing unrelated output so the next redraw starts fresh
    /// rather than moving the cursor over it.
    pub(crate) fn interrupt(&mut self) {
        self.drawn = false;
    }

    fn render(&mut self, decoder: &Decoder) {
        let elapsed = self.start.elapsed().as_secs();
        let lines = [
            format!(
                "  packets: {}   scope: {}   elapsed: {}s",
                decoder.packets.len(),
                decoder.scope.len(),
                elapsed
            ),
            match &self.last_msg {
                Some((msg, sop, mv)) => {
                    format!("  last: {msg}  {sop}  VBUS {:.2} V", *mv as f64 / 1000.0)
                }
                None => "  last: waiting for PD traffic".to_string(),
            },
            level_line(decoder.scope.last(), self.capture_scope),
            format!(
                "  contract: {}",
                self.summary.contract.as_deref().unwrap_or("none yet")
            ),
            format!(
                "  cable: {}",
                self.summary.cable.as_deref().unwrap_or("not discovered")
            ),
        ];

        let mut err = std::io::stderr();
        if self.tty {
            if self.drawn {
                let _ = write!(err, "\x1b[{}A", self.lines);
            }
            for line in &lines {
                let _ = write!(err, "\r\x1b[2K{line}\n");
            }
            self.drawn = true;
            self.lines = lines.len();
        } else {
            let _ = writeln!(err, "{}", lines[0].trim_start());
        }
        let _ = err.flush();
    }
}

/// Build the levels line from the latest scope sample.
fn level_line(sample: Option<&GraphSample>, capture_scope: bool) -> String {
    match sample {
        Some(s) => format!(
            "  levels: VBUS {:.2} V   CC1 {} mV   CC2 {} mV   I {} mA   P {:.1} W",
            s.volt as f64 / 1000.0,
            s.cc1,
            s.cc2,
            s.amp,
            (s.volt as f64 / 1000.0) * (s.amp as f64 / 1000.0),
        ),
        None if !capture_scope => "  levels: (scope disabled)".to_string(),
        None => "  levels: (waiting for scope data)".to_string(),
    }
}

/// Parse a possibly grouped millivolt string (e.g. `"19,800"`) to an integer.
fn parse_mv(s: &str) -> i64 {
    s.replace(',', "").parse().unwrap_or(0)
}

/// Whether a packet is a real PD message, as opposed to a VBUS attach/detach
/// event or a reserved-type placeholder row (both of which carry no useful
/// "last message" for the live display).
fn is_real_message(p: &crate::protocol::Packet) -> bool {
    if p.ok == "VBUS_UP" || p.ok == "VBUS_DN" {
        return false;
    }
    let m = &p.msg;
    m != "GOODCRC"
        && !m.starts_with("C_RSVD")
        && !m.starts_with("D_RSVD")
        && !m.starts_with("E_RSVD")
}
