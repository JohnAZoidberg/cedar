//! libusb transport for the KM003C: device discovery, the request/response
//! exchange on the vendor bulk interface, and the native capture loop.

use std::cell::Cell;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use rusb::{Device, DeviceHandle, GlobalContext};

use super::*;
use crate::capture::Status;
use crate::protocol::Decoder;

const CMD_TIMEOUT: Duration = Duration::from_millis(1000);
/// Pause between PD polls. The meter queues events between polls; ~10 ms keeps
/// the queue short without hogging the bus.
const POLL_INTERVAL: Duration = Duration::from_millis(POLL_INTERVAL_MS);

/// Find the first attached KM003C, if any.
pub fn find_device() -> Result<Option<Device<GlobalContext>>> {
    for dev in rusb::devices()?.iter() {
        if let Ok(desc) = dev.device_descriptor() {
            if desc.vendor_id() == VID && desc.product_id() == PID {
                return Ok(Some(dev));
            }
        }
    }
    Ok(None)
}

/// Describe each attached KM003C (one line per device).
pub fn describe_devices() -> Result<Vec<String>> {
    let mut out = Vec::new();
    for dev in rusb::devices()?.iter() {
        let Ok(desc) = dev.device_descriptor() else {
            continue;
        };
        if desc.vendor_id() != VID || desc.product_id() != PID {
            continue;
        }
        out.push(format!(
            "POWER-Z KM003C at bus {:03} device {:03} [{:04x}:{:04x}]",
            dev.bus_number(),
            dev.address(),
            VID,
            PID
        ));
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn open_error(dev: &Device<GlobalContext>, e: rusb::Error) -> anyhow::Error {
    let node = format!("/dev/bus/usb/{:03}/{:03}", dev.bus_number(), dev.address());
    if matches!(e, rusb::Error::Access) {
        anyhow!(
            "permission denied opening {node}.\n\
             Install the bundled udev rule:\n  \
             sudo cp contrib/71-powerz-km003c.rules /etc/udev/rules.d/ && \
             sudo udevadm control --reload-rules && \
             sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=5fc9"
        )
    } else {
        anyhow!("failed to open KM003C at {node}: {e}")
    }
}

#[cfg(not(target_os = "linux"))]
fn open_error(_dev: &Device<GlobalContext>, e: rusb::Error) -> anyhow::Error {
    anyhow!("failed to open KM003C: {e}")
}

/// A claimed KM003C. Dropping it releases the interface; on Linux libusb then
/// rebinds the `powerz` hwmon driver it detached.
pub struct Km003c {
    handle: DeviceHandle<GlobalContext>,
    next_id: Cell<u8>,
}

impl Km003c {
    pub fn open(dev: &Device<GlobalContext>) -> Result<Self> {
        let handle = dev.open().map_err(|e| open_error(dev, e))?;
        let _ = handle.set_auto_detach_kernel_driver(true);
        handle
            .claim_interface(INTERFACE)
            .map_err(|e| anyhow!("failed to claim KM003C interface {INTERFACE}: {e}"))?;
        let meter = Km003c {
            handle,
            next_id: Cell::new(0),
        };
        meter.drain();
        Ok(meter)
    }

    /// Discard anything left in the IN pipe from an earlier session.
    fn drain(&self) {
        let mut buf = [0u8; 4096];
        while self
            .handle
            .read_bulk(EP_IN, &mut buf, Duration::from_millis(20))
            .is_ok()
        {}
    }

    /// Send `cmd` and return its whole response.
    fn transact(&self, cmd: Command) -> Result<Vec<u8>> {
        let id = self.next_id.get().wrapping_add(1);
        self.next_id.set(id);
        self.handle
            .write_bulk(EP_OUT, &cmd.header(id), CMD_TIMEOUT)
            .map_err(|e| anyhow!("KM003C write failed: {e}"))?;
        let resp = self.receive(id, |m| cmd.response_complete(m))?;
        cmd.check_response(&resp)?;
        Ok(resp)
    }

    /// Read one response with transaction id `id`, discarding stale ones.
    /// `complete` says whether the bytes so far form a whole response.
    fn receive(&self, id: u8, complete: impl Fn(&[u8]) -> Result<bool>) -> Result<Vec<u8>> {
        let deadline = Instant::now() + CMD_TIMEOUT;
        let mut buf = [0u8; 4096];
        let mut msg: Vec<u8> = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("timed out waiting for KM003C response");
            }
            let n = match self.handle.read_bulk(EP_IN, &mut buf, remaining) {
                Ok(n) => n,
                Err(rusb::Error::Timeout) => continue,
                Err(e) => bail!("KM003C read failed: {e}"),
            };
            msg.extend_from_slice(&buf[..n]);
            if msg.len() >= 2 && msg[1] != id {
                log::debug!(
                    "discarding stale KM003C response {:02x?}",
                    &msg[..msg.len().min(8)]
                );
                msg.clear();
                continue;
            }
            if complete(&msg)? {
                return Ok(msg);
            }
        }
    }

    /// Poll the PD queue, returning the whole PutData response (extract the
    /// payload with [`pd_payload`]).
    pub fn poll_pd(&self) -> Result<Vec<u8>> {
        self.transact(Command::PollPd)
    }

    /// Run the capture loop until `stop` is set, decoding into `decoder`.
    ///
    /// If `raw` is given, every poll response that carries PD events is also
    /// written to it as one hex line (the `tests/fixtures/km003c-*.txt`
    /// format), for debugging and new test fixtures.
    pub fn capture(
        &self,
        decoder: &mut Decoder,
        stop: &Arc<AtomicBool>,
        mut raw: Option<&mut dyn Write>,
    ) -> Result<()> {
        self.transact(Command::Connect)?;
        self.transact(Command::PdMonitorOn)?;

        let mut converter = Converter::new();
        let mut status = Status::new(true);
        let result = (|| -> Result<()> {
            while !stop.load(Ordering::Relaxed) {
                let resp = self.poll_pd()?;
                let payload = pd_payload(&resp)?;
                if let Some(w) = raw.as_mut() {
                    if payload.len() > PD_STATUS_SIZE {
                        let line: String = resp.iter().map(|b| format!("{b:02x}")).collect();
                        writeln!(w, "{line}")?;
                    }
                }
                match parse_pd_payload(payload) {
                    Ok((st, events)) => converter.feed(decoder, &st, &events),
                    Err(e) => {
                        status.interrupt();
                        eprintln!("skipping malformed KM003C PD payload: {e:#}");
                    }
                }
                status.tick(decoder, false);
                std::thread::sleep(POLL_INTERVAL);
            }
            Ok(())
        })();
        status.tick(decoder, true);

        // Always try to turn the monitor off again, even after an error.
        let _ = self.transact(Command::PdMonitorOff);
        result
    }
}
