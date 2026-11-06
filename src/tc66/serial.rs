//! Serial-port transport for the TC66: port discovery and the `getva` exchange.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serialport::{ClearBuffer, SerialPort, SerialPortType};

use super::*;

/// How long to wait for a whole reply.
const REPLY_TIMEOUT: Duration = Duration::from_millis(1000);
/// Attempts at a `getva` exchange before giving up (a reply can be cut short
/// or misaligned, e.g. by a stale reply left over from another program).
const ATTEMPTS: usize = 3;

/// Find the serial port of the first attached TC66, if any.
pub fn find_port() -> Result<Option<String>> {
    Ok(ports()?.into_iter().next())
}

fn ports() -> Result<Vec<String>> {
    let mut out: Vec<String> = serialport::available_ports()
        .context("listing serial ports")?
        .into_iter()
        .filter(
            |p| matches!(&p.port_type, SerialPortType::UsbPort(u) if u.vid == VID && u.pid == PID),
        )
        .map(|p| p.port_name)
        .collect();
    out.sort();
    // macOS lists each port as both /dev/tty.* and /dev/cu.*; use cu.
    if out.iter().any(|p| p.starts_with("/dev/cu.")) {
        out.retain(|p| !p.starts_with("/dev/tty."));
    }
    Ok(out)
}

/// Describe each attached TC66 (one line per device).
pub fn describe_devices() -> Result<Vec<String>> {
    Ok(ports()?
        .into_iter()
        .map(|port| format!("TC66 USB-C meter at {port} [{VID:04x}:{PID:04x}]"))
        .collect())
}

/// An open TC66.
pub struct Tc66 {
    port: Box<dyn SerialPort>,
    name: String,
}

impl Tc66 {
    /// Open the meter on serial port `name` and check it runs its normal
    /// firmware.
    pub fn open(name: &str) -> Result<Self> {
        // CDC-ACM ignores the baud rate; 115200 matches the vendor software.
        let port = serialport::new(name, 115_200)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|e| open_error(name, e))?;
        let mut meter = Tc66 {
            port,
            name: name.to_string(),
        };
        let mode = meter.exchange(CMD_QUERY, 4)?;
        match &mode[..] {
            b"firm" => {}
            b"boot" => bail!("the TC66 on {name} is in its bootloader; power-cycle it"),
            other => log::warn!("unexpected TC66 mode reply {other:02x?}"),
        }
        Ok(meter)
    }

    pub fn port_name(&self) -> &str {
        &self.name
    }

    /// Read the live measurements.
    pub fn measure(&mut self) -> Result<Measurement> {
        let mut last_err = None;
        for _ in 0..ATTEMPTS {
            let reply = self.exchange(CMD_GETVA, RESPONSE_SIZE);
            match reply.and_then(|r| parse(&r)) {
                Ok(m) => return Ok(m),
                Err(e) => {
                    log::debug!("TC66 getva failed, retrying: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap()
            .context(format!("reading the TC66 on {}", self.name)))
    }

    /// Send `cmd` and read a `len`-byte reply.
    fn exchange(&mut self, cmd: &[u8], len: usize) -> Result<Vec<u8>> {
        self.port.clear(ClearBuffer::Input)?;
        self.port.write_all(cmd)?;
        self.port.flush()?;
        let mut buf = vec![0u8; len];
        let mut got = 0;
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while got < len {
            match self.port.read(&mut buf[got..]) {
                Ok(0) => {}
                Ok(n) => got += n,
                Err(e) if e.kind() == ErrorKind::TimedOut => {}
                Err(e) => return Err(e.into()),
            }
            if got < len && Instant::now() >= deadline {
                bail!(
                    "TC66 sent {got} of {len} bytes in reply to {:?}",
                    String::from_utf8_lossy(cmd)
                );
            }
        }
        Ok(buf)
    }
}

fn open_error(name: &str, e: serialport::Error) -> anyhow::Error {
    let denied = matches!(
        e.kind(),
        serialport::ErrorKind::Io(ErrorKind::PermissionDenied)
    ) || e.to_string().to_lowercase().contains("permission denied");
    if cfg!(target_os = "linux") && denied {
        anyhow!(
            "permission denied opening {name}.\n\
             Add yourself to the group that owns it (usually dialout), then log in again:\n  \
             sudo usermod -aG dialout $USER"
        )
    } else {
        anyhow!("failed to open TC66 on {name}: {e}")
    }
}
