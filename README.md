# cedar

A small command-line capture tool for the Cypress / Infineon **CY4500 EZ-PD
Protocol Analyzer** (USB `04b4:f67e`). It can also record from a ChargerLab
**POWER-Z KM003C** (USB `5fc9:0063`); see [POWER-Z KM003C](#power-z-km003c).

It talks to the analyzer over USB, streams USB Power Delivery packets and the
oscilloscope (VBUS / CC / current) trace, and on <kbd>Ctrl</kbd>+<kbd>C</kbd>
writes the capture to a file. It is a headless, cross-platform replacement for
the "Start / Stop / Save / Export" workflow of the original Java GUI utility.

Output is **format-compatible with the original tool**:

- **`.ccgx3`** — the native format (a ZIP of Java-serialized packet and scope
  lists). Files open in the original EZ-PD Protocol Analyzer utility and parse
  with existing tooling. The decoder is pinned to the original's output by
  golden tests over real captures, and generated files are verified to
  round-trip through a real Java `ObjectInputStream`.
- **`.csv`** — the same columns the original utility's CSV/Excel export
  produces.
- **`.html`** — a self-contained interactive report: a per-capture summary
  (cable, port partner, negotiated contract), a per-packet VBUS chart, an
  oscilloscope chart with VBUS / current / power over time (stacked, from the
  scope trace), and a filterable packet table (with a **VDM** column summarizing
  each vendor-defined message, e.g. `Enter Mode (DP) ACK`,
  `DP Status (DP) — HPD high`, `DP Configure (DP) — pin D`) where each row
  expands to the full
  USB-PD decode (including the payloads of extended/informational messages —
  source/sink extended capabilities, battery capabilities/status, status, and
  manufacturer info — which cedar decodes from the captured `pktData`)
  (message header, PDOs, RDOs, VDMs, extended messages) plus the raw data words.
  An **event** column annotates the packets where something significant happens
  (attach/detach, cable/partner discovered, contract established/changed/dropped,
  resets, EPR entry); tick "Only events" to read the session as a timeline. The
  PD message decoder is pinned to the reference `parse_ccgx3.py`/`pd_decode.py`
  by golden tests.

There is also a [web version](#web-ui) that records from either analyzer in
Chrome or Edge over WebUSB, with no install.

## Building

Requires a stable Rust toolchain.

```sh
# Linux: install libusb development headers first
sudo apt-get install libusb-1.0-0-dev pkg-config   # Debian/Ubuntu
sudo dnf install libusbx-devel pkgconf-pkg-config  # Fedora

cargo build --release
```

On Windows, libusb is built from source automatically (needs the MSVC build
tools); no extra setup is required.

## Usage

```sh
# Re-decode existing capture(s) into an HTML report (no device needed).
# Reads .ccgx3 from cedar or the original utility. Multiple inputs become
# sections in one report (handy for comparing captures).
cedar report capture.ccgx3                    # writes capture.html
cedar report a.ccgx3 b.ccgx3 -o compare.html

# Plain-text decode to the terminal: summary, then one line per packet.
# --events keeps only annotated packets; --scope interleaves debounced
# VBUS/CC level transitions from the oscilloscope trace.
cedar dump capture.ccgx3
cedar dump --events --scope capture.ccgx3

# List attached analyzers (CY4500 and KM003C)
cedar list

# Print the analyzer's firmware version
cedar version

# Record until Ctrl+C, then save. The extension picks the format.
cedar record capture.ccgx3
cedar record capture.csv
cedar record capture.html              # interactive decoded report

# Force a format, or write several at once
cedar record capture --format both     # writes capture.ccgx3 and capture.csv
cedar record capture --format all      # writes .ccgx3, .csv and .html
cedar record capture.ccgx3 --format ccgx3

# Skip the oscilloscope trace (packets only; smaller files)
cedar record capture.ccgx3 --no-scope

# Pick the analyzer when both are attached (default: CY4500)
cedar record capture.html --analyzer km003c

# KM003C only: also save the raw poll responses (for bug reports / fixtures)
cedar record capture.html --raw capture.km003c.txt
```

A capture runs until you press <kbd>Ctrl</kbd>+<kbd>C</kbd>, at which point the
device is stopped and the file is written.

While recording, a live status is shown (on a terminal) and refreshed in place:

```
  packets: 1503   scope: 77542   elapsed: 76s
  last: ALERT  SOP  VBUS 19.79 V
  levels: VBUS 19.60 V   CC1 1485 mV   CC2 0 mV   I 1208 mA   P 23.7 W
  contract: 20 V @ 5 A (Fixed PDO 5)
  cable: Passive cable — 5 A, 50 V, EPR-capable, USB 2.0 (VID 0x0000)
```

The levels line (and wattage) comes from the oscilloscope stream; the contract
and cable are derived from the PD negotiation as it happens.

## Linux permissions

By default the USB device node is owned by root, so capturing needs either
`sudo` or a udev rule. To grant your user access, install the provided rule:

```sh
sudo cp contrib/71-cy4500.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=04b4
```

Then run `cedar` without `sudo`.

For the KM003C, install `contrib/71-powerz-km003c.rules` instead (see the
comment in the file).

The rules grant access with systemd's `uaccess` tag, which only takes effect
from a rules file that sorts before `73-seat-late.rules`. Earlier versions
shipped the CY4500 rule as `99-cy4500.rules`, which therefore never granted
access; if you installed it, remove it with
`sudo rm /etc/udev/rules.d/99-cy4500.rules`.

## POWER-Z KM003C

`cedar record` uses a KM003C automatically when no CY4500 is attached. For
what each device can and cannot capture, see
[docs/analyzer-comparison.md](docs/analyzer-comparison.md). The
output files are the same: PD events are converted into CY4500 packet records,
so `.ccgx3` captures from the KM003C open in the original EZ-PD utility and
work with `cedar report` / `cedar dump`.

Differences from a CY4500 capture:

- **Timestamps** have 1 ms resolution. Messages that share a millisecond are
  laid out back to back using their estimated on-the-wire duration (so the
  *duration* column is an estimate, not a measurement).
- **Attach/detach** rows (`VBUS_UP` / `VBUS_DN`) come from the meter's CC
  connect/disconnect events, not from VBUS thresholds.
- **Scope trace**: one VBUS / current / CC1 / CC2 sample per poll (about 100 Hz)
  from the meter's status block, instead of the CY4500's high-rate stream.
  Current is stored as a magnitude, like the CY4500.
- **VBUS per packet** is the meter's reading from the previous poll, stored in
  CY4500 ADC counts (about 9 mV resolution).
- **Extended messages** (Source/Sink Capabilities Extended, Status, Battery
  Capabilities, Manufacturer Info, EPR Source Capabilities, …) arrive with
  only their 2-byte message header; the meter drops the payload. They show as
  `(payload not captured)` in the data column.
- Only SOP, SOP' and SOP'' messages are reported; the meter does not report
  hard resets or CRC/EOP errors. `cedar version` prints the USB device version
  only.

cedar talks to the vendor bulk interface (interface 0), temporarily detaching
the Linux `powerz` hwmon driver while it records. It does not use the HID
interface: enabling the PD monitor over HID wedged the meter's HID endpoint,
and polling PD data over HID rebooted it. The protocol follows the
reverse-engineering work in
[okhsunrog/km003c-rs](https://github.com/okhsunrog/km003c-rs).

## Web UI

`web/` is a browser front end built from the same Rust code, compiled to
WebAssembly. It records from a CY4500 or KM003C over WebUSB, shows VBUS,
current, power, the contract and the PD messages live, and afterwards shows
the HTML report and text decode and saves `.ccgx3`, `.csv`, the report, and
(for the KM003C) the raw poll log. It also opens existing `.ccgx3` files; open
several to compare them in one report. Files never leave the browser.

It builds with [Trunk](https://trunkrs.dev), as configured in `Trunk.toml`:

```sh
rustup target add wasm32-unknown-unknown
cargo install trunk --locked   # or download a release binary
trunk serve                    # http://localhost:8080, rebuilds on changes
```

`trunk build --release` writes the same static site to `dist/`. Trunk fetches
the `wasm-bindgen` CLI matching `Cargo.lock` by itself (or uses one on `PATH`
if the version matches). WebUSB only works on HTTPS pages (or `localhost`) and
only in Chromium-based browsers (Chrome, Edge, Opera); opening captures works
in any browser. `.github/workflows/web.yml` builds the site on every push and
deploys `main` to GitHub Pages (set the repository's Pages source to "GitHub
Actions").

If `trunk serve` fails with "failed to build file system watcher: Too many
open files", the desktop session has used up the inotify instance limit (128
on many distributions). Raise it with
`sudo sysctl fs.inotify.max_user_instances=512`, or run `trunk build` and serve
`dist/` with any static file server.

Both analyzers declare Microsoft OS descriptors that bind WinUSB
automatically, so on Windows they work without installing a driver. On Linux
the [udev rules](#linux-permissions) are needed as for the CLI, and the
kernel's `powerz` driver holds the KM003C's interface; unlike the CLI, the
browser can't detach it, so release it first with `sudo modprobe -r powerz`
(or blacklist the module).

## How it works

The CY4500 exposes a vendor interface (interface 0) with four endpoints:

| Endpoint | Direction | Purpose                              |
|----------|-----------|--------------------------------------|
| `0x02`   | OUT       | commands (start / stop / version / …)|
| `0x81`   | IN        | USB-PD packet records (64 bytes each)|
| `0x83`   | IN        | oscilloscope sample records          |
| `0x84`   | IN        | command responses                    |

`cedar` sends `START`, then repeatedly reads packet and scope records until
stopped, decoding each record exactly as the reference firmware/host software
does (timestamp de-wrapping, chunked extended-message reassembly, VBUS/CC/
current scaling), and finally sends `STOP`.

## Tests

```sh
cargo test
```

The golden tests in `tests/golden.rs` decode raw packet bytes captured by the
original utility and assert every decoded field matches what the original tool
stored. See `tests/fixtures/README.md` for how the fixtures are generated.

`tests/km003c.rs` replays KM003C poll responses (`tests/fixtures/km003c-*.txt`,
recorded with `cedar record --raw`) from a Framework 60 W adapter and an Apple
display through the KM003C converter, decoder and session analysis.

## License

BSD-3-Clause.
