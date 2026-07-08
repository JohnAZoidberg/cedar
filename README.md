# cedar

A small command-line capture tool for the Cypress / Infineon **CY4500 EZ-PD
Protocol Analyzer** (USB `04b4:f67e`).

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
  (cable, port partner, negotiated contract), a VBUS-over-time chart, and a
  filterable packet table where each row expands to the full USB-PD decode
  (message header, PDOs, RDOs, VDMs, extended messages) plus the raw data words.
  An **event** column annotates the packets where something significant happens
  (attach/detach, cable/partner discovered, contract established/changed/dropped,
  resets, EPR entry); tick "Only events" to read the session as a timeline. The
  PD message decoder is pinned to the reference `parse_ccgx3.py`/`pd_decode.py`
  by golden tests.

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
# List attached analyzers
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
sudo cp contrib/99-cy4500.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Then replug the analyzer and run `cedar` without `sudo`.

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

## License

BSD-3-Clause.
