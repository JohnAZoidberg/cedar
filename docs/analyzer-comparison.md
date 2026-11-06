# CY4500 vs. POWER-Z KM003C

cedar records from two USB-PD capture devices: the Cypress / Infineon
**CY4500 EZ-PD Protocol Analyzer** and the ChargerLab **POWER-Z KM003C**. Both
produce the same `.ccgx3` / `.csv` / `.html` output, but they don't capture
the same things.

In short: the CY4500 is a PD **protocol analyzer**. The KM003C is a **power
meter** that also sees PD traffic well enough to show how a negotiation went.

Markers used below:

- ✅ **observed**: confirmed with real hardware; the recordings are in
  `tests/fixtures/km003c-*.txt`.
- 📐 **from code**: follows from cedar's decoder or the
  [km003c-rs](https://github.com/okhsunrog/km003c-rs) protocol notes.
- ❔ **unverified**: expected, not yet seen.

## PD capture

| | CY4500 | KM003C |
|---|---|---|
| **Timestamps** | µs, start and end of every message, so real duration and gaps | 1 ms, start only ✅. cedar lays out messages that share a millisecond back to back using their estimated wire duration, so the *duration* column is an estimate |
| **Extended messages** (Source/Sink Capabilities Extended, Status, Battery Capabilities, Manufacturer Info, EPR Source Capabilities, …) | Full payload, chunked messages reassembled and decoded | **Message header only; the meter drops the payload** ✅ (Apple display fixture). Shown as `(payload not captured)` |
| **Errored packets** | CRC and EOP errors flagged (`ER_CRC`, `ER_EOP`) | Not reported; only valid messages are seen 📐 |
| **Hard Reset / Cable Reset** | Reported as their own SOP types | Unknown ❔; none occurred in the recordings so far |
| **SOP types** | SOP, SOP', SOP'', and the debug variants | SOP and SOP' ✅; SOP'' assumed to be code 2 ❔ |
| **Attach / detach** | VBUS and CC events (`VBUS_UP`/`VBUS_DN`, CC current level, `DETACH`) | CC connect/disconnect only, mapped to `VBUS_UP`/`VBUS_DN` ✅. They're CC-based, so an "attach" can appear while VBUS is still at 0 V, and the CC line bounces a few times on plug-in |
| **Transport** | Device streams packet records continuously | Host polls (cedar: every ~10 ms) and the meter queues events in between. Whether a long burst can overflow the queue is unknown ❔ |

## Measurement

| | CY4500 | KM003C |
|---|---|---|
| **VBUS / current / CC trace** | Continuous high-rate stream on its own endpoint | One sample per poll, about 100 Hz in cedar ✅. The meter can stream up to 1000 SPS ("AdcQueue"), but that needs an authentication handshake cedar doesn't do yet 📐 |
| **Current resolution** | About 2.8 mA per ADC count (`(raw − 2048) × 100 / 36` mA) 📐, not usable for low currents | Measurement block: 1 µA, fresh on every ~100 Hz poll, plus the meter's own 1 s average ✅. `cedar meter` uses this. With nothing attached it reads a few hundred µA either side of zero, so measure a zero offset. The PD status block that `cedar record` uses reports whole mA |
| **Current direction** | Magnitude only | Signed ✅ (power flowing male → female reads negative). cedar currently stores the magnitude, to match the CY4500 / `.ccgx3` model |
| **VBUS range** | cedar's scaling (`raw × 3296 × 11 / 4096` mV on a 12-bit ADC) tops out near 36 V, below 48 V EPR 📐 | Rated to about 50 V by ChargerLab; tested only to 20.6 V so far |
| **VBUS per packet** | Sampled with the packet (≈9 mV steps) | The previous poll's reading (≤10 ms old), stored in CY4500 counts (≈9 mV steps) |
| **Other channels** | None | D+ / D− voltage, temperature, on-device logging, its own display 📐. cedar doesn't use these |

## Practical

| | CY4500 | KM003C |
|---|---|---|
| **USB interface** | Vendor interface 0, needs the WinUSB capture firmware | Vendor bulk interface 0 only ✅. Its HID interface answers measurement reads, but enabling the PD monitor over HID wedged the interface, and polling PD data over HID made the meter re-enumerate |
| **Linux setup** | `contrib/99-cy4500.rules` | `contrib/71-powerz-km003c.rules`. cedar detaches the `powerz` hwmon driver while recording and libusb reattaches it afterwards ✅ |
| **`cedar version`** | Firmware version | USB `bcdDevice` only; the firmware version sits behind an encrypted memory read 📐 |
| **High-speed pass-through** | Inline on CC | An Apple display came up at USB4 / Thunderbolt Gen4 through the meter ✅. A first attempt had no picture with an identical PD exchange, so the meter can't be ruled out as a factor on marginal links |
| **Source/sink role** | Can set CC termination (`cmd_termination`, not exposed in cedar) | Can trigger PD/QC voltages from its own menu; not exposed over USB in cedar |

## When to use which

**Use the CY4500** when you need to debug the protocol itself: extended or EPR
messages, timing between messages (e.g. tSenderResponse, tPSTransition), CRC
errors, Hard Resets, or a capture to hand to someone else as evidence.

**Use the KM003C** to see what was negotiated: offered capabilities, the
request, the resulting contract, cable and partner identity, and alt-mode entry.
It also shows how much power actually flows and in which direction. It's
small, cheap, and easy to leave inline.

## Possible KM003C improvements in cedar

- Implement the AdcQueue authentication so the scope trace can run at
  1000 SPS instead of one sample per poll.
- Store current direction (the `.ccgx3` scope model only has a magnitude, so
  this would need an extra channel or a cedar-specific field).
- Confirm how the meter reports Hard Reset and SOP'' and map them explicitly.
