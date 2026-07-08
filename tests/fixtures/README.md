# Golden-test fixtures

These fixtures pin the packet decoder to the behaviour of the original
Cypress/Infineon EZ-PD Protocol Analyzer utility. They are consumed by
`tests/golden.rs`.

Each capture contributes two files:

- `<name>.bin` — every packet's raw `pktData`, stored as a sequence of records:
  a little-endian `u32` byte length followed by that many bytes.
- `<name>.expected.tsv` — the fields the original utility decoded for each
  packet (`sno`, `ok`, `sop`, `msg`, …), one tab-separated row per packet with a
  header row first.

The test feeds each `pktData` record through `Decoder::decode_assembled` and
asserts every decoded field matches the expected value, so any regression in the
decode path fails CI.

## Regenerating

The fixtures are derived from `.ccgx3` capture files (a ZIP of Java-serialized
data). To regenerate them from a set of captures:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install javaobj-py3
python generate.py . path/to/*.ccgx3
```

The captures used here are charger-flipping sessions recorded with both SPR and
EPR chargers over Framework and third-party cables.
