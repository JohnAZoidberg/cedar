#!/usr/bin/env python3
"""Generate golden-test fixtures from `.ccgx3` captures.

For each capture this writes two files next to this script:

  * ``<name>.bin``          — every packet's raw ``pktData`` as a stream of
                              records: a little-endian ``u32`` length followed
                              by that many bytes.
  * ``<name>.expected.tsv`` — the decoded fields the original EZ-PD Protocol
                              Analyzer utility stored for each packet, one
                              tab-separated row per packet (header row first).
  * ``<name>.decode.json``  — the full PD message decode tree per packet from
                              the reference ``pd_decode.py`` (one JSON line per
                              packet, ``null`` where nothing is decoded).

The Rust integration test (`tests/golden.rs`) feeds the raw ``pktData`` through
our decoder and asserts the output matches the expected fields, and separately
re-decodes each packet and asserts the tree matches ``<name>.decode.json`` — so
the fixtures pin both our field decoder and our PD message decoder to the
reference implementation's behaviour.

``pd_decode.py`` must be importable (it lives alongside the source captures).

Usage:
    pip install javaobj-py3
    python generate.py OUT_DIR CAPTURE.ccgx3 [MORE.ccgx3 ...]

Typically run with OUT_DIR set to this directory.
"""
import csv
import json
import os
import struct
import sys
import zipfile

import javaobj  # javaobj-py3
import pd_decode  # reference PD message decoder (from the captures repo)

FIELDS = [
    "sno", "ok", "sop", "msg", "id", "dRole", "pRole", "count", "rev",
    "duration", "delta", "vbus", "data", "sTime", "eTime",
]


def val(x):
    return "" if x is None else str(x)


def main():
    out_dir = sys.argv[1]
    for path in sys.argv[2:]:
        name = os.path.splitext(os.path.basename(path))[0]
        with zipfile.ZipFile(path) as z:
            parts = [n for n in z.namelist() if n.endswith("ezpd_last.part")]
            if not parts:
                print(f"{os.path.basename(path)}: SKIP (no packet data)")
                continue
            raw = z.read(parts[0])
        packets = javaobj.loads(raw)

        rows = [{f: val(getattr(pkt, f, None)) for f in FIELDS} for pkt in packets]

        bin_path = os.path.join(out_dir, name + ".bin")
        tsv_path = os.path.join(out_dir, name + ".expected.tsv")
        with open(bin_path, "wb") as bf, open(tsv_path, "w", newline="") as tf:
            writer = csv.writer(tf, delimiter="\t", quoting=csv.QUOTE_NONE)
            writer.writerow(FIELDS)
            for pkt, row in zip(packets, rows):
                data = bytes([b & 0xFF for b in (pkt.pktData or [])])
                bf.write(struct.pack("<I", len(data)))
                bf.write(data)
                writer.writerow([row[f] for f in FIELDS])

        json_path = os.path.join(out_dir, name + ".decode.json")
        with open(json_path, "w") as jf:
            for dec in pd_decode.decode_capture(rows):
                jf.write("null" if dec is None
                         else json.dumps(dec, separators=(",", ":"),
                                         ensure_ascii=False))
                jf.write("\n")
        print(f"{name}: {len(packets)} packets")


if __name__ == "__main__":
    main()
