#!/usr/bin/env python3
"""Live silicon round-trip: clock the v1.1 golden stream to the FPGA, check the verdicts.

Sends the v1 bloom regression vectors (proving bloom still works on the v1.1 bitstream)
followed by the six stateful scenarios (port-scan, rate-anomaly, boundary reset, combined)
over SPI, reads each verdict back off MISO (one-frame lag), and checks them against the
CPU-reference golden table with silicon_check.evaluate_run.

    sudo python3 spi_verdict_check.py        # SPI needs root, like the bring-up tests

PASS here = the whole v1.1 pipeline (bloom + port-scan + rate-anomaly) works on real
hardware, and the v1 bloom behavior is unchanged.
"""
import sys

from spi_link import SpiLink, FRAME_LEN
from silicon_check import evaluate_run
from gen_verdict_golden import expected_rows

_ROWS = expected_rows()                          # (label, idx, header_hex, verdict_hex)
GOLDEN = [(h, v) for _label, _idx, h, v in _ROWS]
FLUSH = bytes(FRAME_LEN)   # trailing frame to clock out the last verdict (its own is ignored)


def main() -> int:
    headers = [bytes.fromhex(h) for h, _ in GOLDEN]
    expected = [bytes.fromhex(v) for _, v in GOLDEN]

    print(f"# v1.1 silicon round-trip: {len(headers)} golden frames + 1 flush over SPI",
          file=sys.stderr)
    rx_frames = []
    with SpiLink() as link:
        for frame in headers + [FLUSH]:
            rx_frames.append(link.send_frame(frame))

    result = evaluate_run(rx_frames, expected)

    # Print every failure, plus the frames that are supposed to trip a stage (the
    # interesting rows) — otherwise 120 clean lines bury the signal.
    for (label, _idx, _h, vhex), (k, ok, summary) in zip(_ROWS, result.rows):
        trips = int(vhex[2:4], 16) != 0
        if not ok or trips:
            print(f"  [{'PASS' if ok else 'FAIL'}] frame {k:3} {label:9} {summary}")
    for note in result.notes:
        print(f"  note: {note}")

    npass = sum(ok for _, ok, _ in result.rows)
    print(f"\n{'PASS' if result.passed else 'FAIL'}: v1.1 silicon round-trip "
          f"({npass}/{len(result.rows)} verdicts correct)")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
