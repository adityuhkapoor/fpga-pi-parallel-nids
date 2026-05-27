#!/usr/bin/env python3
"""Live silicon round-trip: clock the golden-vector headers to the FPGA, check verdicts.

Runs on the Pi against a board flashed with the verdict bitstream (see PROTOCOL.md /
status/fpga.md handshake). Sends each VERDICT_GOLDEN input header over SPI plus one
trailing flush frame, reads the verdicts back off MISO (one-frame lag), and checks
them against the expected verdicts with silicon_check.evaluate_run.

    sudo python3 spi_verdict_check.py        # SPI may need root, like the bring-up tests

This is the v1 acceptance test: PASS here = the whole pipeline works on real hardware.
"""
import sys

from spi_link import SpiLink, FRAME_LEN
from silicon_check import evaluate_run

# The 6 Tier-2 golden vectors (internal VERDICT_GOLDEN.md): (input header, expected verdict).
GOLDEN = [
    ("c0000201c0000202303900500602003c00000000", "a500000001000000000000000000000000000000"),
    ("c0000201c6336401303901bb0602003c00000000", "a501030102000000000000000000000000000000"),
    ("cb007105c0000201303900500602003c00000000", "a501030103000000000000000000000000000000"),
    ("c0000232c0000263303900351100003c00000000", "a501030104000000000000000000000000000000"),
    ("0a0000010a000002303900351100003c00000000", "a500000005000000000000000000000000000000"),
    ("c6336401cb007105303900500602003c00000000", "a501030106000000000000000000000000000000"),
]
FLUSH = bytes(FRAME_LEN)  # trailing frame to clock out the last verdict (its own verdict is ignored)


def main() -> int:
    headers = [bytes.fromhex(h) for h, _ in GOLDEN]
    expected = [bytes.fromhex(v) for _, v in GOLDEN]

    print(f"# silicon round-trip: {len(headers)} golden headers + 1 flush over SPI", file=sys.stderr)
    rx_frames = []
    with SpiLink() as link:
        for frame in headers + [FLUSH]:
            rx_frames.append(link.send_frame(frame))

    result = evaluate_run(rx_frames, expected)

    for k, ok, summary in result.rows:
        print(f"  header {k}: {'PASS' if ok else 'FAIL'}  {summary}")
    for note in result.notes:
        print(f"  note: {note}")
    print(f"\n{'PASS' if result.passed else 'FAIL'}: v1 silicon round-trip "
          f"({sum(ok for _, ok, _ in result.rows)}/{len(result.rows)} verdicts correct)")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
