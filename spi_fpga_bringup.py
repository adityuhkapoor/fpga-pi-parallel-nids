#!/usr/bin/env python3
"""Bring-up check for the Pi<->FPGA SPI link via the FPGA's frame-pipelined echo.

Sends distinct known 20-byte frames. In echo bring-up mode the FPGA returns
frame N during transfer N+delay (PROTOCOL.md: delay = 1 frame). Each echo is
checked against the frame sent `delay` transfers earlier.

Wire the boards per PROTOCOL.md (Pi pins 19/21/23/24/25 -> JB 1/2/3/4/5), load
the echo bring-up bitstream, then:  sudo python3 spi_fpga_bringup.py
The physical loopback jumper (19<->21) is a delay-0 echo, so --delay 0 against
the jumper validates this script's own logic without the FPGA.
"""
import argparse
import sys

from spi_link import SpiLink, FRAME_LEN

FRAMES = [
    bytes(range(FRAME_LEN)),
    bytes([0xAA]) * FRAME_LEN,
    bytes(range(FRAME_LEN, 2 * FRAME_LEN)),
    bytes.fromhex("c0000201c6336401d43101bb0618020000000000"),  # RFC 5737 doc IPs
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the FPGA SPI echo bring-up.")
    ap.add_argument("--delay", type=int, default=1, help="echo pipeline depth in frames (PROTOCOL.md: 1)")
    args = ap.parse_args()

    link = SpiLink()
    # `delay` trailing flush frames clock out the echoes of the last real frames.
    received = [link.send_frame(f) for f in FRAMES + [bytes(FRAME_LEN)] * args.delay]
    link.close()

    print(f"# frame-pipelined echo check (delay={args.delay})")
    passed = 0
    for i, expected in enumerate(FRAMES):
        rx = received[i + args.delay]
        ok = rx == expected
        passed += ok
        print(f"  frame {i}: sent={expected.hex()}")
        print(f"           echo={rx.hex()}  {'PASS' if ok else 'FAIL'}")

    print(f"\n{passed}/{len(FRAMES)} echoes matched.")
    if passed == len(FRAMES):
        target = "Pi<->FPGA SPI link" if args.delay else "Pi SPI loopback (no FPGA)"
        print(f"PASS — {target} verified.")
        return 0
    if not any(any(r) for r in received):
        print("All rx zero — FPGA sent nothing. Check JB1-4 + GND wiring, CS, and that the echo bitstream is loaded.")
    else:
        print(f"Echoes don't line up at delay={args.delay} — try a different --delay, or check mode/bit order.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
