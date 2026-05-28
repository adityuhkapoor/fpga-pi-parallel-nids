#!/usr/bin/env python3
"""Ramp the SPI clock against the echo bitstream (echo_top) and report BER per step.

Load echo_top onto the FPGA, wire per PROTOCOL.md, then:
    sudo python3 spi_ber_ramp.py

Finds the highest clock with zero bit errors over --frames random frames. The echo
bitstream returns frame N during transfer N+1 (delay-1), so every input bit must
round-trip -- any link error (undersampled SCLK, signal integrity) shows up here.

The Vivado sim cannot prove the achievable clock (no metastability/SI model); this
script is the instrument that establishes the real ceiling on silicon.
"""
import argparse
import os
import random
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from ber import ramp_errors

DEFAULT_CLOCKS_MHZ = [1, 5, 10, 15, 20, 25, 30]


def run_one(speed_hz, frames, seed):
    rng = random.Random(seed)
    sent = [bytes(rng.getrandbits(8) for _ in range(FRAME_LEN)) for _ in range(frames)]
    sent.append(bytes(FRAME_LEN))   # flush frame clocks out the last real echo
    link = SpiLink(speed_hz=speed_hz)
    t0 = time.perf_counter()
    received = [link.send_frame(f) for f in sent]
    elapsed = time.perf_counter() - t0
    link.close()
    r = ramp_errors(sent[:-1], received[:-1], delay=1)
    fps = frames / elapsed if elapsed else 0.0
    return r, fps


def main():
    ap = argparse.ArgumentParser(description="SPI clock BER ramp against echo_top.")
    ap.add_argument("--frames", type=int, default=5000, help="random frames per clock step")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--clocks-mhz", type=int, nargs="+", default=DEFAULT_CLOCKS_MHZ)
    args = ap.parse_args()

    print(f"# SPI BER ramp: {args.frames} frames/step, {FRAME_LEN}B frames, delay-1 echo")
    ceiling = None
    for mhz in args.clocks_mhz:
        r, fps = run_one(mhz * 1_000_000, args.frames, args.seed)
        status = "CLEAN" if r.frame_errors == 0 else f"ERR {r.frame_errors} frames / {r.bit_errors} bits"
        print(f"  {mhz:3d} MHz  BER={r.ber:.2e}  {fps:8,.0f} fps  {status}")
        if r.frame_errors == 0:
            ceiling = mhz
    print(f"\nHighest zero-error clock: {ceiling} MHz" if ceiling is not None
          else "\nNo clean clock found")
    return 0


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("SPI needs root: sudo python3 spi_ber_ramp.py", file=sys.stderr)
    sys.exit(main())
