#!/usr/bin/env python3
"""Silicon step-3 directed test: drive a known bucket collision (src_a/src_b share bucket
but differ in fp). After src_b evicts src_a's cell, src_a's return must NOT trip port_scan
(v1.1's silent-merge would have). Proves the fingerprint-based collision handling works on
real silicon.

    sudo python3 silicon_flow_check.py
"""
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from verdict import decode_verdict
from flow_table_model import bucket, fp


OP_CLASSIFY = 0x00
SRC_A = 0xCB007105
SRC_B = 0x0A000CF5    # bucket collides with SRC_A but fp differs (tb_flow_table uses same pair)
DST   = 0xC0000020


def classify_frame(src_ip: int, dst_ip: int, dst_port: int,
                   proto: int, flags: int, size: int = 60) -> bytes:
    f = bytearray(FRAME_LEN)
    f[0:4]   = src_ip.to_bytes(4, "big")
    f[4:8]   = dst_ip.to_bytes(4, "big")
    f[10:12] = dst_port.to_bytes(2, "big")
    f[12]    = proto
    f[13]    = flags
    f[14:16] = size.to_bytes(2, "big")
    # byte 16 (opcode) defaults to 0x00 = classify
    return bytes(f)


def main() -> int:
    if bucket(SRC_A) != bucket(SRC_B) or fp(SRC_A) == fp(SRC_B):
        print(f"BUG: precondition broken: bucket {bucket(SRC_A):x} vs {bucket(SRC_B):x}, "
              f"fp {fp(SRC_A):x} vs {fp(SRC_B):x}", file=sys.stderr)
        return 1
    print(f"# collision pair: A=0x{SRC_A:08X} fp=0x{fp(SRC_A):04X}, "
          f"B=0x{SRC_B:08X} fp=0x{fp(SRC_B):04X}, both bucket=0x{bucket(SRC_A):03X}",
          file=sys.stderr)

    time.sleep(1.1)        # clear any prior-window state
    with SpiLink() as link:
        # src_a: 4 SYNs to 4 distinct-bit ports (port_bits 8,9,10,12 -- popcount=4, no trip)
        for port in (1, 3, 7, 13):
            link.send_frame(classify_frame(SRC_A, DST, port, 6, 0x02))
        # src_b: 1 SYN -> evicts src_a's cell (bucket collision, fp mismatch)
        link.send_frame(classify_frame(SRC_B, DST, 21, 6, 0x02))
        # src_a returns to a 5th distinct-bit port (port_bit 15). v1.1's silent-merge would
        # have popcount = 5 here and trip port_scan. step 3 evicted -> popcount = 1 -> no trip.
        link.send_frame(classify_frame(SRC_A, DST, 42, 6, 0x02))
        rx_last = link.send_frame(bytes(FRAME_LEN))   # flush; this read = the 6th classify's verdict

    v = decode_verdict(rx_last)
    if not v.valid:
        print(f"FAIL: last verdict invalid (magic=0x{rx_last[0]:02X})", file=sys.stderr)
        return 1
    print(f"# last verdict: {v.describe()}", file=sys.stderr)
    if v.port_scan:
        print(f"FAIL: step 3 should NOT trip port_scan after eviction; v1.1 silent-merge would")
        return 1
    print(f"PASS: silicon collision-evict (src_a evicted by src_b -> no false port_scan on return)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
