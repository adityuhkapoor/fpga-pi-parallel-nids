#!/usr/bin/env python3
"""Read v2 telemetry from the FPGA: per-second snapshot + on-demand CMS point-query.

Send a query frame (opcode in byte 16, optional src_ip key in bytes 0-3); the response shifts
back one frame later (PROTOCOL.md), so we follow each query with a flush read.

    sudo python3 read_telemetry.py                          # poll snapshot once a second
    sudo python3 read_telemetry.py --interval 0.5
    sudo python3 read_telemetry.py --query 198.51.100.1     # CMS point-query for one IP
    sudo python3 read_telemetry.py --hll                    # live HLL state + Pi-side cardinality
"""
import argparse
import socket
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from telemetry import decode_query, decode_snapshot, decode_hll, TELEMETRY_MAGIC

OP_CLASSIFY = 0x00
OP_CMS_Q    = 0x01
OP_SNAPSHOT = 0x02
OP_HLL      = 0x03


def query_frame(opcode: int, key: int = 0) -> bytes:
    f = bytearray(FRAME_LEN)
    f[0:4] = key.to_bytes(4, "big")            # bytes 0-3 = src_ip (used by opcode 0x01)
    f[16]  = opcode                            # PROTOCOL.md: byte 16 = opcode
    return bytes(f)


def issue(link: SpiLink, opcode: int, key: int = 0) -> bytes:
    link.send_frame(query_frame(opcode, key))  # frame N: queries (discard read = N-1's response)
    return link.send_frame(bytes(FRAME_LEN))   # frame N+1: returns frame N's response


def ip_to_int(s: str) -> int:
    return int.from_bytes(socket.inet_aton(s), "big")


def fmt_ip(x: int) -> str:
    return socket.inet_ntoa(x.to_bytes(4, "big"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Read v2 telemetry from the NIDS FPGA over SPI.")
    ap.add_argument("--interval", type=float, default=1.0, help="snapshot poll interval (s)")
    ap.add_argument("--count", type=int, default=0, help="stop after N snapshots (0 = forever)")
    ap.add_argument("--query", type=str, help="one-shot CMS point-query for this src_ip (e.g. 198.51.100.1)")
    ap.add_argument("--hll", action="store_true", help="one-shot live HLL harmonic + Pi cardinality")
    args = ap.parse_args()

    with SpiLink() as link:
        if args.query:
            rx = issue(link, OP_CMS_Q, ip_to_int(args.query))
            if rx[0] != TELEMETRY_MAGIC:
                print(f"no telemetry response (magic {rx[0]:#04x})", file=sys.stderr); return 1
            r = decode_query(rx)
            print(f"cms[{fmt_ip(r.key)}] = {r.count}")
            return 0

        if args.hll:
            rx = issue(link, OP_HLL)
            r = decode_hll(rx)
            print(f"live HLL: harmonic_sum={r.harmonic_sum:#014x} zeros={r.zeros} m={r.m} "
                  f"cardinality~={r.cardinality:.1f}")
            return 0

        n = 0
        while args.count == 0 or n < args.count:
            rx = issue(link, OP_SNAPSHOT)
            if rx[0] != TELEMETRY_MAGIC:
                print(f"window N/A (magic {rx[0]:#04x})");
            else:
                s = decode_snapshot(rx)
                top = fmt_ip(s.top1_key) if s.top1_count else "-"
                print(f"window {s.window:5d}  pkts {s.total:6d}  distinct~{s.distinct_estimate:7.1f}  "
                      f"top {top:>15} ({s.top1_count})")
            n += 1
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
