#!/usr/bin/env python3
"""Closed loop: poll snapshot every --interval s; if top1_count >= --trigger, push a block
rule for top1_key via opcode 0x12 at the symmetric lookup hash. The FPGA then flips
hit_mask bit 3 (rule_match) on subsequent classify frames for that source.

    sudo python3 closed_loop.py
    sudo python3 closed_loop.py --interval 0.5 --trigger 5
"""
import argparse
import socket
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from telemetry import decode_snapshot, TELEMETRY_MAGIC
from control import (
    encode_rule_write, encode_threshold_read, decode_threshold_read,
)

A1, MASK32 = 0x9E3779B1, 0xFFFFFFFF
OP_SNAPSHOT, OP_RULE_W, OP_THRESH_R = 0x02, 0x12, 0x14
THR_RULE_EPOCH = 0x03


def lookup_idx(ip: int) -> int:
    """Symmetric with rule_lookup.v: top 9 bits of (ip * A1) low-32 product."""
    return (((ip * A1) & MASK32) >> 23) & 0x1FF


def fmt_ip(x: int) -> str:
    return socket.inet_ntoa(x.to_bytes(4, "big"))


def _frame(op: int, payload: bytes = b"") -> bytes:
    f = bytearray(FRAME_LEN)
    f[0:len(payload)] = payload
    f[16] = op
    return bytes(f)


def poll_snapshot(link):
    link.send_frame(_frame(OP_SNAPSHOT))
    return link.send_frame(bytes(FRAME_LEN))


def read_rule_epoch(link):
    link.send_frame(encode_threshold_read(THR_RULE_EPOCH))
    return decode_threshold_read(link.send_frame(bytes(FRAME_LEN)))["value"] & 0xFF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--trigger",  type=int,   default=8, help="top1 count to push a rule")
    ap.add_argument("--action",   type=lambda x: int(x, 0), default=0b101)
    ap.add_argument("--severity", type=int,   default=3)
    args = ap.parse_args()
    with SpiLink() as link:
        epoch = read_rule_epoch(link)
        print(f"# current rule_epoch = {epoch}", file=sys.stderr)
        seen = set()
        while True:
            rx = poll_snapshot(link)
            if rx[0] != TELEMETRY_MAGIC:
                time.sleep(args.interval); continue
            s = decode_snapshot(rx)
            if s.top1_count >= args.trigger and s.top1_key not in seen:
                idx = lookup_idx(s.top1_key)
                rule = {"src_ip": s.top1_key, "action": args.action,
                        "severity": args.severity, "epoch": epoch}
                link.send_frame(encode_rule_write(idx, rule))
                link.send_frame(bytes(FRAME_LEN))           # consume ack
                seen.add(s.top1_key)
                print(f"window {s.window}: pushed rule -> block {fmt_ip(s.top1_key)} "
                      f"(count {s.top1_count}, idx {idx})", flush=True)
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
