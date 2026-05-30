#!/usr/bin/env python3
"""Live silicon: write + read-back every step-2 control opcode (threshold, bloom, rule),
assert each read matches what was written. Run AFTER the step-2 bitstream is flashed.

    sudo python3 silicon_runtime_check.py
"""
import sys

from spi_link import SpiLink, FRAME_LEN
from control import (
    encode_bloom_write, encode_bloom_read, decode_bloom_read,
    encode_threshold_write, encode_threshold_read, decode_threshold_read,
    encode_rule_write, encode_rule_read, decode_rule_read,
    decode_write_ack, RESPONSE_MAGIC,
    OP_BLOOM_W, OP_THRESH_W, OP_RULE_W,
)


def send(link, frame):
    return link.send_frame(frame)


def write_then_read(link, write_frame, expected_ack_op, read_frame):
    """Send write -> flush (capture ack) -> read -> flush (capture response). Returns (ack, resp)."""
    send(link, write_frame)
    ack = send(link, bytes(FRAME_LEN))                  # ack for the write
    send(link, read_frame)
    resp = send(link, bytes(FRAME_LEN))                 # response for the read
    return ack, resp


def main() -> int:
    errs = 0
    print("# silicon runtime: write+read-back every step-2 opcode", file=sys.stderr)

    with SpiLink() as link:
        # --- threshold round-trip: write RATE=12, read it back ---
        ack, resp = write_then_read(link,
            encode_threshold_write(tid=0x02, value=12), OP_THRESH_W,
            encode_threshold_read(tid=0x02))
        if ack[0] != RESPONSE_MAGIC or ack[1] != OP_THRESH_W:
            print(f"  FAIL thr_w ack: {ack[:2].hex()}"); errs += 1
        try:
            t = decode_threshold_read(resp)
            ok = (t["tid"] == 0x02 and t["value"] == 12)
            print(f"  [{'PASS' if ok else 'FAIL'}] thr 0x02: got value={t['value']}, expected 12")
            if not ok: errs += 1
        except ValueError as e:
            print(f"  FAIL thr_r decode: {e}"); errs += 1

        # --- bloom round-trip: write addr=0xABC val=0xBEEF, read it back ---
        ack, resp = write_then_read(link,
            encode_bloom_write(addr=0xABC, value=0xBEEF), OP_BLOOM_W,
            encode_bloom_read(addr=0xABC))
        if ack[0] != RESPONSE_MAGIC or ack[1] != OP_BLOOM_W:
            print(f"  FAIL blm_w ack: {ack[:2].hex()}"); errs += 1
        try:
            b = decode_bloom_read(resp)
            ok = (b["addr"] == 0xABC and b["value"] == 0xBEEF)
            print(f"  [{'PASS' if ok else 'FAIL'}] blm 0xABC: got value={b['value']:#06x}, expected 0xBEEF")
            if not ok: errs += 1
        except ValueError as e:
            print(f"  FAIL blm_r decode: {e}"); errs += 1

        # --- rule round-trip: write idx=42 + known rule, read it back ---
        my_rule = {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}
        ack, resp = write_then_read(link,
            encode_rule_write(idx=42, rule=my_rule), OP_RULE_W,
            encode_rule_read(idx=42))
        if ack[0] != RESPONSE_MAGIC or ack[1] != OP_RULE_W:
            print(f"  FAIL rul_w ack: {ack[:2].hex()}"); errs += 1
        try:
            r = decode_rule_read(resp)
            ok = (r["idx"] == 42 and r["rule"] == my_rule)
            print(f"  [{'PASS' if ok else 'FAIL'}] rule 42: got {r['rule']}, expected {my_rule}")
            if not ok: errs += 1
        except ValueError as e:
            print(f"  FAIL rul_r decode: {e}"); errs += 1

    print(f"\n{'PASS' if errs == 0 else 'FAIL'}: silicon runtime control round-trip "
          f"(3 opcodes, {3 - errs}/3 correct)")
    return 0 if errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
