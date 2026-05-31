#!/usr/bin/env python3
"""Silicon step-4 closed-loop demo (self-contained, single script):
  1. flood 10 classify frames from one src
  2. poll snapshot -> top1 should be that src
  3. push a block-rule for top1_key at lookup_idx
  4. send one more classify from that src
  5. read its verdict -> must have rule_match (mask bit 3) AND escalate

Demonstrates the observe -> decide -> act loop end-to-end on real silicon. Run AFTER the
step 3+4 bitstream is flashed.

    sudo python3 silicon_loop_demo.py
"""
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from verdict import decode_verdict
from telemetry import decode_snapshot
from control import encode_rule_write

A1, MASK32 = 0x9E3779B1, 0xFFFFFFFF
OP_SNAPSHOT = 0x02
FLOOD_SRC = 0xCB007105
FLOOD_DST = 0x0A000020
FLOOD_N = 10


def lookup_idx(ip):
    return (((ip * A1) & MASK32) >> 23) & 0x1FF


def classify_frame(src_ip):
    f = bytearray(FRAME_LEN)
    f[0:4] = src_ip.to_bytes(4, "big")
    f[4:8] = FLOOD_DST.to_bytes(4, "big")
    f[10:12] = (80).to_bytes(2, "big")
    f[12] = 17                                # UDP -- no scan/rate side effects unless many
    return bytes(f)


def snap_frame():
    f = bytearray(FRAME_LEN); f[16] = OP_SNAPSHOT; return bytes(f)


def main() -> int:
    print(f"# step-4 closed-loop demo: flood {FLOOD_N} pkts from 0x{FLOOD_SRC:08X}, "
          f"then push rule at idx 0x{lookup_idx(FLOOD_SRC):03X}", file=sys.stderr)
    time.sleep(1.1)        # clear any prior-window state

    with SpiLink() as link:
        # --- (1) flood ---
        for _ in range(FLOOD_N):
            link.send_frame(classify_frame(FLOOD_SRC))
        link.send_frame(bytes(FRAME_LEN))   # flush the last verdict

        # --- (2) poll snapshot for the window that contains our flood. A single sleep can
        # overshoot: the 1 s timer may tumble TWICE in the wait (latching our flood's window,
        # then the next empty window). Poll until we see total >= FLOOD_N (our window has
        # been latched) OR timeout. ---
        s = None
        deadline = time.time() + 2.5
        while time.time() < deadline:
            link.send_frame(snap_frame())
            rx = link.send_frame(bytes(FRAME_LEN))
            if rx[0] == 0x5A:
                cand = decode_snapshot(rx)
                if cand.total >= FLOOD_N and cand.top1_key == FLOOD_SRC:
                    s = cand; break
            time.sleep(0.1)
        if s is None:
            print(f"FAIL: timeout waiting for flood snapshot", file=sys.stderr); return 1
        print(f"# snapshot: window={s.window} total={s.total} top1=0x{s.top1_key:08X} count={s.top1_count}",
              file=sys.stderr)

        # --- (3) push a block-rule for top1_key (action: drop+escalate; severity 3; epoch 0) ---
        rule = {"src_ip": s.top1_key, "action": 0b101, "severity": 3, "epoch": 0}
        link.send_frame(encode_rule_write(lookup_idx(s.top1_key), rule))
        ack = link.send_frame(bytes(FRAME_LEN))
        if ack[0] != 0x5A or ack[1] != 0x12:
            print(f"FAIL: rule write ack magic=0x{ack[0]:02X} op=0x{ack[1]:02X}"); return 1
        print(f"# rule pushed: block 0x{FLOOD_SRC:08X} at idx 0x{lookup_idx(FLOOD_SRC):03X}",
              file=sys.stderr)

        # --- (4) classify the same source again ---
        link.send_frame(classify_frame(FLOOD_SRC))
        # --- (5) read verdict (one-frame lag) ---
        rx_v = link.send_frame(bytes(FRAME_LEN))

    v = decode_verdict(rx_v)
    if not v.valid:
        print(f"FAIL: verdict invalid (magic=0x{rx_v[0]:02X})"); return 1
    print(f"# post-rule verdict: {v.describe()}", file=sys.stderr)
    if not v.rule_match:
        print(f"FAIL: rule_match (mask bit 3) should be set; got mask=0x{rx_v[1]:02X}")
        return 1
    if not v.escalate:
        print(f"FAIL: escalate should be set (rule action bit 2 = 1)")
        return 1
    print(f"PASS: closed-loop demo -- flood -> snapshot -> rule -> rule_match verdict")
    return 0


if __name__ == "__main__":
    sys.exit(main())
