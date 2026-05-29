#!/usr/bin/env python3
"""Live silicon: drive the gen_telemetry_golden STREAM as classify frames, then CMS
point-query each known src and check against the CPU twin (cms_golden). The whole test
fits in well under one 1s window so live CMS reflects all 20 updates.

PASS here = the v2 telemetry path (header_parser -> telemetry -> opcode router -> response)
works on real silicon. Run AFTER the matching nids_top bitstream is flashed.

    sudo python3 silicon_telemetry_check.py
"""
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from telemetry import decode_query, TELEMETRY_MAGIC
from gen_telemetry_golden import STREAM, CMS_QUERIES, cms_golden

OP_CLASSIFY = 0x00
OP_CMS_Q    = 0x01


def classify_frame(src_ip: int) -> bytes:
    f = bytearray(FRAME_LEN)
    f[0:4] = src_ip.to_bytes(4, "big")           # bytes 0-3: src
    # bytes 4-15: dst/ports/proto/flags/size = 0 (minimal valid classify input)
    # byte 16 (opcode) defaults to 0x00 = classify
    return bytes(f)


def query_frame(key: int) -> bytes:
    f = bytearray(FRAME_LEN)
    f[0:4] = key.to_bytes(4, "big")
    f[16] = OP_CMS_Q
    return bytes(f)


def issue_query(link: SpiLink, key: int) -> bytes:
    link.send_frame(query_frame(key))            # frame N: query (read = N-1's response, discard)
    return link.send_frame(bytes(FRAME_LEN))     # frame N+1: response for the query


def main() -> int:
    expected = dict(cms_golden())                # {ip: expected count}
    print(f"# silicon telemetry: {len(STREAM)} classify frames, {len(CMS_QUERIES)} point-queries",
          file=sys.stderr)

    # Window is 1 s; wait past any in-flight prior-run state so we start in a known-clean window.
    time.sleep(1.1)

    with SpiLink() as link:
        for ip in STREAM:
            link.send_frame(classify_frame(ip))
        link.send_frame(bytes(FRAME_LEN))        # flush so the last verdict shifts out

        errs = 0
        for ip in CMS_QUERIES:
            rx = issue_query(link, ip)
            if rx[0] != TELEMETRY_MAGIC:
                print(f"  FAIL {ip:08X}: bad magic {rx[0]:#04x}")
                errs += 1; continue
            r = decode_query(rx)
            exp = expected[ip]
            ok = (r.key == ip) and (r.count == exp)
            print(f"  [{'PASS' if ok else 'FAIL'}] {ip:08X}: got count={r.count}, expected {exp}")
            if not ok: errs += 1

    print(f"\n{'PASS' if errs == 0 else 'FAIL'}: silicon telemetry round-trip "
          f"({len(CMS_QUERIES) - errs}/{len(CMS_QUERIES)} queries correct)")
    return 0 if errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
