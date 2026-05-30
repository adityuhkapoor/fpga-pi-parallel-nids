#!/usr/bin/env python3
"""Hot-load a new C2 IP set into the FPGA's Bloom blocklist at runtime, then verify by
read-back. Demonstrates step 2: classifier behavior swapped without a bitstream rebuild.

    sudo python3 hot_load_bloom.py --new-c2 198.51.100.99,203.0.113.99,192.0.2.42
"""
import argparse
import random
import sys
import time

from spi_link import SpiLink, FRAME_LEN
from bloom import BloomFilter
from control import encode_bloom_write, encode_bloom_read, decode_bloom_read, RESPONSE_MAGIC


def build_words(c2_ips):
    """Rebuild the bloom locally; return the 4096 16-bit words the FPGA's BRAM should hold."""
    bf = BloomFilter.from_ips(c2_ips)
    return [bf.bits[2 * w] | (bf.bits[2 * w + 1] << 8) for w in range(4096)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-c2", required=True,
                    help="comma-separated C2 IPv4 list (e.g. 198.51.100.99,203.0.113.99)")
    ap.add_argument("--sample", type=int, default=8, help="random words to read back")
    args = ap.parse_args()

    ips = [s.strip() for s in args.new_c2.split(",") if s.strip()]
    words = build_words(ips)
    nonzero = sum(1 for w in words if w)
    print(f"# new bloom for {len(ips)} IPs -> {nonzero}/{4096} nonzero words", file=sys.stderr)

    with SpiLink() as link:
        # Write all 4096 words. Each frame's read-back is the prior frame's ack -- we don't
        # need the acks during a bulk load, so we discard them.
        t0 = time.perf_counter()
        for addr, val in enumerate(words):
            link.send_frame(encode_bloom_write(addr, val))
        link.send_frame(bytes(FRAME_LEN))                  # flush -> ack of the last write
        load_s = time.perf_counter() - t0
        print(f"# {len(words)} writes in {load_s * 1000:.0f} ms", file=sys.stderr)

        # Verify: ALL nonzero addresses (these are the meaningful bits the rewrite set) plus a
        # random sample of zero addresses (to catch stray nonzero bits left over from the prior
        # filter contents). A pure-random sample would be overwhelmingly zero for a sparse set.
        nonzero_addrs = [a for a, w in enumerate(words) if w]
        random.seed(0)
        zero_pool = [a for a, w in enumerate(words) if not w]
        zero_sample = random.sample(zero_pool, max(0, args.sample - len(nonzero_addrs)))
        addrs = nonzero_addrs + zero_sample
        errs = 0
        for a in addrs:
            link.send_frame(encode_bloom_read(a))
            resp = link.send_frame(bytes(FRAME_LEN))
            if resp[0] != RESPONSE_MAGIC:
                print(f"  FAIL addr 0x{a:03x}: bad magic {resp[0]:#04x}"); errs += 1; continue
            r = decode_bloom_read(resp)
            ok = (r["addr"] == a and r["value"] == words[a])
            print(f"  [{'PASS' if ok else 'FAIL'}] addr 0x{a:03x}: got 0x{r['value']:04x}, "
                  f"expected 0x{words[a]:04x}")
            if not ok: errs += 1

    status = "PASS" if errs == 0 else "FAIL"
    print(f"\n{status}: C2 set rotated to {ips} "
          f"({args.sample - errs}/{args.sample} sample read-backs)")
    return 0 if errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
