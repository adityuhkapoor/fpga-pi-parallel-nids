#!/usr/bin/env python3
"""FPGA-vs-CPU benchmark for the packet classifier.

Times the CPU reference classifier (`classifier.py`) over a synthetic header workload
and contrasts it with the FPGA classifier core's *deterministic* latency. The point
isn't just "which is faster" — it's jitter: the CPU's per-packet latency varies (OS
scheduling, cache, GC), while the FPGA core is the same cycle count every time.

The FPGA latency is the real v1.1 frame->verdict pipeline depth (8 cycles, see
--fpga-cycles), not a placeholder. The CPU side times the single-packet classify path
(bloom; the stateful stages add negligible per-call work), which is the fair
compute-vs-compute comparison.

    python3 benchmark.py --count 100000 --hit-fraction 0.1

Pure CPU/logic — no hardware. SPI transport is a separate cost (160 µs/frame at 1 MHz)
and is deliberately not part of the *compute* comparison.
"""
import argparse
import math
import random
import statistics
import struct
import time

from bloom import BloomFilter, TEST_C2_SET, ip_to_int
from classifier import Classifier

_TAIL = struct.Struct(">HHBBHI")  # sport,dport,proto,flags,size,reserved (4B)


def _pack(rng, src_int, dst_int) -> bytes:
    # 8B IPs + 12B tail = 20, then 12 more reserved bytes -> 32B v2 frame.
    return (struct.pack(">II", src_int, dst_int)
            + _TAIL.pack(rng.randint(1, 65535), rng.randint(1, 65535),
                         rng.choice((6, 17, 1)), rng.randint(0, 255),
                         rng.randint(40, 1500), 0)
            + bytes(12))


def _random_clean_ip(rng, bloom: BloomFilter) -> int:
    """A 32-bit IP guaranteed not to be a bloom member (no false-positive)."""
    while True:
        x = rng.getrandbits(32)
        if not bloom.member(x):
            return x


def make_workload(n: int, hit_fraction: float = 0.5, seed: int = 0) -> list:
    """n 32-byte headers; exactly round(n*hit_fraction) contain a C2 IP. Deterministic."""
    rng = random.Random(seed)
    bloom = BloomFilter.from_ips(TEST_C2_SET)
    c2_ints = [ip_to_int(ip) for ip in TEST_C2_SET]
    n_hits = round(n * hit_fraction)
    headers = []
    for i in range(n):
        if i < n_hits:
            c2 = rng.choice(c2_ints)
            other = _random_clean_ip(rng, bloom)
            src, dst = (c2, other) if rng.random() < 0.5 else (other, c2)
        else:
            src, dst = _random_clean_ip(rng, bloom), _random_clean_ip(rng, bloom)
        headers.append(_pack(rng, src, dst))
    rng.shuffle(headers)
    return headers


def latency_stats(samples_ns) -> dict:
    """Summarize per-call latencies (nanoseconds in) into microseconds."""
    s = sorted(samples_ns)
    n = len(s)

    def pct(q):
        return s[min(n - 1, max(0, math.ceil(q / 100 * n) - 1))]

    return {
        "count": n,
        "mean_us": statistics.fmean(s) / 1000,
        "median_us": statistics.median(s) / 1000,
        "p99_us": pct(99) / 1000,
        "min_us": s[0] / 1000,
        "max_us": s[-1] / 1000,
        "jitter_us": (statistics.pstdev(s) / 1000) if n > 1 else 0.0,
    }


def fpga_core_latency_ns(cycles: int, clk_hz: int) -> float:
    """Deterministic FPGA classifier-core latency: pipeline cycles x clock period."""
    return cycles / clk_hz * 1e9


def link_frame_us(frame_bytes: int, clk_hz: int) -> float:
    """SPI transport cost of one frame: full-duplex, so frame_bytes*8 bits at clk_hz.

    The link cost is separate from the classifier compute and is what the step-0
    clock upgrade attacks: v1 was 20B @ 1 MHz = 160 us/frame; v2 is 32B at the
    locked clock.
    """
    return frame_bytes * 8 / clk_hz * 1e6


def run_cpu(headers, bloom: BloomFilter):
    """Classify every header with ONE persistent classifier, returning per-call ns.

    Reuses a single Classifier (one state table) across the workload — the realistic
    stateful path, and the fair analogue to the FPGA reusing its BRAM. (The
    classify_header compat wrapper allocates a fresh table per call, which would time
    allocation, not classification.)
    """
    clf = Classifier(bloom)
    samples = []
    perf = time.perf_counter_ns
    for i, h in enumerate(headers):
        t0 = perf()
        clf.classify(h, seq=(i & 0xFF) + 1, frame_count=i)
        samples.append(perf() - t0)
    return samples


def main() -> None:
    ap = argparse.ArgumentParser(description="FPGA-vs-CPU benchmark (v1 bloom classifier).")
    ap.add_argument("--count", type=int, default=100_000, help="headers to classify")
    ap.add_argument("--hit-fraction", type=float, default=0.1, help="fraction that hit a C2 IP")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--fpga-cycles", type=int, default=8,
                    help="FPGA frame->verdict pipeline depth @100MHz (derived from the FSMs): "
                         "header_parser 1 + (bloom||scan_rate) 4 + classifiers combine 2 + "
                         "verdict_encoder 1 = 8 cycles")
    ap.add_argument("--clk-mhz", type=float, default=100.0, help="FPGA clock (Basys 3 = 100 MHz)")
    args = ap.parse_args()

    bloom = BloomFilter.from_ips(TEST_C2_SET)
    headers = make_workload(args.count, args.hit_fraction, args.seed)

    wall0 = time.perf_counter()
    samples = run_cpu(headers, bloom)
    wall = time.perf_counter() - wall0

    cpu = latency_stats(samples)
    fpga_ns = fpga_core_latency_ns(args.fpga_cycles, int(args.clk_mhz * 1e6))
    throughput = args.count / wall

    print(f"# packet classifier (v1.1) — CPU vs FPGA core ({args.count} headers, "
          f"{args.hit_fraction:.0%} C2-hit)")
    print(f"CPU  ({_cpu_name()}):")
    print(f"  throughput   {throughput:,.0f} headers/s")
    print(f"  latency/pkt  mean {cpu['mean_us']:.3f} us | median {cpu['median_us']:.3f} "
          f"| p99 {cpu['p99_us']:.3f} | min {cpu['min_us']:.3f} | max {cpu['max_us']:.3f}")
    print(f"  jitter (std) {cpu['jitter_us']:.3f} us   "
          f"(max/min = {cpu['max_us'] / max(cpu['min_us'], 1e-9):.0f}x)")
    print(f"FPGA core (design, {args.fpga_cycles} cycles @ {args.clk_mhz:.0f} MHz):")
    print(f"  latency/pkt  {fpga_ns:.1f} ns  (deterministic, 0 jitter)")
    print(f"Speedup on compute latency (CPU median / FPGA): "
          f"{cpu['median_us'] * 1000 / fpga_ns:.0f}x")
    v1_us = link_frame_us(20, 1_000_000)
    v2_us = link_frame_us(32, 8_000_000)
    print("Link transport (SPI full-duplex, separate from the compute above):")
    print(f"  v1  20B @ 1 MHz   {v1_us:6.1f} us/frame  ({1e6 / v1_us:>7,.0f} frames/s)")
    print(f"  v2  32B @ 8 MHz   {v2_us:6.1f} us/frame  ({1e6 / v2_us:>7,.0f} frames/s)  "
          f"-> {v1_us / v2_us:.0f}x per-frame (step-0 link upgrade)")


def _cpu_name() -> str:
    import platform
    return platform.processor() or platform.machine()


if __name__ == "__main__":
    main()
