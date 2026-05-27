#!/usr/bin/env python3
"""Live terminal visualizer for the NIDS classification stream.

Shows a scrolling feed of packets with their FPGA verdict (red THREAT / green CLEAN)
and a periodic summary (counts, % flagged, rate).

  # on the Pi, against the flashed FPGA over SPI:
  sudo python3 viz.py --iface eth0 --filter "ip and not port 22"

  # anywhere, no hardware — replays synthetic traffic through the CPU reference classifier:
  python3 viz.py --replay --count 300 --hit-fraction 0.15

Live mode imports scapy + spi_link (Pi-only); replay mode is pure Python.
"""
import argparse
import sys
import time

from bloom import BloomFilter, TEST_C2_SET
from classifier import classify_header
from verdict import decode_verdict
from viz_core import Stats, format_row, format_summary, ips_from_header

SUMMARY_EVERY = 20  # print a summary line every N packets


def _emit(src, dst, verdict, stats, count, color, t0):
    stats.update(verdict)
    print(f"{count:>5}  {format_row(src, dst, verdict, color=color)}", flush=True)
    if count % SUMMARY_EVERY == 0:
        print(f"       {DIM_SUMMARY}{format_summary(stats, time.monotonic() - t0)}{RESET}",
              file=sys.stderr, flush=True)


DIM_SUMMARY = "\033[1;36m"  # bright cyan summary
RESET = "\033[0m"


def run_replay(args) -> None:
    """No hardware: synthesize traffic and classify it with the CPU reference."""
    from benchmark import make_workload  # local import keeps deps tidy
    bloom = BloomFilter.from_ips(TEST_C2_SET)
    headers = make_workload(args.count, args.hit_fraction, args.seed)
    stats, t0 = Stats(), time.monotonic()
    print(f"# replay: {args.count} synthetic packets ({args.hit_fraction:.0%} C2-hit)",
          file=sys.stderr)
    for i, header in enumerate(headers, start=1):
        verdict = decode_verdict(classify_header(header, bloom, seq=i))
        src, dst = ips_from_header(header)
        _emit(src, dst, verdict, stats, i, not args.no_color, t0)
        time.sleep(args.delay)
    print(f"\nFINAL  {format_summary(stats, time.monotonic() - t0)}", file=sys.stderr)


def run_live(args) -> None:
    """On the Pi: sniff, clock each header to the FPGA, show the verdict it returns."""
    from scapy.all import sniff, IP            # Pi-only
    from spi_link import SpiLink
    from packet_capture import extract_header  # reuses the validated packer

    stats, t0 = Stats(), time.monotonic()
    state = {"count": 0}
    print(f"# live: sniffing {args.iface} -> FPGA over SPI (filter={args.filter or 'none'})",
          file=sys.stderr)

    with SpiLink() as link:
        def handle(pkt):
            header = extract_header(pkt)
            if header is None:
                return
            state["count"] += 1
            verdict = decode_verdict(link.send_frame(header))  # verdict for the prior frame
            src, dst = ips_from_header(header)
            _emit(src, dst, verdict, stats, state["count"], not args.no_color, t0)

        sniff(iface=args.iface, prn=handle, filter=args.filter,
              timeout=(args.timeout or None), store=False)
    print(f"\nFINAL  {format_summary(stats, time.monotonic() - t0)}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description="Terminal visualizer for NIDS verdicts.")
    ap.add_argument("--replay", action="store_true", help="no hardware: synth traffic via CPU reference")
    ap.add_argument("--no-color", action="store_true")
    # replay opts
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--hit-fraction", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--delay", type=float, default=0.05, help="replay pause between packets (s)")
    # live opts
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--filter", default=None, help="BPF filter, e.g. 'ip and not port 22'")
    ap.add_argument("--timeout", type=int, default=0, help="stop after N seconds (0 = forever)")
    args = ap.parse_args()

    (run_replay if args.replay else run_live)(args)


if __name__ == "__main__":
    main()
