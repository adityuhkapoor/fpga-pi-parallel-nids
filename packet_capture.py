#!/usr/bin/env python3
"""Capture packets, extract a fixed 32-byte header, print it (and optionally send over SPI).

Stage 1: capture + extraction + packing. With --spi, each header is also clocked
out to the FPGA over SPI (spidev0.0, see PROTOCOL.md); without it, capture only.

    sudo python3 packet_capture.py --iface eth0 --timeout 6
    sudo python3 packet_capture.py --iface eth0 --timeout 6 --spi
"""
import argparse
import socket
import struct
import sys

from scapy.all import sniff, IP, TCP, UDP

from spi_link import SpiLink, FRAME_LEN
from verdict import decode_verdict

# Fixed 32-byte v2 frame, big-endian, word-aligned. The five meaningful 32-bit words
# (the v1 20B layout) followed by 12 reserved zero bytes:
#   word0: src IPv4
#   word1: dst IPv4
#   word2: src port | dst port
#   word3: proto | tcp flags | size
#   word4: reserved | words 5-7: reserved (zero)
# IPv4 addresses are packed as raw network bytes (inet_aton); the rest via _TAIL.
_TAIL = struct.Struct(">HHBBHI")  # src_port, dst_port, proto, flags, size, reserved
HEADER_LEN = FRAME_LEN

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def extract_header(pkt) -> bytes | None:
    """Pack one IPv4 packet into the 32-byte header; return None for non-IPv4."""
    if IP not in pkt:
        return None
    ip = pkt[IP]

    src_port = dst_port = 0
    flags = 0
    if TCP in pkt:
        tcp = pkt[TCP]
        src_port, dst_port = tcp.sport, tcp.dport
        flags = int(tcp.flags)  # FIN SYN RST PSH ACK URG ECE CWR
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port, dst_port = udp.sport, udp.dport

    header = (
        socket.inet_aton(ip.src)
        + socket.inet_aton(ip.dst)
        + _TAIL.pack(src_port, dst_port, ip.proto, flags, len(pkt) & 0xFFFF, 0)
        + bytes(HEADER_LEN - 20)   # pad the v1 20B layout out to the 32B v2 frame
    )
    assert len(header) == HEADER_LEN
    return header


def format_row(pkt, header: bytes) -> str:
    ip = pkt[IP]
    src_port, dst_port, proto, _flags, size, _ = _TAIL.unpack(header[8:20])
    proto_name = _PROTO_NAMES.get(proto, str(proto))
    flag_str = str(pkt[TCP].flags) if TCP in pkt else "-"
    return (
        f"{ip.src:>15}:{src_port:<5} -> {ip.dst:>15}:{dst_port:<5} "
        f"{proto_name:<4} size={size:<5} flags={flag_str:<6} [{header.hex()}]"
    )


def make_handler(link=None):
    count = 0

    def handle(pkt):
        nonlocal count
        header = extract_header(pkt)
        if header is None:
            return
        count += 1
        row = format_row(pkt, header)
        if link is not None:
            # Full-duplex: the 32 bytes read back carry the verdict for the PREVIOUS
            # frame (one-frame pipeline lag, PROTOCOL.md); seq in the summary says which.
            verdict = decode_verdict(link.send_frame(header))
            row += f"  verdict<-{verdict.describe()}"
        print(f"{count:>4}  {row}", flush=True)

    return handle


def main() -> None:
    ap = argparse.ArgumentParser(description="Capture + extract fixed 32-byte packet headers.")
    ap.add_argument("--iface", default="eth0", help="interface to sniff (default: eth0)")
    ap.add_argument("--timeout", type=int, default=0, help="stop after N seconds (0 = forever)")
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0 = unlimited)")
    ap.add_argument("--filter", dest="bpf", default=None,
                    help="BPF capture filter, e.g. 'ip and not port 22' to exclude SSH control traffic")
    ap.add_argument("--spi", action="store_true", help="also clock each header out over SPI (spidev0.0)")
    args = ap.parse_args()

    link = SpiLink() if args.spi else None
    print(
        f"# sniffing {args.iface} "
        f"(timeout={args.timeout or 'inf'}s, count={args.count or 'inf'}, "
        f"filter={args.bpf or 'none'}, spi={'on' if link else 'off'}); {HEADER_LEN}B headers",
        file=sys.stderr,
        flush=True,
    )
    try:
        sniff(
            iface=args.iface,
            prn=make_handler(link),
            filter=args.bpf,
            timeout=(args.timeout or None),
            count=args.count,
            store=False,
        )
    finally:
        if link is not None:
            link.close()


if __name__ == "__main__":
    main()
