#!/usr/bin/env python3
"""Capture packets, extract a fixed 20-byte header, print it.

Stage 1: capture + extraction + packing only. SPI transmission to the FPGA is
stubbed in spi_send().

    sudo python3 packet_capture.py --iface eth0 --timeout 6
"""
import argparse
import socket
import struct
import sys

from scapy.all import sniff, IP, TCP, UDP

# Fixed 20-byte header, big-endian, word-aligned (five 32-bit words):
#   word0: src IPv4
#   word1: dst IPv4
#   word2: src port | dst port
#   word3: proto | tcp flags | size
#   word4: reserved
# IPv4 addresses are packed as raw network bytes (inet_aton); the rest via _TAIL.
_TAIL = struct.Struct(">HHBBHI")  # src_port, dst_port, proto, flags, size, reserved
HEADER_LEN = 20

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def spi_send(header: bytes) -> None:
    """Stub: will clock the 20 bytes out to the FPGA over spidev (bus 0, CE0)."""
    assert len(header) == HEADER_LEN, f"header must be {HEADER_LEN}B, got {len(header)}"
    # TODO(spi): spi.xfer2(list(header))


def extract_header(pkt) -> bytes | None:
    """Pack one IPv4 packet into the 20-byte header; return None for non-IPv4."""
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
    )
    assert len(header) == HEADER_LEN
    return header


def format_row(pkt, header: bytes) -> str:
    ip = pkt[IP]
    src_port, dst_port, proto, _flags, size, _ = _TAIL.unpack(header[8:])
    proto_name = _PROTO_NAMES.get(proto, str(proto))
    flag_str = str(pkt[TCP].flags) if TCP in pkt else "-"
    return (
        f"{ip.src:>15}:{src_port:<5} -> {ip.dst:>15}:{dst_port:<5} "
        f"{proto_name:<4} size={size:<5} flags={flag_str:<6} [{header.hex()}]"
    )


def make_handler():
    count = 0

    def handle(pkt):
        nonlocal count
        header = extract_header(pkt)
        if header is None:
            return
        count += 1
        print(f"{count:>4}  {format_row(pkt, header)}", flush=True)
        spi_send(header)

    return handle


def main() -> None:
    ap = argparse.ArgumentParser(description="Capture + extract fixed 20-byte packet headers.")
    ap.add_argument("--iface", default="eth0", help="interface to sniff (default: eth0)")
    ap.add_argument("--timeout", type=int, default=0, help="stop after N seconds (0 = forever)")
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0 = unlimited)")
    ap.add_argument("--filter", dest="bpf", default=None,
                    help="BPF capture filter, e.g. 'ip and not port 22' to exclude SSH control traffic")
    args = ap.parse_args()

    print(
        f"# sniffing {args.iface} "
        f"(timeout={args.timeout or 'inf'}s, count={args.count or 'inf'}, "
        f"filter={args.bpf or 'none'}); "
        f"{HEADER_LEN}B headers; SPI send stubbed",
        file=sys.stderr,
        flush=True,
    )
    sniff(
        iface=args.iface,
        prn=make_handler(),
        filter=args.bpf,
        timeout=(args.timeout or None),
        count=args.count,
        store=False,
    )


if __name__ == "__main__":
    main()
