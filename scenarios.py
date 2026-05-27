"""Ordered v1.1 golden scenarios: input header sequences (hex). State accumulates
across frames; frame_count = index. Shared by tests and the golden-table generator.

header = src_ip dst_ip src_port dst_port proto flags size(2B) + 4B reserved (zeros).
RFC5737 doc IPs only. C2 set (for bloom): 198.51.100.1=0xC6336401,
203.0.113.5=0xCB007105, 192.0.2.99=0xC0000263.
"""
import struct

def hdr(src, dst, sport, dport, proto, flags, size=60):
    return (struct.pack(">IIHHBBH", src, dst, sport, dport, proto, flags, size)
            + b"\x00\x00\x00\x00").hex()

# benign: varied normal traffic, never trips a new stage and never a C2 IP
BENIGN = [
    hdr(0x0A000001, 0x0A000002, 12345, 443, 6, 0x18),   # established (PSH+ACK)
    hdr(0x0A000003, 0x0A000004, 53, 53,    17, 0x00),   # dns
    hdr(0x0A000005, 0x08080808, 40000, 443, 6, 0x18),
]

# vertical scan: one src SYNs 5 distinct ports to one host -> trips at packet 5
# ports (1,3,7,13,21) verified distinct under port_bit: bits (8,9,10,12,15)
VSCAN = [hdr(0xCB007106, 0xC0000201, 40000, p, 6, 0x02)
         for p in (1, 3, 7, 13, 21)]

# rate flood: 8 udp packets one src -> trips at packet 8
FLOOD = [hdr(0xC0000220, 0xC0000221, 1000 + i, 9999, 17, 0x00) for i in range(8)]

# horizontal scan: one src SYNs 5 distinct hosts (same dst_port) -> trips on the 5th
# via host_fp. The 5 dst IPs (192.0.2.1..5) have distinct host_bit: (12,6,0,10,4).
# src 203.0.113.7=0xCB007107.
HSCAN = [hdr(0xCB007107, d, 40000, 8080, 6, 0x02)
         for d in (0xC0000201, 0xC0000202, 0xC0000203, 0xC0000204, 0xC0000205)]

# window-boundary reset: 17 frames where one src's 5 SYNs straddle the frame-16
# epoch boundary, so the scan never accumulates to a trip (proves the lazy reset).
# boundary src 203.0.113.8=0xCB007108 (bucket 201).
#   frames 0-3: SYN to 4 distinct-port_bit ports (1,2,3,4 -> bits 8,0,9,1); fp popcount=4
#   frames 4-15: 12 filler udp pkts, distinct srcs, none sharing bucket 201
#   frame 16: SYN to a 5th distinct-port_bit port (6 -> bit 2); epoch flips 0->1,
#             entry resets, port_fp popcount=1 -> NO trip.
# Fillers use 10.0.0.16..27 per scenario spec; buckets all != 201, verified distinct.
_BSCAN_SRC = 0xCB007108
_BSCAN_PORTS = (1, 2, 3, 4, 6)   # port_bit (8,0,9,1,2), all distinct
_BSCAN_FILLERS = tuple(range(0x0A000010, 0x0A00001C))  # 12 srcs, bucket != bucket(_BSCAN_SRC)
BOUNDARY = (
    [hdr(_BSCAN_SRC, 0xC0000201, 40000, p, 6, 0x02) for p in _BSCAN_PORTS[:4]]
    + [hdr(f, 0xC0000202, 5000, 53, 17, 0x00) for f in _BSCAN_FILLERS]
    + [hdr(_BSCAN_SRC, 0xC0000201, 40000, _BSCAN_PORTS[4], 6, 0x02)]
)
# contrast: the same 5 SYNs all within ONE window -> the 5th DOES trip. Shows that
# only the boundary reset (not the ports) suppressed the BOUNDARY trip.
BOUNDARY_ONE_WINDOW = [hdr(_BSCAN_SRC, 0xC0000201, 40000, p, 6, 0x02)
                       for p in _BSCAN_PORTS]

# combined: a C2 IP (198.51.100.1=0xC6336401, in the bloom set) also floods 8 udp
# packets -> on the 8th frame bloom_hit AND rate_anomaly (mask bits 0 and 2),
# severity max(3,2)=3, escalate. Requires a seeded bloom.
COMBINED = [hdr(0xC6336401, 0xC0000221, 1000 + i, 9999, 17, 0x00) for i in range(8)]

SCENARIOS = {"benign": BENIGN, "vscan": VSCAN, "flood": FLOOD,
             "hscan": HSCAN, "boundary": BOUNDARY, "combined": COMBINED}
