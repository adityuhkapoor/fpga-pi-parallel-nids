"""Bit-exact CPU model of the FPGA per-source state table (CLASSIFIER.md v1.1).

The Verilog scan_rate.v must implement these exact constants and rules so the
deterministic golden vectors match real silicon. No spidev/scapy here.
"""
A1 = 0x9E3779B1
A2 = 0x85EBCA77
MASK32 = 0xFFFFFFFF

WINDOW_SHIFT = 4      # window = 16 frames
NUM_BUCKETS  = 256
PORT_THRESH  = 5      # distinct dst ports -> vertical scan
HOST_THRESH  = 5      # distinct dst ips   -> horizontal scan
RATE_THRESH  = 8      # packets/window     -> flood

def bucket(src_ip):     return ((src_ip   * A1) & MASK32) >> 24   # 8-bit, 0..255
def port_bit(dst_port): return ((dst_port * A2) & MASK32) >> 28   # 4-bit, 0..15
def host_bit(dst_ip):   return ((dst_ip   * A1) & MASK32) >> 28   # 4-bit, 0..15
def epoch(frame_count): return (frame_count >> WINDOW_SHIFT) & 0xF

def _syn_gate(proto, tcp_flags):
    return proto == 6 and bool(tcp_flags & 0x02) and not (tcp_flags & 0x10)

class ScanRateTable:
    def __init__(self):
        self._t = [self._blank(0) for _ in range(NUM_BUCKETS)]

    @staticmethod
    def _blank(ep):
        return {"epoch": ep, "port_fp": 0, "host_fp": 0, "pkt_count": 0}

    def _entry(self, src_ip):
        return self._t[bucket(src_ip)]

    def update(self, *, src_ip, dst_ip, dst_port, proto, tcp_flags, frame_count):
        """Apply one packet; return (port_scan_hit, rate_hit)."""
        b = bucket(src_ip)
        ep = epoch(frame_count)
        e = self._t[b]
        if e["epoch"] != ep:            # lazy tumbling reset
            e = self._blank(ep)
            self._t[b] = e
        e["pkt_count"] = min(e["pkt_count"] + 1, 0xFF)
        if _syn_gate(proto, tcp_flags):
            e["port_fp"] |= 1 << port_bit(dst_port)
            e["host_fp"] |= 1 << host_bit(dst_ip)
        port_scan_hit = (bin(e["port_fp"]).count("1") >= PORT_THRESH or
                         bin(e["host_fp"]).count("1") >= HOST_THRESH)
        rate_hit = e["pkt_count"] >= RATE_THRESH
        return port_scan_hit, rate_hit
