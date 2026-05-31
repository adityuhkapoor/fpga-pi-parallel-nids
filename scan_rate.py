"""Bit-exact CPU model of the FPGA per-source state table (CLASSIFIER.md v1.1).

The Verilog scan_rate.v must implement these exact constants and rules so the
deterministic golden vectors match real silicon. No spidev/scapy here.

v2 step-2: PORT/HOST/RATE thresholds moved out of this file into thresholds_model.py
since the HDL now reads them from a runtime register file (opcode 0x11). ScanRateTable
takes an optional Thresholds instance; defaults to v1.1's 5/5/8 if not provided, so
existing tests + golden vectors keep working unchanged.
"""
from thresholds_model import Thresholds, PORT_THRESH as _ID_PORT, HOST_THRESH as _ID_HOST, RATE_THRESH as _ID_RATE

A1 = 0x9E3779B1
A2 = 0x85EBCA77
MASK32 = 0xFFFFFFFF

WINDOW_SHIFT = 4      # window = 16 frames
NUM_BUCKETS  = 256

def bucket(src_ip):     return ((src_ip   * A1) & MASK32) >> 24   # 8-bit, 0..255
def port_bit(dst_port): return ((dst_port * A2) & MASK32) >> 28   # 4-bit, 0..15
def host_bit(dst_ip):   return ((dst_ip   * A1) & MASK32) >> 28   # 4-bit, 0..15
def epoch(frame_count): return (frame_count >> WINDOW_SHIFT) & 0xF

def _syn_gate(proto, tcp_flags):
    return proto == 6 and bool(tcp_flags & 0x02) and not (tcp_flags & 0x10)

class ScanRateTable:
    def __init__(self, thresholds=None):
        self._t = [self._blank(0) for _ in range(NUM_BUCKETS)]
        self.thresholds = thresholds if thresholds is not None else Thresholds()

    @staticmethod
    def _blank(ep):
        return {"epoch": ep, "port_fp": 0, "host_fp": 0, "pkt_count": 0}

    def _entry(self, src_ip):
        return self._t[bucket(src_ip)]

    def update(self, *, src_ip, dst_ip, dst_port, proto, tcp_flags, frame_count):
        """Apply one packet; return (port_scan_hit, rate_hit). Reads thresholds on every
        call so runtime writes (opcode 0x11) are reflected immediately, matching HDL."""
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
        port_scan_hit = (bin(e["port_fp"]).count("1") >= self.thresholds.read(_ID_PORT) or
                         bin(e["host_fp"]).count("1") >= self.thresholds.read(_ID_HOST))
        rate_hit = e["pkt_count"] >= self.thresholds.read(_ID_RATE)
        return port_scan_hit, rate_hit
