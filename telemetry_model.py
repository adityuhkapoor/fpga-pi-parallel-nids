"""Bit-exact CPU twin of telemetry.v: wraps CountMin + HyperLogLog, tracks the top-1
heavy hitter, and latches a per-window snapshot on window_tick. Mirror in telemetry.v.

Snapshot of a completed window = {window_index, total_packets, harmonic_sum, zeros,
top1_count, top1_key}. The Pi reads it and finishes the HLL cardinality (hll.estimate_from).
top1 = the source with the largest Count-Min estimate seen during the window (strict max;
ties keep the earlier leader, which is deterministic since the heaviest source keeps growing).
"""
from cms import CountMin
from hll import HyperLogLog


class Telemetry:
    def __init__(self):
        self.cms = CountMin()
        self.hll = HyperLogLog()
        self.window_index = 0
        self.total_packets = 0
        self.top1_count = 0
        self.top1_key = 0
        self.snapshot = None                     # last completed window, or None

    def update(self, src_ip):
        self.cms.update(src_ip)
        self.hll.update(src_ip)
        self.total_packets += 1
        c = self.cms.point_query(src_ip)
        if c > self.top1_count:                  # strict: heaviest source overtakes as it grows
            self.top1_count = c
            self.top1_key = src_ip

    def point_query(self, ip):
        return self.cms.point_query(ip)

    def window_tick(self):
        self.snapshot = {
            "window_index": self.window_index,
            "total_packets": self.total_packets,
            "harmonic_sum": self.hll.harmonic_sum,
            "zeros": self.hll.zeros,
            "top1_count": self.top1_count,
            "top1_key": self.top1_key,
        }
        self.cms.window_tick()
        self.hll.window_tick()
        self.window_index = (self.window_index + 1) & 0xFFFF
        self.total_packets = 0
        self.top1_count = 0
        self.top1_key = 0
