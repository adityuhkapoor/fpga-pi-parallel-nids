"""Bit-exact CPU twin of flow_table.v (v2 step 3). Replaces scan_rate's 256-bucket
undercounting with 4096 buckets + 16-bit fingerprint -> proper collision DETECTION + eviction
(no silent OR-merging). Verdict signals (port_scan_hit, rate_hit) drop in for scan_rate's.
"""
from thresholds_model import (
    Thresholds, PORT_THRESH as _ID_PORT, HOST_THRESH as _ID_HOST, RATE_THRESH as _ID_RATE,
)

A1 = 0x9E3779B1
A2 = 0x85EBCA77
MASK32 = 0xFFFFFFFF
DEPTH  = 4096
WINDOW_SHIFT = 4        # 16-frame window (same as v1.1)
RATE_MAX = (1 << 14) - 1
BYTE_MAX = (1 << 24) - 1
SYN_MAX  = (1 << 12) - 1


def bucket(src_ip):
    return ((src_ip * A1) & MASK32) >> 20                  # top 12 of low-32 product


def fp(src_ip):
    return (((src_ip * A2) & MASK32) >> 12) & 0xFFFF       # 16 bits from a DIFFERENT mult


def port_bit(dst_port):
    return ((dst_port * A2) & MASK32) >> 28


def host_bit(dst_ip):
    return ((dst_ip * A1) & MASK32) >> 28


def epoch(frame_count):
    return (frame_count >> WINDOW_SHIFT) & 0xF


def _syn_gate(proto, tcp_flags):
    return proto == 6 and bool(tcp_flags & 0x02) and not (tcp_flags & 0x10)


class FlowTable:
    def __init__(self, thresholds=None):
        self._t = [self._blank(0, 0) for _ in range(DEPTH)]
        self.thresholds = thresholds if thresholds is not None else Thresholds()

    @staticmethod
    def _blank(ep, the_fp):
        return {"fp": the_fp, "epoch": ep, "pkt_count": 0, "byte_count": 0,
                "syn_count": 0, "dport_fp": 0, "dhost_fp": 0, "flags": 0}

    def _cell_of(self, src_ip):
        return self._t[bucket(src_ip)]

    def update(self, *, src_ip, dst_ip, dst_port, proto, tcp_flags, pkt_size, frame_count):
        b   = bucket(src_ip)
        f   = fp(src_ip)
        ep  = epoch(frame_count)
        cur = self._t[b]
        if cur["fp"] != f or cur["epoch"] != ep:        # mismatch OR stale -> fresh cell
            cur = self._blank(ep, f)
            self._t[b] = cur
        cur["pkt_count"]  = min(cur["pkt_count"] + 1,         RATE_MAX)
        cur["byte_count"] = min(cur["byte_count"] + pkt_size, BYTE_MAX)
        if _syn_gate(proto, tcp_flags):
            cur["syn_count"] = min(cur["syn_count"] + 1, SYN_MAX)
            cur["dport_fp"] |= 1 << port_bit(dst_port)
            cur["dhost_fp"] |= 1 << host_bit(dst_ip)
        cur["flags"] |= tcp_flags
        port_scan_hit = (bin(cur["dport_fp"]).count("1") >= self.thresholds.read(_ID_PORT) or
                         bin(cur["dhost_fp"]).count("1") >= self.thresholds.read(_ID_HOST))
        rate_hit = cur["pkt_count"] >= self.thresholds.read(_ID_RATE)
        return port_scan_hit, rate_hit
