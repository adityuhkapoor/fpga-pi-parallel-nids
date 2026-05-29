"""Bit-exact CPU twin of cms.v (5-bank Count-Min on src_ip). No spidev/scapy.

The Verilog cms.v must implement these exact hashes, layout, and lazy-epoch reset so
the deterministic golden vectors match silicon. Key = source IP, value = packet count
over one window; point_query returns the min across banks (the Count-Min estimate).
"""
MASK32 = 0xFFFFFFFF
CMS_A = [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1]  # odd 32b mixers
CMS_COLS, CMS_ROWS, CMS_CW = 4096, 5, 14
CMS_MAX = (1 << CMS_CW) - 1


class CountMin:
    def __init__(self):
        self.epoch = 0
        self.cell = [[(0, 0) for _ in range(CMS_COLS)] for _ in range(CMS_ROWS)]  # (epoch, count)

    def column(self, ip, j):
        return ((ip * CMS_A[j]) & MASK32) >> 20      # top 12 bits of the low-32 product

    def _count(self, j, c):
        e, v = self.cell[j][c]
        return v if e == self.epoch else 0           # lazy-epoch reset

    def update(self, ip):
        for j in range(CMS_ROWS):
            c = self.column(ip, j)
            v = self._count(j, c)
            self.cell[j][c] = (self.epoch, min(v + 1, CMS_MAX))

    def point_query(self, ip):
        return min(self._count(j, self.column(ip, j)) for j in range(CMS_ROWS))

    def window_tick(self):
        self.epoch = (self.epoch + 1) & 0xF
