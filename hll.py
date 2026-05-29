"""Bit-exact CPU twin of hll.v (HyperLogLog distinct source IPs). No spidev/scapy.

Harmonic sum is stored SCALED as an integer S = sum_j 2^(32 - rank_j) (rank 0 -> 2^32),
so the FPGA maintains it with integer add/sub. The FPGA also tracks `zeros` (registers
still empty this window) because HLL needs linear counting for small cardinalities; the
Pi reads both (S, zeros) and finishes the estimate. hll.v must mirror these exactly.
"""
import math

MASK32 = 0xFFFFFFFF
HLL_M, HLL_IDXB, HLL_RANKBITS = 2048, 11, 21    # m=2^11 registers; rank over the low 21 bits
HLL_ALPHA = 0.7213 / (1 + 1.079 / HLL_M)


def fmix32(h):                                   # Murmur3 finalizer: strong avalanche, HLL needs it
    h &= MASK32
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & MASK32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & MASK32
    h ^= h >> 16
    return h


def _rank(w):                                    # leftmost-1 position in HLL_RANKBITS bits, 1-based
    if w == 0:
        return HLL_RANKBITS + 1
    r = 1
    msb = 1 << (HLL_RANKBITS - 1)
    while not (w & msb):
        r += 1
        w <<= 1
    return r


def estimate_from(harmonic_sum, zeros):
    """The Pi-side finish: raw harmonic estimate, with linear counting for small ranges."""
    e_raw = HLL_ALPHA * HLL_M * HLL_M * (1 << 32) / harmonic_sum
    if e_raw <= 2.5 * HLL_M and zeros > 0:
        return HLL_M * math.log(HLL_M / zeros)   # linear counting
    return e_raw


class HyperLogLog:
    def __init__(self):
        self.epoch = 0
        self.reg = [(0, 0)] * HLL_M              # (epoch, rank)
        self.harmonic_sum = HLL_M * (1 << 32)    # all ranks 0 -> 2^32 each
        self.zeros = HLL_M                       # registers still empty this window

    def _rankval(self, b):
        e, r = self.reg[b]
        return r if e == self.epoch else 0       # lazy-epoch reset

    def update(self, ip):
        h = fmix32(ip)
        b = h >> (32 - HLL_IDXB)
        w = h & ((1 << HLL_RANKBITS) - 1)
        new = _rank(w)
        old = self._rankval(b)
        if new > old:
            if old == 0:                         # first touch this window
                self.zeros -= 1
            self.harmonic_sum += (1 << (32 - new)) - (1 << (32 - old))
            self.reg[b] = (self.epoch, new)

    def estimate(self):
        return estimate_from(self.harmonic_sum, self.zeros)

    def window_tick(self):
        self.epoch = (self.epoch + 1) & 0xF
        self.harmonic_sum = HLL_M * (1 << 32)
        self.zeros = HLL_M
