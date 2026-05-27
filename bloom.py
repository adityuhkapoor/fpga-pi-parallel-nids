"""Bloom filter for the C2-IP match stage (CLASSIFIER.md §Bloom stage).

Builds the bit-array the FPGA queries, and emits it as the BRAM-init `bloom_init.mem`.
Pure stdlib; the hashes/packing here are the contract the FPGA mirrors bit-for-bit.
"""
import socket
import struct

M_BITS = 65536          # bit-array size m = 2**16; index is 16 bits
K_HASHES = 2            # dual-port BRAM friendly
_A1 = 0x9E3779B1        # multiply-shift constants (odd, locked in CLASSIFIER.md)
_A2 = 0x85EBCA77
_MASK32 = 0xFFFFFFFF

# Locked test C2 set (CLASSIFIER.md): deterministic RFC 5737 IPs used for the bloom
# BRAM-init demo and the Tier-2 golden vectors. Live demo can swap in the Feodo feed.
TEST_C2_SET = ["198.51.100.1", "203.0.113.5", "192.0.2.99"]


def ip_to_int(ip: str) -> int:
    """Dotted IPv4 -> 32-bit big-endian unsigned int (matches header_parser src_ip)."""
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def h1(x: int) -> int:
    return ((x * _A1) & _MASK32) >> 16


def h2(x: int) -> int:
    return ((x * _A2) & _MASK32) >> 16


class BloomFilter:
    """k=2 bloom over 32-bit IPs into an m=65536-bit array (CLASSIFIER.md)."""

    def __init__(self):
        self.bits = bytearray(M_BITS // 8)  # 65536 bits = 8192 bytes

    def _set(self, idx: int) -> None:
        self.bits[idx >> 3] |= 1 << (idx & 7)

    def _get(self, idx: int) -> bool:
        return bool(self.bits[idx >> 3] & (1 << (idx & 7)))

    def add(self, x: int) -> None:
        self._set(h1(x))
        self._set(h2(x))

    def member(self, x: int) -> bool:
        return self._get(h1(x)) and self._get(h2(x))

    @classmethod
    def from_ips(cls, ips) -> "BloomFilter":
        bf = cls()
        for ip in ips:
            bf.add(ip_to_int(ip))
        return bf

    def to_mem(self) -> str:
        """$readmemh bit-array: 4096 lines, one 16-bit hex word each.

        Word w covers bits [16w..16w+15], LSB = bit 16w (CLASSIFIER.md). Since the
        byte store already packs bit (i&7) into byte i>>3, word w = byte[2w] | byte[2w+1]<<8.
        """
        words = []
        for w in range(M_BITS // 16):  # 4096
            word = self.bits[2 * w] | (self.bits[2 * w + 1] << 8)
            words.append(f"{word:04x}")
        return "\n".join(words) + "\n"


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "bloom_init.mem"
    bf = BloomFilter.from_ips(TEST_C2_SET)
    with open(out, "w") as f:
        f.write(bf.to_mem())
    print(f"wrote {out}: {len(TEST_C2_SET)} C2 IPs, m={M_BITS}, k={K_HASHES}")
