"""CPU reference classifier — the same v1 logic the FPGA runs (CLASSIFIER.md).

Maps a 20-byte header frame to a 20-byte verdict frame. This is the golden source for
the Tier-2 header->verdict vectors and the CPU half of the FPGA-vs-CPU benchmark, so it
must implement exactly the locked spec (v1: bloom C2-IP match only).
"""
import struct

from bloom import BloomFilter
from verdict import encode_verdict

_BLOOM_SEVERITY = 3  # high, per CLASSIFIER.md


def classify_header(header: bytes, bloom: BloomFilter, seq: int) -> bytes:
    """Run the v1 classifier over one 20-byte header; return its 20-byte verdict.

    src_ip = header bytes 0-3, dst_ip = bytes 4-7 (big-endian, per PROTOCOL.md).
    """
    src_ip, dst_ip = struct.unpack(">II", header[:8])
    bloom_hit = bloom.member(src_ip) or bloom.member(dst_ip)
    if bloom_hit:
        return encode_verdict(bloom_hit=True, severity=_BLOOM_SEVERITY,
                              escalate=True, seq=seq)
    return encode_verdict(seq=seq)
