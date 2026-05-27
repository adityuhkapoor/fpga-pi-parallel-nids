"""CPU reference classifier — the exact logic the FPGA runs (CLASSIFIER.md v1.1).

v1: bloom C2-IP match (stateless). v1.1 adds stateful port-scan + rate-anomaly via
ScanRateTable. Bit-exact to the HDL; the golden source for Tier-2 vectors and the
CPU half of the FPGA-vs-CPU benchmark.
"""
import struct

from bloom import BloomFilter
from verdict import encode_verdict
from scan_rate import ScanRateTable

_BLOOM_SEV = 3
_SCAN_SEV  = 2
_RATE_SEV  = 2

_HDR = struct.Struct(">IIHHBBH")  # first 16 bytes; bytes 16-19 reserved


def _parse(header):
    src_ip, dst_ip, src_port, dst_port, proto, flags, size = _HDR.unpack(header[:16])
    return src_ip, dst_ip, src_port, dst_port, proto, flags, size


class Classifier:
    """Stateful: feed frames in order; frame_count drives the window epoch."""

    def __init__(self, bloom: BloomFilter):
        self.bloom = bloom
        self.table = ScanRateTable()

    def classify(self, header: bytes, seq: int, frame_count: int) -> bytes:
        src_ip, dst_ip, _sp, dst_port, proto, flags, _sz = _parse(header)
        bloom_hit = self.bloom.member(src_ip) or self.bloom.member(dst_ip)
        port_scan, rate = self.table.update(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            proto=proto, tcp_flags=flags, frame_count=frame_count)
        sev = max(_BLOOM_SEV if bloom_hit else 0,
                  _SCAN_SEV  if port_scan else 0,
                  _RATE_SEV  if rate else 0)
        any_hit = bloom_hit or port_scan or rate
        return encode_verdict(bloom_hit=bloom_hit, port_scan=port_scan,
                              rate_anomaly=rate, severity=sev,
                              escalate=any_hit, seq=seq)


def classify_header(header: bytes, bloom: BloomFilter, seq: int) -> bytes:
    """Backward-compatible stateless single-packet classify (v1 API)."""
    return Classifier(bloom).classify(header, seq=seq, frame_count=0)
