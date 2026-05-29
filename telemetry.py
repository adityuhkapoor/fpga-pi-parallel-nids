"""Pi-side decoders for the v2 telemetry response frames (magic 0x5A) and the
HLL cardinality finish. Pure stdlib so it unit-tests off the Pi.

Layouts mirror nids_top.v's response mux (each is 32 bytes, MSB-first per PROTOCOL.md):
  0x01 (CMS point-query):  byte0=5A  | bytes1-4 queried_key | bytes5-6 count (14b in low)
  0x02 (window snapshot):  byte0=5A  | b1-2 window | b3-6 total | b7-12 harmonic_sum |
                           b13-14 zeros | b15-16 top1_count | b17-20 top1_key
  0x03 (live HLL):         byte0=5A  | b1-6 harmonic_sum | b7-8 zeros | b9-10 m
"""
from dataclasses import dataclass

from hll import estimate_from, HLL_M

TELEMETRY_MAGIC = 0x5A
FRAME_LEN = 32


def _be(buf, off, n):
    """Big-endian unsigned int from buf[off:off+n]."""
    return int.from_bytes(buf[off:off + n], "big")


def _check(frame):
    if len(frame) != FRAME_LEN:
        raise ValueError(f"telemetry frame must be {FRAME_LEN} bytes, got {len(frame)}")
    if frame[0] != TELEMETRY_MAGIC:
        raise ValueError(f"bad telemetry magic {frame[0]:#04x} (want 0x5A)")


@dataclass(frozen=True)
class CMSResponse:
    key: int
    count: int


@dataclass(frozen=True)
class SnapResponse:
    window: int
    total: int
    harmonic_sum: int
    zeros: int
    top1_count: int
    top1_key: int

    @property
    def distinct_estimate(self) -> float:
        return estimate_from(self.harmonic_sum, self.zeros)


@dataclass(frozen=True)
class HLLResponse:
    harmonic_sum: int
    zeros: int
    m: int

    @property
    def cardinality(self) -> float:
        return estimate_from(self.harmonic_sum, self.zeros)


def decode_query(frame: bytes) -> CMSResponse:
    _check(frame)
    return CMSResponse(key=_be(frame, 1, 4), count=_be(frame, 5, 2) & 0x3FFF)


def decode_snapshot(frame: bytes) -> SnapResponse:
    _check(frame)
    return SnapResponse(
        window=_be(frame, 1, 2),
        total=_be(frame, 3, 4),
        harmonic_sum=_be(frame, 7, 6),
        zeros=_be(frame, 13, 2) & 0x0FFF,
        top1_count=_be(frame, 15, 2) & 0x3FFF,
        top1_key=_be(frame, 17, 4),
    )


def decode_hll(frame: bytes) -> HLLResponse:
    _check(frame)
    return HLLResponse(
        harmonic_sum=_be(frame, 1, 6),
        zeros=_be(frame, 7, 2) & 0x0FFF,
        m=_be(frame, 9, 2),
    )


# --- response builders (encoder inverses; used by tests + TELEMETRY_VECTORS.md generation) ---

def _be_bytes(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


def encode_query(key: int, count: int) -> bytes:
    body = bytes([TELEMETRY_MAGIC]) + _be_bytes(key, 4) + _be_bytes(count & 0x3FFF, 2)
    return body + bytes(FRAME_LEN - len(body))


def encode_snapshot(window, total, harmonic_sum, zeros, top1_count, top1_key) -> bytes:
    body = (bytes([TELEMETRY_MAGIC])
            + _be_bytes(window, 2) + _be_bytes(total, 4)
            + _be_bytes(harmonic_sum, 6)
            + _be_bytes(zeros & 0x0FFF, 2) + _be_bytes(top1_count & 0x3FFF, 2)
            + _be_bytes(top1_key, 4))
    return body + bytes(FRAME_LEN - len(body))


def encode_hll(harmonic_sum, zeros, m=HLL_M) -> bytes:
    body = (bytes([TELEMETRY_MAGIC]) + _be_bytes(harmonic_sum, 6)
            + _be_bytes(zeros & 0x0FFF, 2) + _be_bytes(m, 2))
    return body + bytes(FRAME_LEN - len(body))
