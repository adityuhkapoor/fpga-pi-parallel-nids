"""Tests for the Pi-side telemetry decoder + cardinality finish.

Roundtrips encoded vectors through decode (encoder is the locked inverse), and verifies the
HLL cardinality computed from a snapshot/HLL response matches the CPU twin's estimate.
"""
import pytest

from telemetry import (
    TELEMETRY_MAGIC, FRAME_LEN,
    decode_query, decode_snapshot, decode_hll,
    encode_query, encode_snapshot, encode_hll,
)
from hll import HyperLogLog


def test_decode_rejects_wrong_length():
    with pytest.raises(ValueError):
        decode_query(bytes(31))
    with pytest.raises(ValueError):
        decode_snapshot(bytes(33))


def test_decode_rejects_bad_magic():
    bad = bytes([0xA5]) + bytes(FRAME_LEN - 1)
    with pytest.raises(ValueError):
        decode_query(bad)


def test_query_roundtrip():
    f = encode_query(key=0xCB007105, count=9)
    r = decode_query(f)
    assert r.key == 0xCB007105 and r.count == 9


def test_query_count_masks_to_14_bits():
    # Even if HW jammed high bits, decode masks to the 14b count field.
    raw = bytearray(encode_query(key=0x0A000001, count=5))
    raw[5] |= 0xC0                                   # set reserved high 2 bits
    r = decode_query(bytes(raw))
    assert r.count == 5 and r.key == 0x0A000001


def test_snapshot_roundtrip():
    f = encode_snapshot(window=7, total=2000, harmonic_sum=0x07FB92000000,
                        zeros=2042, top1_count=9, top1_key=0xCB007105)
    s = decode_snapshot(f)
    assert s.window == 7
    assert s.total == 2000
    assert s.harmonic_sum == 0x07FB92000000
    assert s.zeros == 2042
    assert s.top1_count == 9 and s.top1_key == 0xCB007105


def test_snapshot_distinct_estimate_matches_twin():
    h = HyperLogLog()
    for i in range(1000):
        h.update(0x0A000000 + i)
    f = encode_snapshot(window=0, total=1000, harmonic_sum=h.harmonic_sum,
                        zeros=h.zeros, top1_count=0, top1_key=0)
    s = decode_snapshot(f)
    assert abs(s.distinct_estimate - 1000) / 1000 < 0.10


def test_hll_roundtrip_and_cardinality():
    h = HyperLogLog()
    for i in range(500):
        h.update(0x0A000000 + i)
    f = encode_hll(h.harmonic_sum, h.zeros)
    r = decode_hll(f)
    assert r.harmonic_sum == h.harmonic_sum
    assert r.zeros == h.zeros
    assert r.m == 2048
    assert abs(r.cardinality - 500) / 500 < 0.10


def test_hll_empty_decodes_to_full_m_zeros():
    f = encode_hll(harmonic_sum=2048 * (1 << 32), zeros=2048)
    r = decode_hll(f)
    # cardinality of empty -> 0 via linear counting (V == m -> log(m/m)=0)
    assert r.cardinality == 0.0
