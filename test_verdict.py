"""Unit tests for the v2 verdict decoder/encoder (PROTOCOL.md §Response).

Pure-logic tests — no spidev, so they run anywhere (not just the Pi).
"""
from verdict import decode_verdict, encode_verdict


def test_all_zero_frame_is_not_a_valid_verdict():
    # magic byte 0x00 != 0xA5 -> "no verdict here" (first frame / post-reset / v1).
    v = decode_verdict(bytes(32))
    assert v.valid is False


def test_magic_a5_marks_a_valid_verdict():
    frame = bytes([0xA5]) + bytes(31)
    v = decode_verdict(frame)
    assert v.valid is True


def _frame(magic=0xA5, mask=0, severity=0, flags=0, seq=0):
    return bytes([magic, mask, severity, flags, seq]) + bytes(27)


def test_clean_verdict_has_no_stage_hits():
    v = decode_verdict(_frame(mask=0x00))
    assert v.bloom_hit is False
    assert v.port_scan is False
    assert v.rate_anomaly is False
    assert v.threats == []


def test_bloom_hit_sets_only_bloom():
    v = decode_verdict(_frame(mask=0b001))
    assert v.bloom_hit is True
    assert v.port_scan is False
    assert v.rate_anomaly is False
    assert v.threats == ["bloom"]


def test_port_scan_and_rate_anomaly_both_hit():
    v = decode_verdict(_frame(mask=0b110))
    assert v.bloom_hit is False
    assert v.port_scan is True
    assert v.rate_anomaly is True
    assert v.threats == ["port_scan", "rate_anomaly"]


def test_reserved_mask_bits_are_ignored():
    # bits 4-7 are reserved (bit 3 is now rule_match, v2 step 4); setting them must not invent threats.
    v = decode_verdict(_frame(mask=0b1111_0000))
    assert v.threats == []


def test_severity_levels_decode():
    assert decode_verdict(_frame(severity=0)).severity == 0
    assert decode_verdict(_frame(severity=3)).severity == 3
    assert decode_verdict(_frame(severity=3)).severity_name == "high"
    assert decode_verdict(_frame(severity=0)).severity_name == "clean"


def test_escalate_flag_is_bit0_of_flags_byte():
    assert decode_verdict(_frame(flags=0b0000_0001)).escalate is True
    assert decode_verdict(_frame(flags=0b0000_0000)).escalate is False
    # reserved flag bits 1-7 must not affect escalate.
    assert decode_verdict(_frame(flags=0b1111_1110)).escalate is False


def test_seq_is_the_frame_counter_byte():
    assert decode_verdict(_frame(seq=0)).seq == 0
    assert decode_verdict(_frame(seq=255)).seq == 255


def test_wrong_length_frame_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        decode_verdict(bytes(31))
    with pytest.raises(ValueError):
        decode_verdict(bytes(33))


def test_encode_clean_verdict_is_magic_then_zeros():
    assert encode_verdict() == bytes([0xA5]) + bytes(31)


def test_encode_packs_all_fields():
    frame = encode_verdict(bloom_hit=True, rate_anomaly=True, severity=3,
                           escalate=True, seq=42)
    assert frame == bytes([0xA5, 0b101, 3, 0b1, 42]) + bytes(27)


def test_encode_produces_32_bytes():
    assert len(encode_verdict(seq=255)) == 32


def test_encode_decode_round_trips():
    frame = encode_verdict(port_scan=True, severity=2, escalate=True, seq=7)
    v = decode_verdict(frame)
    assert v.valid is True
    assert v.threats == ["port_scan"]
    assert v.severity == 2
    assert v.escalate is True
    assert v.seq == 7


def test_describe_no_verdict():
    assert decode_verdict(bytes(32)).describe() == "no-verdict"


def test_describe_clean():
    assert decode_verdict(encode_verdict(seq=9)).describe() == "CLEAN seq=9"


def test_describe_threat_with_escalate():
    frame = encode_verdict(bloom_hit=True, severity=3, escalate=True, seq=4)
    assert decode_verdict(frame).describe() == "THREAT[bloom] high ESCALATE seq=4"


def test_describe_multi_threat_no_escalate():
    frame = encode_verdict(port_scan=True, rate_anomaly=True, severity=2, seq=5)
    assert decode_verdict(frame).describe() == "THREAT[port_scan,rate_anomaly] med seq=5"
