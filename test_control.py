from control import (
    encode_bloom_write, encode_threshold_write, encode_rule_write,
    encode_bloom_read, encode_threshold_read, encode_rule_read,
    decode_write_ack, decode_bloom_read, decode_threshold_read, decode_rule_read,
)


def test_bloom_write_frame_is_32_bytes_with_opcode_at_byte_16():
    f = encode_bloom_write(addr=0xABC, value=0x55AA)
    assert len(f) == 32 and f[16] == 0x10
    assert f[0:2] == bytes([0x0A, 0xBC]) and f[2:4] == bytes([0x55, 0xAA])


def test_threshold_write_frame_layout():
    f = encode_threshold_write(tid=0x01, value=0x000C)
    assert f[16] == 0x11 and f[0] == 0x01 and f[1:3] == bytes([0x00, 0x0C])


def test_rule_write_frame_layout():
    rule = {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}
    f = encode_rule_write(idx=42, rule=rule)
    assert f[16] == 0x12 and f[0:2] == bytes([0x00, 0x2A])
    assert f[2:6] == bytes([0xCB, 0x00, 0x71, 0x05]) and f[6:9] == bytes([0b101, 3, 7])


def test_bloom_read_frame_layout():
    f = encode_bloom_read(addr=0xABC)
    assert len(f) == 32 and f[16] == 0x13 and f[0:2] == bytes([0x0A, 0xBC])


def test_write_ack_decode():
    ack = bytes([0x5A, 0x10]) + bytes(30)
    assert decode_write_ack(ack) == 0x10


def test_bloom_read_decode():
    r = bytes([0x5A, 0x0A, 0xBC, 0x55, 0xAA]) + bytes(27)
    assert decode_bloom_read(r) == {"addr": 0x0ABC, "value": 0x55AA}


def test_threshold_read_decode():
    r = bytes([0x5A, 0x02, 0x00, 0x08]) + bytes(28)
    assert decode_threshold_read(r) == {"tid": 0x02, "value": 0x0008}


def test_rule_read_decode():
    payload = bytes([0xCB, 0x00, 0x71, 0x05, 0b101, 3, 7, 0, 0])
    r = bytes([0x5A, 0x00, 0x2A]) + payload + bytes(20)
    assert decode_rule_read(r) == {"idx": 42, "rule":
        {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}}


def test_bad_magic_raises():
    import pytest
    with pytest.raises(ValueError):
        decode_bloom_read(bytes([0xA5]) + bytes(31))


def test_wrong_length_raises():
    import pytest
    with pytest.raises(ValueError):
        decode_write_ack(bytes(31))
