from rule_store_model import RuleStore, encode_rule, decode_rule


def test_default_all_zero():
    rs = RuleStore()
    assert rs.read(0) == {"src_ip": 0, "action": 0, "severity": 0, "epoch": 0}


def test_write_read_roundtrip():
    rs = RuleStore()
    rs.write(42, {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7})
    assert rs.read(42) == {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}


def test_rule_encode_is_9_bytes_with_layout():
    rule = {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}
    b = encode_rule(rule)
    assert len(b) == 9
    assert b[0:4] == bytes([0xCB, 0x00, 0x71, 0x05])
    assert b[4] == 0b101 and b[5] == 3 and b[6] == 7
    assert b[7:9] == b"\x00\x00"


def test_encode_decode_inverse():
    rule = {"src_ip": 0xC0000201, "action": 0b010, "severity": 2, "epoch": 100}
    assert decode_rule(encode_rule(rule)) == rule


def test_index_out_of_range_raises():
    import pytest
    with pytest.raises(IndexError):
        RuleStore().read(512)
