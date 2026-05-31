from rule_lookup_model import lookup_idx, lookup
from rule_store_model import RuleStore


def test_lookup_idx_hash_is_top_9_bits_of_a1_product():
    assert lookup_idx(0xCB007105) == (((0xCB007105 * 0x9E3779B1) & 0xFFFFFFFF) >> 23) & 0x1FF


def test_match_when_src_and_epoch_match():
    rs = RuleStore()
    src = 0xCB007105
    rs.write(lookup_idx(src),
             {"src_ip": src, "action": 0b101, "severity": 3, "epoch": 7})
    r = lookup(rs, src_ip=src, current_rule_epoch=7)
    assert r == {"match": True, "action": 0b101, "severity": 3}


def test_no_match_when_epoch_differs():
    rs = RuleStore()
    src = 0xCB007105
    rs.write(lookup_idx(src),
             {"src_ip": src, "action": 0b101, "severity": 3, "epoch": 7})
    r = lookup(rs, src_ip=src, current_rule_epoch=8)
    assert r["match"] is False


def test_no_match_when_src_differs_at_same_idx():
    rs = RuleStore()
    src_a = 0xCB007105
    rs.write(lookup_idx(src_a),
             {"src_ip": src_a, "action": 0b001, "severity": 1, "epoch": 0})
    src_b = None
    for cand in range(0x0A000000, 0x0A010000):
        if lookup_idx(cand) == lookup_idx(src_a) and cand != src_a:
            src_b = cand; break
    assert src_b is not None
    r = lookup(rs, src_ip=src_b, current_rule_epoch=0)
    assert r["match"] is False


def test_unwritten_bucket_returns_no_match():
    rs = RuleStore()
    r = lookup(rs, src_ip=0x0A000001, current_rule_epoch=0)
    assert r["match"] is False
