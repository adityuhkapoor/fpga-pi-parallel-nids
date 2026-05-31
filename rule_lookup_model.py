"""Bit-exact CPU twin of rule_lookup.v (v2 step 4). On every classify frame, hash src_ip
to a rule_store index, read the stored rule, return match iff (src_ip equals AND epoch
equals current_rule_epoch). The Pi writes rules at the same hash so the lookup finds them.
"""
from rule_store_model import RuleStore

A1 = 0x9E3779B1
MASK32 = 0xFFFFFFFF


def lookup_idx(src_ip):
    return (((src_ip * A1) & MASK32) >> 23) & 0x1FF        # top 9 bits -> 0..511


def lookup(rs: RuleStore, *, src_ip: int, current_rule_epoch: int) -> dict:
    stored = rs.read(lookup_idx(src_ip))
    if stored["src_ip"] == src_ip and stored["epoch"] == current_rule_epoch:
        return {"match": True, "action": stored["action"], "severity": stored["severity"]}
    return {"match": False, "action": 0, "severity": 0}
