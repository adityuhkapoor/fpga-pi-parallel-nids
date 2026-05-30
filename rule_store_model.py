"""Bit-exact CPU twin of rule_store.v. 512 rules indexed 0..511, each 72 bits packed
into 9 bytes (PROTOCOL.md). Pure stdlib so it unit-tests off the Pi."""
RULE_BYTES = 9
RULE_DEPTH = 512


def encode_rule(rule):
    return (rule["src_ip"].to_bytes(4, "big")
            + bytes([rule["action"] & 0xFF, rule["severity"] & 0xFF, rule["epoch"] & 0xFF])
            + bytes(2))


def decode_rule(b):
    if len(b) != RULE_BYTES:
        raise ValueError(f"rule must be {RULE_BYTES} bytes, got {len(b)}")
    return {
        "src_ip":   int.from_bytes(b[0:4], "big"),
        "action":   b[4],
        "severity": b[5] & 0x0F,
        "epoch":    b[6],
    }


class RuleStore:
    def __init__(self):
        self._cells = [{"src_ip": 0, "action": 0, "severity": 0, "epoch": 0}
                       for _ in range(RULE_DEPTH)]

    def write(self, idx, rule):
        if not 0 <= idx < RULE_DEPTH:
            raise IndexError(idx)
        self._cells[idx] = {**rule, "severity": rule.get("severity", 0) & 0x0F}

    def read(self, idx):
        if not 0 <= idx < RULE_DEPTH:
            raise IndexError(idx)
        return dict(self._cells[idx])
