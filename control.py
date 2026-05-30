"""Pi-side encoders for the v2 step-2 write opcodes and decoders for the read responses
(magic 0x5A). Pure stdlib. Frame layouts pinned in PROTOCOL.md; keep in lockstep with
nids_top.v's response mux."""
from rule_store_model import encode_rule, decode_rule

FRAME_LEN = 32
RESPONSE_MAGIC = 0x5A

OP_BLOOM_W, OP_THRESH_W, OP_RULE_W = 0x10, 0x11, 0x12
OP_BLOOM_R, OP_THRESH_R, OP_RULE_R = 0x13, 0x14, 0x15


def _frame(opcode, payload):
    f = bytearray(FRAME_LEN)
    f[0:len(payload)] = payload
    f[16] = opcode
    return bytes(f)


def encode_bloom_write(addr, value):
    return _frame(OP_BLOOM_W, addr.to_bytes(2, "big") + value.to_bytes(2, "big"))


def encode_threshold_write(tid, value):
    return _frame(OP_THRESH_W, bytes([tid & 0xFF]) + value.to_bytes(2, "big"))


def encode_rule_write(idx, rule):
    return _frame(OP_RULE_W, idx.to_bytes(2, "big") + encode_rule(rule))


def encode_bloom_read(addr):
    return _frame(OP_BLOOM_R, addr.to_bytes(2, "big"))


def encode_threshold_read(tid):
    return _frame(OP_THRESH_R, bytes([tid & 0xFF]))


def encode_rule_read(idx):
    return _frame(OP_RULE_R, idx.to_bytes(2, "big"))


def _check(frame):
    if len(frame) != FRAME_LEN:
        raise ValueError(f"frame must be {FRAME_LEN} bytes, got {len(frame)}")
    if frame[0] != RESPONSE_MAGIC:
        raise ValueError(f"bad response magic {frame[0]:#04x} (want 0x5A)")


def decode_write_ack(frame):
    _check(frame)
    return frame[1]                                          # opcode_acked


def decode_bloom_read(frame):
    _check(frame)
    return {"addr": int.from_bytes(frame[1:3], "big"),
            "value": int.from_bytes(frame[3:5], "big")}


def decode_threshold_read(frame):
    _check(frame)
    return {"tid": frame[1], "value": int.from_bytes(frame[2:4], "big")}


def decode_rule_read(frame):
    _check(frame)
    return {"idx": int.from_bytes(frame[1:3], "big"),
            "rule": decode_rule(frame[3:12])}
