"""Pi-side check against the shared Tier-1 verdict format vectors.

Mirrors internal-repo VERDICT_VECTORS.md exactly. The FPGA encoder testbench asserts
it *emits* these frames; here the Pi decoder asserts it *reads* them back to the same
fields. If both pass, the two sides agree on the byte layout — no hardware needed.

Keep this table byte-for-byte in sync with VERDICT_VECTORS.md.
"""
import pytest

from verdict import decode_verdict

# (#, hex frame, valid, threats, severity, escalate, seq)
VECTORS = [
    (1, "a500000001000000000000000000000000000000", True,  [],                                     0, False, 1),
    (2, "a501030102000000000000000000000000000000", True,  ["bloom"],                              3, True,  2),
    (3, "a502020003000000000000000000000000000000", True,  ["port_scan"],                          2, False, 3),
    (4, "a504010004000000000000000000000000000000", True,  ["rate_anomaly"],                       1, False, 4),
    (5, "a507030105000000000000000000000000000000", True,  ["bloom", "port_scan", "rate_anomaly"], 3, True,  5),
    (6, "a5000000ff000000000000000000000000000000", True,  [],                                     0, False, 255),
    (7, "a501030100000000000000000000000000000000", True,  ["bloom"],                              3, True,  0),
    (8, "0000000000000000000000000000000000000000", False, [],                                     0, False, 0),
]


@pytest.mark.parametrize("num,hexframe,valid,threats,severity,escalate,seq", VECTORS)
def test_format_vector(num, hexframe, valid, threats, severity, escalate, seq):
    v = decode_verdict(bytes.fromhex(hexframe))
    assert v.valid is valid, f"vector {num}: valid"
    assert v.threats == threats, f"vector {num}: threats"
    assert v.severity == severity, f"vector {num}: severity"
    assert v.escalate is escalate, f"vector {num}: escalate"
    assert v.seq == seq, f"vector {num}: seq"
