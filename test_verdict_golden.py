"""Pi-side check against the shared Tier-2 golden vectors (internal VERDICT_GOLDEN.md).

The CPU reference classifier must produce exactly the verdicts in that doc; the FPGA
pipeline TB asserts the same. Keep this table byte-for-byte in sync with VERDICT_GOLDEN.md.
"""
import pytest

from bloom import BloomFilter, TEST_C2_SET
from classifier import classify_header

# (seq, header hex, expected verdict hex)
GOLDEN = [
    (1, "c0000201c0000202303900500602003c00000000", "a500000001000000000000000000000000000000"),
    (2, "c0000201c6336401303901bb0602003c00000000", "a501030102000000000000000000000000000000"),
    (3, "cb007105c0000201303900500602003c00000000", "a501030103000000000000000000000000000000"),
    (4, "c0000232c0000263303900351100003c00000000", "a501030104000000000000000000000000000000"),
    (5, "0a0000010a000002303900351100003c00000000", "a500000005000000000000000000000000000000"),
    (6, "c6336401cb007105303900500602003c00000000", "a501030106000000000000000000000000000000"),
]


@pytest.mark.parametrize("seq,header_hex,verdict_hex", GOLDEN)
def test_golden_vector(seq, header_hex, verdict_hex):
    bf = BloomFilter.from_ips(TEST_C2_SET)
    got = classify_header(bytes.fromhex(header_hex), bf, seq=seq)
    assert got.hex() == verdict_hex, f"vector {seq}"
