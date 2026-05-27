"""Generate the locked v1.1 header->verdict golden table from the CPU reference.

The table is the exact ordered stream the silicon round-trip clocks over SPI: the v1 bloom
single-packet regression vectors first (proving bloom still works on the v1.1 bitstream),
then the six stateful scenarios. State accumulates across the whole stream and frame_count =
clock index, exactly as the FPGA sees it (fresh config -> frame counter starts at 0). The
CPU reference (classifier.Classifier) is the oracle; the FPGA must reproduce every verdict.

Run `python3 gen_verdict_golden.py` to print the table for VERDICT_GOLDEN.md. The
build_stream() / expected_rows() helpers are imported by spi_verdict_check.py so the live
test and the locked table never drift.
"""
from bloom import BloomFilter
from classifier import Classifier
import scenarios

# Locked test C2 set (RFC5737), matches bloom_init.mem / VERDICT_GOLDEN.
C2 = [0xC6336401, 0xCB007105, 0xC0000263]

# The v1 Tier-2 bloom vectors (single packets) — kept as the v1.1 regression prefix.
V1_BLOOM_INPUTS = [
    "c0000201c0000202303900500602003c00000000",   # clean
    "c0000201c6336401303901bb0602003c00000000",   # dst C2 -> bloom
    "cb007105c0000201303900500602003c00000000",   # src C2 -> bloom
    "c0000232c0000263303900351100003c00000000",   # dst C2 -> bloom
    "0a0000010a000002303900351100003c00000000",   # clean
    "c6336401cb007105303900500602003c00000000",   # both C2 -> bloom
]

# Scenario order in the stream (boundary spans 17 frames so it always crosses an epoch).
_ORDER = ["benign", "vscan", "flood", "hscan", "boundary", "combined"]


def build_stream():
    """The exact ordered (label, header_hex) stream the silicon test clocks.

    Each scenario is padded to start on a 16-frame window boundary so its packets land in
    one epoch and the stateful detectors can actually trip (an unaligned flood would split
    across the boundary and never reach the rate threshold). Padding frames are benign,
    single-packet, unique-source UDP that never trip a stage. The boundary scenario is 17
    frames so it still deliberately crosses one window edge to prove the lazy reset.
    """
    stream = [("v1bloom", h) for h in V1_BLOOM_INPUTS]
    fill = [0]   # unique-source counter for padding frames

    def pad_to_window():
        while len(stream) % 16 != 0:
            src = 0x0A001000 + fill[0]
            stream.append(("pad", scenarios.hdr(src, 0xC0000202, 5000, 53, 17, 0x00)))
            fill[0] += 1

    for name in _ORDER:
        pad_to_window()
        stream += [(name, h) for h in scenarios.SCENARIOS[name]]
    return stream


def expected_rows():
    """(label, index, header_hex, verdict_hex) for each frame, from the CPU reference."""
    bloom = BloomFilter()
    for ip in C2:
        bloom.add(ip)
    clf = Classifier(bloom)
    rows = []
    for i, (label, h) in enumerate(build_stream()):
        v = clf.classify(bytes.fromhex(h), seq=(i & 0xFF) + 1, frame_count=i)
        rows.append((label, i, h, v.hex()))
    return rows


if __name__ == "__main__":
    print(f"{'label':9} {'idx':>3}  {'header':40}  verdict")
    for label, i, h, v in expected_rows():
        print(f"{label:9} {i:3}  {h}  {v}")
