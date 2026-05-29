"""Generate telemetry golden vectors from the CPU twins, for the self-checking
testbenches (tb_cms / tb_hll / tb_telemetry) and TELEMETRY_VECTORS.md.

Run `python3 gen_telemetry_golden.py` to print Verilog-pasteable expected values for a
fixed deterministic stream (RFC5737 doc + RFC1918 example IPs). The tbs replay the same
STREAM and assert these outputs; keep the tb literals in sync with this output.
"""
from cms import CountMin
from hll import HyperLogLog
from telemetry_model import Telemetry

# Deterministic stream: a clear heavy hitter (CB007105 x9), a runner-up, singletons.
STREAM = ([0xCB007105] * 9 + [0xC0000201] * 3
          + [0x0A000001, 0x0A000002, 0x0A000003] + [0xC0000263] * 5)

CMS_QUERIES = [0xCB007105, 0xC0000201, 0xC0000263, 0x0A000001, 0x08080808]


def cms_golden(stream=STREAM, queries=CMS_QUERIES):
    cm = CountMin()
    for ip in stream:
        cm.update(ip)
    return [(ip, cm.point_query(ip)) for ip in queries]


def hll_golden(stream=STREAM):
    h = HyperLogLog()
    for ip in stream:
        h.update(ip)
    return h.harmonic_sum, h.zeros


def telemetry_snapshot(stream=STREAM):
    t = Telemetry()
    for ip in stream:
        t.update(ip)
    t.window_tick()
    return t.snapshot


def _vh(x, bits):
    return f"{bits}'h{x:0{(bits + 3) // 4}X}"


if __name__ == "__main__":
    print(f"// STREAM ({len(STREAM)} src IPs):")
    print("  // " + ", ".join(f"{ip:08X}" for ip in STREAM))
    print("\n// tb_cms expected point-queries (ip -> count):")
    for ip, c in cms_golden():
        print(f"  {ip:08X} -> {c}   ({_vh(c, 14)})")
    hsum, zeros = hll_golden()
    print(f"\n// tb_hll after stream: harmonic_sum={_vh(hsum, 48)}  zeros={zeros} ({_vh(zeros, 12)})")
    snap = telemetry_snapshot()
    print("\n// tb_telemetry snapshot after one window_tick:")
    for k, v in snap.items():
        print(f"  {k:14} = {v}  ({_vh(v, 48 if k == 'harmonic_sum' else 32)})")
