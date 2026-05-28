#!/usr/bin/env python3
"""
Derive each memory's dimensions from the use case + the governing theory, then cost
it in real Artix-7 BRAM/DSP primitives. Nothing here is a round-number guess: every
depth/width falls out of a stated workload or accuracy target. Change the inputs at
the top, rerun, and the whole budget re-derives.

USE CASE (change these -- everything else recomputes):
  - Pi sniffs a small/home-scale network (<= a few hundred local hosts).
  - Link: 30 MHz SPI, compact ~32-byte header frames. This is a TARGET to validate in
    build step 0 (v1 ran 1 MHz "conservative for jumper wiring"; 30 MHz over Pmod
    jumpers must be proven on hardware) -- not a measured given.
  - Telemetry window: 1 second.
  - It flags, doesn't block -> a ~0.1% Bloom false-positive rate is tolerable.
"""
import math

# ---------- chip limits (xc7a35t) ----------
TOTAL_RAMB36, TOTAL_DSP = 50, 90
RAMB36_CFG = [(512, 72), (1024, 36), (2048, 18), (4096, 9), (8192, 4), (16384, 2), (32768, 1)]
RAMB18_CFG = [(512, 36), (1024, 18), (2048, 9), (4096, 4), (8192, 2), (16384, 1)]
# A 32-bit multiply-shift hash costs ~3 DSP48E1 (empirical: v1 used 14 DSP for 5 such
# hashes -> ~2.8 each; a 32x32 multiply doesn't fit one DSP). Hashes could move to LUTs
# if DSP gets tight, but DSP is not the binding resource here.
DSP_PER_HASH = 3


def _prim(w, d, cfg):
    return min(math.ceil(w / wp) * math.ceil(d / dp) for dp, wp in cfg)


def bram(w, d):
    """Min RAMB36-equivalents to hold a d-deep x w-wide memory (RAMB18 counts as 0.5)."""
    return min(_prim(w, d, RAMB36_CFG), _prim(w, d, RAMB18_CFG) * 0.5)


def p2(x):
    return 1 << math.ceil(math.log2(x))   # round up to a power of two


# ---------- workload bounds (derived, not assumed) ----------
SPI_HZ, FRAME_BYTES = 8e6, 32     # 8 MHz: measured zero-error ceiling is 9 MHz (SI-limited over Pmod jumpers); run derated
pps_theory = SPI_HZ / (FRAME_BYTES * 8)
PPS = pps_theory * 0.45                 # ~55% spidev/userland overhead (typical; validate in step 0)
WINDOW_S = 1.0
N_win = PPS * WINDOW_S
cw = math.ceil(math.log2(N_win))        # counter bits so a window can't overflow

# ---------- structure parameters (each derived from theory) ----------
# Count-Min: d independent rows. Row j is read at column h_j(x); the columns DIFFER per
# row, so the rows cannot share one word/address -- each row is its own bank + own hash.
eps, delta = 0.001, 0.01
w_cms = p2(math.e / eps)
d_cms = math.ceil(math.log(1 / delta))

# HyperLogLog
hll_err = 0.03
m_hll = p2((1.04 / hll_err) ** 2)
hll_reg = math.ceil(math.log2(32 - int(math.log2(m_hll)) + 1))

# Bloom: k hashes, but derived from 2 base hashes via Kirsch-Mitzenmacher
# (h_i = h1 + i*h2) -> only 2 multipliers regardless of k.
n_bl, p_bl = 16384, 0.001
m_bl = p2(-n_bl * math.log(p_bl) / (math.log(2) ** 2))
k_bl = round((m_bl / n_bl) * math.log(2))
p_eff = (1 - math.exp(-k_bl * n_bl / m_bl)) ** k_bl

# Flow/connection table
flow_depth = 4096
fields = {"epoch": 8, "pkt_count": cw, "byte_count": 24, "syn_count": 12,
          "dport_fp": 16, "dhost_fp": 16, "flags": 8}
flow_w = sum(fields.values())

# Runtime-loadable rule store
rule_depth, rule_w = 512, 72

# (name, per-bank depth, per-bank width, n_banks, n_hashes, rationale)
STRUCTS = [
    ("Count-Min (heavy hitters)", w_cms, cw, d_cms, d_cms,
     f"{d_cms} independent rows/banks x {w_cms} cols x {cw}b; eps={eps}, delta={delta}"),
    ("HyperLogLog (distinct hosts)", m_hll, hll_reg, 1, 1,
     f"m={m_hll} regs x {hll_reg}b -> actual err {1.04 / math.sqrt(m_hll) * 100:.1f}%"),
    ("Bloom blocklist", m_bl, 1, 1, 2,
     f"{n_bl} IPs @ real p={p_eff * 100:.3f}%, m={m_bl}b, k={k_bl} via 2 base hashes (Kirsch-Mitzenmacher)"),
    ("Flow/connection table", flow_depth, flow_w, 1, 1,
     f"{flow_depth} flows x {flow_w}b ({'+'.join(f'{k}:{v}' for k, v in fields.items())})"),
    ("Runtime rule store", rule_depth, rule_w, 1, 0,
     f"{rule_depth} rules x {rule_w}b (Pi hot-loads; no rebuild)"),
]

# ---------- report ----------
print("== workload bounds ==")
print(f"link {SPI_HZ/1e6:.0f}MHz, {FRAME_BYTES}B frames -> {pps_theory:,.0f} pps theory, "
      f"~{PPS:,.0f} pps after overhead")
print(f"1s window -> {N_win:,.0f} packets -> counters need {cw} bits "
      f"(~{100e6/PPS:,.0f} clk cycles/packet @100MHz, so multi-cycle/packet is fine)\n")

print(f"{'Memory':<30}{'depth':>8}{'width':>7}{'banks':>6}{'BRAM':>7}{'DSP':>5}")
print("-" * 70)
tb = td = 0.0
for name, depth, width, banks, nh, why in STRUCTS:
    blk = banks * bram(width, depth)
    dsp = nh * DSP_PER_HASH
    tb += blk
    td += dsp
    print(f"{name:<30}{depth:>8}{width:>7}{banks:>6}{blk:>7.1f}{dsp:>5}")
    print(f"    -> {why}")
print("-" * 70)
print(f"{'TOTAL':<30}{'':>8}{'':>7}{'':>6}{tb:>7.1f}{int(td):>5}")
print(f"\nBRAM {tb:.1f}/{TOTAL_RAMB36} blocks ({100*tb/TOTAL_RAMB36:.0f}%), {TOTAL_RAMB36-tb:.1f} free"
      f"  |  DSP {int(td)}/{TOTAL_DSP} ({100*td/TOTAL_DSP:.0f}%) at {DSP_PER_HASH} DSP/hash")
print("BRAM is the binding resource; timing closure is the real risk (not capacity).")
