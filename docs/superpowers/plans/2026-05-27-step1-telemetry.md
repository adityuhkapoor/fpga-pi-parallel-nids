# v2 Step 1 — Hardware Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hardware Count-Min (packets/source-IP heavy hitters) + HyperLogLog (distinct source IPs) telemetry over a 1 s window to the NIDS, read out by the Pi through a new command sublayer, with bit-exact Python twins + golden vectors + self-checking testbenches.

**Architecture:** Two new sketch modules (`cms.v`, `hll.v`) each with a bit-exact Python twin (`cms.py`, `hll.py`), wrapped by `telemetry.v` (window timer → `window_tick`, snapshot, top-1 max-tracker). Telemetry runs in parallel with the untouched v1.1 classifier path off the same `header_parser` stream. The Pi reads it via a frame-opcode command sublayer (byte 16). Per-window reset is a lazy 4-bit epoch per cell (modelable, BRAM-free); the window boundary is an explicit `window_tick` so the cycle-timer (trivial) and the sketch logic (modelable) are decoupled.

**Tech Stack:** Verilog-2001 (Vivado xsim + synth, xc7a35t, 100 MHz), Python 3 (pytest, pure-stdlib twins), autonomous build/sim/flash over SSH, live Pi tests at 8 MHz / 32 B.

**Conventions:** lowercase imperative commits, no prefix/attribution; RFC5737 IPs only; public-repo clean. TDD per module: failing test → golden model → golden vectors → self-checking tb → HDL → green. Full pytest + Vivado sim stay green; WNS stays positive after each HDL module.

---

## Locked design constants (single source of truth for both twin and HDL)

```
# Count-Min: 5 independent multiply-shift hashes of src_ip -> column in [0,4096)
CMS_A    = [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1]  # odd 32b mixers
CMS_COLS = 4096            # w; column = ((src*A_j) & 0xFFFFFFFF) >> 20   (top 12 bits)
CMS_ROWS = 5               # d banks, independent
CMS_CW   = 14              # saturating counter bits (max 0x3FFF); cell = {epoch:4, count:14} = 18b
# point-query(ip) = min over j of bank[j][column_j(ip)] (stale-epoch cells read 0)

# HyperLogLog: 1 hash of src_ip
HLL_A    = 0x2545F4914F6CDD1D & 0xFFFFFFFF   # = 0x4F6CDD1D (odd 32b mixer, distinct from CMS)
HLL_M    = 2048            # registers, = 2^11
HLL_IDXB = 11              # bucket = (h*A>>0)... see hll.py; bucket = top 11 bits of 32b product
HLL_RANKBITS = 21          # remaining bits; rank = leading-zero-count(remaining)+1, clamp [1,22]
HLL_REGW = 5               # rank fits 5b (<=22<31); register cell = {epoch:4, rank:5} = 9b
# harmonic sum stored SCALED as integer S = sum_j 2^(32 - rank_j), rank 0 -> 2^32.
#   all-zero state: S0 = HLL_M * 2^32 = 2^43.  Pi computes card = alpha*m^2 * 2^32 / S.
HLL_ALPHA_2048 = 0.7213 / (1 + 1.079 / 2048)   # ~0.72092, applied on the Pi

# Window: explicit window_tick boundary. On silicon a cycle timer pulses it.
WINDOW_CYCLES = 100_000_000   # 1 s @100 MHz (parameter; tb overrides to a tiny value)
# epoch = window_index & 0xF (4 bits); lazy reset: cell.epoch != current -> value 0, then write current.
```

## File structure

| File | Responsibility | New/Mod |
|---|---|---|
| `cms.py` | bit-exact Count-Min twin (update, point_query, lazy-epoch reset) | create |
| `hll.py` | bit-exact HLL twin (update, harmonic_sum, lazy-epoch reset) | create |
| `telemetry_model.py` | window/snapshot/top-1 twin wrapping cms.py+hll.py | create |
| `gen_telemetry_golden.py` | deterministic stream → golden vectors (CMS queries, HLL sum, snapshots) | create |
| `test_cms.py`, `test_hll.py`, `test_telemetry_model.py` | pytest for the twins | create |
| `fpga/src/cms.v` | 5-bank Count-Min, lazy-epoch, point-query | create |
| `fpga/src/hll.v` | 2048-reg HLL, incremental scaled harmonic sum, lazy-epoch | create |
| `fpga/src/telemetry.v` | window timer→tick, snapshot regs, top-1, wraps cms+hll | create |
| `fpga/sim/tb_cms.v`, `tb_hll.v`, `tb_telemetry.v` | self-checking tbs vs golden | create |
| `fpga/src/nids_top.v` | instantiate telemetry ‖ classifiers; route opcode frames | modify |
| `fpga/src/cmd_router.v` | decode byte-16 opcode → telemetry query / response frame mux | create |
| `telemetry.py` | Pi-side: decode snapshot/query responses, compute HLL cardinality | create |
| `test_telemetry.py` | pytest for the Pi-side decode + cardinality math | create |
| `read_telemetry.py` | Pi script: poll snapshot, point-query, print top talker + distinct est | create |
| `PROTOCOL.md`, `TELEMETRY_VECTORS.md` | opcode/response contract + Tier-1 format vectors | modify/create |
| `fpga/sim/run_sim.tcl`, `fpga/build.tcl` | add new src + tbs | modify |

---

## Task 1: Count-Min twin (`cms.py`)

**Files:** Create `cms.py`, `test_cms.py`.

- [ ] **Step 1: Write failing tests** (`test_cms.py`):
```python
from cms import CountMin, CMS_A, CMS_COLS

def test_column_is_top_12_bits_of_multiply():
    cm = CountMin()
    assert cm.column(0xC0000201, 0) == ((0xC0000201 * CMS_A[0]) & 0xFFFFFFFF) >> 20
    assert all(0 <= cm.column(0xC0000201, j) < CMS_COLS for j in range(5))

def test_single_source_counts_then_point_query():
    cm = CountMin()
    for _ in range(7):
        cm.update(0xCB007105)
    assert cm.point_query(0xCB007105) == 7      # no collision -> exact

def test_counter_saturates_at_14_bits():
    cm = CountMin()
    for _ in range(20000):                      # > 2^14-1
        cm.update(0xC0000263)
    assert cm.point_query(0xC0000263) == 0x3FFF

def test_unseen_key_estimates_zero_or_low():
    cm = CountMin()
    cm.update(0xC0000201)
    assert cm.point_query(0xCB007105) in (0, 1) # min over banks; tiny collision risk

def test_window_tick_resets_via_epoch():
    cm = CountMin()
    cm.update(0xCB007105); cm.update(0xCB007105)
    cm.window_tick()                            # epoch advances -> stale
    assert cm.point_query(0xCB007105) == 0
    cm.update(0xCB007105)
    assert cm.point_query(0xCB007105) == 1
```

- [ ] **Step 2: Run, verify fail** — `python3 -m pytest test_cms.py -v` → `ModuleNotFoundError: cms`.

- [ ] **Step 3: Implement `cms.py`**:
```python
"""Bit-exact CPU twin of cms.v (5-bank Count-Min on src_ip). No spidev/scapy."""
MASK32 = 0xFFFFFFFF
CMS_A = [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1]
CMS_COLS, CMS_ROWS, CMS_CW = 4096, 5, 14
CMS_MAX = (1 << CMS_CW) - 1

class CountMin:
    def __init__(self):
        self.epoch = 0
        self.cell = [[(0, 0) for _ in range(CMS_COLS)] for _ in range(CMS_ROWS)]  # (epoch, count)

    def column(self, ip, j):
        return ((ip * CMS_A[j]) & MASK32) >> 20

    def _count(self, j, c):
        e, v = self.cell[j][c]
        return v if e == self.epoch else 0      # lazy-epoch reset

    def update(self, ip):
        for j in range(CMS_ROWS):
            c = self.column(ip, j)
            v = self._count(j, c)
            self.cell[j][c] = (self.epoch, min(v + 1, CMS_MAX))

    def point_query(self, ip):
        return min(self._count(j, self.column(ip, j)) for j in range(CMS_ROWS))

    def window_tick(self):
        self.epoch = (self.epoch + 1) & 0xF
```

- [ ] **Step 4: Run, verify pass** — `python3 -m pytest test_cms.py -v` → all pass.
- [ ] **Step 5: Commit** — `add count-min cpu twin (cms.py)`.

## Task 2: `cms.v` + `tb_cms.v` (TDD vs Task-1 golden)

**Files:** Create `fpga/src/cms.v`, `fpga/sim/tb_cms.v`; modify `fpga/sim/run_sim.tcl`.

Interface:
```verilog
module cms #(parameter COLS=4096, CW=14) (
  input clk, rst,
  input [31:0] src_ip, input upd_valid,      // pulse to +1 this src across 5 banks
  input win_tick,                            // advance epoch (lazy reset)
  input [31:0] q_ip, input q_valid,          // point-query request
  output reg [CW-1:0] q_count, output reg q_done
);
```
Implementation notes: 5 parallel banks, each a `(* ram_style="block" *) reg [17:0] mem [0:4095]` holding `{epoch[3:0],count[13:0]}`. Register the 5 multiply hashes in a phase-0 stage (isolate DSP, as `scan_rate.v` does) → meet 100 MHz. Update = read-modify-write per bank; lazy reset compares stored epoch to a 4-bit `cur_epoch` register advanced on `win_tick`. Point-query reads 5 banks, outputs min. Multi-cycle FSM per op (frame period ≫ cycles, no self-collision — same reasoning as scan_rate).

- [ ] **Step 1:** Write `tb_cms.v` that drives the SAME stream as a small golden table emitted by `gen_telemetry_golden.py --module cms` (RFC5737 srcs incl. a saturating one and a post-tick reset), asserts `q_count` matches; PASS/FAIL print like existing tbs.
- [ ] **Step 2:** Add `cms.v` + `tb_cms.v` to `run_sim.tcl`; run sim → expect FAIL (no cms.v).
- [ ] **Step 3:** Implement `cms.v` per the interface/notes.
- [ ] **Step 4:** Run Vivado sim → `PASS: tb_cms ...`; full suite still green.
- [ ] **Step 5:** Commit — `add count-min sketch stage + self-checking tb`.

## Task 3: HyperLogLog twin (`hll.py`)

**Files:** Create `hll.py`, `test_hll.py`.

- [ ] **Step 1: Write failing tests** (`test_hll.py`):
```python
from hll import HyperLogLog, HLL_M

def test_empty_harmonic_sum_is_m_times_2pow32():
    assert HyperLogLog().harmonic_sum == HLL_M * (1 << 32)

def test_distinct_count_estimate_in_tolerance():
    h = HyperLogLog()
    for i in range(1000):
        h.update(0x0A000000 + i)               # 1000 distinct srcs
    est = h.estimate()
    assert abs(est - 1000) / 1000 < 0.10        # within ~10% (2.3% std err, loose bound)

def test_repeated_source_does_not_inflate():
    h = HyperLogLog()
    for _ in range(500):
        h.update(0xCB007105)
    assert h.estimate() < 5                      # ~1 distinct

def test_window_tick_resets():
    h = HyperLogLog()
    for i in range(100):
        h.update(0x0A000000 + i)
    h.window_tick()
    assert h.harmonic_sum == HLL_M * (1 << 32)   # back to empty
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `hll.py`**:
```python
"""Bit-exact CPU twin of hll.v (distinct source IPs). Harmonic sum stored scaled."""
MASK32 = 0xFFFFFFFF
HLL_A = 0x4F6CDD1D
HLL_M, HLL_IDXB, HLL_RANKBITS = 2048, 11, 21
HLL_ALPHA = 0.7213 / (1 + 1.079 / HLL_M)

def _rank(w):                                    # leftmost-1 position in HLL_RANKBITS bits, 1-based
    if w == 0:
        return HLL_RANKBITS + 1
    r = 1
    msb = 1 << (HLL_RANKBITS - 1)
    while not (w & msb):
        r += 1; w <<= 1
    return r

class HyperLogLog:
    def __init__(self):
        self.epoch = 0
        self.reg = [(0, 0)] * HLL_M              # (epoch, rank)
        self.harmonic_sum = HLL_M * (1 << 32)    # all ranks 0 -> sum 2^32 each

    def _rankval(self, b):
        e, r = self.reg[b]
        return r if e == self.epoch else 0

    def update(self, ip):
        h = (ip * HLL_A) & MASK32
        b = h >> (32 - HLL_IDXB)
        w = h & ((1 << HLL_RANKBITS) - 1)
        new = _rank(w)
        old = self._rankval(b)
        if new > old:
            self.harmonic_sum += (1 << (32 - new)) - (1 << (32 - old))
            self.reg[b] = (self.epoch, new)

    def estimate(self):
        return HLL_ALPHA * HLL_M * HLL_M * (1 << 32) / self.harmonic_sum

    def window_tick(self):
        self.epoch = (self.epoch + 1) & 0xF
        self.harmonic_sum = HLL_M * (1 << 32)
```

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `add hyperloglog cpu twin (hll.py)`.

## Task 4: `hll.v` + `tb_hll.v`

**Files:** Create `fpga/src/hll.v`, `fpga/sim/tb_hll.v`; modify `run_sim.tcl`.

Interface: like `cms` but one bank; outputs `harmonic_sum[47:0]` (scaled, the FPGA maintains it incrementally) on query. Register layout `{epoch[3:0], rank[4:0]}`. `win_tick` resets `harmonic_sum` to `HLL_M<<32` and advances epoch. Rank = leading-zero count of the 21-bit remainder (priority encoder).

- [ ] **Step 1:** `tb_hll.v` vs `gen_telemetry_golden.py --module hll` (assert `harmonic_sum` after a known distinct-source stream + a post-tick reset; the estimate is checked Pi-side).
- [ ] **Step 2:** add to `run_sim.tcl`; sim → FAIL.
- [ ] **Step 3:** implement `hll.v`.
- [ ] **Step 4:** sim → `PASS: tb_hll`; suite green.
- [ ] **Step 5:** Commit — `add hyperloglog stage + self-checking tb`.

## Task 5: telemetry twin + golden generator

**Files:** Create `telemetry_model.py`, `gen_telemetry_golden.py`, `test_telemetry_model.py`.

`telemetry_model.py` wraps `CountMin`+`HyperLogLog`, tracks `top1=(count,key)` updated on each `update(ip)` (query the cms count after update; latch if larger), and on `window_tick` latches a snapshot `{window_index, total_packets, harmonic_sum, top1_count, top1_key}` then resets counters/top1. `gen_telemetry_golden.py` emits per-module golden tables (consumed by the tbs) and a full-stream snapshot table for `TELEMETRY_VECTORS.md`.

- [ ] **Step 1:** failing tests: top-1 tracks the heaviest src; snapshot latches the completed window then resets; total_packets counts updates.
- [ ] **Step 2:** run → fail. **Step 3:** implement. **Step 4:** pass.
- [ ] **Step 5:** Commit — `add telemetry window/snapshot/top-1 twin + golden generator`.

## Task 6: `telemetry.v` + `tb_telemetry.v`

**Files:** Create `fpga/src/telemetry.v`, `fpga/sim/tb_telemetry.v`; modify `run_sim.tcl`.

`telemetry.v`: instantiate `cms` + `hll`; a `WINDOW_CYCLES` down-counter pulses `win_tick` (tb sets `WINDOW_CYCLES` tiny, e.g. 200); snapshot register block latched on `win_tick`; top-1 max-tracker (compare cms `q_count` of the just-updated src). Expose query ports for the command router.

- [ ] **Step 1:** `tb_telemetry.v` drives a stream with a tiny window, asserts snapshot fields + top-1 vs golden. **Step 2:** sim FAIL. **Step 3:** implement. **Step 4:** sim PASS; suite green.
- [ ] **Step 5: Confirm WNS** — build (Task 8 harness) or `report_timing_summary` after synth; WNS must stay > 0 (5 CMS hashes are the risk; pipeline them). Commit — `add telemetry wrapper (window timer + snapshot + top-1)`.

## Task 7: command sublayer + nids_top integration

**Files:** Create `fpga/src/cmd_router.v`, `telemetry.py`, `test_telemetry.py`, `TELEMETRY_VECTORS.md`; modify `fpga/src/nids_top.v`, `PROTOCOL.md`, `fpga/sim/tb_nids_top.v`, `run_sim.tcl`, `build.tcl`.

Opcode = request byte 16. `0x00`→classify (unchanged verdict path). `0x01`→CMS point-query (src_ip bytes 0-3) → response `{0x5A, key:32, count:14}`. `0x02`→snapshot → response block. `0x03`→HLL harmonic sum → `{0x5A, harmonic_sum:48, m:16}`. Responses use magic `0x5A` (≠ verdict `0xA5`), one-frame lag (reuse the verdict_reg/tx_frame path). `cmd_router.v` selects verdict vs telemetry response into `tx_frame`.

- [ ] **Step 1:** `test_telemetry.py` (Pi-side): `telemetry.py` decodes each response type from `TELEMETRY_VECTORS.md` hex and computes cardinality = `HLL_ALPHA*m*m*2^32/sum`; assert against golden. **Step 2:** fail. **Step 3:** implement `telemetry.py` + vectors. **Step 4:** pass.
- [ ] **Step 5:** implement `cmd_router.v`, wire telemetry ‖ classifiers in `nids_top.v` (telemetry fed from `header_parser`, updated on opcode `0x00` frames; queries on `0x01-0x03`). Extend `tb_nids_top.v`: send a classify frame, then `0x01/0x02/0x03` query frames, assert responses (re-anchored `FRAME_BITS` slices). Update `PROTOCOL.md`. Add files to `run_sim.tcl`/`build.tcl`.
- [ ] **Step 6:** full pytest + Vivado sim green. Commit — `add telemetry command sublayer + nids_top integration`.

## Task 8: build + timing + silicon validation

**Files:** none (validation); refresh `docs/reports/*`.

- [ ] **Step 1:** build `nids_top` over SSH; confirm `BITSTREAM_OK` and **WNS > 0** (refresh `docs/reports/`).
- [ ] **Step 2:** flash; scp the new Pi modules (`cms.py hll.py telemetry.py` + the v1 set) to the Pi.
- [ ] **Step 3:** regression — re-run `spi_verdict_check.py` → **120/120** (telemetry must not disturb the verdict path).
- [ ] **Step 4:** telemetry round-trip — a Pi check sends a known classify stream, then `0x01/0x02/0x03` queries, asserts CMS counts / snapshot / cardinality vs the CPU twin. Commit — `silicon: telemetry round-trip + v1.1 regression`.

## Task 9: Pi readout + live demo

**Files:** Create `read_telemetry.py`.

- [ ] **Step 1:** `read_telemetry.py` polls `0x02` each second → prints `window N: distinct≈C, total P, top talker X (count C)`; `--query IP` does a `0x01` point-query. **Step 2:** run on the Pi against live `packet_capture --spi` traffic; drive flood/scan from the Pi Zero and watch distinct-source + top-1 move. Commit — `add Pi telemetry readout + live demo`.

---

## Self-Review

- **Spec coverage:** CMS packets/src → Tasks 1-2; HLL distinct-src → Tasks 3-4; window/snapshot/top-1 → Tasks 5-6; command sublayer/opcodes/response-magic → Task 7; TDD twins+vectors+tbs → every module; resource/WNS → Tasks 6/8; Pi cardinality finish + readout → Tasks 7/9; v1.1 regression → Task 8. ✔
- **Placeholder scan:** constants/layouts/interfaces pinned in the Locked-constants block; golden models given in full; HDL specified by interface + notes + golden-vector contract (the twin is the behavioral spec). No TBD. ✔
- **Type consistency:** `window_tick`/`win_tick`, `harmonic_sum`, `point_query`/`q_count`, `CMS_A`/`HLL_A`, snapshot field names consistent across twin↔HDL↔Pi. ✔

## Unresolved / watch
- 100 MHz WNS with 5 parallel CMS multiply-shift hashes — pipeline the hashes (scan_rate precedent); if tight, move some hashes to LUTs (sizing note) or serialize bank reads (ample per-packet cycle budget at 8 MHz).
- HLL `harmonic_sum` width 48b (max 2^43) — confirm no overflow; Pi does the float divide.
- Window via explicit `win_tick` keeps the twin bit-exact; the cycle-timer itself gets a tiny standalone check in `tb_telemetry`.
