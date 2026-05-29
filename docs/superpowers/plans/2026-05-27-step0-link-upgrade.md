# v2 Step 0 — SPI Link Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise the Pi↔FPGA SPI link from the v1 1 MHz / 20-byte frame to the highest clock the hardware actually sustains with zero bit errors, widen the frame to the v2 32-byte geometry, and re-measure end-to-end throughput — without regressing the v1.1 silicon behavior.

**Architecture:** The clock ceiling is the real unknown and is *orthogonal* to frame width, so we prove it first on the existing oversampling slave using a pure frame-echo bitstream as a bit-error-rate (BER) instrument, ramping 1→30 MHz on real silicon. Only if the measured zero-error ceiling falls below target do we escalate to an MMCM 200 MHz sampler with a CDC handshake (not the full source-synchronous rewrite — jumper signal integrity likely caps us first). We then re-lock `sizing.py`/`SPEC_v2.md` around the *measured* clock, perform the mechanical 20→32B widening (verified by Vivado sim + pytest regression), and re-measure throughput.

**Tech Stack:** Verilog-2001 (Vivado xsim + synth, xc7a35t), Python 3 (pytest, spidev), autonomous build/sim/flash over the existing SSH pipeline (`build.tcl`/`run_sim.tcl`/`program.tcl`), live silicon tests on the Pi.

**Conventions (override the skill's defaults):** Commit messages are short lowercase imperative summaries — NO `feat:`/`fix:` prefixes, NO Claude attribution, NO Co-Authored-By. SHOW the proposed message and get explicit OK before every `git commit`. NEVER `git push` without explicit instruction. Public-repo hygiene: zero infra detail (no hostnames/SSH/paths/real IPs) in any committed file; RFC5737 doc IPs only.

---

## High-Level Requirements

1. **Prove the link clock empirically.** Find the highest SPI clock the Pi↔Basys-3 jumper link sustains with **zero bit errors** over a statistically meaningful frame count, by ramping on real silicon. Do not assume 30 MHz.
2. **Re-lock the spec around the measured rate.** Update `docs/sizing.py` `SPI_HZ` and `SPEC_v2.md` to the sustained clock (run at ~75% of the BER cliff for margin). Confirm telemetry counters stay 16-bit (true for any sustained pps < 65,536, i.e. any clock ≤ ~37 MHz at 32-byte frames).
3. **Widen the frame to 32 bytes.** Bytes 0–15 keep the exact v1 header layout; bytes 16–31 are reserved/zero (concrete telemetry fields defined in later steps). Ripple through HDL, Python, golden vectors, and docs.
4. **Re-measure throughput.** Show system-throughput scaling from v1 (1 MHz/20B) to v2 (locked clock/32B), both via a transport-cost model in `benchmark.py` and a live sustained-rate measurement on silicon.
5. **No v1 regression.** Full pytest suite AND the Vivado sim suite stay green; the 120-frame golden silicon round-trip (`spi_verdict_check.py`) still passes at the new clock and frame width; 100 MHz WNS stays positive.

## Architecture Decisions

- **BER instrument = pure frame-echo bitstream**, not the verdict path. The verdict path maps input→verdict non-bijectively, so a flipped link bit can still yield a plausible verdict — a weak probe. A frame echo (`tx_frame = last rx_frame`) requires every input bit to round-trip, making it maximally sensitive to link errors. New `fpga/src/echo_top.v`.
- **Sim proves logic; silicon proves the rate.** xsim does not model metastability/jitter/signal integrity, so it *cannot* establish the real clock ceiling — only the silicon ramp can. The Vivado testbench's job is to prove functional correctness of the (possibly MMCM-redesigned) RTL and any CDC handshake; the BER ramp script proves the achievable rate.
- **Contingent MMCM, not a rewrite.** The current slave 2-FF-oversamples SCLK at the 100 MHz fabric clock (~3.3 samples/period at 30 MHz — below the ~4–8× a 2-FF edge-detect needs). Predicted ceiling ~15–20 MHz. If that's below target, add an MMCM 200 MHz sampler (~6.7× oversample at 30 MHz) and a valid-pulse CDC of the assembled frame into the 100 MHz domain (frames are ≥8.5 µs apart vs an 8-cycle/80 ns classifier — enormous CDC margin). Full source-synchronous rewrite is explicitly out of scope.
- **Clock raise and frame widening are sequenced, not merged.** Clock first (Tasks 1–4) on the unchanged 20B echo path to isolate link physics; widening second (Task 5) as a sim-verifiable mechanical change; throughput + regression last (Tasks 6–7).

## Data Models

**v2 32-byte request frame (Pi→FPGA, MOSI), big-endian:** bytes 0–15 identical to v1 (`src_ip` 0–3, `dst_ip` 4–7, `src_port` 8–9, `dst_port` 10–11, `proto` 12, `tcp_flags` 13, `pkt_size` 14–15), **bytes 16–31 reserved (zero)**. v1 had bytes 16–19 reserved; v2 extends the reserved tail by 12 bytes — the parsed field set is unchanged.

**v2 32-byte verdict frame (FPGA→Pi, MISO):** bytes 0–5 identical to v1 (`magic`, `stage-hit mask`, `severity`, `flags`, `seq`, then byte 5 reserved start), **bytes 5–31 reserved (zero)** — `verdict_encoder`'s `RSVD = (FRAME_BYTES-5)*8` already scales; only the frame width parameter changes.

**HDL field slicing (the one non-mechanical HDL change):** `header_parser.v` currently hardcodes `frame[159:128]` etc., anchored to a 160-bit frame. These must be re-anchored to `FRAME_BITS-1` so they're width-agnostic (byte 0 = `frame[FRAME_BITS-1 -: 8]`). `spi_slave_rx.v` and `verdict_encoder.v` are already parametric (`byte_cnt[4:0]` holds 0..31 exactly at 32 bytes — verified).

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `fpga/src/echo_top.v` | **new** — pure SPI frame-echo top, BER instrument | create |
| `fpga/build_echo.tcl` | **new** — build echo_top bitstream | create |
| `fpga/constraints/echo.xdc` | **new** — pins for echo_top (clk/btnC/spi only, no LEDs needed) | create |
| `spi_ber_ramp.py` | **new** — sweep clock, count byte/frame errors vs delay-1 echo, report BER + ceiling | create |
| `ber.py` | **new** — pure BER-counting logic (no spidev), unit-tested off-Pi | create |
| `test_ber.py` | **new** — unit tests for `ber.py` | create |
| `fpga/sim/tb_spi_slave_rx.v` | parametrize SCLK half-period; add fast-SCLK case | modify |
| `docs/sizing.py` | re-lock `SPI_HZ` to measured clock | modify |
| `docs/SPEC_v2.md` | re-lock workload bounds table | modify |
| `fpga/src/nids_top.v` | `FRAME_BYTES` 20→32 | modify |
| `fpga/src/header_parser.v` | re-anchor field slices to `FRAME_BITS` | modify |
| `fpga/sim/tb_header_parser.v`, `tb_nids_top.v`, `tb_spi_slave_rx.v`, `tb_verdict_golden.v` | widen frame constants 160→256 bit | modify |
| `spi_link.py` | `FRAME_LEN` 20→32 | modify |
| `verdict.py` | `VERDICT_LEN` 20→32, padding | modify |
| `scenarios.py`, `benchmark.py`, `packet_capture.py`, `gen_verdict_golden.py` | frame builders widen to 32B | modify |
| `PROTOCOL.md`, `VERDICT_GOLDEN.md`, `VERDICT_VECTORS.md` | 32B layout + regenerated vectors | modify |
| `benchmark.py` | add link-transport throughput model | modify |
| `docs/reports/*.rpt` | refreshed timing/utilization | modify |

---

## Task 0: Establish baseline green + worktree

**Files:** none modified — verification only.

- [ ] **Step 1: Create/confirm an isolated worktree** (via superpowers:using-git-worktrees) off `main`.

- [ ] **Step 2: Run the Python suite, confirm green baseline**

Run: `python3 -m pytest -q`
Expected: all pass (this is the regression anchor; record the pass count).

- [ ] **Step 3: Run the Vivado sim suite over SSH, confirm green baseline**

Run: `vivado -mode batch -source fpga/sim/run_sim.tcl` (via the autonomous Vivado-over-SSH pipeline; `caffeinate` the Mac for the duration).
Expected: every `run_tb` prints PASS; the TCL errors if any doesn't.

- [ ] **Step 4: No commit** — baseline only.

---

## Task 1: Parameterize the Pi-side SPI clock

**Files:**
- Modify: `spi_link.py` (constructor already takes `speed_hz`; keep 1 MHz default, no code change needed unless a CLI hook is missing)

- [ ] **Step 1: Confirm `SpiLink(speed_hz=...)` already supports arbitrary clocks**

`spi_link.py:12` already has `def __init__(self, ..., speed_hz=MAX_SPEED_HZ, ...)`. No change required — the ramp script (Task 2) passes `speed_hz` per step. Default stays 1 MHz so all existing v1 scripts are unaffected.

- [ ] **Step 2: No commit** — confirmation only; the real change is Task 2.

---

## Task 2: BER ramp instrument (echo bitstream + ramp script + unit-tested logic)

**Files:**
- Create: `ber.py`, `test_ber.py`, `spi_ber_ramp.py`, `fpga/src/echo_top.v`, `fpga/constraints/echo.xdc`, `fpga/build_echo.tcl`
- Modify: `fpga/sim/tb_spi_slave_rx.v`

- [ ] **Step 1: Write the failing BER-logic test**

`test_ber.py`:
```python
from ber import ramp_errors

def test_perfect_echo_zero_errors():
    sent = [bytes([i, (i * 7) & 0xFF]) for i in range(10)]
    # delay-1 echo: received[k] == sent[k-1]; received[0] is zeros
    received = [bytes(2)] + sent[:-1]
    r = ramp_errors(sent, received, delay=1)
    assert r.frame_errors == 0
    assert r.bit_errors == 0
    assert r.frames_compared == 9   # first frame has no prior to compare

def test_single_bit_flip_counted():
    sent = [bytes([0x00, 0x00]) for _ in range(3)]
    received = [bytes(2), bytes([0x00, 0x01]), bytes([0x00, 0x00])]  # one bit flipped in echo of frame 0
    r = ramp_errors(sent, received, delay=1)
    assert r.frame_errors == 1
    assert r.bit_errors == 1
```

- [ ] **Step 2: Run it, verify it fails**

Run: `python3 -m pytest test_ber.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ber'`.

- [ ] **Step 3: Implement `ber.py`**

```python
"""BER accounting for the SPI clock ramp. Pure stdlib so it unit-tests off the Pi."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RampResult:
    frames_compared: int
    frame_errors: int
    bit_errors: int

    @property
    def ber(self) -> float:
        bits = self.frames_compared * self._frame_bits
        return self.bit_errors / bits if bits else 0.0

    _frame_bits: int = 0


def ramp_errors(sent, received, delay=1):
    """Compare a delay-N frame echo. received[k] should equal sent[k-delay];
    the first `delay` reads have no prior frame and are skipped."""
    frame_errors = bit_errors = compared = 0
    fbits = len(sent[0]) * 8 if sent else 0
    for k in range(delay, len(sent)):
        exp, got = sent[k - delay], received[k]
        compared += 1
        if got != exp:
            frame_errors += 1
            bit_errors += sum(bin(a ^ b).count("1") for a, b in zip(exp, got))
    return RampResult(compared, frame_errors, bit_errors, _frame_bits=fbits)
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `python3 -m pytest test_ber.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Create `fpga/src/echo_top.v` — pure frame-echo BER instrument**

```verilog
`timescale 1ns/1ps
// BER instrument: spi_slave_rx in pure frame-echo mode (tx_frame = last rx_frame),
// the delay-1 echo spi_ber_ramp.py checks. No classifier — isolates the link only.
module echo_top (
    input  wire        clk,    // 100 MHz
    input  wire        btnC,   // reset
    input  wire        sclk,
    input  wire        cs_n,
    input  wire        mosi,
    output wire        miso,
    output wire [15:0] led
);
    localparam FRAME_BYTES = 20;          // BER ramp runs on the v1 20B frame (link-only test)
    localparam FRAME_BITS  = FRAME_BYTES*8;
    wire rst = btnC;

    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    reg [FRAME_BITS-1:0] echo_reg;
    reg [15:0]           frame_count;
    always @(posedge clk) begin
        if (rst) begin echo_reg <= {FRAME_BITS{1'b0}}; frame_count <= 16'd0; end
        else if (rx_frame_valid) begin echo_reg <= rx_frame; frame_count <= frame_count + 16'd1; end
    end
    assign led = frame_count;

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) u_spi (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(echo_reg), .miso(miso),
        .rx_byte(), .rx_byte_valid(), .byte_index(),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );
endmodule
```

- [ ] **Step 6: Create `fpga/constraints/echo.xdc`** — copy `nids.xdc` verbatim but with `nids_top`→`echo_top` not needed (ports match: clk/btnC/sclk/cs_n/mosi/miso/led). The existing `nids.xdc` already constrains exactly these ports, so `echo.xdc` is a byte-for-byte copy of `nids.xdc`. (Kept separate so the echo build is self-contained.)

```bash
cp fpga/constraints/nids.xdc fpga/constraints/echo.xdc
```

- [ ] **Step 7: Create `fpga/build_echo.tcl`** — clone of `build.tcl` targeting `echo_top`

```tcl
# Build echo_top (BER instrument) to a bitstream.
#   vivado -mode batch -source build_echo.tcl
set origin   [file dirname [file normalize [info script]]]
set proj_dir $origin/build/echo
create_project -force echo $proj_dir -part xc7a35tcpg236-1
add_files -norecurse [list $origin/src/echo_top.v $origin/src/spi_slave_rx.v]
add_files -fileset constrs_1 -norecurse $origin/constraints/echo.xdc
set_property top echo_top [current_fileset]
update_compile_order -fileset sources_1
launch_runs synth_1 -jobs 4
wait_on_run synth_1
if {[get_property PROGRESS [get_runs synth_1]] ne "100%"} { error "synth failed: [get_property STATUS [get_runs synth_1]]" }
launch_runs impl_1 -to_step write_bitstream -jobs 4
wait_on_run impl_1
if {[get_property PROGRESS [get_runs impl_1]] ne "100%"} { error "impl failed: [get_property STATUS [get_runs impl_1]]" }
set bit $proj_dir/echo.runs/impl_1/echo_top.bit
if {![file exists $bit]} { error "no bitstream at $bit" }
puts "BITSTREAM_OK $bit"
```

- [ ] **Step 8: Create `spi_ber_ramp.py`** — sweep clocks on the loaded echo bitstream

```python
#!/usr/bin/env python3
"""Ramp the SPI clock against the echo bitstream (echo_top) and report BER per step.

Load echo_top, wire per PROTOCOL.md, then:  sudo python3 spi_ber_ramp.py
Finds the highest clock with zero bit errors over --frames random frames.
"""
import argparse, os, random, sys
from spi_link import SpiLink, FRAME_LEN
from ber import ramp_errors

DEFAULT_CLOCKS_HZ = [1, 5, 10, 15, 20, 25, 30]   # MHz


def run_one(speed_hz, frames, seed):
    rng = random.Random(seed)
    sent = [bytes(rng.getrandbits(8) for _ in range(FRAME_LEN)) for _ in range(frames)]
    sent.append(bytes(FRAME_LEN))   # flush frame to clock out the last echo
    link = SpiLink(speed_hz=speed_hz)
    received = [link.send_frame(f) for f in sent]
    link.close()
    return ramp_errors(sent[:-1], received[:-1], delay=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--frames", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--clocks-mhz", type=int, nargs="+", default=DEFAULT_CLOCKS_HZ)
    args = ap.parse_args()

    print(f"# SPI BER ramp: {args.frames} frames/step, {FRAME_LEN}B frames, delay-1 echo")
    ceiling = None
    for mhz in args.clocks_mhz:
        r = run_one(mhz * 1_000_000, args.frames, args.seed)
        status = "CLEAN" if r.frame_errors == 0 else f"ERR {r.frame_errors} frames / {r.bit_errors} bits"
        print(f"  {mhz:3d} MHz  BER={r.ber:.2e}  {status}")
        if r.frame_errors == 0:
            ceiling = mhz
    print(f"\nHighest zero-error clock: {ceiling} MHz" if ceiling else "\nNo clean clock found")
    return 0


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("SPI needs root: sudo python3 spi_ber_ramp.py", file=sys.stderr)
    sys.exit(main())
```

- [ ] **Step 9: Parametrize the SCLK half-period in `tb_spi_slave_rx.v` + add a fast-SCLK case**

In `fpga/sim/tb_spi_slave_rx.v`, change `localparam HALF = 250;` to a non-localparam `integer HALF;` driven per run, OR add a second `initial` block that re-runs the A/B/A sequence with `HALF = 17` (≈30 MHz). Minimal version: keep the existing 2 MHz pass and add an assertion the deserialize still matches at `HALF=17`. (Note in the tb comment: xsim cannot model metastability — this proves *logic* at a 100 MHz:30 MHz sample ratio, not silicon margin; the silicon ceiling comes from Task 3.)

- [ ] **Step 10: Run the Vivado sim suite, confirm still green**

Run: `vivado -mode batch -source fpga/sim/run_sim.tcl`
Expected: all PASS including the new fast-SCLK assertion.

- [ ] **Step 11: Commit** (show message, get OK first)

Proposed message: `add spi BER ramp instrument (echo_top + clock sweep)`
```bash
git add ber.py test_ber.py spi_ber_ramp.py fpga/src/echo_top.v \
        fpga/constraints/echo.xdc fpga/build_echo.tcl fpga/sim/tb_spi_slave_rx.v
git commit   # only after explicit OK
```

---

## Task 3: Silicon clock ramp — find the real ceiling

**Files:** none modified — measurement only (autonomous over SSH).

- [ ] **Step 1: Build the echo bitstream**

Run: `vivado -mode batch -source fpga/build_echo.tcl`
Expected: `BITSTREAM_OK .../echo_top.bit`.

- [ ] **Step 2: Flash it to the Basys 3**

Run: `vivado -mode batch -source fpga/program.tcl -tclargs <echo_top.bit path>`
Expected: `PROGRAM_OK`.

- [ ] **Step 3: Run the BER ramp on the Pi**

Run (on the Pi, over SSH): `sudo python3 spi_ber_ramp.py --frames 5000`
Expected: a per-clock BER table; record the highest zero-error clock.

- [ ] **Step 4: Decision gate**
  - If ceiling ≥ ~30 MHz with margin → set the locked clock to ~0.75× the cliff (or 30 if clean), skip Task 3b, proceed to Task 4.
  - If ceiling < target (predicted ~15–20 MHz) → **either** re-lock the spec to ~0.75× the ceiling and proceed (acceptable: counters stay 16-bit, telemetry still works), **or** do Task 3b for more headroom. Bring the measured numbers back to the user before choosing — this is the one point where measured reality may change the spec.

- [ ] **Step 5: No commit** — measurement; results inform Task 4.

---

## Task 3b (CONTINGENT — only if Task 3 ceiling < target): MMCM 200 MHz sampler + CDC

**Files:**
- Modify: `fpga/src/echo_top.v` / `nids_top.v` (instantiate MMCM, run `spi_slave_rx` in 200 MHz domain), `fpga/constraints/*.xdc` (MMCM/clock constraints)
- Create: `fpga/sim/tb_spi_cdc.v` (CDC handshake correctness)

- [ ] **Step 1: Write the failing CDC testbench** — drive a 30 MHz SCLK master against `spi_slave_rx` clocked at 200 MHz, assert the assembled `rx_frame` crosses to a 100 MHz consumer domain exactly once per frame via a valid-pulse synchronizer (no drops, no duplicates).
- [ ] **Step 2: Run it, verify it fails** (no MMCM/CDC yet).
- [ ] **Step 3: Add MMCM** (100→200 MHz) + move `spi_slave_rx` to the 200 MHz domain; CDC `rx_frame_valid` via a toggle/pulse synchronizer and hold `rx_frame` stable (safe: frames ≥8.5 µs apart). Update XDC with `create_generated_clock` + `set_clock_groups -asynchronous`.
- [ ] **Step 4: Run sim, verify CDC test + existing suite pass.**
- [ ] **Step 5: Rebuild echo bitstream, re-run the silicon ramp** (Task 3 steps), confirm the new ceiling.
- [ ] **Step 6: Confirm 100 MHz WNS still positive** (`report_timing_summary`) — the MMCM adds a clock domain; timing must still close.
- [ ] **Step 7: Commit** — proposed: `add mmcm 200mhz spi sampler + frame cdc`.

---

## Task 4: Re-lock the rate in `sizing.py` and `SPEC_v2.md`

**Files:**
- Modify: `docs/sizing.py:42` (`SPI_HZ`), `docs/SPEC_v2.md` (workload bounds section + table)

- [ ] **Step 1: Set `SPI_HZ` to the locked clock**

In `docs/sizing.py`, change `SPI_HZ, FRAME_BYTES = 30e6, 32` to the measured/locked clock (keep `FRAME_BYTES = 32`).

- [ ] **Step 2: Rerun the model, confirm counters stay 16-bit**

Run: `python3 docs/sizing.py`
Expected: `counters need 16 bits` still holds (true for sustained pps < 65,536). If the locked clock somehow pushes pps ≥ 65,536, the counter width and CMS BRAM change — re-read the full table and update `SPEC_v2.md` accordingly. (At ≤30 MHz/32B this never happens.)

- [ ] **Step 3: Update `SPEC_v2.md`** — the "Workload bounds" link line and any "30 MHz" references to the locked clock; add one line noting it's the *measured-and-locked* rate, not a target.

- [ ] **Step 4: Commit** — proposed: `re-lock spi clock to <N>mhz from measured ceiling`.

---

## Task 5: Widen the frame 20 → 32 bytes

**Files:** HDL, Python builders, golden vectors, docs (see table). Sub-stepped; the regression run (Step 9) is the gate.

- [ ] **Step 1: Re-anchor `header_parser.v` slices to `FRAME_BITS`** (the only non-mechanical HDL change)

Replace the hardcoded `frame[159:128]`… with width-relative slices:
```verilog
src_ip    <= frame[FRAME_BITS-1   -: 32];   // bytes 0-3
dst_ip    <= frame[FRAME_BITS-33  -: 32];   // bytes 4-7
src_port  <= frame[FRAME_BITS-65  -: 16];   // bytes 8-9
dst_port  <= frame[FRAME_BITS-81  -: 16];   // bytes 10-11
proto     <= frame[FRAME_BITS-97  -:  8];   // byte 12
tcp_flags <= frame[FRAME_BITS-105 -:  8];   // byte 13
pkt_size  <= frame[FRAME_BITS-113 -: 16];   // bytes 14-15
```
Add `localparam FRAME_BITS = FRAME_BYTES*8;` to the parser. (Verify against v1: at `FRAME_BYTES=20`, `FRAME_BITS-1=159` → identical to the current slices, so the parser tb still passes before the width bump.)

- [ ] **Step 2: Bump `FRAME_BYTES` to 32 in `nids_top.v:15`.** `spi_slave_rx.v` and `verdict_encoder.v` are already parametric — no edits (confirm `byte_cnt[4:0]` covers 0..31).

- [ ] **Step 3: Widen testbench frame constants 160→256 bit** in `tb_spi_slave_rx.v`, `tb_header_parser.v`, `tb_nids_top.v`, `tb_verdict_golden.v`. Rule: each `160'h…` header constant gains 12 trailing zero bytes → `256'h…00000000_00000000_00000000`. Update `localparam FRAME_BYTES` in each tb to 32.

- [ ] **Step 4: Widen Python frame builders.** Exact changes:
  - `spi_link.py`: `FRAME_LEN = 20` → `32`.
  - `verdict.py`: `VERDICT_LEN = 20` → `32`; `encode_verdict` trailing `bytes(15)` → `bytes(27)`.
  - `benchmark.py`: `_TAIL = struct.Struct(">HHBBHI")` produces 12 bytes after the 8-byte IP pair = 20; extend the reserved tail to 24 bytes so total = 32 (e.g. append `bytes(12)` in `_pack`).
  - `scenarios.py`: `hdr()` builder — pad output to 32 bytes (append zero bytes).
  - `gen_verdict_golden.py`: `V1_BLOOM_INPUTS` hex strings (currently 40 hex chars = 20B) → append `"000000000000000000000000"` (24 hex = 12B) to each → 32B.
  - `packet_capture.py`: any frame assembly padded to 32B.
  - Grep gate: `grep -rn "20" *.py | grep -iE "frame|len|reserved"` and `grep -rn "bytes(15)\|FRAME_LEN\|VERDICT_LEN"` to catch stragglers.

- [ ] **Step 5: Regenerate golden vectors**

Run: `python3 gen_verdict_golden.py` → paste into `VERDICT_GOLDEN.md`. Update `VERDICT_VECTORS.md` and any format-vector lengths. Update `PROTOCOL.md` (32B request + response tables, reserved 16–31 / 5–31, clock = locked value, loopback note still valid).

- [ ] **Step 6: Update Python tests asserting lengths** — `test_verdict.py`, `test_verdict_vectors.py`, `test_verdict_golden.py`, `test_classifier.py`, `test_benchmark.py`: any `== 20` / `len(... ) == 20` → 32; regenerate any inline expected hex.

- [ ] **Step 7: Run the Python suite, confirm green**

Run: `python3 -m pytest -q`
Expected: all pass (same count as Task 0 baseline; behavior unchanged, only widths).

- [ ] **Step 8: Run the Vivado sim suite, confirm green**

Run: `vivado -mode batch -source fpga/sim/run_sim.tcl`
Expected: every tb PASS.

- [ ] **Step 9: Commit** — proposed: `widen frame to 32 bytes (v2 geometry)`.

---

## Task 6: Re-measure throughput

**Files:**
- Modify: `benchmark.py` (add transport model)
- Create: test for the transport arithmetic (in `test_benchmark.py`)

- [ ] **Step 1: Write the failing transport-model test** in `test_benchmark.py`:
```python
def test_link_frame_time():
    from benchmark import link_frame_us
    # 20B @ 1 MHz = 160 bits / 1e6 = 160 us
    assert abs(link_frame_us(20, 1_000_000) - 160.0) < 1e-6
    # 32B @ 30 MHz = 256 bits / 30e6 ≈ 8.533 us
    assert abs(link_frame_us(32, 30_000_000) - 256/30) < 1e-3
```
- [ ] **Step 2: Run it, verify it fails** (`link_frame_us` undefined).
- [ ] **Step 3: Implement `link_frame_us(frame_bytes, clk_hz)` in `benchmark.py`** = `frame_bytes*8 / clk_hz * 1e6`; add a printed "system throughput" line (v1 1 MHz/20B vs locked-clock/32B: µs/frame and frames/sec).
- [ ] **Step 4: Run the test, verify it passes.**
- [ ] **Step 5: Live sustained-rate measurement** — on the Pi, time N frames through `SpiLink` at the locked clock; report measured frames/sec vs the model. (Reuse `spi_ber_ramp.py` timing or a tiny wall-clock loop.)
- [ ] **Step 6: Commit** — proposed: `add link transport throughput model to benchmark`.

---

## Task 7: Full silicon regression at the new clock + frame width

**Files:** none modified — final validation.

- [ ] **Step 1: Rebuild `nids_top` (now 32B)**

Run: `vivado -mode batch -source fpga/build.tcl`
Expected: `BITSTREAM_OK`.

- [ ] **Step 2: Confirm 100 MHz WNS still positive**

Inspect the impl timing summary; refresh `docs/reports/timing_summary.rpt` and `utilization.rpt`. Expected: WNS > 0 (v1 was +0.41 ns; the 32B widening adds wiring but no new logic depth — confirm, don't assume).

- [ ] **Step 3: Flash + run the 120-frame golden round-trip on silicon at the locked clock**

Set `spi_verdict_check.py`'s link to the locked clock (it uses default `SpiLink()` = 1 MHz today; pass `speed_hz`), flash, run: `sudo python3 spi_verdict_check.py`.
Expected: `PASS: v1.1 silicon round-trip (120/120 verdicts correct)` — proves the wider frame + faster clock didn't regress v1 behavior.

- [ ] **Step 4: Commit** — proposed: `refresh impl reports for 32b/<N>mhz build`.

---

## Self-Review

- **Spec coverage:** Step-0 spec line ("raise 1 MHz→~30 MHz; stream compact headers not-20B-fixed; re-run benchmark.py to show throughput scaling") → clock ramp (Tasks 2–4), 32B widening (Task 5), throughput (Task 6). Methodology mandates (golden model + golden vectors + self-checking tb; full pytest + sim green; per-module WNS check) → Tasks 2/5/6 carry tests alongside; Tasks 5/7 are the regression + timing gates. ✔
- **Placeholder scan:** all code steps carry real code or exact transformation rules + grep gates; no TBD/TODO. The one judgement point (Task 3 decision gate) is explicitly flagged to return to the user with measured numbers. ✔
- **Type/name consistency:** `ramp_errors`/`RampResult` used identically in `ber.py`, `test_ber.py`, `spi_ber_ramp.py`; `FRAME_BYTES`/`FRAME_BITS` parametric throughout HDL; `link_frame_us` signature matches between test and impl. ✔

## Unresolved Questions

- Task 3 ceiling < target → re-lock spec to 0.75× ceiling vs do Task 3b MMCM? (return w/ measured numbers; user decides)
- echo.xdc duplicates nids.xdc — acceptable, or prefer one parametric XDC? (chose duplicate for self-contained builds)
- 32B rationale is "keeps pps<65,536 → 16-bit counters"; the extra 12 bytes are reserved now. OK to leave field definition to step 1, or pre-spec a capture-timestamp field? (plan assumes reserved-for-now)
- frames/step for a credible BER (5000 default ≈ 1.28M bits/step) — enough, or want 10⁷+ bits for a tighter bound at the top clocks?
