# v2 Step 2 — Runtime Rule Loading Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Bloom + classifier thresholds + a new 512×72 rule_store runtime-writable by the Pi over the existing SPI link, using a new opcode group `0x10–0x15` layered on step 1's framing.

**Architecture:** Each surface gets a clean module + bit-exact Python twin (mirrors `scan_rate.py ↔ scan_rate.v`). Bloom turns dual-port (read=classifier query, write=Pi hot-load); a tiny `thresholds.v` register file replaces `scan_rate.v`'s `localparam` thresholds; a new `rule_store.v` is 1 RAMB36 in 512×72 mode. `nids_top` gains a 6-opcode write/read mux that mirrors step 1's response-frame pattern. No new sketches — pure control plane.

**Tech Stack:** Verilog-2001 (Vivado xsim + synth, xc7a35t, 100 MHz), Python 3 (pytest, pure-stdlib twins), autonomous build/sim/flash over SSH, live Pi tests at 8 MHz / 32 B.

**Conventions:** terse lowercase commit messages matching v1 style (no `feat:` prefix / no attribution); RFC5737 IPs only; public-repo clean. TDD per module: failing test → twin → golden vectors → self-checking tb → HDL → green. Full pytest + Vivado sim stay green; WNS stays positive (currently +0.107 ns) after each HDL module.

---

## Locked frame layouts (single source of truth — pin in both HDL and Pi-side `control.py`)

All frames are 32 bytes, big-endian, byte 16 = opcode. Reserved bytes = 0.

```
# Write requests
0x10 bloom write:     b0-1=word_addr(low 12 used) | b2-3=word_value(16) | rest reserved
0x11 threshold write: b0=threshold_id(8)          | b1-2=value(16)      | rest reserved
0x12 rule write:      b0-1=rule_idx(low 9 used)   | b2-10=rule(9 bytes) | rest reserved

# Read requests
0x13 bloom read req:  b0-1=word_addr
0x14 threshold read:  b0=threshold_id
0x15 rule read req:   b0-1=rule_idx

# Write ack responses (all writes return the same shape)
{ magic=0x5A, opcode_acked:8, 240 bits reserved }

# Read responses (magic=0x5A in byte 0)
0x13: b0=0x5A | b1-2=addr_echo | b3-4=value(16)              | rest 0
0x14: b0=0x5A | b1=id_echo     | b2-3=value(16)              | rest 0
0x15: b0=0x5A | b1-2=idx_echo  | b3-11=rule(9 bytes)         | rest 0

# Rule (9 bytes packed = 72 bits, byte-aligned for clean wire serialization)
b0-3 = src_ip:32 | b4 = action:8 | b5 = severity:8 (low 4 used) | b6 = epoch:8 | b7-8 = reserved:16

# Threshold IDs
0x00 = PORT_THRESH (default 5) | 0x01 = HOST_THRESH (default 5) | 0x02 = RATE_THRESH (default 8)
```

## File structure

| File | Responsibility | New/Mod |
|---|---|---|
| `rule_store_model.py` | bit-exact twin of `rule_store.v` (load/get) | create |
| `thresholds_model.py` | bit-exact twin of `thresholds.v` (defaults + write/read) | create |
| `control.py` | Pi-side encoders for 0x10–0x12, decoders for 0x13–0x15, write-then-readback helpers | create |
| `test_rule_store_model.py`, `test_thresholds_model.py`, `test_control.py` | pytest | create |
| `fpga/src/rule_store.v` | 512×72 BRAM (1 RAMB36 in 512×72 mode), sync read + write port | create |
| `fpga/src/thresholds.v` | 3 × 16-bit register file with power-on defaults | create |
| `fpga/sim/tb_rule_store.v`, `tb_thresholds.v` | self-checking tbs vs the twins | create |
| `fpga/src/bloom_filter.v` | add port-B write interface (TDP); query path on port A unchanged | modify |
| `fpga/sim/tb_bloom_filter.v` | extend with a write→query round-trip | modify |
| `fpga/src/scan_rate.v` | the 3 `localparam` thresholds become module inputs | modify |
| `fpga/src/classifiers.v` | thread threshold inputs through to scan_rate | modify |
| `fpga/sim/tb_scan_rate.v` | drive thresholds explicitly (preserve existing PASS) | modify |
| `fpga/src/nids_top.v` | instantiate thresholds + rule_store; opcode `0x10–0x15` decode + response mux | modify |
| `fpga/sim/tb_nids_top.v` | extend with write+readback round-trip per opcode | modify |
| `PROTOCOL.md` | document opcodes `0x10–0x15`, rule format, threshold IDs | modify |
| `hot_load_bloom.py` | Pi script: take a new C2 set, write the whole Bloom over SPI, verify | create |
| `silicon_runtime_check.py` | Pi script: round-trip every opcode against the twin | create |
| `fpga/sim/run_sim.tcl`, `fpga/build.tcl` | add new src + tbs | modify |

---

## Task 1: Python twins + Pi-side control

**Files:** Create `rule_store_model.py`, `thresholds_model.py`, `control.py`, three matching `test_*.py`.

- [ ] **Step 1: Write failing tests** for `rule_store_model.py`:

```python
from rule_store_model import RuleStore, encode_rule, decode_rule

def test_default_all_zero():
    rs = RuleStore()
    assert rs.read(0) == {"src_ip": 0, "action": 0, "severity": 0, "epoch": 0}

def test_write_read_roundtrip():
    rs = RuleStore()
    rs.write(42, {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7})
    assert rs.read(42) == {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}

def test_rule_encode_is_9_bytes_with_layout():
    rule = {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}
    b = encode_rule(rule)
    assert len(b) == 9
    assert b[0:4] == bytes([0xCB, 0x00, 0x71, 0x05])
    assert b[4] == 0b101 and b[5] == 3 and b[6] == 7
    assert b[7:9] == b"\x00\x00"

def test_encode_decode_inverse():
    rule = {"src_ip": 0xC0000201, "action": 0b010, "severity": 2, "epoch": 100}
    assert decode_rule(encode_rule(rule)) == rule

def test_index_out_of_range_raises():
    import pytest
    with pytest.raises(IndexError):
        RuleStore().read(512)
```

- [ ] **Step 2: Run, verify fail** — `python3 -m pytest test_rule_store_model.py -v` → `ModuleNotFoundError`.

- [ ] **Step 3: Implement `rule_store_model.py`**:

```python
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
```

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Write failing tests** for `thresholds_model.py`:

```python
from thresholds_model import Thresholds, PORT_THRESH, HOST_THRESH, RATE_THRESH

def test_defaults_match_v11():
    t = Thresholds()
    assert t.read(PORT_THRESH) == 5
    assert t.read(HOST_THRESH) == 5
    assert t.read(RATE_THRESH) == 8

def test_write_read_roundtrip():
    t = Thresholds()
    t.write(PORT_THRESH, 12)
    assert t.read(PORT_THRESH) == 12

def test_unknown_id_raises():
    import pytest
    with pytest.raises(KeyError):
        Thresholds().write(0xEE, 0)
```

- [ ] **Step 6: Run, verify fail.**

- [ ] **Step 7: Implement `thresholds_model.py`**:

```python
"""Bit-exact CPU twin of thresholds.v. v1.1 default values restored on reset."""
PORT_THRESH, HOST_THRESH, RATE_THRESH = 0x00, 0x01, 0x02
_DEFAULTS = {PORT_THRESH: 5, HOST_THRESH: 5, RATE_THRESH: 8}


class Thresholds:
    def __init__(self):
        self._v = dict(_DEFAULTS)

    def write(self, tid, value):
        if tid not in _DEFAULTS:
            raise KeyError(tid)
        self._v[tid] = value & 0xFFFF

    def read(self, tid):
        if tid not in _DEFAULTS:
            raise KeyError(tid)
        return self._v[tid]
```

- [ ] **Step 8: Run, verify pass.**

- [ ] **Step 9: Write failing tests** for `control.py` (Pi-side encoder/decoder for opcodes 0x10–0x15):

```python
from control import (
    encode_bloom_write, encode_threshold_write, encode_rule_write,
    encode_bloom_read, encode_threshold_read, encode_rule_read,
    decode_write_ack, decode_bloom_read, decode_threshold_read, decode_rule_read,
)

def test_bloom_write_frame_is_32_bytes_with_opcode_at_byte_16():
    f = encode_bloom_write(addr=0xABC, value=0x55AA)
    assert len(f) == 32 and f[16] == 0x10
    assert f[0:2] == bytes([0x0A, 0xBC]) and f[2:4] == bytes([0x55, 0xAA])

def test_threshold_write_frame_layout():
    f = encode_threshold_write(tid=0x01, value=0x000C)
    assert f[16] == 0x11 and f[0] == 0x01 and f[1:3] == bytes([0x00, 0x0C])

def test_rule_write_frame_layout():
    rule = {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}
    f = encode_rule_write(idx=42, rule=rule)
    assert f[16] == 0x12 and f[0:2] == bytes([0x00, 0x2A])
    assert f[2:6] == bytes([0xCB, 0x00, 0x71, 0x05]) and f[6:9] == bytes([0b101, 3, 7])

def test_write_ack_decode():
    ack = bytes([0x5A, 0x10]) + bytes(30)
    assert decode_write_ack(ack) == 0x10

def test_bloom_read_decode():
    r = bytes([0x5A, 0x0A, 0xBC, 0x55, 0xAA]) + bytes(27)
    assert decode_bloom_read(r) == {"addr": 0x0ABC, "value": 0x55AA}

def test_rule_read_decode():
    payload = bytes([0xCB, 0x00, 0x71, 0x05, 0b101, 3, 7, 0, 0])
    r = bytes([0x5A, 0x00, 0x2A]) + payload + bytes(20)
    assert decode_rule_read(r) == {"idx": 42, "rule":
        {"src_ip": 0xCB007105, "action": 0b101, "severity": 3, "epoch": 7}}

def test_bad_magic_raises():
    import pytest
    with pytest.raises(ValueError):
        decode_bloom_read(bytes([0xA5]) + bytes(31))
```

- [ ] **Step 10: Run, verify fail.**

- [ ] **Step 11: Implement `control.py`**:

```python
"""Pi-side encoders for the v2 step-2 write opcodes and decoders for the read responses
(magic 0x5A). Pure stdlib. Frame layouts are pinned in PROTOCOL.md; keep in lockstep with
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


def _check(frame, expect_len=FRAME_LEN):
    if len(frame) != expect_len:
        raise ValueError(f"frame must be {expect_len} bytes, got {len(frame)}")
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
```

- [ ] **Step 12: Run, verify pass** — full `python3 -m pytest -q` should now report all step-1 tests still green plus the new ones.
- [ ] **Step 13: Commit** — `add step-2 cpu twins + pi control codec`. No push (Python only; goes to Pi via scp at Task 8).

## Task 2: `rule_store.v` + `tb_rule_store.v`

**Files:** Create `fpga/src/rule_store.v`, `fpga/sim/tb_rule_store.v`; modify `fpga/sim/run_sim.tcl`.

Interface:
```verilog
module rule_store (
  input  wire        clk,
  input  wire [8:0]  w_idx,  input  wire [71:0] w_rule,  input  wire w_en,    // Pi writes
  input  wire [8:0]  r_idx,  output reg  [71:0] r_rule                          // step-4 reads
);
```
Inside: `(* ram_style="block" *) reg [71:0] mem[0:511];`. Sync read on r_idx; sync write on w_en. Vivado will map to 1 RAMB36 (512×72 mode).

- [ ] **Step 1: Write `tb_rule_store.v`** — drives 3 distinct writes, then 3 reads, asserts each read returns the rule that was written; pulse `w_en` for one cycle per write. Print `PASS: tb_rule_store write/read roundtrip` on success.
- [ ] **Step 2:** Add `rule_store.v` + `tb_rule_store.v` to `run_sim.tcl`; run sim → expect FAIL.
- [ ] **Step 3:** Implement `rule_store.v` (~20 lines).
- [ ] **Step 4:** Run sim → `PASS: tb_rule_store ...`; full suite still green.
- [ ] **Step 5: Commit** — `add rule_store stage`.

## Task 3: `thresholds.v` + `tb_thresholds.v`

**Files:** Create `fpga/src/thresholds.v`, `fpga/sim/tb_thresholds.v`; modify `run_sim.tcl`.

Interface:
```verilog
module thresholds (
  input  wire        clk, rst,
  input  wire [7:0]  w_id,  input  wire [15:0] w_val,  input  wire w_en,
  input  wire [7:0]  r_id,  output reg  [15:0] r_val,
  output wire [15:0] port_thresh, host_thresh, rate_thresh        // direct taps for scan_rate
);
```
Three internal regs initialized to {5, 5, 8} on reset. Decode `w_id ∈ {0x00, 0x01, 0x02}` to select the write target; ignore other IDs. Direct taps stay live; `r_val` is a registered read for the opcode 0x14 response.

- [ ] **Step 1: Write `tb_thresholds.v`** — assert defaults on reset, write to each ID, read back, also assert unknown IDs leave state unchanged.
- [ ] **Step 2:** Add to `run_sim.tcl`; sim FAIL.
- [ ] **Step 3:** Implement `thresholds.v`.
- [ ] **Step 4:** Sim PASS.
- [ ] **Step 5: Commit** — `add thresholds register file`.

## Task 4: `bloom_filter.v` — add port-B write interface

**Files:** Modify `fpga/src/bloom_filter.v`, `fpga/sim/tb_bloom_filter.v`.

Add ports: `input wire [11:0] w_word_addr, input wire [15:0] w_word_value, input wire w_word_en`. Inside, instantiate the existing BRAM with a second port: write port (B) writes one 16-bit word per `w_word_en` pulse; read port (A) is the existing classifier query path. Vivado RAMB36 TDP mode handles both.

- [ ] **Step 1:** Extend `tb_bloom_filter.v` — keep all existing tests; add a phase that (a) queries an IP that initially HITS (one of the v1.1 C2 IPs), (b) overwrites every word touched by that IP's hash to zero via port B, (c) queries again and asserts MISS. (Demonstrates port-B writes affect port-A queries.)
- [ ] **Step 2:** Run sim → expect FAIL (new ports don't exist).
- [ ] **Step 3:** Modify `bloom_filter.v` to add port B.
- [ ] **Step 4:** Run sim → PASS.
- [ ] **Step 5: Commit** — `make bloom_filter dual-port for hot-load`.

## Task 5: `scan_rate.v` thresholds become module inputs

**Files:** Modify `fpga/src/scan_rate.v`, `fpga/src/classifiers.v`, `fpga/sim/tb_scan_rate.v`.

Change `localparam integer PORT_THRESH = 5, HOST_THRESH = 5, RATE_THRESH = 8;` to module inputs `input wire [15:0] port_thresh, host_thresh, rate_thresh`. Pass them through `classifiers.v` (add corresponding ports there too). Update comparisons in `scan_rate.v` to use the wire values (same comparison depth — no timing change expected).

- [ ] **Step 1:** Update `tb_scan_rate.v` to drive the three thresholds at their v1.1 default values (5, 5, 8) so the existing PASS is preserved.
- [ ] **Step 2:** Run sim → expect FAIL (mismatch on the new ports of scan_rate/classifiers).
- [ ] **Step 3:** Modify `scan_rate.v` and `classifiers.v`.
- [ ] **Step 4:** Run sim → `PASS: tb_scan_rate ...` AND `PASS: tb_classifiers ...` (the latter must also drive the thresholds).
- [ ] **Step 5: Commit** — `make scan_rate thresholds runtime-configurable`.

## Task 6: `nids_top.v` — opcode `0x10–0x15` decode + response mux

**Files:** Modify `fpga/src/nids_top.v`, `fpga/sim/tb_nids_top.v`, `fpga/build.tcl`, `fpga/sim/run_sim.tcl`.

Inside `nids_top`:
1. Instantiate `thresholds` with its `port/host/rate_thresh` taps fed into `classifiers` (which threads to `scan_rate`).
2. Instantiate `rule_store`.
3. Extend `bloom_filter` instantiation with the new `w_word_addr/value/en` ports.
4. Add an opcode router (combinational decode of `inflight_op`) that drives:
   - `w_word_en` on `0x10` (data: rx_frame bytes 2-3 to word_value, bytes 0-1 to word_addr)
   - `thresholds.w_en` on `0x11`
   - `rule_store.w_en` on `0x12`
5. Extend the existing response mux with the 6 new cases. Writes load `tx_reg <= {0x5A, opcode, 240'd0}`. Reads load:
   - `0x13`: `{0x5A, addr_echo, bloom_read_value, 216'd0}` — needs a small registered bloom-read port (extract from existing query interface or add a 3rd read port; simplest: a 1-cycle pulse on `bloom_filter`'s query path with `q_ip` synthesized from `{20'd0, w_word_addr}` doesn't fit — instead add an explicit `read_word_addr` / `read_word_value` to `bloom_filter.v` Task 4.)

Add the small `read_word_*` read interface to `bloom_filter.v` retroactively as part of Task 4 (single-cycle synchronous BRAM read on port A or B — TDP allows it).

- [ ] **Step 1: Extend `tb_nids_top.v`** — preserve every existing assertion; then for each opcode in `{0x10, 0x11, 0x12}`, send the write frame, send a flush, send the matching read frame, send a flush, assert the read-back equals what was written (magic 0x5A in byte 0; payload as specified). One representative case per opcode is enough.
- [ ] **Step 2:** Run sim → FAIL.
- [ ] **Step 3:** Modify `nids_top.v` (router + mux + new instances).
- [ ] **Step 4:** Run sim → all 12 testbenches PASS (the 11 from step 1 + `tb_rule_store` + `tb_thresholds`).
- [ ] **Step 5: Confirm WNS** via `build.tcl` (Task 9) — must stay > 0 (currently +0.107 ns; the new response-mux cases are pure registered logic, no new logic depth expected). If the response mux becomes the critical path, pipeline it into its own register stage.
- [ ] **Step 6:** Add `fpga/src/rule_store.v`, `thresholds.v` to `build.tcl`'s `add_files` list (mirroring how cms/hll/telemetry were added in step 1).
- [ ] **Step 7: Commit** — `integrate write opcodes into nids_top`.

## Task 7: Protocol doc + Tier-1 vector update

**Files:** Modify `PROTOCOL.md`; create `RUNTIME_VECTORS.md` (or extend `TELEMETRY_VECTORS.md`).

Add a "Runtime control (opcodes 0x10–0x15)" section to `PROTOCOL.md` containing the locked frame layouts table verbatim from this plan's "Locked frame layouts" block. Create a `RUNTIME_VECTORS.md` with a few representative hex frames generated by `control.py` (one per opcode), same Tier-1 format as `TELEMETRY_VECTORS.md`.

- [ ] **Step 1:** Run `python3 -c "from control import *; ..."` to print 3-6 representative hex frames; paste into `RUNTIME_VECTORS.md`.
- [ ] **Step 2:** Update `PROTOCOL.md` with the new opcode section (after the telemetry response section).
- [ ] **Step 3: Commit** — `document step-2 opcodes + runtime vectors`.

## Task 8: Pi-side hot-load script + silicon round-trip checker

**Files:** Create `hot_load_bloom.py`, `silicon_runtime_check.py`.

`silicon_runtime_check.py`: for each opcode, write a known value, read it back, assert it matches the twin's prediction. Run after flashing to validate every opcode works end-to-end.

`hot_load_bloom.py`: takes a new C2 set, rebuilds the bloom locally via `bloom.py`, then writes all 4096 words via `0x10`, then read-back-verifies a sample, then prints "C2 set rotated to {ips}".

- [ ] **Step 1:** Write `silicon_runtime_check.py` (pure I/O; no new logic). One write+read round-trip per opcode, plus a "rotated bloom" check (write a value, read it back, write the original back, read again).
- [ ] **Step 2:** Write `hot_load_bloom.py`.
- [ ] **Step 3: Commit** — `add pi hot-load + runtime round-trip scripts`.

## Task 9: build + WNS + silicon validation

**Files:** none modified — validation.

- [ ] **Step 1:** Build `nids_top` over SSH. Confirm `BITSTREAM_OK` and **WNS > 0** (refresh `docs/reports/` if it dipped meaningfully). If the response mux is the critical path, pipeline and rebuild.
- [ ] **Step 2:** Flash; scp new Pi modules (`rule_store_model.py thresholds_model.py control.py hot_load_bloom.py silicon_runtime_check.py`) plus any updated v1 Python.
- [ ] **Step 3:** Regression — `spi_verdict_check.py` → **120/120** (bake-in bloom still works at boot, threshold defaults intact).
- [ ] **Step 4:** Step-1 regression — `silicon_telemetry_check.py` → **5/5** (telemetry/opcodes 0x00–0x03 unchanged).
- [ ] **Step 5:** Round-trip — `silicon_runtime_check.py` writes+reads each new opcode, asserts equality.
- [ ] **Step 6: Hot-load demo (the headline)** — `hot_load_bloom.py --new-c2 198.51.100.99,203.0.113.99,192.0.2.42`. After the load, send packets carrying NEW C2s → bloom-hit; send packets carrying the ORIGINAL bake-in C2s (`CB007105 / C0000263 / C6336401`) → no longer hit. This proves the full hot-load path on real silicon.
- [ ] **Step 7: Commit** — `silicon: step-2 round-trips + bloom hot-load demo`.

---

## Self-Review

- **Spec coverage:** Bloom hot-load (Task 4 + 6 + 8 + 9); thresholds runtime (Task 3 + 5 + 6 + 9); rule_store (Task 2 + 6 + 9); opcode contract (Task 1 control.py, Task 7 docs); TDD twins+vectors+tbs per module; per-task WNS check; v1.1 + step-1 regression preserved (Task 9 steps 3-4); silicon hot-load demo (Task 9 step 6). ✔
- **Placeholder scan:** all opcode layouts, rule format, threshold IDs, file interfaces given in full above; no TBD. ✔
- **Type consistency:** `encode_rule` / `decode_rule` / `RuleStore.read` field names match across `rule_store_model.py`, `control.py`, and tests; opcode constants (`OP_BLOOM_W` etc.) match the locked frame layouts. ✔

## Unresolved / watch

- WNS margin after adding 6 cases to the response mux + the threshold tap into `scan_rate`. The pipelined mux + small register file shouldn't bite, but watch the routed report.
- Bloom `bidx_return0__3 → addr_b_reg` path has been the marginal one since v1; `Performance_ExtraTimingOpt` (from step 1) is already in `build.tcl` and gives the needed margin. Keep it on.
- The mass-expire `current_rule_epoch` register and rule_store's epoch-match consumer are defined as fields here but only ENFORCED in step 4. If step-3 work changes the rule layout, update Task 1's encode/decode in lockstep.
