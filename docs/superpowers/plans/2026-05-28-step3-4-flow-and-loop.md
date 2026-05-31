# v2 Step 3+4 — Flow Table + Closed-Loop Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace v1.1 `scan_rate.v` with a **4096-bucket fingerprinted** `flow_table.v` (step 3) and add a `rule_lookup.v` that reads the existing `rule_store` per packet + ORs its match into the verdict, closing the observe→decide→act loop when the Pi's `closed_loop.py` pushes a block-rule for the heaviest talker (step 4). One combined design / plan / build / silicon validation cycle. Verdict frame layout unchanged — only previously-reserved `hit_mask` bit 3 gets meaning.

**Architecture:** New modules `flow_table.v` + `rule_lookup.v` + Python twins; `classifiers.v` swaps `scan_rate` → `flow_table` and adds `rule_lookup` into the verdict combine; `thresholds.v` grows a 4th register (`id=0x03 = current_rule_epoch`); `rule_store.r_idx` gets a mux between Pi readback (op 0x15) and per-packet classifier lookup. Pi-side adds `closed_loop.py` that polls snapshot via op 0x02, pushes block-rule via op 0x12 when the top talker crosses a threshold.

**Tech Stack:** Verilog-2001 (Vivado xsim + synth, xc7a35t, 100 MHz), Python 3 (pytest, pure-stdlib twins), autonomous build/sim/flash over SSH, live Pi tests at 8 MHz / 32 B.

**Conventions:** terse lowercase commits, no prefix/attribution, RFC5737 IPs only, public-repo clean. TDD per module: failing test → twin → golden vectors → self-checking tb → HDL → green. Full pytest + Vivado sim stay green; WNS stays positive (currently +0.289 ns).

---

## Locked design constants (single source of truth for both twin and HDL)

```
# flow_table (replaces scan_rate)
FT_DEPTH = 4096                                  # 12-bit bucket index
FT_FP_BITS = 16                                  # fingerprint width
FT_CELL_BITS = 114                               # fp(16) + epoch(8) + pkt(14) + byte(24)
                                                 #   + syn(12) + dport_fp(16) + dhost_fp(16) + flags(8)
A1 = 0x9E3779B1                                  # same multiplier family as v1.1
A2 = 0x85EBCA77
bucket(src_ip) = ((src_ip * A1) & 0xFFFFFFFF) >> 20            # top 12 bits of low-32 product
fp(src_ip)     = ((src_ip * A2) & 0xFFFFFFFF) >> 12 & 0xFFFF   # 16 bits from a DIFFERENT mult

# rule_lookup (consumes existing rule_store)
RL_HASH(ip) = ((ip * A1) & 0xFFFFFFFF) >> 23 & 0x1FF           # top 9 bits -> 0..511 (rule_store depth)
RL_MATCH    = (stored.src_ip == query.src_ip) && (stored.epoch == current_rule_epoch)

# thresholds extension
THRESH_RULE_EPOCH = 0x03                         # new id; 8-bit value stored in low 8 of 16-bit reg

# verdict combine (in classifiers.v)
hit_mask    = {rule_match, rate_hit, port_scan_hit, bloom_hit}    # bit 3 added; bits 4-7 stay reserved
severity    = max(classifier_severity, rule.severity)             # both 2-bit clamped
escalate    = (any classifier bit) | rule.action[2]
```

## File structure

| File | Responsibility | New/Mod |
|---|---|---|
| `flow_table_model.py` | bit-exact twin of `flow_table.v` (bucket+fp, lazy-epoch, fp-evict, state update, verdict signals) | create |
| `rule_lookup_model.py` | bit-exact twin of `rule_lookup.v` (hash, match logic, action/severity decode) | create |
| `test_flow_table_model.py`, `test_rule_lookup_model.py` | pytest | create |
| `fpga/src/flow_table.v` | 4-phase RMW on 4096×114b BRAM with fp-collision-evict | create |
| `fpga/src/rule_lookup.v` | drives `rule_store.r_idx`, registers `r_rule`, decodes match | create |
| `fpga/sim/tb_flow_table.v`, `tb_rule_lookup.v` | self-checking tbs vs the twins | create |
| `fpga/src/thresholds.v` | add `id=0x03 = rule_epoch_r` register | modify |
| `fpga/sim/tb_thresholds.v` | add id-0x03 write/read assert | modify |
| `fpga/src/classifiers.v` | swap scan_rate→flow_table; instantiate rule_lookup; verdict combine | modify |
| `fpga/sim/tb_classifiers.v` | drive new thresholds + (idle) rule_lookup; keep PASS | modify |
| `fpga/src/nids_top.v` | instantiate flow_table+rule_lookup; mux rule_store.r_idx; wire rule_epoch | modify |
| `fpga/sim/tb_nids_top.v` | add rule_hit verdict test (write rule, classify matching src, assert bit 3) | modify |
| `closed_loop.py` | Pi script: poll snapshot, push block-rule on top1>threshold | create |
| `test_closed_loop.py` | pure-logic test of the policy decision (synth snapshots → expected rule push) | create |
| `silicon_loop_demo.py` | end-to-end live demo on the Pi (flood from a src, observe rule pushed + rule_hit verdicts) | create |
| `fpga/sim/run_sim.tcl`, `fpga/build.tcl` | add new src + tbs | modify |
| `PROTOCOL.md`, `docs/SPEC_v2.md` | document step 3+4: new mask bit, new threshold id, rule lookup contract | modify |

---

## Task 1: `flow_table_model.py` + tests (Python twin first, no HDL)

**Files:** Create `flow_table_model.py`, `test_flow_table_model.py`.

- [ ] **Step 1: Write failing tests** in `test_flow_table_model.py`:

```python
from flow_table_model import FlowTable, bucket, fp
from thresholds_model import Thresholds, RATE_THRESH


def test_bucket_and_fp_use_different_multipliers():
    # bucket = src*A1 >> 20; fp = src*A2 >> 12 & 0xFFFF
    assert bucket(0xCB007105) == ((0xCB007105 * 0x9E3779B1) & 0xFFFFFFFF) >> 20
    assert fp(0xCB007105)     == (((0xCB007105 * 0x85EBCA77) & 0xFFFFFFFF) >> 12) & 0xFFFF


def test_single_source_counts_then_verdicts():
    t = FlowTable()
    for i in range(8):
        t.update(src_ip=0xCB007105, dst_ip=0x0A000001, dst_port=80, proto=17,
                 tcp_flags=0, pkt_size=60, frame_count=i)
    res = t.update(src_ip=0xCB007105, dst_ip=0x0A000001, dst_port=80, proto=17,
                   tcp_flags=0, pkt_size=60, frame_count=8)
    assert res == (False, True)        # 9 pkts >= RATE_THRESH default 8 -> rate_hit


def test_collision_eviction_does_not_merge():
    """Two sources crafted to share a bucket but differ in fp: second evicts first.
    After eviction, the first source's state is GONE (no false port-scan trip from merging)."""
    t = FlowTable()
    src_a = 0xCB007105
    # find a src_b with same bucket(src_a) but different fp(src_a) -- search a small range
    src_b = None
    for cand in range(0x0A000000, 0x0A001000):
        if bucket(cand) == bucket(src_a) and fp(cand) != fp(src_a):
            src_b = cand; break
    assert src_b is not None, "couldn't find a colliding bucket in test range"
    # 4 syn-syn packets from src_a hitting 4 distinct ports -> port_fp popcount=4
    for i, p in enumerate([1, 3, 7, 13]):
        t.update(src_ip=src_a, dst_ip=0x0A000020, dst_port=p, proto=6,
                 tcp_flags=0x02, pkt_size=60, frame_count=i)
    # src_b arrives, evicts src_a
    res_b = t.update(src_ip=src_b, dst_ip=0x0A000020, dst_port=21, proto=6,
                     tcp_flags=0x02, pkt_size=60, frame_count=4)
    # src_a comes back: its evicted state was overwritten, so it sees a fresh cell
    res_a = t.update(src_ip=src_a, dst_ip=0x0A000020, dst_port=42, proto=6,
                     tcp_flags=0x02, pkt_size=60, frame_count=5)
    # In v1.1, the 4 ports of src_a would still be there (silently OR'd) and the 5th port
    # would push popcount to 5 -> port_scan_hit. In step 3, src_a was evicted: only 1 port_fp
    # bit set, no scan trip.
    assert res_a == (False, False), \
        "step 3 should NOT trip port-scan after eviction; v1.1's silent-merge would have"


def test_lazy_epoch_reset_at_window_boundary():
    t = FlowTable()
    t.update(src_ip=0x0A000001, dst_ip=0x0A000002, dst_port=80, proto=17,
             tcp_flags=0, pkt_size=60, frame_count=0)
    assert t._cell_of(0x0A000001)["pkt_count"] == 1
    # crossing the window (epoch advances)
    t.update(src_ip=0x0A000001, dst_ip=0x0A000002, dst_port=80, proto=17,
             tcp_flags=0, pkt_size=60, frame_count=16)   # epoch 0 -> 1
    c = t._cell_of(0x0A000001)
    assert c["pkt_count"] == 1   # reset to 0, then +1, NOT 2


def test_runtime_thresholds_change_verdict():
    """Same composite-twin check as scan_rate but on flow_table."""
    thr = Thresholds()
    t = FlowTable(thresholds=thr)
    for i in range(5):
        t.update(src_ip=0x0A000010, dst_ip=0x0A000020, dst_port=53,
                 proto=17, tcp_flags=0, pkt_size=60, frame_count=i)
    thr.write(RATE_THRESH, 6)
    _, rh = t.update(src_ip=0x0A000010, dst_ip=0x0A000020, dst_port=53,
                     proto=17, tcp_flags=0, pkt_size=60, frame_count=5)
    assert rh


def test_byte_count_accumulates():
    t = FlowTable()
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=0, proto=17, tcp_flags=0,
             pkt_size=1500, frame_count=0)
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=0, proto=17, tcp_flags=0,
             pkt_size=500,  frame_count=1)
    assert t._cell_of(0x0A000001)["byte_count"] == 2000


def test_syn_count_only_increments_on_syn_no_ack():
    t = FlowTable()
    # SYN without ACK -> count
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=80, proto=6, tcp_flags=0x02,
             pkt_size=60, frame_count=0)
    # SYN+ACK -> do NOT count
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=80, proto=6, tcp_flags=0x12,
             pkt_size=60, frame_count=1)
    # plain ACK -> do not count
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=80, proto=6, tcp_flags=0x10,
             pkt_size=60, frame_count=2)
    assert t._cell_of(0x0A000001)["syn_count"] == 1
```

- [ ] **Step 2: Run, verify fail** — `ModuleNotFoundError: flow_table_model`.

- [ ] **Step 3: Implement `flow_table_model.py`**:

```python
"""Bit-exact CPU twin of flow_table.v (v2 step 3). Replaces scan_rate's 256-bucket
undercounting with 4096 buckets + 16-bit fingerprint -> proper collision DETECTION + eviction
(no silent OR-merging). Bit-exact contract: same hashes, same fp-match rule, same lazy-epoch
reset, same verdict signals as scan_rate (port_scan_hit, rate_hit) but per-flow accurate.
"""
from thresholds_model import Thresholds, PORT_THRESH as _ID_PORT, HOST_THRESH as _ID_HOST, RATE_THRESH as _ID_RATE

A1 = 0x9E3779B1
A2 = 0x85EBCA77
MASK32 = 0xFFFFFFFF
DEPTH  = 4096
WINDOW_SHIFT = 4       # 16-frame window epoch (same as v1.1)
RATE_MAX = (1 << 14) - 1
BYTE_MAX = (1 << 24) - 1
SYN_MAX  = (1 << 12) - 1


def bucket(src_ip):
    return ((src_ip * A1) & MASK32) >> 20


def fp(src_ip):
    return (((src_ip * A2) & MASK32) >> 12) & 0xFFFF


def port_bit(dst_port):
    return ((dst_port * A2) & MASK32) >> 28


def host_bit(dst_ip):
    return ((dst_ip * A1) & MASK32) >> 28


def epoch(frame_count):
    return (frame_count >> WINDOW_SHIFT) & 0xF


def _syn_gate(proto, tcp_flags):
    return proto == 6 and bool(tcp_flags & 0x02) and not (tcp_flags & 0x10)


class FlowTable:
    def __init__(self, thresholds=None):
        self._t = [self._blank(0, 0) for _ in range(DEPTH)]
        self.thresholds = thresholds if thresholds is not None else Thresholds()

    @staticmethod
    def _blank(ep, the_fp):
        return {"fp": the_fp, "epoch": ep, "pkt_count": 0, "byte_count": 0,
                "syn_count": 0, "dport_fp": 0, "dhost_fp": 0, "flags": 0}

    def _cell_of(self, src_ip):
        return self._t[bucket(src_ip)]

    def update(self, *, src_ip, dst_ip, dst_port, proto, tcp_flags, pkt_size, frame_count):
        b   = bucket(src_ip)
        f   = fp(src_ip)
        ep  = epoch(frame_count)
        cur = self._t[b]
        # Effective state: only "ours" if fp matches AND epoch is current.
        if cur["fp"] != f or cur["epoch"] != ep:
            cur = self._blank(ep, f)            # eviction OR lazy reset -- both start fresh
            self._t[b] = cur
        cur["pkt_count"]  = min(cur["pkt_count"] + 1,           RATE_MAX)
        cur["byte_count"] = min(cur["byte_count"] + pkt_size,   BYTE_MAX)
        if _syn_gate(proto, tcp_flags):
            cur["syn_count"] = min(cur["syn_count"] + 1, SYN_MAX)
            cur["dport_fp"] |= 1 << port_bit(dst_port)
            cur["dhost_fp"] |= 1 << host_bit(dst_ip)
        cur["flags"] |= tcp_flags
        port_scan_hit = (bin(cur["dport_fp"]).count("1") >= self.thresholds.read(_ID_PORT) or
                         bin(cur["dhost_fp"]).count("1") >= self.thresholds.read(_ID_HOST))
        rate_hit = cur["pkt_count"] >= self.thresholds.read(_ID_RATE)
        return port_scan_hit, rate_hit
```

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `add flow_table cpu twin`.

## Task 2: `rule_lookup_model.py` + tests

**Files:** Create `rule_lookup_model.py`, `test_rule_lookup_model.py`.

- [ ] **Step 1: Write failing tests**:

```python
from rule_lookup_model import lookup_idx, lookup
from rule_store_model import RuleStore


def test_lookup_idx_hash_is_top_9_bits_of_a1_product():
    assert lookup_idx(0xCB007105) == (((0xCB007105 * 0x9E3779B1) & 0xFFFFFFFF) >> 23) & 0x1FF


def test_match_when_src_and_epoch_match():
    rs = RuleStore()
    src = 0xCB007105
    rs.write(lookup_idx(src),
             {"src_ip": src, "action": 0b101, "severity": 3, "epoch": 7})
    r = lookup(rs, src_ip=src, current_rule_epoch=7)
    assert r == {"match": True, "action": 0b101, "severity": 3}


def test_no_match_when_epoch_differs():
    rs = RuleStore()
    src = 0xCB007105
    rs.write(lookup_idx(src),
             {"src_ip": src, "action": 0b101, "severity": 3, "epoch": 7})
    r = lookup(rs, src_ip=src, current_rule_epoch=8)        # Pi advanced epoch -> rule expired
    assert r["match"] is False


def test_no_match_when_src_differs_at_same_idx():
    """Different src whose bucket happens to collide -> NO false match."""
    rs = RuleStore()
    src_a = 0xCB007105
    rs.write(lookup_idx(src_a),
             {"src_ip": src_a, "action": 0b001, "severity": 1, "epoch": 0})
    # craft src_b with same lookup_idx but a different value
    src_b = None
    for cand in range(0x0A000000, 0x0A010000):
        if lookup_idx(cand) == lookup_idx(src_a) and cand != src_a:
            src_b = cand; break
    assert src_b is not None
    r = lookup(rs, src_ip=src_b, current_rule_epoch=0)
    assert r["match"] is False


def test_unwritten_bucket_returns_no_match():
    rs = RuleStore()
    r = lookup(rs, src_ip=0x0A000001, current_rule_epoch=0)
    assert r["match"] is False        # empty bucket has src_ip=0, can't match a nonzero query
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `rule_lookup_model.py`**:

```python
"""Bit-exact CPU twin of rule_lookup.v. On every classify frame, hash src_ip to a
rule_store index, read the stored rule, return match iff (src_ip equals AND epoch equals
current_rule_epoch). The Pi writes rules at the same hash so the lookup finds them."""
from rule_store_model import RuleStore

A1 = 0x9E3779B1
MASK32 = 0xFFFFFFFF


def lookup_idx(src_ip):
    return (((src_ip * A1) & MASK32) >> 23) & 0x1FF       # top 9 bits -> 0..511


def lookup(rs: RuleStore, *, src_ip: int, current_rule_epoch: int) -> dict:
    stored = rs.read(lookup_idx(src_ip))
    if stored["src_ip"] == src_ip and stored["epoch"] == current_rule_epoch:
        return {"match": True, "action": stored["action"], "severity": stored["severity"]}
    return {"match": False, "action": 0, "severity": 0}
```

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `add rule_lookup cpu twin`.

## Task 3: `flow_table.v` + `tb_flow_table.v`

**Files:** Create `fpga/src/flow_table.v`, `fpga/sim/tb_flow_table.v`; modify `fpga/sim/run_sim.tcl`.

**Interface** (same shape as scan_rate.v's I/O so classifiers.v's wiring is a port swap):

```verilog
module flow_table (
    input  wire        clk, rst,
    input  wire [31:0] src_ip, dst_ip,
    input  wire [15:0] dst_port,
    input  wire [7:0]  proto, tcp_flags,
    input  wire [15:0] pkt_size, frame_count,
    input  wire [15:0] port_thresh, host_thresh, rate_thresh,
    input  wire        in_valid,
    output reg         port_scan_hit, rate_hit, out_valid
);
```

Internals (mirror `scan_rate.v`'s 4-phase FSM):

- 4096×114 BRAM `(* ram_style="block" *) reg [113:0] mem [0:4095]`. Cell layout
  `{fp:16, epoch:4, pkt_count:14, byte_count:24, syn_count:12, dport_fp:16, dhost_fp:16, flags:8} = 110`
  (epoch is 4-bit not 8 — same as v1.1; sizing.py's 8-bit budget was loose). Pad cell to 114
  to match the spec — 4 reserved bits.
- Phase 0: latch the 4 hashes (bucket, fp, port_bit, host_bit) in registers (DSP-isolated).
- Phase 1: BRAM read latency.
- Phase 2: rdata valid; compute `eff` (fp+epoch match? then keep state, else blank); update
  counters; write back. Latch new counts to s* scratch regs.
- Phase 3: popcount + threshold compare → `port_scan_hit`, `rate_hit`; pulse `out_valid`.

**Use the cms.v 4-phase pattern as the template** — it's the proven shape. Critical-path
isolation: keep the popcount + 3 magnitude compares in phase 3, off the BRAM-read+RMW path.

- [ ] **Step 1:** Write `tb_flow_table.v` driving the SAME stream as `tb_scan_rate.v` (so we
  can sanity-check the per-source semantics match v1.1 in the no-collision case), plus a
  directed collision test using the same `src_a`/`src_b` pair from `test_flow_table_model.py`.
  Assert `port_scan_hit`/`rate_hit` per the twin.
- [ ] **Step 2:** Add `flow_table.v` + `tb_flow_table.v` to `run_sim.tcl`; sim → FAIL.
- [ ] **Step 3:** Implement `flow_table.v`.
- [ ] **Step 4:** Sim → `PASS: tb_flow_table ...` + full suite still green (now 14 tbs).
- [ ] **Step 5: Commit** — `add flow_table stage`.

## Task 4: `rule_lookup.v` + `tb_rule_lookup.v`

**Files:** Create `fpga/src/rule_lookup.v`, `fpga/sim/tb_rule_lookup.v`; modify `run_sim.tcl`.

```verilog
module rule_lookup (
    input  wire        clk, rst,
    input  wire [31:0] src_ip,
    input  wire        in_valid,
    input  wire [7:0]  current_rule_epoch,
    // wires to rule_store
    output wire [8:0]  rs_r_idx,
    input  wire [71:0] rs_r_rule,
    // outputs
    output reg         match, out_valid,
    output reg  [7:0]  action,
    output reg  [3:0]  severity
);
    localparam [31:0] A1 = 32'h9E3779B1;
    assign rs_r_idx = ((src_ip * A1) >> 23) & 9'h1FF;        // combinational hash
    // ... 2-phase FSM: phase 0 issue read (registers bidx, src_ip_lat); phase 1 rs_r_rule
    // valid, decode {stored_src:32, stored_action:8, stored_sev:8(low4), stored_epoch:8}
    // from the 72-bit rule per PROTOCOL.md, set match + out_valid.
```

- [ ] **Step 1:** Write `tb_rule_lookup.v`. Preload a few rule_store entries directly (drive
  `rs_r_rule` from the tb, bypassing the Pi-side path), query several src_ips, assert
  match/no-match + action/severity passthrough. Cover: match, src_ip differs, epoch differs.
- [ ] **Step 2:** Add to `run_sim.tcl`; sim → FAIL.
- [ ] **Step 3:** Implement `rule_lookup.v`.
- [ ] **Step 4:** Sim → PASS.
- [ ] **Step 5: Commit** — `add rule_lookup stage`.

## Task 5: extend `thresholds.v` with `id=0x03 rule_epoch`

**Files:** Modify `fpga/src/thresholds.v`, `fpga/sim/tb_thresholds.v`, `thresholds_model.py`,
`test_thresholds_model.py`.

- [ ] **Step 1:** Add `RULE_EPOCH = 0x03` to `thresholds_model.py`'s `_DEFAULTS` (default 0),
  add an output property `rule_epoch` for the twin. Add a failing test.
- [ ] **Step 2:** Implement: dict entry added; reads/writes route. Run pytest → pass.
- [ ] **Step 3:** Extend `thresholds.v`: add `reg [7:0] rule_epoch_r` (default 0 on reset),
  case branch for `w_id == 8'h03`, output `rule_epoch[7:0]` tap. Extend `tb_thresholds.v` to
  assert id-0x03 write/read.
- [ ] **Step 4:** Sim → PASS for tb_thresholds.
- [ ] **Step 5: Commit** — `add rule_epoch threshold (id 0x03)`.

## Task 6: swap `scan_rate`→`flow_table` in `classifiers.v` + verdict combine

**Files:** Modify `fpga/src/classifiers.v`, `fpga/sim/tb_classifiers.v`.

- [ ] **Step 1:** Edit `classifiers.v`:
  - Instantiate `flow_table` instead of `scan_rate` (port-compatible).
  - Instantiate `rule_lookup` fed by `src_ip` + `fields_valid`.
  - Pass through new ports: `current_rule_epoch:8`, `rs_r_idx:9`, `rs_r_rule:72` (latter two
    wire out to nids_top → rule_store).
  - Verdict combine extends `hit_mask` to 4 bits: `{rule_match, rate_hit, ps_hit, bloom_hit}`.
    Severity becomes `max(classifier_sev, rule_sev[1:0])`. Escalate ORs `rule_action[2]`.
- [ ] **Step 2:** Update `tb_classifiers.v` to drive `current_rule_epoch=0` and tie the new
  rule_store wires to "no rule" (rs_r_rule = 72'd0). Existing test stream should still PASS
  (no rules in store → no rule_match → original verdict signals unchanged).
- [ ] **Step 3:** Sim → `PASS: tb_classifiers` + suite green.
- [ ] **Step 4: Commit** — `swap scan_rate->flow_table in classifiers; add rule_lookup`.

## Task 7: `nids_top.v` — wire flow_table + rule_lookup + mux rule_store.r_idx

**Files:** Modify `fpga/src/nids_top.v`, `fpga/sim/tb_nids_top.v`, `fpga/build.tcl`.

- [ ] **Step 1:** Edit `nids_top.v`:
  - `thresholds.v` now exposes a `rule_epoch` tap; route into classifiers.
  - `rule_store.r_idx` becomes a mux: `rs_r_idx = (ctrl_now && opcode==8'h15) ? op_b0_1[8:0] : classifier_rs_r_idx`. The mux holds (registered or combinational — combinational is fine, no functional conflict since 0x15 frames don't go through classify_now).
  - Wire `classifier_rs_r_idx` from classifiers.v's `rule_lookup` output.
- [ ] **Step 2:** Extend `tb_nids_top.v`: after the existing rule round-trip
  (RUL_W/RUL_R), send a CLASSIFY frame whose src_ip matches the rule's src_ip; capture the
  verdict; assert `mask[3] == 1` (rule_match) and `severity == max(default, rule.severity)`.
- [ ] **Step 3:** Add `flow_table.v` + `rule_lookup.v` to `build.tcl`'s `add_files`.
- [ ] **Step 4:** Sim → full 15 tbs PASS (was 13; +tb_flow_table + tb_rule_lookup).
- [ ] **Step 5: Commit** — `wire flow_table + rule_lookup into nids_top`.

## Task 8: `closed_loop.py` + test_closed_loop.py

**Files:** Create `closed_loop.py`, `test_closed_loop.py`.

`closed_loop.py` (~80 lines):

```python
#!/usr/bin/env python3
"""Closed loop: poll snapshot every --interval s; if top1_count >= --trigger, push a block
rule for top1_key via opcode 0x12 at the symmetric lookup hash. Pi treats verdicts as
advisory; FPGA flips mask bit 3 (rule_match) on classify frames for that source."""
import argparse, sys, time, socket
from spi_link import SpiLink, FRAME_LEN
from telemetry import decode_snapshot
from control import encode_rule_write, encode_threshold_read, decode_threshold_read

A1, MASK32 = 0x9E3779B1, 0xFFFFFFFF
def lookup_idx(ip): return (((ip * A1) & MASK32) >> 23) & 0x1FF
def fmt_ip(x): return socket.inet_ntoa(x.to_bytes(4, "big"))

OP_SNAPSHOT, OP_RULE_W, OP_THRESH_R = 0x02, 0x12, 0x14
SNAP_REQ = b"\x00" * 16 + bytes([OP_SNAPSHOT]) + b"\x00" * 15
THR_RULE_EPOCH = 0x03
def thr_read_req(tid): return bytes([tid]) + b"\x00" * 15 + bytes([OP_THRESH_R]) + b"\x00" * 15

def poll_snapshot(link):
    link.send_frame(SNAP_REQ); return link.send_frame(bytes(FRAME_LEN))

def read_rule_epoch(link):
    link.send_frame(thr_read_req(THR_RULE_EPOCH))
    return decode_threshold_read(link.send_frame(bytes(FRAME_LEN)))["value"] & 0xFF

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--trigger",  type=int,   default=8, help="top1 count to push a rule")
    ap.add_argument("--action",   type=lambda x: int(x, 0), default=0b101)
    ap.add_argument("--severity", type=int,   default=3)
    args = ap.parse_args()
    with SpiLink() as link:
        epoch = read_rule_epoch(link)
        seen = set()                                        # don't re-push the same key
        while True:
            rx = poll_snapshot(link)
            if rx[0] != 0x5A: time.sleep(args.interval); continue
            s = decode_snapshot(rx)
            if s.top1_count >= args.trigger and s.top1_key not in seen:
                idx = lookup_idx(s.top1_key)
                rule = {"src_ip": s.top1_key, "action": args.action,
                        "severity": args.severity, "epoch": epoch}
                link.send_frame(encode_rule_write(idx, rule))
                link.send_frame(bytes(FRAME_LEN))           # consume ack
                seen.add(s.top1_key)
                print(f"window {s.window}: pushed rule -> block {fmt_ip(s.top1_key)} "
                      f"(count {s.top1_count}, idx {idx})")
            time.sleep(args.interval)

if __name__ == "__main__":
    sys.exit(main() or 0)
```

`test_closed_loop.py` — pure-logic test of the **decision** (not the SPI side):

```python
from closed_loop import lookup_idx           # only the hash helper -- the policy lives in main
from rule_lookup_model import lookup_idx as ref_lookup_idx

def test_idx_hash_matches_rule_lookup_twin():
    """The Pi's lookup_idx MUST match the FPGA's rule_lookup hash exactly."""
    for ip in [0x0A000001, 0xCB007105, 0xC0000201, 0xFFFFFFFF, 0x00000001]:
        assert lookup_idx(ip) == ref_lookup_idx(ip)
```

- [ ] **Step 1:** Write the test (failing — module doesn't exist).
- [ ] **Step 2:** Implement `closed_loop.py`.
- [ ] **Step 3:** Run, pass.
- [ ] **Step 4: Commit** — `add closed_loop policy script`.

## Task 9: build + WNS check + silicon validation

**Files:** none modified — validation only. Refresh `docs/reports/*` if WNS changed materially.

- [ ] **Step 1:** Build `nids_top` over SSH (background, `Performance_ExtraTimingOpt` already
  in `build.tcl` from step 1). Confirm `BITSTREAM_OK` and **WNS > 0** (currently +0.289 ns;
  flow_table is the same FSM shape as scan_rate but bigger BRAM + fp-compare; rule_lookup is a
  registered mux on rule_store output — small additional logic). Refresh `docs/reports/`
  utilization + timing.
- [ ] **Step 2:** Flash. scp new Pi modules (`flow_table_model.py rule_lookup_model.py
  closed_loop.py silicon_loop_demo.py`) to the Pi.
- [ ] **Step 3:** **v1.1 regression** — `spi_verdict_check.py`. Expected: **120/120**, but
  the spec's known-good-improvement risk fires here if the v1.1 golden stream had a
  256-bucket hash collision that step-3's eviction would resolve differently. If <120/120,
  the divergent rows are documented (see "regression watch" in the design doc) — regenerate
  goldens from the new twin and verify the diff is *only* the rows v1.1 was silently merging.
- [ ] **Step 4:** **Step 1 + 2 regressions** — `silicon_telemetry_check.py` (5/5),
  `silicon_runtime_check.py` (3/3 incl. rule round-trip).
- [ ] **Step 5:** **Step 3 directed silicon test** — `silicon_flow_check.py` (new, small):
  drives the `flow_table_model` test's collision stream (`src_a` 4 SYNs + `src_b` 1 SYN +
  `src_a` again), captures verdicts, asserts `src_a`'s 6th packet does NOT trip port_scan
  (would have under v1.1's silent merge).
- [ ] **Step 6:** **Step 4 closed-loop demo** — start `closed_loop.py --trigger 8 &` on the
  Pi; flood 9 packets from one src via `silicon_telemetry_check`'s stream pattern; within
  ~2 s observe (a) the snapshot's top1 spikes, (b) the script pushes a rule, (c) subsequent
  classify frames for that src come back with `mask[3]==1` and severity max'd. Captured to
  `docs/step4_demo.log`.
- [ ] **Step 7: Commit** — `silicon: step-3+4 validation (flow eviction + closed-loop demo)`.

---

## Self-Review

- **Spec coverage:**
  - Step 3 flow_table (replacement, 4096 buckets, 16-bit fp, eviction-on-collision) → Tasks 1, 3, 6.
  - Step 4 rule_lookup (hash to rule_store, src+epoch match) → Tasks 2, 4, 6.
  - rule_epoch threshold (id 0x03) → Task 5.
  - nids_top wiring + r_idx mux → Task 7.
  - Closed-loop Pi policy → Task 8.
  - Build + WNS + silicon (v1.1 + step-1 + step-2 regressions + step-3 collision + step-4
    closed loop demo) → Task 9.
- **Placeholder scan:** constants/layouts/interfaces pinned in the "Locked design constants"
  block; both Python twins given in full; HDL specified by interface + notes + golden-vector
  contract (the twin is the behavioral spec). No TBD. ✔
- **Type consistency:** `lookup_idx` is the same hash in `rule_lookup_model.py`,
  `closed_loop.py`, and `rule_lookup.v`; field names in `_blank` match the storage format.
  `bucket`/`fp` helpers match between twin and HDL by construction (same constants).
  Threshold IDs `PORT/HOST/RATE/RULE_EPOCH = 0x00/0x01/0x02/0x03` consistent across HDL and
  Python.

## Unresolved / watch

- v1.1 silicon regression may drop below 120/120 if the existing golden stream encoded a
  v1.1 silent-merge collision — design doc treats this as known-good improvement; Task 9
  Step 3 handles by diffing + selectively regenerating.
- WNS pressure from the verdict combine (more inputs muxed now). If it drops below ~+0.1 ns,
  pipeline `classifiers.v`'s verdict combine into its own register stage (one cycle of latency
  added; doesn't affect frame timing at 8 MHz).
- CMS BRAM inference (audit MED #5) — fix opportunistically during the Task 9 build if the
  one-block-per-bank SDP refactor is quick; otherwise carry forward to `audit-followups.md`.
- `flow_table.v` cell width: spec said 100b (sizing.py); audit re-deriv = 98b actual fields;
  this plan uses 110b real + 4 reserved = 114b (114 = 13 RAMB36/bank in 4096×9). The extra
  +14b is the 16-bit fingerprint that makes "collision handling" actually mean something.
  Documented in design doc.
