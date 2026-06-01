# Step 5 synthetic demo — implementation plan

**Goal:** ship the v2 capstone — a single-process synthetic-mode demo that
visibly drives the closed loop on the Pi 4B + FPGA, with a curses dashboard.

**Architecture:** single Python process owns `/dev/spidev0.0`; event loop pulls
frames from a scenario iterator, sends each over SPI, decodes the returned
verdict, periodically polls snapshot, pushes a rule when the trigger trips,
renders curses dashboard.

**Tech stack:** Python 3.11, stdlib `curses`, existing `spi_link.py`,
`verdict.py`, `telemetry.py`, `control.py`. No new dependencies.

---

## File map

| File | Responsibility |
|---|---|
| `demo/__init__.py` | empty marker |
| `demo/scenarios.py` | frame generators + Schedule |
| `demo/orchestrator.py` | event loop, SPI link, rule push logic, DemoState |
| `demo/dashboard.py` | curses render + headless text logger |
| `run_demo.py` | CLI entry, argparse, curses.wrapper |
| `tests/test_scenarios.py` | scenario generator unit tests |
| `tests/test_orchestrator.py` | orchestrator logic with mocked SpiLink |
| `docs/STEP5_DEMO.md` | how to run, expected output |

---

## Task 1 — scenarios: frame builder + benign generator

**Files:** Create `demo/__init__.py`, `demo/scenarios.py`, `tests/test_scenarios.py`.

- [ ] **Step 1.1: failing test for frame structure**

```python
# tests/test_scenarios.py
import struct
from demo.scenarios import build_classify_frame, benign

def test_build_classify_frame_layout():
    f = build_classify_frame(src_ip=0xC0000201, dst_ip=0xC0000202,
                             src_port=12345, dst_port=80, proto=6, flags=0x02, size=64)
    assert len(f) == 32
    assert f[0:4] == (0xC0000201).to_bytes(4, "big")
    assert f[4:8] == (0xC0000202).to_bytes(4, "big")
    assert int.from_bytes(f[8:10], "big") == 12345
    assert int.from_bytes(f[10:12], "big") == 80
    assert f[12] == 6
    assert f[13] == 0x02
    assert int.from_bytes(f[14:16], "big") == 64
    assert f[16] == 0x00                                # opcode = classify
    assert f[17:32] == bytes(15)
```

Run: `pytest tests/test_scenarios.py::test_build_classify_frame_layout -v`
Expected: FAIL (module not found).

- [ ] **Step 1.2: write `demo/__init__.py`**

```python
# demo/__init__.py
"""Step-5 synthetic demo orchestrator + scenarios + curses dashboard."""
```

- [ ] **Step 1.3: implement `build_classify_frame`**

```python
# demo/scenarios.py
"""Synthetic adversary + benign frame generators for the step-5 capstone demo.

Each generator yields 32-byte classify frames (opcode 0x00) with the layout
documented in PROTOCOL.md (matches packet_capture.py:50-55). Generators are
deterministic given a seed so tests can pin behavior.
"""
import random
import struct
from dataclasses import dataclass
from typing import Iterator, Sequence

FRAME_LEN = 32
OP_CLASSIFY = 0x00

# Locked C2 set (sourced from fpga/src/bloom_init.mem; mirrored in tb_classifiers.v:5).
C2_IPS = (0xC6336401,    # 198.51.100.1
          0xCB007105,    # 203.0.113.5
          0xC0000263)    # 192.0.2.99 ... wait, the locked set is 198.51.100.1 / 203.0.113.5 / 192.0.2.99
# 192.0.2.99 = 0xC0000263, so the third entry is correct as 0xC0000263.


def build_classify_frame(*, src_ip: int, dst_ip: int, src_port: int = 0,
                         dst_port: int = 0, proto: int = 17, flags: int = 0,
                         size: int = 64) -> bytes:
    """Pack one 32-byte classify frame; matches PROTOCOL.md / packet_capture.py layout."""
    f = bytearray(FRAME_LEN)
    f[0:4]   = (src_ip   & 0xFFFFFFFF).to_bytes(4, "big")
    f[4:8]   = (dst_ip   & 0xFFFFFFFF).to_bytes(4, "big")
    f[8:10]  = (src_port & 0xFFFF).to_bytes(2, "big")
    f[10:12] = (dst_port & 0xFFFF).to_bytes(2, "big")
    f[12]    = proto & 0xFF
    f[13]    = flags & 0xFF
    f[14:16] = (size & 0xFFFF).to_bytes(2, "big")
    f[16]    = OP_CLASSIFY
    return bytes(f)
```

- [ ] **Step 1.4: rerun and pass**

Run: `pytest tests/test_scenarios.py::test_build_classify_frame_layout -v`
Expected: PASS.

- [ ] **Step 1.5: failing test for benign**

Add to `tests/test_scenarios.py`:

```python
def test_benign_diverse_srcs():
    frames = list(benign(seed=1, count=100))
    srcs = {int.from_bytes(f[0:4], "big") for f in frames}
    assert len(frames) == 100
    assert len(srcs) >= 10                           # diverse
    # benign uses RFC5737 / RFC1918 — no C2 sources
    from demo.scenarios import C2_IPS
    assert not (srcs & set(C2_IPS))
```

Run: FAIL — `benign` not defined.

- [ ] **Step 1.6: implement `benign`**

Add to `demo/scenarios.py`:

```python
# RFC5737 documentation pools — public-repo safe. 198.51.100.0/24 and 203.0.113.0/24
# are reserved for documentation. RFC1918 192.168.x for variety. No collisions with
# the locked C2 set.
_BENIGN_SRC_POOLS = (
    (0xC0A80000, 0xFFFFFF00),    # 192.168.0.0/24
    (0xC0A80100, 0xFFFFFF00),    # 192.168.1.0/24
    (0xC0A80200, 0xFFFFFF00),    # 192.168.2.0/24
)
_BENIGN_DST = 0x0A000020
_BENIGN_DPORTS = (53, 80, 443, 8080)


def _is_c2(ip: int) -> bool:
    return ip in C2_IPS


def benign(seed: int = 0, count: int | None = None) -> Iterator[bytes]:
    """Diverse-source UDP traffic, no C2 IPs, low packets-per-source. Trips nothing."""
    rng = random.Random(seed)
    emitted = 0
    while count is None or emitted < count:
        base, mask = rng.choice(_BENIGN_SRC_POOLS)
        src = base | (rng.randint(1, 254) & ~mask & 0xFF)
        if _is_c2(src):                              # defensive; pools don't overlap
            continue
        dport = rng.choice(_BENIGN_DPORTS)
        yield build_classify_frame(src_ip=src, dst_ip=_BENIGN_DST,
                                   dst_port=dport, proto=17, size=rng.randint(64, 512))
        emitted += 1
```

- [ ] **Step 1.7: rerun and pass**

Run: `pytest tests/test_scenarios.py -v`
Expected: 2 passing.

- [ ] **Step 1.8: commit**

```bash
git add demo/__init__.py demo/scenarios.py tests/test_scenarios.py
git commit -q -m "demo scenarios: frame builder + benign generator"
```

---

## Task 2 — scenarios: c2 / port_scan / flood

**Files:** Modify `demo/scenarios.py`, `tests/test_scenarios.py`.

- [ ] **Step 2.1: failing tests**

```python
def test_c2_only_c2_srcs():
    frames = list(c2(seed=2, count=30))
    srcs = {int.from_bytes(f[0:4], "big") for f in frames}
    from demo.scenarios import C2_IPS
    assert srcs <= set(C2_IPS)
    assert len(srcs) == 3                            # cycles through all three


def test_port_scan_one_src_distinct_dports():
    frames = list(port_scan(src_ip=0x0A000005, count=12))
    srcs = {int.from_bytes(f[0:4], "big") for f in frames}
    dports = [int.from_bytes(f[10:12], "big") for f in frames]
    assert srcs == {0x0A000005}
    assert dports == sorted(set(dports))             # strictly increasing
    assert all(f[13] & 0x02 for f in frames)         # SYN flag set


def test_flood_mono_src_mono_dport():
    frames = list(flood(src_ip=0x0A000006, dst_port=443, count=20))
    srcs = {int.from_bytes(f[0:4], "big") for f in frames}
    dports = {int.from_bytes(f[10:12], "big") for f in frames}
    assert srcs == {0x0A000006}
    assert dports == {443}
    assert all(f[13] & 0x02 for f in frames)
```

Run: FAIL — generators not defined.

- [ ] **Step 2.2: implement the three generators**

Append to `demo/scenarios.py`:

```python
def c2(seed: int = 0, count: int | None = None,
       dst_ip: int = 0x0A000020) -> Iterator[bytes]:
    """Source rotates through the locked C2 IPs. Trips bloom (mask bit 0)."""
    rng = random.Random(seed)
    emitted = 0
    while count is None or emitted < count:
        src = C2_IPS[emitted % len(C2_IPS)]
        yield build_classify_frame(src_ip=src, dst_ip=dst_ip,
                                   dst_port=rng.choice((80, 443, 8443)),
                                   proto=6, flags=0x02, size=64)
        emitted += 1


def port_scan(src_ip: int, count: int = 12,
              dst_ip: int = 0x0A000020,
              start_port: int = 20) -> Iterator[bytes]:
    """One source, strictly increasing distinct dports. Trips port_scan (bit 1)."""
    for i in range(count):
        yield build_classify_frame(src_ip=src_ip, dst_ip=dst_ip,
                                   dst_port=start_port + i, proto=6,
                                   flags=0x02, size=64)


def flood(src_ip: int, count: int = 20, dst_ip: int = 0x0A000020,
          dst_port: int = 443) -> Iterator[bytes]:
    """One src, same dport, many packets. Trips rate (bit 2) and, with the closed-loop
    orchestrator, eventually rule_match (bit 3)."""
    for _ in range(count):
        yield build_classify_frame(src_ip=src_ip, dst_ip=dst_ip,
                                   dst_port=dst_port, proto=6, flags=0x02, size=64)
```

- [ ] **Step 2.3: pass tests**

Run: `pytest tests/test_scenarios.py -v`
Expected: 5 passing.

- [ ] **Step 2.4: commit**

```bash
git add demo/scenarios.py tests/test_scenarios.py
git commit -q -m "demo scenarios: c2 / port_scan / flood generators"
```

---

## Task 3 — scenarios: Schedule

**Files:** Modify `demo/scenarios.py`, `tests/test_scenarios.py`.

- [ ] **Step 3.1: failing test**

```python
def test_default_schedule_transitions():
    from demo.scenarios import default_schedule
    sched = default_schedule()
    names = [name for (name, _gen, _dur) in sched.steps]
    assert names == ["benign", "c2", "port_scan", "flood", "benign"]
    durations = [dur for (_n, _g, dur) in sched.steps]
    assert durations == [10.0, 10.0, 10.0, 15.0, 15.0]


def test_schedule_iterate_yields_frames():
    from demo.scenarios import default_schedule
    sched = default_schedule()
    it = sched.frames(monotonic_now=lambda: 0.0)     # frozen clock
    frame = next(it)
    assert len(frame) == 32 and frame[16] == 0x00
```

Run: FAIL.

- [ ] **Step 3.2: implement `Schedule`**

Append to `demo/scenarios.py`:

```python
import time
from collections.abc import Callable


@dataclass
class ScheduleStep:
    name: str
    gen_factory: Callable[[], Iterator[bytes]]
    duration_s: float


class Schedule:
    """A sequence of (name, generator-factory, duration). Iterating frames() advances
    through the steps based on wall-clock time elapsed since first call."""
    def __init__(self, steps: Sequence[ScheduleStep]):
        self.steps = list(steps)

    def total_s(self) -> float:
        return sum(s.duration_s for s in self.steps)

    def active_name(self, elapsed_s: float) -> str:
        t = 0.0
        for s in self.steps:
            t += s.duration_s
            if elapsed_s < t:
                return s.name
        return self.steps[-1].name

    def frames(self, monotonic_now: Callable[[], float] = time.monotonic) -> Iterator[bytes]:
        """Yields frames forever (or until schedule exhausts). Switches generator at each step boundary."""
        start = monotonic_now()
        for s in self.steps:
            end = start + sum(p.duration_s for p in self.steps[:self.steps.index(s) + 1])
            gen = s.gen_factory()
            while monotonic_now() < end:
                try:
                    yield next(gen)
                except StopIteration:
                    gen = s.gen_factory()            # restart bounded generator within step
                    yield next(gen)


def default_schedule() -> Schedule:
    """0-10s benign, 10-20s c2, 20-30s port_scan from 10.0.0.5, 30-45s flood from 10.0.0.6,
    45-60s benign. The flood from 10.0.0.6 trips rate AND becomes top1 -> closed-loop rule push."""
    return Schedule([
        ScheduleStep("benign",    lambda: benign(seed=0),                    10.0),
        ScheduleStep("c2",        lambda: c2(seed=1),                        10.0),
        ScheduleStep("port_scan", lambda: port_scan(src_ip=0x0A000005),      10.0),
        ScheduleStep("flood",     lambda: flood(src_ip=0x0A000006, count=10_000), 15.0),
        ScheduleStep("benign",    lambda: benign(seed=2),                    15.0),
    ])
```

- [ ] **Step 3.3: pass**

Run: `pytest tests/test_scenarios.py -v`
Expected: 7 passing.

- [ ] **Step 3.4: commit**

```bash
git add demo/scenarios.py tests/test_scenarios.py
git commit -q -m "demo schedule: default 60s scripted run"
```

---

## Task 4 — orchestrator: DemoState + verdict recording

**Files:** Create `demo/orchestrator.py`, `tests/test_orchestrator.py`.

- [ ] **Step 4.1: failing test**

```python
# tests/test_orchestrator.py
from demo.orchestrator import DemoState, record_verdict
from verdict import Verdict

def test_record_verdict_appends_and_caps():
    state = DemoState(scenario_name="benign", start_monotonic=0.0)
    for i in range(20):
        record_verdict(state, Verdict(valid=True, mask=0, severity=0, escalate=False,
                                      bloom_hit=False, port_scan_hit=False,
                                      rate_anomaly=False, rule_match=False, seq=i & 0xFF))
    assert len(state.recent_verdicts) == 12          # capped
    assert state.recent_verdicts[-1].seq == 19
```

Run: FAIL.

- [ ] **Step 4.2: implement**

```python
# demo/orchestrator.py
"""Step-5 demo orchestrator: single-process event loop owning the SPI link.

Pulls 32-byte classify frames from a scenario iterator, sends each frame over SPI,
decodes the verdict the FPGA returns (one-frame lag), periodically polls snapshot,
and pushes a block-rule when a top talker emerges. Curses dashboard reads from a
DemoState — pure data, no IO."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from verdict import Verdict, decode_verdict
from telemetry import decode_snapshot, TELEMETRY_MAGIC, Snapshot
from control import encode_rule_write, encode_threshold_read, decode_threshold_read
from spi_link import SpiLink, FRAME_LEN

A1, MASK32 = 0x9E3779B1, 0xFFFFFFFF
OP_SNAPSHOT, OP_RULE_W, OP_THRESH_R = 0x02, 0x12, 0x14
THR_RULE_EPOCH = 0x03
VERDICTS_KEPT = 12
RULES_SHOWN = 5


def lookup_idx(ip: int) -> int:
    """Symmetric with rule_lookup.v and closed_loop.lookup_idx."""
    return (((ip * A1) & MASK32) >> 23) & 0x1FF


@dataclass
class PushedRule:
    src_ip: int
    idx: int
    pushed_at_monotonic: float


@dataclass
class DemoState:
    scenario_name: str
    start_monotonic: float
    snapshot: Optional[Snapshot] = None
    pushed_rules: list[PushedRule] = field(default_factory=list)
    recent_verdicts: deque = field(default_factory=lambda: deque(maxlen=VERDICTS_KEPT))
    rule_epoch: int = 0
    frames_sent: int = 0


def record_verdict(state: DemoState, v: Verdict) -> None:
    state.recent_verdicts.append(v)
```

- [ ] **Step 4.3: pass**

Run: `pytest tests/test_orchestrator.py -v`
Expected: 1 passing.

- [ ] **Step 4.4: commit**

```bash
git add demo/orchestrator.py tests/test_orchestrator.py
git commit -q -m "demo orchestrator: DemoState + verdict recording"
```

---

## Task 5 — orchestrator: rule-push logic with mocked link

**Files:** Modify `demo/orchestrator.py`, `tests/test_orchestrator.py`.

- [ ] **Step 5.1: failing test**

```python
def test_lookup_idx_symmetric():
    from demo.orchestrator import lookup_idx as orch_idx
    from closed_loop import lookup_idx as cl_idx
    for ip in (0xCB007105, 0x0A000005, 0xC0000201, 0xFFFFFFFF, 0x00000001):
        assert orch_idx(ip) == cl_idx(ip)


class _FakeLink:
    """Records every frame sent; returns canned responses keyed by inbound opcode."""
    def __init__(self):
        self.sent: list[bytes] = []
        self.responses: dict[int, bytes] = {}

    def send_frame(self, frame: bytes) -> bytes:
        self.sent.append(bytes(frame))
        op = frame[16]
        resp = self.responses.get(op, bytes(FRAME_LEN))
        return resp


def test_maybe_push_rule_fires_once_on_trigger():
    from demo.orchestrator import maybe_push_rule, DemoState
    from telemetry import Snapshot
    link = _FakeLink()
    state = DemoState(scenario_name="flood", start_monotonic=0.0, rule_epoch=0)
    snap = Snapshot(window=10, total=20, harmonic_sum=0, zeros=0,
                    top1_count=12, top1_key=0x0A000006)
    state.snapshot = snap
    pushed = maybe_push_rule(link, state, trigger=8, now_monotonic=lambda: 1.0)
    assert pushed is True
    # one rule-write frame was sent
    rule_writes = [f for f in link.sent if f[16] == 0x12]
    assert len(rule_writes) == 1
    assert len(state.pushed_rules) == 1
    assert state.pushed_rules[0].src_ip == 0x0A000006

    # second call: same snapshot, must NOT re-push
    pushed2 = maybe_push_rule(link, state, trigger=8, now_monotonic=lambda: 2.0)
    assert pushed2 is False
    assert len([f for f in link.sent if f[16] == 0x12]) == 1
```

Run: FAIL — `maybe_push_rule` not defined.

- [ ] **Step 5.2: implement**

Append to `demo/orchestrator.py`:

```python
def maybe_push_rule(link, state: DemoState, *, trigger: int,
                    now_monotonic=time.monotonic,
                    action: int = 0b101, severity: int = 3) -> bool:
    """If snapshot top1_count meets trigger and src is unseen, push a block-rule and
    record it. Returns True iff a rule was pushed this call."""
    s = state.snapshot
    if s is None or s.top1_count < trigger:
        return False
    if any(r.src_ip == s.top1_key for r in state.pushed_rules):
        return False
    idx = lookup_idx(s.top1_key)
    rule = {"src_ip": s.top1_key, "action": action,
            "severity": severity, "epoch": state.rule_epoch}
    link.send_frame(encode_rule_write(idx, rule))
    link.send_frame(bytes(FRAME_LEN))                # consume ack frame
    state.pushed_rules.append(PushedRule(src_ip=s.top1_key, idx=idx,
                                          pushed_at_monotonic=now_monotonic()))
    return True
```

- [ ] **Step 5.3: pass**

Run: `pytest tests/test_orchestrator.py -v`
Expected: 3 passing.

- [ ] **Step 5.4: commit**

```bash
git add demo/orchestrator.py tests/test_orchestrator.py
git commit -q -m "orchestrator: rule push fires once per src on trigger"
```

---

## Task 6 — orchestrator: snapshot polling + main loop

**Files:** Modify `demo/orchestrator.py`, `tests/test_orchestrator.py`.

- [ ] **Step 6.1: failing test**

```python
def test_poll_snapshot_updates_state():
    from demo.orchestrator import poll_snapshot, DemoState
    from telemetry import TELEMETRY_MAGIC
    link = _FakeLink()
    # canned snapshot response on the 0x02 frame: build a minimally-valid 32B response
    resp = bytearray(32)
    resp[0] = TELEMETRY_MAGIC           # 0x5A
    resp[1:3] = (42).to_bytes(2, "big")             # window
    resp[3:7] = (100).to_bytes(4, "big")            # total
    # harmonic_sum bytes 7:13 -> 0, zeros bytes 13:15 -> 0
    resp[15:17] = (7).to_bytes(2, "big")            # top1_count
    resp[17:21] = (0x0A000006).to_bytes(4, "big")   # top1_key
    link.responses[0x02] = bytes(resp)
    state = DemoState(scenario_name="flood", start_monotonic=0.0)
    poll_snapshot(link, state)
    assert state.snapshot is not None
    assert state.snapshot.top1_key == 0x0A000006
    assert state.snapshot.top1_count == 7
```

Run: FAIL.

- [ ] **Step 6.2: implement**

Append to `demo/orchestrator.py`:

```python
def _snap_frame() -> bytes:
    f = bytearray(FRAME_LEN); f[16] = OP_SNAPSHOT; return bytes(f)


def poll_snapshot(link, state: DemoState) -> None:
    """Send opcode 0x02; the response carries the snapshot for the LAST completed window.
    Magic mismatch is tolerated (window still warming) — state.snapshot stays unchanged."""
    link.send_frame(_snap_frame())
    rx = link.send_frame(bytes(FRAME_LEN))
    if rx[0] != TELEMETRY_MAGIC:
        return
    state.snapshot = decode_snapshot(rx)


def read_rule_epoch(link) -> int:
    link.send_frame(encode_threshold_read(THR_RULE_EPOCH))
    return decode_threshold_read(link.send_frame(bytes(FRAME_LEN)))["value"] & 0xFF
```

- [ ] **Step 6.3: implement `run_loop`**

Append to `demo/orchestrator.py`:

```python
def run_loop(link, schedule, *, dashboard, trigger: int = 8,
             snap_every: int = 50, fps: float = 500.0,
             duration_s: float | None = None,
             monotonic=time.monotonic, sleep=time.sleep) -> DemoState:
    """Single-process event loop. Owns nothing — link, schedule, dashboard are injected.

    Each tick:
      1. pull next frame from schedule
      2. send over SPI; decode returned verdict (1-frame lag) and record
      3. every snap_every ticks: poll snapshot, maybe push rule
      4. dashboard.render(state)

    Stops when duration_s elapses (or schedule exhausts, whichever first)."""
    epoch = read_rule_epoch(link)
    state = DemoState(scenario_name="(starting)", start_monotonic=monotonic(),
                      rule_epoch=epoch)
    tick_interval = 1.0 / fps if fps > 0 else 0.0
    frames_iter = schedule.frames(monotonic_now=monotonic)
    next_tick = monotonic()
    tick = 0
    end_at = (state.start_monotonic + duration_s) if duration_s else None

    while True:
        if end_at is not None and monotonic() >= end_at:
            break
        try:
            frame = next(frames_iter)
        except StopIteration:
            break
        state.scenario_name = schedule.active_name(monotonic() - state.start_monotonic)
        rx = link.send_frame(frame)
        state.frames_sent += 1
        v = decode_verdict(rx)
        if v.valid:
            record_verdict(state, v)
        if tick % snap_every == 0 and tick > 0:
            poll_snapshot(link, state)
            maybe_push_rule(link, state, trigger=trigger, now_monotonic=monotonic)
            if dashboard is not None:
                dashboard.render(state)
        tick += 1
        next_tick += tick_interval
        delay = next_tick - monotonic()
        if delay > 0:
            sleep(delay)
        else:
            next_tick = monotonic()                   # drift recovery
    if dashboard is not None:
        dashboard.render(state)                       # final paint
    return state
```

- [ ] **Step 6.4: failing test for run_loop**

```python
def test_run_loop_emits_frames_and_polls_snapshot():
    from demo.orchestrator import run_loop, DemoState
    from demo.scenarios import default_schedule
    from telemetry import TELEMETRY_MAGIC
    link = _FakeLink()
    # thresh-read response (rule_epoch): magic 0x5A, op 0x14, id 0x03, value 0
    thr_resp = bytearray(32); thr_resp[0] = 0x5A; thr_resp[1] = 0x14
    thr_resp[2] = 0x03; thr_resp[3:5] = (0).to_bytes(2, "big")
    link.responses[0x14] = bytes(thr_resp)
    # snapshot response with top1_count=12 (above default trigger)
    snap_resp = bytearray(32); snap_resp[0] = TELEMETRY_MAGIC
    snap_resp[15:17] = (12).to_bytes(2, "big")
    snap_resp[17:21] = (0x0A000006).to_bytes(4, "big")
    link.responses[0x02] = bytes(snap_resp)

    sched = default_schedule()

    class _NoTui:
        def render(self, state): pass

    # frozen clock so we can run a finite tick count deterministically
    state = run_loop(link, sched, dashboard=_NoTui(), trigger=8, snap_every=5,
                     fps=0, duration_s=None, monotonic=lambda: 0.0,
                     sleep=lambda *_: None)
    # ... but duration_s=None + monotonic frozen will loop forever; use a bounded sched instead
```

Actually the above test would loop forever — refactor to a bounded fake schedule:

```python
def test_run_loop_emits_frames_and_polls_snapshot():
    from demo.orchestrator import run_loop, DemoState, lookup_idx
    from demo.scenarios import Schedule, ScheduleStep, flood
    from telemetry import TELEMETRY_MAGIC

    link = _FakeLink()
    thr_resp = bytearray(32); thr_resp[0] = 0x5A; thr_resp[1] = 0x14
    thr_resp[2] = 0x03; thr_resp[3:5] = (0).to_bytes(2, "big")
    link.responses[0x14] = bytes(thr_resp)
    snap_resp = bytearray(32); snap_resp[0] = TELEMETRY_MAGIC
    snap_resp[15:17] = (12).to_bytes(2, "big")
    snap_resp[17:21] = (0x0A000006).to_bytes(4, "big")
    link.responses[0x02] = bytes(snap_resp)

    # bounded schedule: 20 frames of flood, total duration 0 (we stop on StopIteration)
    sched = Schedule([ScheduleStep("flood", lambda: flood(0x0A000006, count=20), 999.0)])

    class _NoTui:
        def render(self, state): pass

    fake_t = [0.0]
    def fake_now(): fake_t[0] += 0.001; return fake_t[0]

    state = run_loop(link, sched, dashboard=_NoTui(), trigger=8, snap_every=5,
                     fps=0, duration_s=None, monotonic=fake_now,
                     sleep=lambda *_: None)
    assert state.frames_sent == 20
    # at least one snapshot poll occurred -> rule push expected
    assert len(state.pushed_rules) == 1
    assert state.pushed_rules[0].src_ip == 0x0A000006
    assert state.pushed_rules[0].idx == lookup_idx(0x0A000006)
```

- [ ] **Step 6.5: pass**

Run: `pytest tests/test_orchestrator.py -v`
Expected: 4 passing.

- [ ] **Step 6.6: commit**

```bash
git add demo/orchestrator.py tests/test_orchestrator.py
git commit -q -m "orchestrator: snapshot poll + run_loop with injected clock"
```

---

## Task 7 — dashboard: headless text logger

**Files:** Create `demo/dashboard.py`.

The curses path is terminal-dependent and best validated by the Pi smoke test.
Build the headless path first — it's what the smoke test asserts against.

- [ ] **Step 7.1: implement headless logger**

```python
# demo/dashboard.py
"""Demo dashboard: curses TUI for live viewing + headless text logger for CI/smoke.

Both speak the same interface: render(state). The curses one paints panes; the
headless one streams human-readable lines to stderr."""
from __future__ import annotations
import curses
import sys
import time
from typing import Optional

from demo.orchestrator import DemoState


def _fmt_ip(ip: int) -> str:
    return ".".join(str((ip >> (24 - 8*i)) & 0xFF) for i in range(4))


def _verdict_line(v) -> str:
    bits = []
    if v.bloom_hit:     bits.append("bloom")
    if v.port_scan_hit: bits.append("port_scan")
    if v.rate_anomaly:  bits.append("rate")
    if v.rule_match:    bits.append("rule_match")
    tag = f"THREAT[{','.join(bits)}]" if bits else "OK"
    esc = " ESCALATE" if v.escalate else ""
    return f"seq {v.seq:3d}  {tag} sev{v.severity}{esc}"


class HeadlessDashboard:
    """Streams snapshot + rule events + last-verdict to stderr."""
    def __init__(self, stream=sys.stderr):
        self.stream = stream
        self._last_window: Optional[int] = None
        self._last_rule_count = 0

    def render(self, state: DemoState) -> None:
        s = state.snapshot
        elapsed = time.monotonic() - state.start_monotonic
        if s is not None and s.window != self._last_window:
            print(f"[{elapsed:6.2f}s] scenario={state.scenario_name:9s} "
                  f"window={s.window} total={s.total} "
                  f"top={_fmt_ip(s.top1_key)} count={s.top1_count} "
                  f"sent={state.frames_sent}",
                  file=self.stream, flush=True)
            self._last_window = s.window
        if len(state.pushed_rules) > self._last_rule_count:
            r = state.pushed_rules[-1]
            print(f"[{elapsed:6.2f}s] RULE pushed: block {_fmt_ip(r.src_ip)} (idx 0x{r.idx:03X})",
                  file=self.stream, flush=True)
            self._last_rule_count = len(state.pushed_rules)
        if state.recent_verdicts:
            v = state.recent_verdicts[-1]
            if v.bloom_hit or v.port_scan_hit or v.rate_anomaly or v.rule_match:
                print(f"[{elapsed:6.2f}s] verdict: {_verdict_line(v)}",
                      file=self.stream, flush=True)
```

- [ ] **Step 7.2: implement CursesDashboard**

Append to `demo/dashboard.py`:

```python
class CursesDashboard:
    """Three-pane curses TUI. Q quits (handled at run_demo top level)."""
    _COLOR_OK     = 1
    _COLOR_BLOOM  = 2
    _COLOR_THREAT = 3
    _COLOR_RULE   = 4

    def __init__(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(self._COLOR_OK,     curses.COLOR_GREEN,  -1)
        curses.init_pair(self._COLOR_BLOOM,  curses.COLOR_YELLOW, -1)
        curses.init_pair(self._COLOR_THREAT, curses.COLOR_RED,    -1)
        curses.init_pair(self._COLOR_RULE,   curses.COLOR_CYAN,   -1)
        stdscr.nodelay(True)

    def _verdict_color(self, v) -> int:
        if v.rule_match or v.escalate:
            return curses.color_pair(self._COLOR_THREAT)
        if v.bloom_hit or v.port_scan_hit or v.rate_anomaly:
            return curses.color_pair(self._COLOR_BLOOM)
        return curses.color_pair(self._COLOR_OK)

    def render(self, state: DemoState) -> None:
        scr = self.stdscr
        scr.erase()
        h, w = scr.getmaxyx()
        elapsed = time.monotonic() - state.start_monotonic
        title = " nids closed-loop demo — q to quit "
        scr.addstr(0, 0, title.ljust(w - 1), curses.A_REVERSE)
        scr.addstr(1, 0, f" scenario: {state.scenario_name:<10s}  uptime: {int(elapsed):3d}s "
                          f" sent: {state.frames_sent}")
        if state.snapshot is not None:
            s = state.snapshot
            scr.addstr(2, 0, f" window {s.window:5d}   distinct~{max(0, 2048 - s.zeros):4d}   "
                              f"top: {_fmt_ip(s.top1_key):15s} count {s.top1_count}")
        else:
            scr.addstr(2, 0, " window  (warming up)")

        scr.addstr(4, 0, "+- active rules " + "-" * (w - 17), curses.A_DIM)
        for i, r in enumerate(state.pushed_rules[-5:]):
            age = elapsed - (r.pushed_at_monotonic - state.start_monotonic)
            scr.addstr(5 + i, 1, f"{_fmt_ip(r.src_ip):15s}  block  idx 0x{r.idx:03X}  "
                                   f"ago {age:5.1f}s",
                       curses.color_pair(self._COLOR_RULE))

        row0 = 11
        scr.addstr(row0, 0, "+- recent verdicts " + "-" * (w - 20), curses.A_DIM)
        for i, v in enumerate(list(state.recent_verdicts)[-(h - row0 - 2):]):
            scr.addstr(row0 + 1 + i, 1, _verdict_line(v), self._verdict_color(v))

        scr.noutrefresh()
        curses.doupdate()
```

- [ ] **Step 7.3: smoke test the headless logger**

```python
# tests/test_orchestrator.py (additional)
def test_headless_dashboard_prints_on_new_window(capsys):
    from demo.dashboard import HeadlessDashboard
    from demo.orchestrator import DemoState
    from telemetry import Snapshot
    d = HeadlessDashboard()
    state = DemoState(scenario_name="x", start_monotonic=time.monotonic())
    state.snapshot = Snapshot(window=5, total=10, harmonic_sum=0, zeros=2000,
                              top1_count=3, top1_key=0x0A000005)
    d.render(state)
    out = capsys.readouterr().err
    assert "window=5" in out and "10.0.0.5" in out
```

Run: `pytest tests/test_orchestrator.py -v`
Expected: 5 passing.

- [ ] **Step 7.4: commit**

```bash
git add demo/dashboard.py tests/test_orchestrator.py
git commit -q -m "demo dashboard: headless logger + curses TUI"
```

---

## Task 8 — run_demo.py CLI

**Files:** Create `run_demo.py`.

- [ ] **Step 8.1: implement**

```python
#!/usr/bin/env python3
"""Step-5 capstone: synthetic-mode closed-loop demo on Pi 4B.

    sudo python3 run_demo.py                          # default 60s scripted schedule + curses
    sudo python3 run_demo.py --scenario flood         # one scenario, run forever
    sudo python3 run_demo.py --no-tui --duration 15   # CI smoke: streaming text log
"""
import argparse
import curses
import sys

from spi_link import SpiLink
from demo.orchestrator import run_loop
from demo.dashboard import CursesDashboard, HeadlessDashboard
from demo.scenarios import (default_schedule, Schedule, ScheduleStep,
                            benign, c2, port_scan, flood)


_SOLO = {
    "benign":    lambda: benign(seed=0),
    "c2":        lambda: c2(seed=0),
    "port_scan": lambda: port_scan(src_ip=0x0A000005),
    "flood":     lambda: flood(src_ip=0x0A000006, count=10_000),
}


def _build_schedule(args):
    if args.scenario:
        if args.scenario not in _SOLO:
            print(f"unknown scenario {args.scenario}", file=sys.stderr); sys.exit(2)
        gen = _SOLO[args.scenario]
        return Schedule([ScheduleStep(args.scenario, gen, args.duration or 60.0)])
    return default_schedule()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", choices=list(_SOLO.keys()),
                    help="pin one scenario instead of the scripted schedule")
    ap.add_argument("--duration", type=float, default=None,
                    help="seconds to run (default: scripted=60s, --scenario=forever)")
    ap.add_argument("--trigger", type=int, default=8,
                    help="top1 count that triggers a rule push (default 8)")
    ap.add_argument("--fps", type=float, default=500.0,
                    help="target classify frames per second (default 500)")
    ap.add_argument("--no-tui", action="store_true",
                    help="stream text log to stderr instead of curses TUI")
    args = ap.parse_args()
    schedule = _build_schedule(args)
    duration = args.duration if args.duration is not None else (schedule.total_s() if not args.scenario else None)

    def _go(dashboard):
        with SpiLink() as link:
            run_loop(link, schedule, dashboard=dashboard, trigger=args.trigger,
                     fps=args.fps, duration_s=duration)

    if args.no_tui:
        _go(HeadlessDashboard())
    else:
        curses.wrapper(lambda stdscr: _go(CursesDashboard(stdscr)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 8.2: import-smoke test**

```python
# tests/test_orchestrator.py (additional)
def test_run_demo_imports():
    import run_demo
    assert callable(run_demo.main)
```

Run: `pytest tests/test_orchestrator.py -v`
Expected: 6 passing.

- [ ] **Step 8.3: commit**

```bash
git add run_demo.py tests/test_orchestrator.py
git commit -q -m "run_demo: CLI entry with --scenario / --duration / --no-tui"
```

---

## Task 9 — full pytest run

- [ ] **Step 9.1: run all tests locally**

```bash
pytest -q
```

Expected: all existing 142 + new step-5 tests pass.

If anything red, fix before proceeding.

---

## Task 10 — Pi 4B smoke test

- [ ] **Step 10.1: deploy demo/ to Pi**

```bash
rsync -av demo/ run_demo.py claw:~/
```

- [ ] **Step 10.2: smoke flood scenario**

```bash
ssh -o ClearAllForwardings=yes claw 'sudo python3 run_demo.py --no-tui --scenario flood --duration 15' 2>&1 | tee /tmp/step5_flood.log
```

Expected output contains:
- `RULE pushed: block 10.0.0.6` (rule push fired)
- `verdict: ... THREAT[...rule_match...]` (rule_match observed after push)

- [ ] **Step 10.3: full 60s demo**

```bash
ssh -o ClearAllForwardings=yes claw 'sudo python3 run_demo.py --no-tui --duration 60' 2>&1 | tee /tmp/step5_full.log
```

Expected output contains evidence of all four scenario phases AND verdicts with
bloom, port_scan, rate, rule_match bits set across the run.

- [ ] **Step 10.4: commit logs as evidence**

```bash
mkdir -p docs/demo_logs
cp /tmp/step5_flood.log /tmp/step5_full.log docs/demo_logs/
git add docs/demo_logs/
git commit -q -m "step-5 demo logs: flood smoke + 60s scripted run"
```

---

## Task 11 — documentation + memory + final push

- [ ] **Step 11.1: write `docs/STEP5_DEMO.md`**

Content (write it):

```markdown
# Step 5 — synthetic-mode closed-loop demo

The v2 capstone. A single Python process on the Pi 4B generates parameterized
adversarial traffic, feeds it to the FPGA over SPI, polls telemetry, pushes
runtime rules when a top talker emerges, and renders a live curses dashboard.

## Run it

    sudo python3 run_demo.py

Default 60-second scripted schedule: 10s benign -> 10s C2 -> 10s port scan ->
15s flood (closed loop pushes block-rule mid-scenario) -> 15s benign.

Q to quit early.

## Other modes

    sudo python3 run_demo.py --scenario flood          # one scenario forever
    sudo python3 run_demo.py --scenario c2 --duration 20
    sudo python3 run_demo.py --no-tui --duration 60    # streaming text log (CI / screencap-friendly)

## Expected output (text-log mode)

    [  0.10s] scenario=benign    window=1 total=42 top=192.168.0.117 count=2 sent=50
    [ 10.45s] scenario=c2        window=11 total=120 top=192.0.2.99 count=43 sent=5021
    [ 10.45s] verdict: seq  47  THREAT[bloom] sev3 ESCALATE
    [ 20.51s] scenario=port_scan window=21 total=215 top=10.0.0.5 count=89 sent=10074
    [ 20.51s] verdict: seq 124  THREAT[port_scan] sev2 ESCALATE
    [ 30.12s] scenario=flood     window=31 total=358 top=10.0.0.6 count=312 sent=15103
    [ 30.62s] RULE pushed: block 10.0.0.6 (idx 0x1DD)
    [ 30.62s] verdict: seq 153  THREAT[rate,rule_match] sev3 ESCALATE

Demo logs from the silicon-validated runs live in `docs/demo_logs/`.

## Architecture summary

See `docs/superpowers/specs/2026-05-28-step5-synthetic-demo-design.md`.
```

- [ ] **Step 11.2: extend README with capstone link**

Add a short "Step 5 — closed-loop demo" section near the existing GIF block,
pointing to `docs/STEP5_DEMO.md`. Don't remove existing v1 content.

- [ ] **Step 11.3: write v2-step5-done memory**

Path: `/Users/adityakapoor/.claude/projects/-Users-adityakapoor-dev-personal-projects-pi-stuff-fpga-pi-parallel-nids/memory/v2-step5-done.md`

Fields: type=project, links to step3-4 memory, summary of what shipped, links
to demo log evidence.

Add to MEMORY.md index.

- [ ] **Step 11.4: final commit + push**

```bash
git add docs/STEP5_DEMO.md README.md
git commit -q -m "docs: STEP5_DEMO + README capstone link"
git push -q origin main
```

---

## Self-review

- All 4 specs sections have implementing tasks (scenarios T1-3, orchestrator T4-6, dashboard T7, run_demo T8).
- Testing tasks ride alongside (T1-6 each have unit tests).
- Smoke test on hardware is its own task (T10).
- No placeholders. Every step shows real code or an exact command.
- Type consistency: `DemoState`, `PushedRule`, `Snapshot`, `Verdict` names used uniformly.
- `lookup_idx` symmetric with `closed_loop.lookup_idx` and `rule_lookup.v` (asserted in T5).

## Execution

Inline execution this session (no subagent). Will mark tasks completed via TaskUpdate as we go.
