# v2 step 5 — synthetic-mode capstone demo

**Date:** 2026-05-28
**Status:** design locked, ready to plan

## Goal

Make the v2 NIDS *visibly* defend itself. A single Python process on the Pi 4B
generates parameterized adversarial traffic, feeds it to the FPGA over SPI,
polls telemetry, pushes runtime rules when a top talker emerges, and renders a
live curses dashboard. The whole observe → decide → act loop runs in one
terminal on existing hardware — no second box required.

## Why synthetic, not LAN

The FPGA cannot distinguish a 32-byte frame that came from `scapy.sniff(eth0)`
from a frame built by `bytearray(32)` and clocked straight to MOSI — `silicon_loop_demo.py`
already proves this end-to-end. Removing the sniff path eliminates the need for
a second Pi, lets the demo run deterministically anywhere we have the FPGA + Pi
4B wired, and shortens the path to "v2 done" by ~2-4 hours of physical-setup
overhead. A LAN mode is a strict extension (replace the synthetic emitter with a
sniff loop, same orchestrator) and is deferred as a polish item.

## Architecture

**Single Python process, single SPI link, event loop.** Three reasons:

1. `/dev/spidev0.0` has no frame-level lock. Concurrent `xfer2` from multiple
   processes would interleave at byte granularity and corrupt frames.
2. The existing silicon scripts already follow this pattern (`silicon_loop_demo.py`
   in particular) — it's proven.
3. No IPC, no thread coordination, no signal handling for child processes;
   Ctrl-C just exits the loop.

```
+-- run_demo.py (CLI) ----------------------------------+
| argparse -> orchestrator                              |
+-------------------------------------------------------+
                          |
                          v
+-- demo/orchestrator.py --------------------------------+
| with SpiLink() as link:                                |
|   epoch = read_rule_epoch(link)                        |
|   for frame in scenario_iter():                        |
|     verdict = link.send_frame(frame)                   |
|     state.record_verdict(decode_verdict(verdict))      |
|     if tick % SNAP_EVERY == 0:                         |
|       s = poll_snapshot(link); state.update(s)         |
|       maybe_push_rule(link, s, state, epoch)           |
|     dashboard.render(state)                            |
+--------------------------------------------------------+
            |                            |
            v                            v
+-- demo/scenarios.py ---+   +-- demo/dashboard.py -----+
| benign / c2 /          |   | curses panes + colors    |
| port_scan / flood      |   | header, rules, verdicts  |
| + schedule loader      |   +--------------------------+
+------------------------+
```

## Components

### `demo/scenarios.py` (~120 lines)

Four generators, each a Python iterator yielding 32-byte classify frames
(opcode byte 16 = 0x00):

| Generator | Trips | Pattern |
|---|---|---|
| `benign` | nothing | random RFC5737 srcs, varied dports, UDP, low rate |
| `c2` | `bloom` (bit 0) | src cycles through `198.51.100.1`, `203.0.113.5`, `192.0.2.99` |
| `port_scan` | `port_scan` (bit 1) | one src, distinct dports 1..N, SYN |
| `flood` | `rate` (bit 2) + `rule_match` (bit 3) | one src, same dport, SYN, N >> trigger |

The C2 set is sourced from `tb_classifiers.v:5` and matches the bloom_init.mem
locked at flash time.

Each generator takes `(seed, **params)` and yields frames deterministically. A
`Schedule` class composes generators with `(duration_s, generator)` tuples; the
default schedule runs 0–10 s benign, 10–20 s c2, 20–30 s port_scan, 30–45 s
flood, 45–60 s benign.

Frame layout matches `packet_capture.py:50-55`:

```
byte 0-3   src_ip       (big-endian)
byte 4-7   dst_ip
byte 8-9   src_port
byte 10-11 dst_port
byte 12    proto
byte 13    tcp_flags
byte 14-15 pkt_size
byte 16    opcode = 0x00
byte 17-31 reserved zeros
```

### `demo/orchestrator.py` (~150 lines)

Owns the SpiLink. Single event loop:

1. Pull next frame from the active scenario iterator.
2. `link.send_frame(frame)` — the 32 bytes shifted in are the verdict for the
   PREVIOUS classify (one-frame pipeline lag); decode + record.
3. Every `SNAP_EVERY` ticks (default 50, ≈100 ms at ~500 fps), poll snapshot
   (opcode 0x02). Update `DemoState.snapshot`.
4. If `s.top1_count >= trigger` and `s.top1_key not in pushed_rules`, build a
   block rule (action=0b101, severity=3, epoch=current_rule_epoch), push via
   opcode 0x12 at `lookup_idx(s.top1_key)`. Add to `pushed_rules`.
5. Call `dashboard.render(state)` (curses can no-op in headless mode).

Tick cadence is wall-clock paced: target ~500 frames/sec so the 1 s window
contains plenty of samples but the SPI bus isn't saturated. `time.monotonic`
controls pacing.

### `demo/dashboard.py` (~150 lines)

`DemoDashboard(stdscr)` with three panes:
- header: scenario name, uptime, window index, distinct cardinality, top-1
- rules: last 5 pushed rules (src_ip + age)
- verdicts: last 12 verdicts, color-coded (red THREAT+ESC, yellow bloom-only,
  green OK)

Uses `curses.halfdelay(1)` for 100 ms input timeout — Q quits, no other keys.
Decoupled from SpiLink — takes a `DemoState` snapshot via `render(state)`.
Headless mode (`--no-tui`) substitutes a streaming text logger for environments
without a TTY (e.g., CI smoke test).

### `run_demo.py` (~30 lines)

CLI entry point at repo root, next to `silicon_loop_demo.py`:

```
sudo python3 run_demo.py                          # default 60s scripted schedule
sudo python3 run_demo.py --scenario flood         # pin one scenario, run forever
sudo python3 run_demo.py --duration 30            # custom duration on default schedule
sudo python3 run_demo.py --no-tui --duration 15   # CI-friendly text log
```

Wraps orchestrator in `curses.wrapper(...)` (or bypasses when `--no-tui`).

## Demo state model

```python
@dataclass
class DemoState:
    scenario_name: str
    start_monotonic: float
    snapshot: Optional[Snapshot] = None
    pushed_rules: list[PushedRule] = field(default_factory=list)
    recent_verdicts: deque[Verdict] = field(default_factory=lambda: deque(maxlen=12))
    rule_epoch: int = 0
```

Pure data, no IO. Mocked in orchestrator tests.

## Testing strategy

| Test | What it asserts |
|---|---|
| `test_scenarios.py::test_benign_diverse_srcs` | benign iterator yields ≥10 distinct srcs over 100 frames |
| `test_scenarios.py::test_c2_only_c2_srcs` | every src in c2 is in the locked C2 set |
| `test_scenarios.py::test_port_scan_distinct_dports` | port_scan dports strictly increasing, single src |
| `test_scenarios.py::test_flood_single_src_single_dport` | flood is mono-src, mono-dport, SYN-flagged |
| `test_scenarios.py::test_frame_structure` | every yielded frame is 32 bytes with opcode=0x00 |
| `test_scenarios.py::test_schedule_transitions` | default schedule switches scenarios at correct timestamps |
| `test_orchestrator.py::test_rule_push_fires_on_trigger` | mock snapshot shows top1_count >= trigger -> rule write opcode 0x12 sent exactly once |
| `test_orchestrator.py::test_rule_push_no_repush` | second trigger for same src does NOT re-push |
| `test_orchestrator.py::test_verdict_decode_into_state` | mocked verdict bytes -> state.recent_verdicts[-1] matches |
| `test_orchestrator.py::test_lookup_idx_symmetric` | orchestrator.lookup_idx(src) == closed_loop.lookup_idx(src) |

Curses rendering itself is not unit-tested (terminal-dependent). Smoke test on
the Pi covers it.

**Smoke + integration on Pi 4B:**
- `run_demo.py --no-tui --scenario flood --duration 15` — output must contain
  at least one verdict with `rule_match` bit set after the trigger fires.
- `run_demo.py --no-tui --duration 60` — output must show verdicts with bits 0
  (bloom), 1 (port_scan), 2 (rate), 3 (rule_match) across the run.

## Files

```
demo/
  __init__.py
  scenarios.py
  orchestrator.py
  dashboard.py
tests/
  test_scenarios.py
  test_orchestrator.py
run_demo.py
docs/STEP5_DEMO.md
```

## Done criteria

1. All step-5 unit tests pass locally on Mac.
2. Pi 4B smoke test: `--scenario flood` produces ≥1 `rule_match` verdict.
3. Pi 4B full demo: 60 s scripted run observes all 4 hit_mask bits.
4. STEP5_DEMO.md documents how to run + expected output.
5. v2-step5-done memory written.
6. Final commit + push to main.

## Open questions

None. All four design forks resolved:
- Scripted 60s schedule default ✓
- Trigger = 8 (matches `closed_loop.py`) ✓
- Stdlib `curses`, no external deps ✓
- `run_demo.py` at repo root ✓
