"""Orchestrator unit tests using a fake SPI link that records sends + serves canned responses."""
from __future__ import annotations
import time

from spi_link import FRAME_LEN
from verdict import Verdict, encode_verdict, VERDICT_MAGIC
from telemetry import SnapResponse, TELEMETRY_MAGIC, encode_snapshot

from demo.orchestrator import (
    DemoState, PushedRule, record_verdict, lookup_idx,
    maybe_push_rule, poll_snapshot, read_rule_epoch, run_loop,
    OP_SNAPSHOT, OP_RULE_W, OP_THRESH_R, THR_RULE_EPOCH,
)


class FakeLink:
    """Models the FPGA's one-frame pipeline lag: the response to send N comes back on
    send N+1. responses[opcode] is the canned reply queued when that opcode goes in;
    the next send_frame call returns it. Default reply = all zeros (decode_verdict
    marks invalid -> ignored)."""
    def __init__(self):
        self.sent: list[bytes] = []
        self.responses: dict[int, bytes] = {}
        self._queued: bytes = bytes(FRAME_LEN)        # nothing in the pipe yet

    def send_frame(self, frame: bytes) -> bytes:
        self.sent.append(bytes(frame))
        out = self._queued
        self._queued = self.responses.get(frame[16], bytes(FRAME_LEN))
        return out


# ----- lookup hash symmetry with the HDL + closed_loop --------------------------------------

def test_lookup_idx_symmetric_with_closed_loop():
    from closed_loop import lookup_idx as cl_idx
    for ip in (0xCB007105, 0x0A000005, 0x0A000006, 0xC0000201, 0xFFFFFFFF, 0x00000001):
        assert lookup_idx(ip) == cl_idx(ip)


# ----- verdict bookkeeping ---------------------------------------------------------------------

def test_record_verdict_appends_and_caps():
    state = DemoState(scenario_name="benign", start_monotonic=0.0)
    for i in range(20):
        record_verdict(state, Verdict(valid=True, bloom_hit=False, port_scan=False,
                                      rate_anomaly=False, rule_match=False,
                                      severity=0, escalate=False, seq=i & 0xFF))
    assert len(state.recent_verdicts) == 12          # capped at VERDICTS_KEPT
    assert state.recent_verdicts[-1].seq == 19


# ----- rule push logic ------------------------------------------------------------------------

def _snap_response(*, window=10, total=20, harmonic_sum=0, zeros=2000,
                   top1_count=12, top1_key=0x0A000006) -> bytes:
    return encode_snapshot(window, total, harmonic_sum, zeros, top1_count, top1_key)


def test_maybe_push_rule_fires_once_on_trigger():
    link = FakeLink()
    state = DemoState(scenario_name="flood", start_monotonic=0.0, rule_epoch=0)
    state.snapshot = SnapResponse(window=10, total=20, harmonic_sum=0, zeros=2000,
                                  top1_count=12, top1_key=0x0A000006)

    assert maybe_push_rule(link, state, trigger=8, now_monotonic=lambda: 1.0) is True
    rule_writes = [f for f in link.sent if f[16] == OP_RULE_W]
    assert len(rule_writes) == 1
    assert len(state.pushed_rules) == 1
    assert state.pushed_rules[0].src_ip == 0x0A000006
    assert state.pushed_rules[0].idx == lookup_idx(0x0A000006)

    # Same snapshot still present -> must NOT re-push the same src
    assert maybe_push_rule(link, state, trigger=8, now_monotonic=lambda: 2.0) is False
    assert len([f for f in link.sent if f[16] == OP_RULE_W]) == 1


def test_maybe_push_rule_below_trigger_does_nothing():
    link = FakeLink()
    state = DemoState(scenario_name="flood", start_monotonic=0.0)
    state.snapshot = SnapResponse(window=1, total=5, harmonic_sum=0, zeros=2000,
                                  top1_count=3, top1_key=0x0A000006)
    assert maybe_push_rule(link, state, trigger=8) is False
    assert state.pushed_rules == []
    assert link.sent == []


def test_maybe_push_rule_none_snapshot():
    link = FakeLink()
    state = DemoState(scenario_name="benign", start_monotonic=0.0)
    assert maybe_push_rule(link, state, trigger=8) is False


def test_maybe_push_rule_skips_zero_top_key():
    """FPGA returns top1_key=0.0.0.0 when no source dominates (warmup / sparse window).
    The orchestrator must NOT push a rule for that junk sentinel."""
    link = FakeLink()
    state = DemoState(scenario_name="benign", start_monotonic=0.0)
    state.snapshot = SnapResponse(window=1, total=10, harmonic_sum=0, zeros=2048,
                                  top1_count=10, top1_key=0x00000000)
    assert maybe_push_rule(link, state, trigger=8) is False
    assert state.pushed_rules == []


# ----- snapshot polling -----------------------------------------------------------------------

def test_poll_snapshot_updates_state():
    link = FakeLink()
    link.responses[OP_SNAPSHOT] = _snap_response(window=42, total=100,
                                                  top1_count=7, top1_key=0x0A000006)
    state = DemoState(scenario_name="flood", start_monotonic=0.0)
    poll_snapshot(link, state)
    assert state.snapshot is not None
    assert state.snapshot.window == 42
    assert state.snapshot.top1_count == 7
    assert state.snapshot.top1_key == 0x0A000006


def test_poll_snapshot_tolerates_magic_mismatch():
    link = FakeLink()
    link.responses[OP_SNAPSHOT] = bytes(FRAME_LEN)   # magic = 0x00, not 0x5A
    state = DemoState(scenario_name="flood", start_monotonic=0.0)
    poll_snapshot(link, state)
    assert state.snapshot is None                    # silently skipped


# ----- rule_epoch read ------------------------------------------------------------------------

def test_read_rule_epoch():
    link = FakeLink()
    # threshold-read response (control.py:62-64): byte 0=0x5A, byte 1=tid, bytes 2-3=value
    resp = bytearray(FRAME_LEN)
    resp[0] = 0x5A; resp[1] = THR_RULE_EPOCH
    resp[2:4] = (7).to_bytes(2, "big")
    link.responses[OP_THRESH_R] = bytes(resp)
    assert read_rule_epoch(link) == 7


# ----- run_loop end-to-end with mocked link -------------------------------------------------

def _verdict_response(seq: int, *, mask: int = 0, severity: int = 0,
                      escalate: bool = False) -> bytes:
    """Build a 32-byte valid verdict frame."""
    return encode_verdict(
        bloom_hit=bool(mask & 1), port_scan=bool(mask & 2),
        rate_anomaly=bool(mask & 4), rule_match=bool(mask & 8),
        severity=severity, escalate=escalate, seq=seq,
    )


class OneShotSchedule:
    """Tiny stand-in for Schedule that ends on first generator exhaust (so finite-count
    test generators naturally end the loop instead of restarting forever)."""
    def __init__(self, gen_factory, name="test"):
        self._gf = gen_factory
        self._name = name

    def frames(self, monotonic_now=None):
        return self._gf()

    def active_name(self, _elapsed):
        return self._name


def test_run_loop_emits_frames_polls_snapshot_pushes_rule():
    from demo.scenarios import flood
    link = FakeLink()
    thr = bytearray(FRAME_LEN); thr[0] = 0x5A; thr[1] = THR_RULE_EPOCH
    link.responses[OP_THRESH_R] = bytes(thr)
    link.responses[OP_SNAPSHOT] = _snap_response(top1_count=12, top1_key=0x0A000006)
    link.responses[0x00] = _verdict_response(seq=1)

    sched = OneShotSchedule(lambda: flood(src_ip=0x0A000006, count=30), name="flood")

    class NoTui:
        def __init__(self): self.renders = 0
        def render(self, state): self.renders += 1
    tui = NoTui()

    fake = [0.0]
    def now(): fake[0] += 0.001; return fake[0]
    state = run_loop(link, sched, dashboard=tui, trigger=8, snap_every=5,
                     fps=0, duration_s=None, monotonic=now,
                     sleep=lambda *_: None)
    assert state.frames_sent == 30
    assert state.rule_epoch == 0
    # snap_every=5 -> polls at ticks 5,10,15,20,25 -> rule pushed exactly once
    assert len(state.pushed_rules) == 1
    assert state.pushed_rules[0].src_ip == 0x0A000006
    assert state.pushed_rules[0].idx == lookup_idx(0x0A000006)
    # at least one render per snapshot poll + a final paint
    assert tui.renders >= 5


def test_headless_dashboard_prints_window_and_rule_events(capsys):
    from demo.dashboard import HeadlessDashboard
    d = HeadlessDashboard(stream=sys.stdout)
    state = DemoState(scenario_name="flood", start_monotonic=time.monotonic())
    state.snapshot = SnapResponse(window=5, total=10, harmonic_sum=0, zeros=2000,
                                  top1_count=3, top1_key=0x0A000005)
    d.render(state)
    out = capsys.readouterr().out
    assert "scenario -> flood" in out
    assert "window=5" in out and "10.0.0.5" in out

    # advance: rule pushed -> RULE line appears
    state.pushed_rules.append(PushedRule(src_ip=0x0A000006, idx=lookup_idx(0x0A000006),
                                          pushed_at_monotonic=time.monotonic()))
    d.render(state)
    out2 = capsys.readouterr().out
    assert "RULE pushed: block 10.0.0.6" in out2


import sys                                              # noqa: E402  (used above)


def test_run_loop_records_verdicts():
    from demo.scenarios import c2
    link = FakeLink()
    thr = bytearray(FRAME_LEN); thr[0] = 0x5A; thr[1] = THR_RULE_EPOCH
    link.responses[OP_THRESH_R] = bytes(thr)
    link.responses[0x00] = _verdict_response(seq=5, mask=0b0001, severity=3, escalate=True)

    sched = OneShotSchedule(lambda: c2(seed=0, count=15), name="c2")
    class NoTui:
        def render(self, state): pass

    fake = [0.0]
    def now(): fake[0] += 0.001; return fake[0]
    state = run_loop(link, sched, dashboard=NoTui(), trigger=8, snap_every=100,
                     fps=0, monotonic=now, sleep=lambda *_: None)
    assert state.frames_sent == 15
    assert len(state.recent_verdicts) > 0
    v = state.recent_verdicts[-1]
    assert v.valid and v.bloom_hit and v.escalate
