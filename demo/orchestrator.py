"""Step-5 demo orchestrator: single-process event loop owning the SPI link.

Pulls 32-byte classify frames from a scenario iterator, sends each over SPI, decodes
the verdict the FPGA returns (one-frame pipeline lag, PROTOCOL.md), periodically polls
snapshot, and pushes a block-rule when a top talker emerges. The dashboard reads from
a DemoState dataclass -- pure data, no IO -- so the loop is testable with a fake link."""
from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Optional

from spi_link import FRAME_LEN
from verdict import Verdict, decode_verdict
from telemetry import SnapResponse, TELEMETRY_MAGIC, decode_snapshot
from control import (
    encode_rule_write, encode_threshold_read, decode_threshold_read,
)

A1, MASK32 = 0x9E3779B1, 0xFFFFFFFF
OP_SNAPSHOT, OP_RULE_W, OP_THRESH_R = 0x02, 0x12, 0x14
THR_RULE_EPOCH = 0x03
VERDICTS_KEPT = 12


def lookup_idx(ip: int) -> int:
    """Symmetric with rule_lookup.v and closed_loop.lookup_idx (top 9 bits of low-32)."""
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
    snapshot: Optional[SnapResponse] = None
    pushed_rules: list[PushedRule] = field(default_factory=list)
    recent_verdicts: deque = field(default_factory=lambda: deque(maxlen=VERDICTS_KEPT))
    rule_epoch: int = 0
    frames_sent: int = 0


def record_verdict(state: DemoState, v: Verdict) -> None:
    state.recent_verdicts.append(v)


def _snap_frame() -> bytes:
    f = bytearray(FRAME_LEN); f[16] = OP_SNAPSHOT; return bytes(f)


def poll_snapshot(link, state: DemoState) -> None:
    """Opcode 0x02. Response carries the LAST completed window's stats. Magic mismatch
    is tolerated (window still warming) -- state.snapshot stays unchanged."""
    link.send_frame(_snap_frame())
    rx = link.send_frame(bytes(FRAME_LEN))
    if rx[0] != TELEMETRY_MAGIC:
        return
    state.snapshot = decode_snapshot(rx)


def read_rule_epoch(link) -> int:
    link.send_frame(encode_threshold_read(THR_RULE_EPOCH))
    return decode_threshold_read(link.send_frame(bytes(FRAME_LEN)))["value"] & 0xFF


def maybe_push_rule(link, state: DemoState, *, trigger: int,
                    now_monotonic: Callable[[], float] = time.monotonic,
                    action: int = 0b101, severity: int = 3) -> bool:
    """If snapshot top1_count meets trigger and src is unseen, push a block-rule and
    record it. Returns True iff a rule was pushed this call."""
    s = state.snapshot
    if s is None or s.top1_count < trigger:
        return False
    if s.top1_key == 0:
        return False                                   # FPGA's "no clear top" sentinel
    if any(r.src_ip == s.top1_key for r in state.pushed_rules):
        return False
    idx = lookup_idx(s.top1_key)
    rule = {"src_ip": s.top1_key, "action": action,
            "severity": severity, "epoch": state.rule_epoch}
    link.send_frame(encode_rule_write(idx, rule))
    link.send_frame(bytes(FRAME_LEN))                # consume ack frame
    state.pushed_rules.append(PushedRule(
        src_ip=s.top1_key, idx=idx,
        pushed_at_monotonic=now_monotonic()))
    return True


def run_loop(link, schedule, *, dashboard, trigger: int = 8,
             snap_every: int = 50, fps: float = 500.0,
             duration_s: Optional[float] = None,
             monotonic: Callable[[], float] = time.monotonic,
             sleep: Callable[[float], None] = time.sleep) -> DemoState:
    """Single-process event loop. link, schedule, dashboard are injected so the loop
    is testable with fakes.

    Each tick: pull frame -> send (1-frame-lag verdict comes back) -> record. Every
    snap_every ticks: poll snapshot + maybe_push_rule + dashboard.render. Stops when
    duration_s elapses OR the schedule exhausts."""
    epoch = read_rule_epoch(link)
    state = DemoState(scenario_name="(starting)",
                      start_monotonic=monotonic(),
                      rule_epoch=epoch)
    tick_interval = 1.0 / fps if fps > 0 else 0.0
    frames_iter = schedule.frames(monotonic_now=monotonic)
    next_tick = monotonic()
    tick = 0
    end_at = (state.start_monotonic + duration_s) if duration_s is not None else None

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
        if snap_every > 0 and tick > 0 and tick % snap_every == 0:
            poll_snapshot(link, state)
            maybe_push_rule(link, state, trigger=trigger, now_monotonic=monotonic)
            if dashboard is not None:
                dashboard.render(state)
        tick += 1
        if tick_interval > 0:
            next_tick += tick_interval
            delay = next_tick - monotonic()
            if delay > 0:
                sleep(delay)
            else:
                next_tick = monotonic()              # drift recovery on slow tick
    if dashboard is not None:
        dashboard.render(state)                      # final paint
    return state
