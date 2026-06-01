"""Demo dashboard: curses TUI for live viewing + headless text logger for CI / screencap.

Both speak the same render(state) interface so run_demo.py picks one at startup. The
curses path is hard to unit-test (terminal-dependent) -- smoke validation happens on
the Pi. The headless logger is unit-tested via capsys."""
from __future__ import annotations

import curses
import sys
import time

from demo.orchestrator import DemoState


def _fmt_ip(ip: int) -> str:
    return ".".join(str((ip >> (24 - 8 * i)) & 0xFF) for i in range(4))


def _verdict_line(v) -> str:
    bits = []
    if v.bloom_hit:    bits.append("bloom")
    if v.port_scan:    bits.append("port_scan")
    if v.rate_anomaly: bits.append("rate")
    if v.rule_match:   bits.append("rule_match")
    tag = f"THREAT[{','.join(bits)}]" if bits else "OK"
    esc = " ESCALATE" if v.escalate else ""
    return f"seq {v.seq:3d}  {tag} sev{v.severity}{esc}"


class HeadlessDashboard:
    """Streams scenario / snapshot / rule / threat events to a stream (default stderr).
    Quiet by default -- only logs when state changes (new window, new rule, threat verdict)."""
    def __init__(self, stream=None):
        self.stream = stream if stream is not None else sys.stderr
        self._last_window: int | None = None
        self._last_rule_count: int = 0
        self._last_scenario: str | None = None

    def render(self, state: DemoState) -> None:
        elapsed = time.monotonic() - state.start_monotonic
        if state.scenario_name != self._last_scenario:
            print(f"[{elapsed:6.2f}s] scenario -> {state.scenario_name}",
                  file=self.stream, flush=True)
            self._last_scenario = state.scenario_name

        s = state.snapshot
        if s is not None and s.window != self._last_window:
            print(f"[{elapsed:6.2f}s] window={s.window} total={s.total} "
                  f"top={_fmt_ip(s.top1_key)} count={s.top1_count} "
                  f"sent={state.frames_sent}",
                  file=self.stream, flush=True)
            self._last_window = s.window

        if len(state.pushed_rules) > self._last_rule_count:
            r = state.pushed_rules[-1]
            print(f"[{elapsed:6.2f}s] RULE pushed: block {_fmt_ip(r.src_ip)} "
                  f"(idx 0x{r.idx:03X})",
                  file=self.stream, flush=True)
            self._last_rule_count = len(state.pushed_rules)

        if state.recent_verdicts:
            v = state.recent_verdicts[-1]
            if v.bloom_hit or v.port_scan or v.rate_anomaly or v.rule_match:
                print(f"[{elapsed:6.2f}s] verdict: {_verdict_line(v)}",
                      file=self.stream, flush=True)


class CursesDashboard:
    """Three-pane curses TUI: header, active rules, recent verdicts. Color-coded by
    severity / threat composition. Q quits (key handling in run_demo.py)."""
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

    def _verdict_attr(self, v) -> int:
        if v.rule_match or v.escalate:
            return curses.color_pair(self._COLOR_THREAT)
        if v.bloom_hit or v.port_scan or v.rate_anomaly:
            return curses.color_pair(self._COLOR_BLOOM)
        return curses.color_pair(self._COLOR_OK)

    def _safe_addstr(self, y, x, text, attr=0):
        h, w = self.stdscr.getmaxyx()
        if y >= h or x >= w:
            return
        try:
            self.stdscr.addstr(y, x, text[: max(0, w - x - 1)], attr)
        except curses.error:
            pass                                       # terminal too small; skip

    def render(self, state: DemoState) -> None:
        scr = self.stdscr
        scr.erase()
        h, w = scr.getmaxyx()
        elapsed = time.monotonic() - state.start_monotonic
        title = " nids closed-loop demo — q to quit "
        self._safe_addstr(0, 0, title.ljust(w - 1), curses.A_REVERSE)
        self._safe_addstr(1, 0,
            f" scenario: {state.scenario_name:<10s}  uptime: {int(elapsed):3d}s "
            f" sent: {state.frames_sent}")
        if state.snapshot is not None:
            s = state.snapshot
            distinct = max(0, 2048 - s.zeros)          # linear-counting rough estimate
            self._safe_addstr(2, 0,
                f" window {s.window:5d}   distinct~{distinct:4d}   "
                f"top: {_fmt_ip(s.top1_key):15s} count {s.top1_count}")
        else:
            self._safe_addstr(2, 0, " window  (warming up)")

        self._safe_addstr(4, 0, "+- active rules " + "-" * max(0, w - 17),
                          curses.A_DIM)
        for i, r in enumerate(state.pushed_rules[-5:]):
            age = elapsed - (r.pushed_at_monotonic - state.start_monotonic)
            self._safe_addstr(5 + i, 1,
                f"{_fmt_ip(r.src_ip):15s}  block  idx 0x{r.idx:03X}  ago {age:5.1f}s",
                curses.color_pair(self._COLOR_RULE))

        row0 = 11
        self._safe_addstr(row0, 0,
            "+- recent verdicts " + "-" * max(0, w - 20), curses.A_DIM)
        verdicts = list(state.recent_verdicts)
        for i, v in enumerate(verdicts[-(max(1, h - row0 - 2)):]):
            self._safe_addstr(row0 + 1 + i, 1, _verdict_line(v), self._verdict_attr(v))

        scr.noutrefresh()
        curses.doupdate()
