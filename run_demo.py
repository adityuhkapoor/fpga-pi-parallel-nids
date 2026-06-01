#!/usr/bin/env python3
"""Step-5 capstone: synthetic-mode closed-loop demo (Pi 4B + FPGA over SPI).

    sudo python3 run_demo.py                          # default 60s scripted schedule + curses TUI
    sudo python3 run_demo.py --scenario flood         # pin one scenario, run forever
    sudo python3 run_demo.py --no-tui --duration 15   # text log (CI / screencap-friendly)
"""
import argparse
import curses
import sys

from spi_link import SpiLink
from demo.orchestrator import run_loop
from demo.dashboard import CursesDashboard, HeadlessDashboard
from demo.scenarios import (
    Schedule, ScheduleStep, default_schedule,
    benign, c2, port_scan, flood,
)


_SOLO_FACTORIES = {
    "benign":    lambda: benign(seed=0),
    "c2":        lambda: c2(seed=0),
    "port_scan": lambda: port_scan(src_ip=0x0A000005, count=10_000),
    "flood":     lambda: flood(src_ip=0x0A000006, count=10_000),
}


def _build_schedule(args) -> Schedule:
    if args.scenario:
        return Schedule([ScheduleStep(args.scenario,
                                       _SOLO_FACTORIES[args.scenario],
                                       args.duration or 60.0)])
    return default_schedule()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", choices=list(_SOLO_FACTORIES),
                    help="pin one scenario; default = scripted 60s schedule")
    ap.add_argument("--duration", type=float, default=None,
                    help="seconds to run (default: scripted=60s, --scenario=infinite)")
    ap.add_argument("--trigger", type=int, default=8,
                    help="top1 count that triggers a rule push (default 8)")
    ap.add_argument("--fps", type=float, default=500.0,
                    help="target classify frames per second (default 500)")
    ap.add_argument("--no-tui", action="store_true",
                    help="stream text log to stderr instead of curses TUI (CI-friendly)")
    args = ap.parse_args()

    schedule = _build_schedule(args)
    duration = args.duration if args.duration is not None else (
        schedule.total_s() if not args.scenario else None)

    def _run(dashboard):
        with SpiLink() as link:
            run_loop(link, schedule, dashboard=dashboard,
                     trigger=args.trigger, fps=args.fps,
                     duration_s=duration)

    if args.no_tui:
        _run(HeadlessDashboard())
    else:
        curses.wrapper(lambda stdscr: _run(CursesDashboard(stdscr)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
