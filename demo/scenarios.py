"""Synthetic adversary + benign frame generators for the step-5 capstone demo.

Each generator yields 32-byte classify frames (opcode byte 16 = 0x00) matching the
PROTOCOL.md / packet_capture.py:50-55 layout. Generators are deterministic given a
seed so tests pin behavior."""
from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Iterator, Sequence

FRAME_LEN = 32
OP_CLASSIFY = 0x00

# Locked C2 set — mirrors fpga/src/bloom_init.mem (the only IPs the flashed bloom
# filter knows). Same set asserted by tb_classifiers.v:5.
#   198.51.100.1 = 0xC6336401
#   203.0.113.5  = 0xCB007105
#   192.0.2.99   = 0xC0000263
C2_IPS = (0xC6336401, 0xCB007105, 0xC0000263)


def build_classify_frame(*, src_ip: int, dst_ip: int, src_port: int = 0,
                         dst_port: int = 0, proto: int = 17, flags: int = 0,
                         size: int = 64) -> bytes:
    """Pack one 32-byte classify frame (opcode 0x00, byte 16)."""
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


# RFC5737 doc pools + RFC1918 — public-repo safe and disjoint from C2_IPS.
_BENIGN_SRC_POOLS = (0xC0A80000, 0xC0A80100, 0xC0A80200)   # 192.168.{0,1,2}.0/24
_BENIGN_DST = 0x0A000020
_BENIGN_DPORTS = (53, 80, 443, 8080)


def benign(seed: int = 0, count: int | None = None) -> Iterator[bytes]:
    """Diverse-source UDP traffic, no C2 IPs, low pkts-per-src. Trips nothing."""
    rng = random.Random(seed)
    emitted = 0
    while count is None or emitted < count:
        src = rng.choice(_BENIGN_SRC_POOLS) | rng.randint(1, 254)
        if src in C2_IPS:                            # defensive; pools don't overlap
            continue
        yield build_classify_frame(src_ip=src, dst_ip=_BENIGN_DST,
                                   dst_port=rng.choice(_BENIGN_DPORTS),
                                   proto=17, size=rng.randint(64, 512))
        emitted += 1


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


def port_scan(src_ip: int, count: int = 12, dst_ip: int = 0x0A000020,
              start_port: int = 20) -> Iterator[bytes]:
    """One source, strictly increasing distinct dports. Trips port_scan (bit 1)."""
    for i in range(count):
        yield build_classify_frame(src_ip=src_ip, dst_ip=dst_ip,
                                   dst_port=start_port + i, proto=6,
                                   flags=0x02, size=64)


def flood(src_ip: int, count: int = 20, dst_ip: int = 0x0A000020,
          dst_port: int = 443) -> Iterator[bytes]:
    """Mono-src, mono-dport, SYN-flagged. Trips rate (bit 2) and, with the closed loop
    running, becomes top1 -> rule push -> rule_match (bit 3) on subsequent frames."""
    for _ in range(count):
        yield build_classify_frame(src_ip=src_ip, dst_ip=dst_ip,
                                   dst_port=dst_port, proto=6, flags=0x02, size=64)


@dataclass
class ScheduleStep:
    name: str
    gen_factory: Callable[[], Iterator[bytes]]
    duration_s: float


class Schedule:
    """Sequence of (name, generator-factory, duration). frames() yields forever (or
    until exhausted) while advancing the active step based on monotonic-clock elapsed."""
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

    def frames(self, monotonic_now: Callable[[], float] = time.monotonic
               ) -> Iterator[bytes]:
        start = monotonic_now()
        cum = 0.0
        for s in self.steps:
            cum += s.duration_s
            step_end = start + cum
            gen = s.gen_factory()
            while monotonic_now() < step_end:
                try:
                    yield next(gen)
                except StopIteration:
                    gen = s.gen_factory()            # restart bounded gen within step
                    yield next(gen)


def default_schedule() -> Schedule:
    """0-10s benign, 10-20s c2, 20-30s port_scan from 10.0.0.5, 30-45s flood from
    10.0.0.6, 45-60s benign. The flood from 10.0.0.6 trips rate AND becomes top1 ->
    closed loop pushes rule -> rule_match on the tail of the flood."""
    return Schedule([
        ScheduleStep("benign",    lambda: benign(seed=0),                          10.0),
        ScheduleStep("c2",        lambda: c2(seed=1),                              10.0),
        ScheduleStep("port_scan", lambda: port_scan(src_ip=0x0A000005, count=10_000), 10.0),
        ScheduleStep("flood",     lambda: flood(src_ip=0x0A000006, count=10_000),  15.0),
        ScheduleStep("benign",    lambda: benign(seed=2),                          15.0),
    ])
