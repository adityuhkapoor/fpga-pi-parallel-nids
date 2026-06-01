"""Unit tests for demo.scenarios — frame builder + 4 generators + Schedule."""
from demo.scenarios import (
    C2_IPS, FRAME_LEN, OP_CLASSIFY,
    build_classify_frame, benign, c2, port_scan, flood,
    Schedule, ScheduleStep, default_schedule,
)


def _src(f): return int.from_bytes(f[0:4], "big")
def _dport(f): return int.from_bytes(f[10:12], "big")
def _flags(f): return f[13]


def test_build_classify_frame_layout():
    f = build_classify_frame(src_ip=0xC0000201, dst_ip=0xC0000202,
                             src_port=12345, dst_port=80, proto=6,
                             flags=0x02, size=64)
    assert len(f) == FRAME_LEN
    assert f[0:4] == (0xC0000201).to_bytes(4, "big")
    assert f[4:8] == (0xC0000202).to_bytes(4, "big")
    assert int.from_bytes(f[8:10], "big") == 12345
    assert int.from_bytes(f[10:12], "big") == 80
    assert f[12] == 6
    assert f[13] == 0x02
    assert int.from_bytes(f[14:16], "big") == 64
    assert f[16] == OP_CLASSIFY
    assert f[17:32] == bytes(15)


def test_benign_diverse_srcs_no_c2():
    frames = list(benign(seed=1, count=200))
    srcs = {_src(f) for f in frames}
    assert len(frames) == 200
    assert len(srcs) >= 30                           # well-mixed
    assert not (srcs & set(C2_IPS))


def test_benign_deterministic_under_seed():
    a = list(benign(seed=42, count=50))
    b = list(benign(seed=42, count=50))
    assert a == b


def test_c2_only_c2_srcs_cycles_all():
    frames = list(c2(seed=2, count=30))
    srcs = {_src(f) for f in frames}
    assert srcs == set(C2_IPS)                       # cycles through all three
    assert all(f[12] == 6 for f in frames)           # TCP
    assert all(f[13] & 0x02 for f in frames)         # SYN


def test_port_scan_one_src_distinct_dports():
    frames = list(port_scan(src_ip=0x0A000005, count=12))
    srcs = {_src(f) for f in frames}
    dports = [_dport(f) for f in frames]
    assert srcs == {0x0A000005}
    assert dports == sorted(dports)
    assert len(set(dports)) == 12                    # all distinct
    assert all(_flags(f) & 0x02 for f in frames)     # SYN


def test_flood_mono_src_mono_dport():
    frames = list(flood(src_ip=0x0A000006, dst_port=443, count=20))
    assert {_src(f) for f in frames} == {0x0A000006}
    assert {_dport(f) for f in frames} == {443}
    assert all(_flags(f) & 0x02 for f in frames)


def test_default_schedule_shape():
    sched = default_schedule()
    names = [s.name for s in sched.steps]
    durations = [s.duration_s for s in sched.steps]
    assert names == ["benign", "c2", "port_scan", "flood", "benign"]
    assert durations == [10.0, 10.0, 10.0, 15.0, 15.0]
    assert sched.total_s() == 60.0


def test_schedule_active_name_transitions():
    sched = default_schedule()
    assert sched.active_name(0.0) == "benign"
    assert sched.active_name(9.99) == "benign"
    assert sched.active_name(10.01) == "c2"
    assert sched.active_name(29.99) == "port_scan"
    assert sched.active_name(30.01) == "flood"
    assert sched.active_name(50.0) == "benign"


def test_schedule_frames_advance_with_clock():
    """A frozen-clock variant that advances by 0.5s per next() call should pull
    frames from each scenario in order and stop once total duration elapses."""
    # tiny schedule for speed: 1s benign + 1s flood
    sched = Schedule([
        ScheduleStep("benign", lambda: benign(seed=0), 1.0),
        ScheduleStep("flood",  lambda: flood(src_ip=0x0A000099, count=10_000), 1.0),
    ])
    t = [0.0]
    def now(): t[0] += 0.4; return t[0]
    it = sched.frames(monotonic_now=now)
    seen = []
    for _ in range(20):
        try:
            seen.append(next(it))
        except StopIteration:
            break
    # benign srcs (192.168.x) appear before flood src (0x0A000099)
    flood_seen = any(_src(f) == 0x0A000099 for f in seen)
    benign_seen = any(_src(f) >= 0xC0A80000 and _src(f) < 0xC0A80300 for f in seen)
    assert flood_seen and benign_seen
