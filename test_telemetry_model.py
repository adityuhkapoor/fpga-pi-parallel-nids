from telemetry_model import Telemetry


def test_top1_tracks_heaviest_source():
    t = Telemetry()
    for _ in range(3):
        t.update(0x0A000001)
    for _ in range(9):
        t.update(0xCB007105)                     # heaviest
    for _ in range(5):
        t.update(0x0A000002)
    assert t.top1_key == 0xCB007105
    assert t.top1_count == 9


def test_total_packets_counts_updates():
    t = Telemetry()
    for i in range(17):
        t.update(0x0A000000 + i)
    assert t.total_packets == 17


def test_window_tick_latches_snapshot_then_resets():
    t = Telemetry()
    for _ in range(4):
        t.update(0xCB007105)
    t.update(0x0A000009)
    t.window_tick()
    snap = t.snapshot
    assert snap["window_index"] == 0
    assert snap["total_packets"] == 5
    assert snap["top1_key"] == 0xCB007105 and snap["top1_count"] == 4
    # after tick: counters reset, next window starts clean
    assert t.total_packets == 0 and t.top1_count == 0 and t.window_index == 1
    assert t.point_query(0xCB007105) == 0


def test_second_window_independent():
    t = Telemetry()
    t.update(0xCB007105)
    t.window_tick()
    t.update(0x0A000002)
    t.update(0x0A000002)
    t.window_tick()
    assert t.snapshot["window_index"] == 1
    assert t.snapshot["top1_key"] == 0x0A000002 and t.snapshot["top1_count"] == 2
