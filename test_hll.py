from hll import HyperLogLog, HLL_M


def test_empty_harmonic_sum_is_m_times_2pow32():
    assert HyperLogLog().harmonic_sum == HLL_M * (1 << 32)


def test_distinct_count_estimate_in_tolerance():
    h = HyperLogLog()
    for i in range(1000):
        h.update(0x0A000000 + i)               # 1000 distinct srcs
    est = h.estimate()
    assert abs(est - 1000) / 1000 < 0.10        # within ~10% (2.3% std err, loose bound)


def test_repeated_source_does_not_inflate():
    h = HyperLogLog()
    for _ in range(500):
        h.update(0xCB007105)
    assert h.estimate() < 5                      # ~1 distinct


def test_window_tick_resets():
    h = HyperLogLog()
    for i in range(100):
        h.update(0x0A000000 + i)
    h.window_tick()
    assert h.harmonic_sum == HLL_M * (1 << 32)   # back to empty
