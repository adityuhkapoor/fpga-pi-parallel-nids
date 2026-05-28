"""Tests for the FPGA-vs-CPU benchmark's pure pieces (workload + stats).

The timing/printing in benchmark.__main__ is a measurement script (not unit-tested);
the deterministic parts that decide what gets measured are tested here.
"""
from benchmark import make_workload, latency_stats, fpga_core_latency_ns, link_frame_us
from bloom import BloomFilter, TEST_C2_SET
from classifier import classify_header
from verdict import decode_verdict


def _hit_count(headers):
    bf = BloomFilter.from_ips(TEST_C2_SET)
    return sum(decode_verdict(classify_header(h, bf, seq=1)).bloom_hit for h in headers)


def test_workload_has_requested_length():
    assert len(make_workload(100)) == 100


def test_workload_hit_fraction_is_exact():
    headers = make_workload(100, hit_fraction=0.25)
    assert _hit_count(headers) == 25


def test_workload_all_clean_and_all_hit():
    assert _hit_count(make_workload(40, hit_fraction=0.0)) == 0
    assert _hit_count(make_workload(40, hit_fraction=1.0)) == 40


def test_workload_is_deterministic_for_a_seed():
    assert make_workload(50, seed=7) == make_workload(50, seed=7)
    assert make_workload(50, seed=7) != make_workload(50, seed=8)


def test_workload_headers_are_32_bytes():
    assert all(len(h) == 32 for h in make_workload(30))


def test_latency_stats_on_known_samples():
    s = latency_stats([1000, 2000, 3000, 4000, 5000])  # nanoseconds
    assert s["count"] == 5
    assert s["mean_us"] == 3.0
    assert s["median_us"] == 3.0
    assert s["min_us"] == 1.0
    assert s["max_us"] == 5.0
    assert s["p99_us"] == 5.0


def test_fpga_core_latency_is_deterministic_cycles_times_period():
    # 5 pipeline cycles at 100 MHz = 50 ns.
    assert fpga_core_latency_ns(cycles=5, clk_hz=100_000_000) == 50.0


def test_link_frame_time():
    # 20B @ 1 MHz = 160 bits / 1e6 = 160 us (the v1 link cost).
    assert abs(link_frame_us(20, 1_000_000) - 160.0) < 1e-6
    # 32B @ 30 MHz = 256 bits / 30e6 ~= 8.533 us.
    assert abs(link_frame_us(32, 30_000_000) - 256 / 30) < 1e-3


def test_link_frame_time_scales_with_clock_and_size():
    # Halving the clock doubles the per-frame time; doubling bytes doubles it.
    assert link_frame_us(20, 2_000_000) == link_frame_us(20, 1_000_000) / 2
    assert link_frame_us(40, 1_000_000) == link_frame_us(20, 1_000_000) * 2
