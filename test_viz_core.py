"""Tests for the visualizer's pure display logic (no curses, no hardware)."""
from verdict import decode_verdict, encode_verdict
from viz_core import Stats, format_row, format_summary, ips_from_header

_CLEAN = decode_verdict(encode_verdict(seq=1))
_THREAT = decode_verdict(encode_verdict(bloom_hit=True, severity=3, escalate=True, seq=2))
_NONE = decode_verdict(bytes(20))


def test_ips_from_header_reads_src_and_dst():
    h = bytes.fromhex("c0000201c6336401303901bb0602003c00000000")
    assert ips_from_header(h) == ("192.0.2.1", "198.51.100.1")


def test_stats_counts_clean_and_flagged():
    s = Stats()
    s.update(_CLEAN)
    s.update(_THREAT)
    assert (s.total, s.clean, s.flagged, s.bloom, s.escalations) == (2, 1, 1, 1, 1)
    assert s.pct_flagged == 50.0


def test_stats_ignores_no_verdict():
    s = Stats()
    s.update(_NONE)
    assert s.total == 0


def test_pct_flagged_is_zero_when_empty():
    assert Stats().pct_flagged == 0.0


def test_rate_is_total_over_elapsed():
    s = Stats()
    for _ in range(10):
        s.update(_CLEAN)
    assert s.rate(2.0) == 5.0
    assert s.rate(0) == 0.0


def test_format_row_plain_shows_flow_and_verdict():
    row = format_row("192.0.2.1", "198.51.100.1", _THREAT, color=False)
    assert "192.0.2.1" in row and "198.51.100.1" in row and "THREAT" in row
    assert "CLEAN" in format_row("10.0.0.1", "10.0.0.2", _CLEAN, color=False)


def test_format_row_color_wraps_threat_in_red():
    red = "\033[31m"
    assert red in format_row("1.1.1.1", "2.2.2.2", _THREAT, color=True)
    assert red not in format_row("1.1.1.1", "2.2.2.2", _CLEAN, color=True)


def test_format_summary_reports_counts_and_pct():
    s = Stats()
    s.update(_THREAT)
    line = format_summary(s, elapsed_s=1.0)
    assert "flagged 1" in line and "%" in line and "pkts/s" in line
