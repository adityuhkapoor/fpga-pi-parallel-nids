"""Tests for the silicon round-trip evaluator (pure logic, no hardware).

The live test on the Pi clocks N headers + 1 flush frame and reads back N+1 frames
(full-duplex, one-frame lag): rx[0] is the pre-first-frame, rx[k] is the verdict for
header k. evaluate_run() checks each verdict's content against the golden expectation
and that seq increments by 1 — robust to whether the board's counter was reset to 0.
"""
from silicon_check import evaluate_run
from verdict import encode_verdict

# expected verdicts for 3 toy headers at seq 1,2,3: clean, bloom-hit, clean
EXP = [
    encode_verdict(seq=1),
    encode_verdict(bloom_hit=True, severity=3, escalate=True, seq=2),
    encode_verdict(seq=3),
]


def test_perfect_fresh_run_passes():
    rx = [bytes(20)] + list(EXP)  # rx[0]=no-verdict, rx[1..3]=verdicts, seq 1..3
    assert evaluate_run(rx, EXP).passed is True


def test_content_mismatch_fails():
    # header 1 should be clean but the board returned a bloom hit
    rx = [bytes(20),
          encode_verdict(bloom_hit=True, severity=3, escalate=True, seq=1),
          EXP[1], EXP[2]]
    assert evaluate_run(rx, EXP).passed is False


def test_seq_offset_but_correct_content_passes_with_note():
    # board wasn't reset: seqs start at 11, but content is right and increments by 1
    rx = [bytes(20),
          encode_verdict(seq=11),
          encode_verdict(bloom_hit=True, severity=3, escalate=True, seq=12),
          encode_verdict(seq=13)]
    r = evaluate_run(rx, EXP)
    assert r.passed is True
    assert any("seq" in n.lower() for n in r.notes)


def test_broken_seq_increment_fails():
    rx = [bytes(20),
          encode_verdict(seq=1),
          encode_verdict(bloom_hit=True, severity=3, escalate=True, seq=5),  # gap
          encode_verdict(seq=6)]
    assert evaluate_run(rx, EXP).passed is False


def test_needs_a_flush_frame():
    import pytest
    # only N frames, no flush -> can't read the last verdict
    with pytest.raises(ValueError):
        evaluate_run([bytes(20)] + list(EXP[:2]), EXP)
