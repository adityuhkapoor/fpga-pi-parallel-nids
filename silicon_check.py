"""Evaluate a live SPI round-trip against the golden verdicts (pure logic).

Separated from the hardware runner (spi_verdict_check.py) so the lag/seq logic is
unit-tested off the Pi. Pass/fail is decided by verdict *content* (threats, severity,
escalate) matching the golden expectation plus seq incrementing by 1 — the absolute
seq depends on whether the board was reset, so an offset is noted, not failed.
"""
from dataclasses import dataclass, field

from verdict import decode_verdict


@dataclass
class RunResult:
    passed: bool
    rows: list = field(default_factory=list)   # (k, ok, summary) per header
    notes: list = field(default_factory=list)


def evaluate_run(rx_frames, expected_verdicts) -> RunResult:
    """rx_frames[k] = the 20 bytes read back during transfer k.

    rx_frames[0] is the pre-first-frame read; rx_frames[k] (k>=1) is the verdict for
    header k. Requires len(rx_frames) >= len(expected_verdicts)+1 (the trailing flush
    transfer that clocks out the last verdict).
    """
    n = len(expected_verdicts)
    if len(rx_frames) < n + 1:
        raise ValueError(f"need {n + 1} read-back frames (N headers + 1 flush), got {len(rx_frames)}")

    notes = []
    first = decode_verdict(rx_frames[0])
    if first.valid:
        notes.append(f"first transfer returned a valid verdict (seq={first.seq}) — "
                     "board likely not reset before the run")
    else:
        notes.append("first transfer = no-verdict (clean fresh start)")

    rows, seqs, content_ok = [], [], True
    for k in range(1, n + 1):
        rv = decode_verdict(rx_frames[k])
        ev = decode_verdict(expected_verdicts[k - 1])
        ok = (rv.valid and rv.threats == ev.threats
              and rv.severity == ev.severity and rv.escalate == ev.escalate)
        content_ok = content_ok and ok
        seqs.append(rv.seq)
        rows.append((k, ok, f"got [{rv.describe()}]  want [threats={ev.threats} "
                            f"sev={ev.severity_name} esc={ev.escalate}]"))

    incr_ok = all((seqs[i] - seqs[i - 1]) % 256 == 1 for i in range(1, len(seqs)))
    if not incr_ok:
        notes.append(f"seq did not increment by 1 across frames: {seqs}")
    if seqs and seqs[0] != 1:
        notes.append(f"first verdict seq={seqs[0]} (expected 1 from a fresh reset); "
                     "content checked regardless")

    return RunResult(passed=content_ok and incr_ok, rows=rows, notes=notes)
