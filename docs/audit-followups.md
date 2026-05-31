# Audit follow-ups (2026-05-28)

Third-party audit of step 1+2 (`docs/superpowers/audits/...`) surfaced no HIGH bugs. This file
tracks the MED/LOW items deferred past step 3+4 execution, with the reasoning for each defer.

## Fixed before step 3+4 implementation

- ✅ **Runtime-thresh twin gap (MED #1):** `ScanRateTable` parametrized on `thresholds`;
  `Classifier(bloom, thresholds=...)` plumbs through. Runtime threshold writes via opcode 0x11
  are now reflected in the CPU twin (`test_scan_rate.py::test_runtime_thresholds_change_verdict`).
- ✅ **`tb_nids_top` dead RUL vectors (MED #4):** the `RUL_W` / `RUL_R` frames were declared but
  never sent. Now we send + assert the rule round-trip end-to-end through nids_top.
- ✅ **`thresholds_model` unknown-id mismatch (MED #8):** twin now silently no-ops on writes
  and returns 0 on reads for unknown ids, matching `thresholds.v`'s `default:` cases.
- ✅ **SPEC drift on bloom (MED #3):** `docs/SPEC_v2.md`'s bloom row annotated to mark the
  v1-carry-forward reality (m=2¹⁶, k=2, 1 BRAM, FP ≈ 15.5 % @ 16k IPs) vs the aspirational
  v2 sizing. v2-sized bloom is a future step.
- ✅ **`RUNTIME_VECTORS.md` hex typos (LOW #1):** doc samples regenerated from `control.py`
  to be exactly 64 hex chars (32 bytes).
- ✅ **`verdict_encoder.v` doc says "20-byte" (LOW #2):** stale comment, fixed.

## Deferred — non-blocking, do during step 3+4 build or after

- ⏳ **CMS BRAM inference (MED #5):** Vivado is mapping CMS as **2 RAMB36/bank instead of 1**
  (5 banks × 2 = 10, explains the +3 vs predicted 7 for CMS + others). Root cause: each
  bank's read-path and write-path live in separate `always` blocks → not collapsed to clean
  SDP. Fix: merge into a single `always` block per bank using a `read_first` SDP template.
  Could recover ~3 BRAM. Worth investigating during the step-3+4 build cycle since we're
  rebuilding anyway.
- ⏳ **`win_tick` mid-pipeline hazard in `cms.v` (MED #5):** if `win_tick` fires while a
  packet is mid-FSM (phase 1 or 2), the write uses the *old* `cur_epoch` but subsequent
  queries see the new — that packet's count is silently lost. Twin has no mid-update concept.
  Won't bite at 14k pps + 100 MHz (frame period ≫ 4-cycle FSM). Fix: gate `win_tick` until
  `phase==0`, or hold the new epoch until the in-flight RMW finishes. Documented; not bit-
  exact under adversarial timing but bit-exact under realistic input.
- ⏳ **`telemetry.v` same hazard for `total_packets` (MED #6):** packet arriving on the same
  edge as `win_tick` falls through both the if-tick and else-upd branches, dropped. Twin
  increments first then snapshots/resets — different order. Same realistic-vs-adversarial
  distinction.

## Deferred — chip away as tests grow

- ⏳ **`tb_cms` saturation coverage (MED #6):** twin tests 20,000 increments to verify the
  14-bit saturation; HDL TB only does 9 increments. Add a 16,384-iter saturation loop.
- ⏳ **`tb_cms` multi-tick lazy reset (MED #6):** single `do_tick` only; the 4-bit `cur_epoch`
  wraps every 16 ticks. Add a multi-window (≥16 ticks) regression with re-updates in between.
- ⏳ **`tb_scan_rate` / `tb_classifiers` runtime-thresh composite (LOW #4):** both TBs hardcode
  port_thresh=5/host_thresh=5/rate_thresh=8. No HDL test writes a new RATE and verifies the
  classifier verdict reflects the change. The CPU twin now covers it
  (`test_runtime_thresholds_change_verdict`); add the HDL-side analog.
- ⏳ **`tb_telemetry` `force_tick` + `upd_valid` collision (LOW #5):** related to MED #5/#6; not
  exercised in current tb. Adding `force_tick=1` while `upd_valid=1` would expose the
  divergence and force the gate fix.
- ⏳ **`tb_nids_top` opcode 0x03 (live HLL) test (LOW #6):** snapshot path is tested but the
  live-harmonic-sum read isn't. Silicon-only coverage today.

## Won't fix

- **`hll.py` `<= 2.5 * HLL_M` (LOW #7):** matches Flajolet's recommended threshold convention.
  Audit flagged it only because the prompt asked; no bug.

## Original audit transcript

Available in this session's harness output file (large JSONL — not committed). Summarized
findings are above; key quote on overall impression:

> "The methodology is mostly honored, but selectively. The CMS and HLL twin/HDL pairs are
> genuinely bit-exact for the central update path … Where the discipline starts to fray:
> edge cases at boundaries … spec drift in the bloom … runtime-thresh twin gap … coverage
> gaps that 'look complete, aren't exercising the surface.' It's a real differentiator, not
> performative — but it needs the discipline applied to the seams with the same rigor."
