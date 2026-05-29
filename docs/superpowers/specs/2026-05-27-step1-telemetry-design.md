# v2 Step 1 — Hardware Telemetry (Count-Min + HyperLogLog) Design

Status: **proposed** (2026-05-27). Implements build-order step 1 of `docs/SPEC_v2.md` on the
locked **8 MHz / 32-byte** link (see [[v2-step0-link-locked]]). Dimensions are the locked
`docs/sizing.py` values; this doc fixes the *semantics, datapath, and readout contract*.

## Goal

Answer, in hardware, over a true 1-second window: **"Of the source hosts talking this second,
how many distinct ones are there, and which are sending the most?"** — network **cardinality**
(HyperLogLog) + **heavy hitters** (Count-Min), both keyed on **source IP**. Runs in parallel with
the v1.1 classifier pipeline (bloom + port-scan + rate-anomaly), reusing the same parsed header
stream. Stands alone as a result: the Pi reads per-second top-talker counts and a distinct-source
estimate without spending CPU to maintain per-source counters.

## Measurement semantics (the contract)

- **Count-Min sketch** — key = **source IP**, value = **packet count** in the window. Heavy hitter
  = top talker / flood source. Grounded in standard network CMS practice (per-source packet/byte
  counts for DDoS detection). Packets (not bytes): the threats are floods/scans (packet-rate), v1.1
  already reasons in packet-rate, and the locked **14-bit** counter holds one window's max
  (~14 k pps < 2¹⁴). Update is **+1 per packet** to all 5 banks at their per-bank hash column.
- **HyperLogLog** — counts **distinct source IPs** seen in the window (network cardinality).
  A spike in distinct sources is a classic DDoS/spoofing signal. Single global HLL, m = 2048
  registers × 5 bits, ~2.3 % standard error.
- *(Out of step-1 scope, noted for later: distinct-**destination** HLL detects scanners but needs
  per-source HLL for attribution → step 3+; bytes-per-source is a second CMS instance → not now.)*

## Architecture

New modules, each with one responsibility and a bit-exact CPU twin (TDD, below):

| Module | Responsibility | BRAM | DSP |
|---|---|---|---|
| `cms.v` (`count_min`) | 5 banks × 4096 × 14b; 5 multiply-shift hashes of src_ip; +1 per packet; point-query returns min over banks | 10.0 | 15 |
| `hll.v` (`hyperloglog`) | 2048 × 5b registers; 1 hash of src_ip → (bucket, rank); register = max(rank); maintains incremental harmonic sum | 0.5 | 3 |
| `telemetry.v` | wraps cms + hll, drives the 1 s window + snapshot, owns the top-1 max-tracker | — | — |
| (in `nids_top.v`) | instantiate `telemetry` fed from `header_parser`; route command frames to it | — | — |

**Data flow:** `spi_slave_rx → header_parser → { classifiers (v1.1, unchanged) ‖ telemetry (new) }`.
Every classified packet also updates CMS + HLL on its `src_ip`. The verdict path is untouched;
telemetry is read through the new command sublayer (below).

**Window + snapshot (single-buffered, stays in budget):** a 100 M-cycle counter (1 s @100 MHz)
defines a **tumbling window**. At each boundary the FPGA latches a small **snapshot register
block** for the just-completed window, then clears the active CMS + HLL by a **sequential
background walk** (parallel across the 5 banks; 4096 + 2048 cycles ≈ 60 µs ≪ 1 s). Packets
arriving during the ~60 µs clear are dropped — deterministic and modeled exactly in the reference.
Double-buffering (a frozen copy) is rejected: it would cost 2×10 = 20 BRAM and push the full v2
total past 50, starving build steps 3–5.

**Snapshot register block** (the stable, fast read each window):
`{ window_index:16, total_packets:32, distinct_harmonic_sum:32, top1_count:14, top1_key:32 }`.
The **top-1 heavy hitter** is a running `max(count, key)` updated by one compare-and-latch per CMS
update — the headline hitter with no hardware sort. The Pi point-queries the CMS for the specific
sources *it* observed (it is the capture point) to rank the rest. HLL **cardinality is finished on
the Pi**: the FPGA maintains the harmonic sum incrementally (a 2⁻ᴹ lookup add/sub per register
change); the Pi reads the sum and computes `α·m²/sum` — trivial math, keeps the HW divide-free.

## Readout / command sublayer (extends `PROTOCOL.md`)

A request frame's **byte 16 = opcode** (byte 16 was reserved; v1 frames are all-zero there →
back-compatible, opcode `0x00` = classify):

| opcode | meaning | request payload | response (MISO, next transfer) |
|---|---|---|---|
| `0x00` | packet header (classify) | bytes 0–15 header | verdict frame (v1.1, unchanged) |
| `0x01` | CMS point-query | src_ip in bytes 0–3 | `{rsp_magic, queried_key:32, count:14}` (live window, best-effort) |
| `0x02` | read window snapshot | — | snapshot register block |
| `0x03` | read HLL harmonic sum | — | `{rsp_magic, harmonic_sum:32, m:16}` |

Responses carry a **response-magic** distinct from the verdict `0xA5` (e.g. `0x5A`) in byte 0 so
the Pi tells verdict vs telemetry-response apart; the one-frame pipeline lag is identical to the
verdict path. Exact field offsets are pinned in `PROTOCOL.md` + a Tier-1 format-vector table
(`TELEMETRY_VECTORS.md`), same two-tier scheme as the verdict path.

## Verification methodology (non-negotiable, mirrors `scan_rate.py ↔ scan_rate.v`)

- **`cms.py`** — bit-exact CPU Count-Min: same 5 multiply-shift hash constants, 4096 cols, 14b
  saturating counters, min-query. **`hll.py`** — bit-exact CPU HLL: same hash, bucket/rank split,
  register-max, harmonic-sum. Both pure stdlib, unit-tested.
- **Golden vectors**: a deterministic stream (RFC5737 IPs) → expected CMS point-query results,
  HLL registers + harmonic sum, top-1, and window snapshots, generated by the CPU twins
  (`gen_telemetry_golden.py`) and asserted by both `pytest` and self-checking testbenches
  (`tb_cms.v`, `tb_hll.v`, `tb_telemetry.v`).
- **Regression**: full `pytest` AND the Vivado sim suite stay green (v1.1 must not regress).
- **Timing**: after each module lands, confirm 100 MHz WNS stays positive (5 parallel hashes +
  popcount-free min-query are the watch items; isolate hash multiplies in their own pipeline stage
  as v1.1's scan_rate did to hit closure).

## Resource check (from locked `sizing.py`)

CMS 10.0 + HLL 0.5 = **10.5 BRAM** added; **18 DSP** (15 + 3). Plus the existing v1.1 (~2 BRAM,
14 DSP). Well within 50 BRAM / 90 DSP, leaving room for steps 2–5. Timing, not capacity, is the
risk.

## Scope boundaries (YAGNI — explicitly NOT step 1)

- No hardware top-K heap (top-1 + Pi point-query only).
- No per-source HLL / distinct-destination scan attribution (step 3+).
- No double-buffered snapshot (single-buffer + summary snapshot).
- No closed-loop enforcement (step 4); no runtime rule loading (step 2). Telemetry is read-only
  measurement this step.

## Build/demo result

The Pi polls `0x02` each second → prints `distinct sources ≈ N, top talker = X (count C)`, and can
`0x01`-query any source's exact window count. Drive it with the Pi Zero adversary (flood/scan) to
watch the distinct-source count and top-1 move in real time.
