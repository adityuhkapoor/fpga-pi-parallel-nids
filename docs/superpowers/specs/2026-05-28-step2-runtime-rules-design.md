# v2 Step 2 — Runtime Rule Loading Design

Status: **proposed** (2026-05-28). Implements build-order step 2 of `docs/SPEC_v2.md`. Layers a
write path on the opcode framing established in step 1 (see [[v2-step1-telemetry-done]]) — no new
sketches, just a control plane the Pi uses to hot-load classifier state at runtime without a
bitstream rebuild.

## Goal

Three pieces of classifier state become runtime-writable from the Pi:

1. **Bloom blocklist** — currently baked into the bitstream from `bloom_init.mem` at build time.
   After step 2 the Pi can rewrite all 4096 × 16-bit words at runtime; old contents are
   overwritten word-by-word, so swapping in a new C2 set just means writing the full filter.
2. **Classifier thresholds** — v1.1's `PORT_THRESH=5`, `HOST_THRESH=5`, `RATE_THRESH=8` move from
   `localparam`s in `scan_rate.v` to runtime registers writable over SPI.
3. **Rule store** — the locked **512 × 72-bit** structure from `sizing.py`. New for v2. Step 2
   builds the storage + the loader and pins the rule layout in `PROTOCOL.md`; **lookup and
   enforcement are step 4's job** (closed loop).

## The 6 new opcodes (back-compatible with steps 0–1)

Steps 0–1 use `0x00–0x03`. Step 2 adds `0x10–0x15`. Layout convention (32-byte frame, byte 16 =
opcode, big-endian):

| op | dir | request payload (bytes 0–15 + 17–31) | response (magic `0x5A`) |
|---|---|---|---|
| `0x10` | W | `word_addr:16` (b0–1) · `word_value:16` (b2–3) | ack `{0x5A, 0x10}` |
| `0x11` | W | `threshold_id:8` (b0) · `value:16` (b1–2) | ack `{0x5A, 0x11}` |
| `0x12` | W | `rule_idx:16` (b0–1) · `rule:72` (b2–10, see format) | ack `{0x5A, 0x12}` |
| `0x13` | R | `word_addr:16` (b0–1) | `{0x5A, addr_echo:16, word_value:16}` |
| `0x14` | R | `threshold_id:8` (b0) | `{0x5A, id_echo:8, value:16}` |
| `0x15` | R | `rule_idx:16` (b0–1) | `{0x5A, idx_echo:16, rule:72}` |

Write opcodes return a minimal magic+opcode ack so the Pi can distinguish "the bitstream
understood this" from a stale verdict. Verification is via the explicit read opcodes — the Pi
writes, then reads back, comparing to what it wrote.

**One word per write frame** — chose simplicity over throughput. A full 4096-word Bloom rewrite
is 4096 frames × 32 µs/frame ≈ **130 ms** at the locked 8 MHz link. That's a control-plane event,
not in the per-packet path, so a clean per-frame protocol beats fighting to pack multiple words
into one frame.

## Rule format (locked here, byte-aligned for clean wire serialization)

Step-4 consumes this; step 2 just stores it. The 72 bits pack into 9 bytes (the awkward
4-bit/8-bit/20-bit slivers get byte-aligned so wire serialization is direct):

| Bytes | Field | Meaning |
|---:|---|---|
| 0–3 | `src_ip` (32) | source IP pattern this rule matches |
| 4 | `action` (8) | bit 0 drop/flag · bit 1 alert · bit 2 escalate · bits 3–7 reserved |
| 5 | `severity` (8 → low 4 used) | 0–3, maxed with v1.1 classifier severity |
| 6 | `epoch` (8) | rule active only if `stored == current_rule_epoch` register (mass-expire via Pi incrementing epoch — one frame, no per-rule cleanup) |
| 7–8 | reserved (16) | zero |

Total 9 bytes = 72 bits.

Threshold IDs (8-bit; only the low 4 used today, reserved upward):

| id | name | wired into |
|---:|---|---|
| `0x00` | `PORT_THRESH` | `scan_rate.v` port-fingerprint popcount threshold (default 5) |
| `0x01` | `HOST_THRESH` | `scan_rate.v` host-fingerprint popcount threshold (default 5) |
| `0x02` | `RATE_THRESH` | `scan_rate.v` per-source pkt-count threshold (default 8) |

A power-on reset restores the defaults; reads (`0x14`) confirm them.

## Architecture

New / modified modules, each with a clear single responsibility:

| Module | Responsibility | BRAM |
|---|---|---|
| `bloom_filter.v` *(modify)* | add port-B write interface (TDP) — query on port A, hot-load on port B; same 8 BRAM | 8.0 (unchanged) |
| `thresholds.v` *(new)* | tiny register file: 3 × 16-bit thresholds + power-on defaults; ports written by opcode `0x11`, read by `0x14` | 0 (flops) |
| `rule_store.v` *(new)* | 512 × 72-bit BRAM (1 RAMB36 in 512×72 mode); single write port (Pi), single read port (step 4) | 1.0 |
| `scan_rate.v` *(modify)* | `PORT_THRESH`/`HOST_THRESH`/`RATE_THRESH` `localparam`s become module *inputs* fed from `thresholds.v` | — |
| `nids_top.v` *(modify)* | decode opcodes `0x10–0x15`, route writes to the right BRAM/register, build read-back response frames; pattern mirrors step 1's response mux | — |

**Data flow (write path):** `spi_slave_rx → header_parser → cmd-route on byte 16 → { bloom write port, thresholds reg-file, rule_store write port }`. Reads use the same routing pattern as step 1's snapshot/HLL responses.

## Atomicity — single-buffer, accept transient state during bulk Bloom load

- Bloom is a true dual-port (TDP) BRAM on Xilinx RAMB36 — port A query, port B write. Same
  physical 8 BRAM, no doubling. While the Pi writes (130 ms), classifier queries see a
  partially-updated filter. That's a control-plane convention every real router uses; the Pi
  treats verdicts as advisory during a bulk load.
- **No double-buffer.** Would cost +8 BRAM (~16% of the chip) just to avoid a 130 ms transient
  on an infrequent event. Hard no.
- Threshold writes are single-register, atomic at the clock edge. No transient.
- Rule store writes are per-entry single-word BRAM updates, atomic. Reading rule N during a
  write to rule N would race, but the use case is "Pi loads rules, then they get consumed" — not
  simultaneously.

## Verification methodology (TDD, same discipline as steps 0–1)

Per module a bit-exact Python twin + golden vectors + a self-checking testbench, **mirroring
`scan_rate.py ↔ scan_rate.v`**:

- **`rule_store_model.py`** — 512-entry list of rule dicts; `write(idx, rule)` / `read(idx)`;
  trivially bit-exact to `rule_store.v`'s registered read of a 72-bit BRAM word.
- **`thresholds_model.py`** — 3-entry dict with the documented defaults; `write(id, val)` /
  `read(id)`.
- **Bloom hot-load round-trip** — no new model needed; the existing `bloom.py` builds the bit
  array, the Pi loader writes each word, then a `read(addr)` round-trip per word confirms.
- **`control.py`** (Pi-side, new) — encoders for opcodes `0x10–0x15`, decoders for the read
  responses, write-then-readback helpers used by the silicon demo.
- **pytest**: round-trip per opcode (write a known value, read it back, assert match); bloom
  hot-load + member-query consistency check using the existing CPU classifier.
- **Vivado sim**: extend `tb_bloom_filter` (write→query round-trip, the port-B path); new
  `tb_rule_store` and `tb_thresholds`; extend `tb_nids_top` to send each new opcode as a frame,
  capture the response one frame later, assert read-back matches written value.
- **WNS check after each new module** — `thresholds` is trivial; `rule_store` is a single 1-cycle
  BRAM read so no logic depth; `bloom_filter` gains a TDP write port (same RAMB36 timing); the
  `nids_top` response mux grows by 6 cases but stays a registered mux. None of these should
  threaten the +0.107 ns margin from step 1, but confirm after build.

## Resource impact

- `bloom_filter`: same 8 BRAM (TDP doesn't double cost), +few LUTs for write-port wiring.
- `thresholds`: 3 × 16-bit registers, trivial.
- `rule_store`: **+1 BRAM** (512×72 in 1 RAMB36).
- `nids_top`: opcode decode + write routing + read-back mux — pattern-extension of step 1.

Step-2 totals: **13.5 / 50 BRAM (27%)**, DSP unchanged (35 / 90, 39%). Headroom intact for
steps 3–5.

## Silicon demo (the headline)

Replaces v1.1's bake-it-in C2 set with a **runtime swap**:

1. Boot the step-2 bitstream → bloom starts from `bloom_init.mem` (default C2 set).
2. Run `spi_verdict_check.py` → **120 / 120** (baseline regression).
3. Hot-load a NEW C2 set: Pi recomputes the bloom locally (`bloom.py from_ips(new_set)`), then
   writes all 4096 words via opcode `0x10`. ~130 ms.
4. Read-back via `0x13` confirms every word matches what was written.
5. Send a custom verdict-check stream — packets carrying the NEW C2 IPs should bloom-hit; the
   ORIGINAL C2 IPs (gone after the rewrite) should NOT hit.

This proves the entire hot-load path on real silicon: write → BRAM → classifier query path.

## Scope boundaries (YAGNI — explicitly NOT step 2)

- **Rule-store lookup / enforcement** — step 4. Step 2 stops at "rules can be loaded and read
  back, format pinned."
- **Double-buffer / atomic-swap for Bloom** — single-buffer, brief transient accepted.
- **New sketches, new telemetry, closed-loop logic** — out of scope.
- **Authentication / write-protect** — none. The Pi is trusted; SPI is point-to-point on
  jumpers; no security boundary needed at the control-plane interface.

## Open / watch

- A wide multiplexed read-back response mux in `nids_top` could become a timing hotspot as
  opcodes accumulate. Mitigation: pipeline the response mux into its own stage if WNS dips.
- Bloom hot-load is byte-by-word; if the 130 ms transient turns out to actually matter at demo
  time, an "enable" gate on the bloom query path (freeze classifier verdicts during a load) is a
  small additive change for a future revision.
