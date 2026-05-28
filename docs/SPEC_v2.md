# v2 Spec — Telemetry + Runtime-Loadable Rules (LOCKED)

Status: **locked** (2026-05-27; SPI clock re-locked 30 MHz → 8 MHz after the step-0
hardware ramp — see Workload bounds). Resource dimensions below are derived from the
workload + each structure's accuracy formula, not chosen by hand. The parametric
model that produced them is `docs/sizing.py` — change an input there and rerun to
re-derive everything.

## Goal

Keep the v1 gist — **Pi sniffs packets → FPGA classifies/measures → verdict back to
Pi** — but take the design from *functionally tiny* (v1: 241 LUTs, ~1.2% of the chip,
20-byte headers over a 1 MHz SPI link) to a coherent system that uses ~60% of the
board and does something real:

1. **Line-rate telemetry** — Count-Min heavy-hitters + HyperLogLog distinct-host
   cardinality, computed in hardware over a 1 s window.
2. **Runtime-loadable rules** — the Pi acts as a control plane and hot-loads
   blocklists / thresholds / rules into FPGA BRAM **without a bitstream rebuild**
   (this is the achievable substitute for partial reconfiguration; DFX is **not
   supported** on the xc7a35t — verified, do not attempt).
3. **Closed loop** — telemetry feeds policy: FPGA measures a host turning into a
   heavy hitter → Pi reads it → Pi pushes a new rule down → FPGA enforces. Classic
   observe-decide-act.

## Target chip — xc7a35t (Basys 3)

| Resource | Total | v2 budget | Headroom |
|---|---|---|---|
| BRAM (36 Kb blocks) | 50 | **30.5 (61%)** | 19.5 free |
| DSP48E1 | 90 | **27 (30%)** | 63 free |
| LUT | 20,800 | not binding (control logic only) | — |

BRAM is the binding resource. Capacity fits comfortably; **the real risk is timing
closure** (see Constraints).

## Workload bounds (these force the counter/window sizes)

- Link: **8 MHz SPI**, compact **32-byte header frames**. The 30 MHz target was tested on
  hardware in Build Order step 0 and **did not hold**: over Pmod jumpers the zero-error
  ceiling is **9 MHz** — signal-integrity limited, not logic (confirmed by a BER ramp on
  silicon: clean ≤9 MHz over 100k frames, ~16% BER at 10 MHz, ~50% BER ≥15 MHz; more
  oversampling can't recover a degraded edge, so the fix is physical wiring, not an MMCM).
  We run **8 MHz** derated (8× v1's 1 MHz, clean over 100k frames). Sizing rests on this
  measured rate.
- Throughput: ~14,000 packets/sec after ~55% userland/spidev overhead.
- Telemetry window: **1 s** → ~14,000 packets/window → **counters need 14 bits**
  (`ceil(log2(14062))`). (A faster link later still needs ≤16 bits for any pps < 65,536,
  which the same BRAM primitives hold — so the budget is robust to the clock.)

## Locked memory spec

| Memory | depth | width | BRAM | DSP | Derived from |
|---|---|---|---|---|---|
| **Count-Min sketch** | 5 × 4096 | 14b/row | 10.0 | 15 | ε=0.1% → `w=⌈e/ε⌉`=4096 cols; δ=1% → `d=⌈ln(1/δ)⌉`=5 rows; **5 independent banks** (see note) |
| **HyperLogLog** | 2048 | 5 | 0.5 | 3 | 3% error target → `m=(1.04/err)²`=2048 (actual 2.3%) |
| **Bloom blocklist** | 262144 | 1 | 8.0 | 6 | 16,384 IPs @ 0.1% target → `m=-n·ln(p)/(ln2)²`=2¹⁸, k=11, real FP 0.046%; **2 base hashes (Kirsch-Mitzenmacher)** |
| **Flow/connection table** | 4096 | 98 | 11.0 | 3 | 4096 concurrent flows × 98b state (below) |
| **Runtime rule store** | 512 | 72 | 1.0 | 0 | 512 hot-loadable rules, Pi-written |
| **TOTAL** | | | **30.5** | **27** | DSP at ~3 DSP/hash (v1-measured); move hashes to LUTs if DSP gets tight |

**Flow-table 98-bit state field budget:** `epoch:8 + pkt_count:14 + byte_count:24 +
syn_count:12 + dport_fp:16 + dhost_fp:16 + flags:8 = 98`.

**Count-Min layout note:** the 5 rows are **independent banks**, each 4096×16 with its
own hash. For input `x`, row `j` is read at column `h_j(x)`, and those columns *differ
per row* — so the rows **cannot** share one word/address (that would force all hashes
equal and destroy the independence CMS relies on for its error bound). Five parallel
bank reads per packet; with ~1,900 clk/packet of budget there's ample room even if read
sequentially. Cost: 5 × 2 = 10 BRAM.

## Architecture / hardware roles

- **FPGA (Basys 3)** — line-rate measurement + enforcement (fast, parallel, dumb).
- **Pi 5** — control plane: reads telemetry, applies policy, hot-loads rules.
- **Pi Zero** — dedicated adversary node (scans/floods via nmap/hping3/scapy).
- **Pi 4** — benign background traffic generator / second capture vantage point.

The two extra Pis are **not gratuitous**: a bigger detector needs traffic to feed and
demo it, and they provide the benign+adversarial load that makes the closed loop
visibly do something.

## Build order (each stage independently shippable + demoable)

0. **Link upgrade (prerequisite)** — raise SPI 1 MHz → **8 MHz** (30 MHz target tested,
   signal-integrity-capped at 9 MHz over jumpers; see Workload bounds); stream compact
   headers (not 20B fixed). Re-run `benchmark.py` to show system-throughput scaling.
   Without this the bigger classifier starves.
1. **Telemetry half** — Count-Min + HyperLogLog in BRAM, 1 s window, read out by Pi.
   Biggest board-filling piece; stands alone as a result.
2. **Runtime rule loading** — Pi writes Bloom blocklist + thresholds + rule store into
   BRAM at runtime; bidirectional link. Smaller, layers on top of step 1's data path.
3. **Flow/connection table** — per-flow state, replaces v1's 256-bucket undercounting
   table with collision handling.
4. **Close the loop** — telemetry → Pi policy → rule push → enforcement.
5. **Demo testbed** — wire up the Pi Zero / Pi 4 traffic generators.

## Constraints / non-negotiables

- **Verification methodology is mandatory for every new module.** v1's strongest asset
  is bit-exact CPU golden models (`scan_rate.py` ↔ `scan_rate.v`). Every new structure
  (Count-Min, HLL, Bloom, flow table) gets a bit-exact Python reference + golden vectors
  + a self-checking testbench. This is the project's differentiator — do not skip it.
- **Timing, not capacity, is the real risk.** 61% BRAM is fine, but packing memories +
  hash logic can break the 100 MHz closure v1 achieved. After **each** module lands,
  confirm WNS stays positive via `report_utilization`/timing reports. Capacity is a
  spreadsheet; timing is the engineering.
- **No DFX / partial reconfiguration** on this chip — unsupported on small Artix-7.
  Runtime reconfiguration is *data* (BRAM writes), never *logic*.

## Re-tuning

All inputs live at the top of `docs/sizing.py`: link speed, frame size, window, ε, δ,
blocklist size n, FP rate p, flow count, field widths. Change any → dimensions and the
BRAM/DSP budget recompute. Run `python3 docs/sizing.py`.
