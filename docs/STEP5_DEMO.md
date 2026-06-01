# Step 5 — synthetic-mode closed-loop demo

The v2 capstone. One Python process on the Pi 4B owns `/dev/spidev0.0`, runs an
event loop that pulls 32-byte classify frames from a scenario iterator, sends each
over SPI, decodes the verdict the FPGA returns one frame later, polls telemetry,
and pushes a runtime block-rule when a top talker emerges. A live curses dashboard
(or `--no-tui` text log) shows the closed loop firing.

No second box. No sniffing. The FPGA can't tell the difference between a frame
that came off eth0 and one built with `bytearray(32)` — `silicon_loop_demo.py`
already proved the equivalence end-to-end.

## Run it

    sudo python3 run_demo.py                          # default 60s scripted schedule + curses TUI
    sudo python3 run_demo.py --scenario flood         # pin one scenario, run forever
    sudo python3 run_demo.py --no-tui --duration 60   # text log (CI / screencap-friendly)

Q quits the TUI early.

## Default schedule (60 s)

| t (s) | Scenario | What it demonstrates |
|---|---|---|
| 0–10  | `benign`    | quiet baseline — diverse RFC5737/RFC1918 srcs, no verdicts |
| 10–20 | `c2`        | source cycles through the locked C2 IPs → `bloom` bit + 3 rule pushes |
| 20–30 | `port_scan` | one src, distinct dports → `port_scan` bit + rule push |
| 30–45 | `flood`     | one src floods → `rate` bit, then rule push, then `rule_match` |
| 45–60 | `benign`    | quiet again — rules persist, but the talkers are gone |

## Evidence — silicon-verified 60 s run

From `docs/demo_logs/step5_60s_scripted.log` (real Pi 4B + FPGA):

    [  0.10s] scenario -> benign
    [ 10.00s] scenario -> c2
    [ 10.60s] RULE pushed: block 198.51.100.1 (idx 0x0DC)
    [ 11.60s] RULE pushed: block 192.0.2.99   (idx 0x0BC)
    [ 12.60s] RULE pushed: block 203.0.113.5  (idx 0x1DD)
    [ 20.00s] scenario -> port_scan
    [ 20.60s] RULE pushed: block 10.0.0.5     (idx 0x002)
    [ 30.00s] scenario -> flood
    [ 30.60s] RULE pushed: block 10.0.0.6     (idx 0x13E)
    [ 45.00s] scenario -> benign

**Verdict-bit coverage in the same run:**

| Bit | Verdicts observed |
|---|---|
| `bloom`      | 100 |
| `port_scan`  |  76 |
| `rate`       |  99 |
| `rule_match` | 349 |

All four bits trip; the FPGA flags every flood frame post-rule-push with both
`rate` and `rule_match`, exactly as the architecture predicts.

## Architecture summary

Single Python process owns the SPI link. The orchestrator's event loop:

1. Pulls the next 32-byte frame from the active scenario iterator.
2. `link.send_frame(frame)` — the 32 bytes shifted back are the verdict for the
   *previous* classify (one-frame pipeline lag per `PROTOCOL.md`).
3. Every `--snap-every` ticks (default 50), polls snapshot via opcode `0x02`.
4. If `top1_count >= --trigger` and that source hasn't been ruled, builds a
   block-rule (`action=0b101`, `severity=3`) and writes it at `lookup_idx(top1)`
   via opcode `0x12`. The FPGA's `rule_lookup` hashes the same source to the
   same index on subsequent frames and flips `hit_mask` bit 3.
5. Renders the dashboard.

Single fd → no spidev contention. No threads, no IPC, no signal handling. Ctrl-C
exits the loop cleanly.

See:
- spec: `docs/superpowers/specs/2026-05-28-step5-synthetic-demo-design.md`
- plan: `docs/superpowers/plans/2026-05-28-step5-synthetic-demo.md`

## Adding LAN mode later

Strict extension. Replace `schedule.frames()` with a `scapy.sniff(iface="eth0",
prn=...)`-driven generator that yields the same 32-byte frame shape, and the
orchestrator loop is unchanged. A second Pi running `hping3 --flood` / `nmap`
becomes the adversary. The dashboard, rule push, and verdict bookkeeping all
stay identical.
