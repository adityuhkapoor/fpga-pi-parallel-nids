# Runtime control vectors — write/read opcode round-trip (Tier 1)

Format vectors for the v2 step-2 control opcodes (`PROTOCOL.md` § Runtime control). Each row
is the parsed fields ⇄ the exact bytes on MOSI (request) or MISO (response). Pins the byte
layout decoupled from any sketch behavior, so both sides verify independently:

- **FPGA side:** `nids_top.v`'s opcode router consumes these requests and the response mux must
  emit the listed hex. `tb_nids_top` asserts the threshold + bloom round-trip; the rule
  round-trip is covered by `tb_rule_store` standalone.
- **Pi side:** `control.py` encoders generated the hex below; decoders parse responses to the
  listed fields (`test_control.py`).

## Request frames (Pi → FPGA, MOSI)

| Opcode | Fields | 32-byte frame (hex) |
|---|---|---|
| `0x10` | bloom write: `addr=0xABC, value=0xBEEF` | `0abcbeef00000000000000000000000010000000000000000000000000000000` |
| `0x11` | threshold write: `id=0x02 (RATE), value=12` | `02000c0000000000000000000000000011000000000000000000000000000000` |
| `0x12` | rule write: `idx=42, src_ip=CB007105, action=0b101, sev=3, epoch=7` | `002acb0071050503070000000000000012000000000000000000000000000000` |
| `0x13` | bloom read: `addr=0xABC` | `0abc000000000000000000000000000013000000000000000000000000000000` |
| `0x14` | threshold read: `id=0x02` | `0200000000000000000000000000000014000000000000000000000000000000` |
| `0x15` | rule read: `idx=42` | `002a000000000000000000000000000015000000000000000000000000000000` |

## Response frames (FPGA → Pi, MISO; byte 0 = `0x5A` for any valid response)

| Opcode | Response fields | Sample 32-byte response (hex) |
|---|---|---|
| `0x10` ack | `{magic=0x5A, op=0x10}` | `5a10000000000000000000000000000000000000000000000000000000000000` |
| `0x11` ack | `{magic=0x5A, op=0x11}` | `5a11000000000000000000000000000000000000000000000000000000000000` |
| `0x12` ack | `{magic=0x5A, op=0x12}` | `5a12000000000000000000000000000000000000000000000000000000000000` |
| `0x13` resp | `{magic, addr_echo=0x0ABC, value=0xBEEF}` | `5a0abcbeef000000000000000000000000000000000000000000000000000000` |
| `0x14` resp | `{magic, id_echo=0x02, value=0x000C}` | `5a02000c00000000000000000000000000000000000000000000000000000000` |
| `0x15` resp | `{magic, idx_echo=0x002A, rule=9 bytes}` | `5a002acb00710505030700000000000000000000000000000000000000000000` |

Byte 0 ≠ `0x5A` means the request didn't yield a runtime response (e.g., the frame was a
classify or telemetry opcode); receivers must reject such frames for the runtime path.
