# SPI Protocol — Pi (master) ↔ Basys 3 FPGA (slave)

Authoritative contract for the SPI link between the two halves of
**fpga-pi-parallel-nids**. The Pi-side `spi_send()` (master) and the FPGA-side
SPI slave both build against this. Any change must be agreed by both sides.


## Link parameters
- Roles: Raspberry Pi 5 = SPI **master**; Basys 3 (Artix-7) = SPI **slave**.
- Pi device: `/dev/spidev0.0` (SPI0, chip-enable CE0).
- **Mode 0** (CPOL=0, CPHA=0): clock idles low, data sampled on the rising edge.
- **MSB-first.**
- **8-bit** words.
- **Clock: 8 MHz.** v1 ran 1 MHz (conservative for jumper wiring); a step-0 hardware BER
  ramp found the zero-error ceiling is 9 MHz over the Pmod jumpers (signal-integrity
  limited), so v2 runs **8 MHz** derated.
- **Framing: CE0 (chip-select).** CS is held low for an entire transfer; one frame = exactly **32 bytes** between CS going low and CS going high. The FPGA resets its byte counter on the CS rising edge. (`spidev.xfer2()` asserts CS for the duration of each call and deasserts after — so one `spi_send()` == one CS-framed 32-byte frame.)

## Request frame — 32-byte packet header (Pi → FPGA, MOSI)
Big-endian, word-aligned. The 16 header bytes below (the v1 layout) plus 16 reserved bytes:

| Bytes | Field        | Notes                            |
|------:|--------------|----------------------------------|
| 0–3   | src IPv4     |                                  |
| 4–7   | dst IPv4     |                                  |
| 8–9   | src port     | 0 if not TCP/UDP                 |
| 10–11 | dst port     | 0 if not TCP/UDP                 |
| 12    | protocol     | IP protocol number               |
| 13    | TCP flags    | FIN SYN RST PSH ACK URG ECE CWR  |
| 14–15 | packet size  | bytes                            |
| 16–31 | reserved     | zero                             |

## Response — 32-byte verdict (FPGA → Pi, MISO)
SPI is full-duplex: during each 32-byte transfer the FPGA shifts 32 bytes back.

- **v1 (bring-up):** FPGA returns zeros (or a frame echo); the Pi ignores the read
  data. `magic != 0xA5` means "no verdict here," so v1 is forward-compatible with v2.
- **v2 (pipelined):** the 32 bytes shifted back during the transfer of frame N carry
  the verdict for the **previous** frame, N−1 — the classifier needs cycles, so the
  result lags by exactly one frame. The very first transfer (no prior frame) and any
  transfer after reset return `magic = 0x00`, i.e. "no valid verdict yet."

Verdict byte layout (single-byte, byte-aligned fields — no multi-byte endianness):

| Byte  | Field             | Meaning                                                                 |
|------:|-------------------|-------------------------------------------------------------------------|
| 0     | **magic**         | `0xA5` = this is a valid verdict; anything else = no verdict (ignore)   |
| 1     | **stage-hit mask**| bit0 = bloom C2-IP match · bit1 = port-scan · bit2 = rate-anomaly · bits 3–7 reserved (0) |
| 2     | **severity**      | 0 = clean · 1 = low · 2 = med · 3 = high (max severity across hit stages) |
| 3     | **flags**         | bit0 = escalate (Pi should deep-inspect this flow) · bits 1–7 reserved (0) |
| 4     | **seq**           | `frame_count & 0xFF` — **1-based** (first received frame → `seq=1`); lets the Pi line up the one-frame lag |
| 5–31  | reserved          | zero                                                                    |

Notes:
- **`seq` semantics (1-based, confirmed by both sides):** `frame_count` starts at 0 on
  reset and increments **before** each verdict is produced, so the **first received frame
  → `seq=1`**. `seq = frame_count & 0xFF`, so it wraps `…254, 255, 0, 1, …` — meaning
  **`seq=0` is a legal value** (frames 256, 512, …), **not** a sentinel. Validity is
  decided solely by `magic`, never by `seq`. After classifying frame K the FPGA loads the
  verdict with `seq = K & 0xFF`; that verdict is shifted out during the transfer of frame
  K+1. The Pi keeps an identical 1-based send counter: the verdict read back during the
  Pi's transfer N describes frame N−1 and must carry `seq = (N−1) & 0xFF`.
- **`stage-hit mask = 0` with `magic = 0xA5`** is a valid "clean" verdict (all stages
  ran, nothing matched) — distinct from "no verdict" (`magic != 0xA5`).
- **`0xA5`** is the standard alternating-bit sync pattern (`1010_0101`): chosen over
  `0x00`/`0xFF` because it makes a bit-shift or stuck line on MISO immediately visible.
- Reserved bits/bytes are 0 on the wire today; receivers must ignore them so the
  layout can grow without breaking the contract.

## Physical wiring (verified against the Pi's `pinout` and pinout.xyz)
Both sides are 3.3V — wire directly, no level shifter.

| Signal | Pi GPIO | Pi phys pin | FPGA dir | Basys 3 Pmod JB        |
|--------|---------|-------------|----------|------------------------|
| MOSI   | GPIO10  | 19          | input    | JB1 (conn pin 1) = A14 |
| MISO   | GPIO9   | 21          | output   | JB2 (conn pin 2) = A16 |
| SCLK   | GPIO11  | 23          | input    | JB3 (conn pin 3) = B15 |
| CE0    | GPIO8   | 24          | input    | JB4 (conn pin 4) = B16 |
| GND    | —       | 25 (or 20)  | —        | JB GND (conn pin 5)    |

Rules:
- Connect **only** the 4 signals + a shared **GND**. Each board is self-powered.
- **Do NOT** connect anything to the Pmod VCC pins (6 & 12).
- FPGA assigns the exact Pmod pins in its XDC; directions: MOSI/SCLK/CE0 are
  FPGA **inputs**, MISO is an FPGA **output**.

## Loopback test (Pi only, before the FPGA exists)
Bridge Pi **pin 19 (MOSI) ↔ pin 21 (MISO)** with one jumper. `spi_send()` writes
the 32 bytes; the bytes read back on the same transfer must equal what was sent.
This proves the Pi's SPI transmit/receive path independent of the FPGA.
