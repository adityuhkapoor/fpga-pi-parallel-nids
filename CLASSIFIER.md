# Classifier spec — Pi ↔ FPGA shared logic

The detection logic both sides implement. It **must match bit-for-bit** between the
FPGA (queries) and the Pi CPU reference (builds the data + runs the same logic for the
HW-vs-CPU benchmark). Source of truth, same as `PROTOCOL.md`. Changes need both sides.

## Scope
- **v1:** the **bloom C2-IP match** stage (mask bit0). Stateless.
- **v1.1 (implemented):** **port-scan** (bit1) and **rate-anomaly** (bit2) — stateful,
  specced in the "v1.1" section below. Made bit-identical across HW and CPU by using
  frame-count windows (not wall-clock) so golden vectors stay deterministic.
- Verdict severity = max of the fired stages (bloom 3, port-scan 2, rate 2); escalate =
  any stage fired; mask = {rate, port_scan, bloom}.

---

## Bloom stage — C2 IP exact-match

### Purpose
Flag any packet whose **src or dst IPv4** is on a known command-and-control blocklist
(abuse.ch **Feodo Tracker**, /32 IPs — exact-match, never CIDR). A Bloom filter gives
O(1) membership with a tiny, fixed memory footprint that lives in FPGA BRAM.

### Parameters (LOCKED — both sides hardcode these)
| Param | Value | Why |
|---|---|---|
| bit-array size `m` | **65536** (2¹⁶) | 8 KB — one Basys 3 BRAM; index is exactly 16 bits |
| hash count `k` | **2** | two lookups map to dual-port BRAM → single-cycle membership |
| hash family | multiply-shift (Dietzfelbinger) | one 32×32 multiply each; identical in Verilog and Python |

### Hashing
Let `x` = the IPv4 as a 32-bit big-endian unsigned int (e.g. `192.0.2.1 = 0xC0000201`,
exactly the value `header_parser` puts on `src_ip[31:0]`). Two 16-bit indices:

```
h1(x) = ((x * 0x9E3779B1) & 0xFFFFFFFF) >> 16
h2(x) = ((x * 0x85EBCA77) & 0xFFFFFFFF) >> 16
```

Both constants are odd (required for multiply-shift). In Verilog: `prod = x * A;` (take
low 32 bits) then index = `prod[31:16]`. In Python: `((x * A) & 0xFFFFFFFF) >> 16`.

### Membership & hit rule
```
member(ip)  = bitarray[h1(ip)] AND bitarray[h2(ip)]
bloom_hit   = member(src_ip) OR member(dst_ip)
```
A `bloom_hit` sets **mask bit0**, **severity = 3 (high)**, **escalate = 1**.
(With only bloom in v1: no hit → clean verdict `mask=0, severity=0, escalate=0`.)

### Bit-array construction (Pi builds it)
For every C2 IP in the feed set: set `bitarray[h1(ip)] = 1` and `bitarray[h2(ip)] = 1`.
Expected false-positive rate at n≈1000 IPs: ≈0.09% — fine for a pre-filter/offload.

### FPGA BRAM init — `bloom_init.mem`
The Pi emits the bit-array as a `$readmemh` file the FPGA bakes into BRAM init:
- **4096 lines**, each one **16-bit** hex word (4 hex digits).
- Line `w` (0-indexed) holds bits `[16w … 16w+15]`; **bit `p` of the word (p=0 = LSB)
  = `bitarray[16w + p]`**.
- FPGA reads index `b`: `word = mem[b >> 4]; bit = word[b & 0xF]`.

`bloom_init.mem` is a generated artifact committed to this repo when the feed changes;
the FPGA `$readmemh`s it into the bloom BRAM. (No runtime load protocol in v1 — the feed
is static per bitstream.)

### Test C2 set (for Tier-2 golden vectors — deterministic, no live feed)
Tier-2 vectors use this fixed RFC 5737 set as "known C2" so `header → verdict` is
reproducible without pulling a live blocklist:
```
198.51.100.1   (0xC6336401)
203.0.113.5    (0xCB007105)
192.0.2.99     (0xC0000263)
```
The live demo can swap in the real Feodo Tracker feed; the test vectors stay on this set.

---

## Tier-2 golden vectors (header → verdict)
Once the bloom builder + CPU reference exist (Pi side), the Pi generates
`VERDICT_GOLDEN.md`: each a 20-byte **input header** → the 20-byte **verdict** the
classifier must produce, computed by the CPU reference over the test C2 set above. The
FPGA pipeline TB asserts it produces the same verdict; the Pi asserts its CPU reference
matches. Same cross-check pattern as the header parser's golden vectors.

---

## v1.1 — port-scan + rate-anomaly (stateful)

Both stages share **one per-source state table** in BRAM (one read-modify-write per
packet). HDL: `scan_rate.v`. CPU reference: `scan_rate.py` (`ScanRateTable`). LOCKED and
bit-exact across both.

### Window model
Frame-count windows (no wall-clock): `epoch = frame_count >> 4` → **16-frame windows**.
`frame_count` is the 0-based packet index (the FPGA feeds the pre-increment frame counter,
`nids_top.frame_idx`, so the board epoch matches the CPU reference exactly).

### State table (LOCKED)
- **256 buckets**, direct-mapped, `bucket = ((src_ip * 0x9E3779B1) & 0xFFFFFFFF) >> 24`.
  Collisions cause false positives — accepted, same as the bloom.
- **Entry (64-bit):** `{ rsvd[19:0], epoch[3:0], host_fp[15:0], port_fp[15:0], pkt_count[7:0] }`
  → pkt_count `[7:0]`, port_fp `[23:8]`, host_fp `[39:24]`, epoch `[43:40]`.
- **Lazy tumbling reset:** on touch, if the stored 4-bit epoch ≠ current epoch, zero the
  entry before applying the packet.

### Fingerprints (approximate distinct-counting)
```
port_bit = ((dst_port * 0x85EBCA77) & 0xFFFFFFFF) >> 28   # 0..15, set in port_fp
host_bit = ((dst_ip   * 0x9E3779B1) & 0xFFFFFFFF) >> 28   # 0..15, set in host_fp
```
popcount(fp) ≈ distinct count (collisions undercount).

### Rules (per packet, after the lazy reset)
- **Port-scan (bit1)** updates the fingerprints **only on TCP SYN-without-ACK**
  (`proto==6 && tcp_flags[1] && !tcp_flags[4]`). Fires if
  `popcount(port_fp) >= 5` (vertical/port sweep) **OR** `popcount(host_fp) >= 5`
  (horizontal/host sweep). severity 2.
- **Rate-anomaly (bit2):** `pkt_count` increments on **every** packet (saturating 0xFF).
  Fires if `pkt_count >= 8` in the window. severity 2.

### Locked parameters
| Param | Value |
|---|---|
| Window | 16 frames (`epoch = frame_count >> 4`) |
| Buckets | 256 |
| Port-sweep / host-sweep threshold | popcount ≥ 5 |
| Rate threshold | pkt_count ≥ 8 |
| Scan gate | TCP (proto 6) && SYN && !ACK |

v1.1 golden vectors (the silicon stream) are in `VERDICT_GOLDEN.md`, generated by
`gen_verdict_golden.py` over the CPU reference.
