#!/usr/bin/env python3
"""SPI loopback self-test. Jumper Pi pin 19 (MOSI) -> pin 21 (MISO).

With the jumper, each transfer reads back exactly what it sent, proving the Pi's
SPI TX/RX path works without the FPGA. Run: sudo python3 spi_loopback_test.py
"""
import sys

from spi_link import SpiLink, FRAME_LEN, MAX_SPEED_HZ, MODE

PATTERNS = {
    "incrementing": bytes(range(FRAME_LEN)),
    "0xAA":         bytes([0xAA]) * FRAME_LEN,
    "0x55":         bytes([0x55]) * FRAME_LEN,
    # 192.0.2.1 -> 198.51.100.1 (RFC 5737 doc IPs), sport 54321, dport 443, TCP, flags 0x18, size 512
    "header-like":  bytes.fromhex("c0000201c6336401d43101bb0618020000000000" + "00" * 12),
}


def main() -> int:
    link = SpiLink()
    print(f"# spidev0.0: mode {MODE}, {MAX_SPEED_HZ // 1000} kHz, MSB-first, {FRAME_LEN}B frames")

    passed = 0
    saw_nonzero = False
    for name, tx in PATTERNS.items():
        rx = link.send_frame(tx)
        ok = rx == tx
        passed += ok
        saw_nonzero |= any(rx)
        print(f"  {name:13} tx={tx.hex()}")
        print(f"  {'':13} rx={rx.hex()}  {'PASS' if ok else 'MISMATCH'}")
    link.close()

    print(f"\n{passed}/{len(PATTERNS)} patterns matched.")
    if passed == len(PATTERNS):
        print("LOOPBACK PASS — Pi SPI TX/RX verified.")
        return 0
    if not saw_nonzero:
        print("All readback bytes were 0x00 (MISO saw nothing) — is the pin 19 -> pin 21 jumper connected?")
    else:
        print("Readback differs from sent — check the jumper / SPI settings.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
