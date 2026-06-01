"""SPI link to the FPGA. Pi is master on /dev/spidev0.0; see PROTOCOL.md.

spidev is imported lazily inside SpiLink.__init__ so constants (FRAME_LEN) can be
pulled in for off-Pi unit tests on machines without spidev installed."""

# Locked SPI parameters (PROTOCOL.md).
BUS, DEVICE = 0, 0           # /dev/spidev0.0 (SPI0, CE0)
MODE = 0b00                  # CPOL=0, CPHA=0
MAX_SPEED_HZ = 8_000_000     # 8 MHz (step-0 measured ceiling 9 MHz, run derated)
FRAME_LEN = 32               # v2 frame width (v1 was 20)


class SpiLink:
    def __init__(self, bus=BUS, device=DEVICE, speed_hz=MAX_SPEED_HZ, mode=MODE):
        import spidev                   # Pi-only; importing eagerly would break off-Pi tests
        self.spi = spidev.SpiDev()
        self.spi.open(bus, device)
        self.spi.max_speed_hz = speed_hz
        self.spi.mode = mode
        self.spi.bits_per_word = 8
        self.spi.lsbfirst = False  # MSB-first

    def send_frame(self, frame: bytes) -> bytes:
        """Clock a 32-byte frame out on MOSI; return the 32 bytes shifted in on MISO.

        xfer2 holds CE0 low for the whole transfer and raises it after — the
        chip-select framing the FPGA uses to delimit frames.
        """
        if len(frame) != FRAME_LEN:
            raise ValueError(f"frame must be {FRAME_LEN} bytes, got {len(frame)}")
        return bytes(self.spi.xfer2(list(frame)))

    def close(self) -> None:
        self.spi.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
