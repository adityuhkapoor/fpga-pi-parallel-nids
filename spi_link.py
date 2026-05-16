"""SPI link to the FPGA. Pi is master on /dev/spidev0.0; see PROTOCOL.md."""
import spidev

# Locked SPI parameters (PROTOCOL.md).
BUS, DEVICE = 0, 0           # /dev/spidev0.0 (SPI0, CE0)
MODE = 0b00                  # CPOL=0, CPHA=0
MAX_SPEED_HZ = 1_000_000     # 1 MHz
FRAME_LEN = 20


class SpiLink:
    def __init__(self, bus=BUS, device=DEVICE, speed_hz=MAX_SPEED_HZ, mode=MODE):
        self.spi = spidev.SpiDev()
        self.spi.open(bus, device)
        self.spi.max_speed_hz = speed_hz
        self.spi.mode = mode
        self.spi.bits_per_word = 8
        self.spi.lsbfirst = False  # MSB-first

    def send_frame(self, frame: bytes) -> bytes:
        """Clock a 20-byte frame out on MOSI; return the 20 bytes shifted in on MISO.

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
