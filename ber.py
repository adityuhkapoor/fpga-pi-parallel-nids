"""Bit-error accounting for the SPI clock ramp. Pure stdlib so it unit-tests off the Pi."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RampResult:
    frames_compared: int
    frame_errors: int
    bit_errors: int
    _frame_bits: int = 0

    @property
    def ber(self) -> float:
        bits = self.frames_compared * self._frame_bits
        return self.bit_errors / bits if bits else 0.0


def ramp_errors(sent, received, delay=1):
    """Compare a delay-N frame echo: received[k] should equal sent[k-delay].

    The first `delay` reads have no prior frame to echo and are skipped. Returns
    frame/bit error counts over the comparable frames.
    """
    frame_errors = bit_errors = compared = 0
    frame_bits = len(sent[0]) * 8 if sent else 0
    for k in range(delay, len(sent)):
        exp, got = sent[k - delay], received[k]
        compared += 1
        if got != exp:
            frame_errors += 1
            bit_errors += sum(bin(a ^ b).count("1") for a, b in zip(exp, got))
    return RampResult(compared, frame_errors, bit_errors, _frame_bits=frame_bits)
