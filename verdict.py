"""Decode the 32-byte v2 verdict frame the FPGA returns on MISO (PROTOCOL.md §Response).

Pure stdlib (no spidev) so it can be unit-tested off the Pi.
"""
from dataclasses import dataclass

VERDICT_MAGIC = 0xA5
VERDICT_LEN = 32             # v2 frame width (v1 was 20)

# Stage-hit mask bits (byte 1), in wire-bit order.
_STAGE_BITS = [("bloom", 0), ("port_scan", 1), ("rate_anomaly", 2)]

# Severity (byte 2): 0 clean / 1 low / 2 med / 3 high.
_SEVERITY_NAMES = {0: "clean", 1: "low", 2: "med", 3: "high"}

_FLAG_ESCALATE = 1 << 0  # flags byte (byte 3), bit0


@dataclass(frozen=True)
class Verdict:
    valid: bool
    bloom_hit: bool
    port_scan: bool
    rate_anomaly: bool
    severity: int
    escalate: bool
    seq: int

    @property
    def threats(self) -> list[str]:
        """Names of the stages that fired, in bit order."""
        hits = {"bloom": self.bloom_hit, "port_scan": self.port_scan,
                "rate_anomaly": self.rate_anomaly}
        return [name for name, _ in _STAGE_BITS if hits[name]]

    @property
    def severity_name(self) -> str:
        return _SEVERITY_NAMES.get(self.severity, str(self.severity))

    def describe(self) -> str:
        """One-line human summary for the live capture path."""
        if not self.valid:
            return "no-verdict"
        if not self.threats:
            return f"CLEAN seq={self.seq}"
        tag = f"THREAT[{','.join(self.threats)}] {self.severity_name}"
        if self.escalate:
            tag += " ESCALATE"
        return f"{tag} seq={self.seq}"


def encode_verdict(*, bloom_hit: bool = False, port_scan: bool = False,
                   rate_anomaly: bool = False, severity: int = 0,
                   escalate: bool = False, seq: int = 0) -> bytes:
    """Build a 32-byte valid verdict frame (magic=0xA5). Inverse of decode_verdict.

    Used to generate the shared format vectors and, later, the CPU reference
    classifier's output for the FPGA-vs-CPU comparison.
    """
    mask = (bloom_hit << 0) | (port_scan << 1) | (rate_anomaly << 2)
    flags = _FLAG_ESCALATE if escalate else 0
    head = bytes([VERDICT_MAGIC, mask, severity, flags, seq & 0xFF])
    return head + bytes(VERDICT_LEN - len(head))


def decode_verdict(frame: bytes) -> Verdict:
    """Decode a 32-byte verdict frame into its fields."""
    if len(frame) != VERDICT_LEN:
        raise ValueError(f"verdict frame must be {VERDICT_LEN} bytes, got {len(frame)}")
    mask = frame[1]
    return Verdict(
        valid=frame[0] == VERDICT_MAGIC,
        bloom_hit=bool(mask & (1 << 0)),
        port_scan=bool(mask & (1 << 1)),
        rate_anomaly=bool(mask & (1 << 2)),
        severity=frame[2],
        escalate=bool(frame[3] & _FLAG_ESCALATE),
        seq=frame[4],
    )
