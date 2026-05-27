"""Pure display logic for the terminal classification visualizer.

No spidev / scapy / curses here so it's unit-testable and importable anywhere; viz.py
is the thin live/replay runner on top.
"""
import socket

RED = "\033[31m"
GREEN = "\033[32m"
DIM = "\033[2m"
RESET = "\033[0m"


def ips_from_header(header: bytes):
    """(src, dst) dotted IPv4 from a 20-byte header (bytes 0-3 src, 4-7 dst)."""
    return socket.inet_ntoa(header[0:4]), socket.inet_ntoa(header[4:8])


class Stats:
    """Running tallies over decoded verdicts (no-verdict frames are ignored)."""

    def __init__(self):
        self.total = self.clean = self.flagged = self.bloom = self.escalations = 0

    def update(self, verdict) -> None:
        if not verdict.valid:
            return
        self.total += 1
        if verdict.threats:
            self.flagged += 1
            if verdict.bloom_hit:
                self.bloom += 1
            if verdict.escalate:
                self.escalations += 1
        else:
            self.clean += 1

    @property
    def pct_flagged(self) -> float:
        return (self.flagged / self.total * 100) if self.total else 0.0

    def rate(self, elapsed_s: float) -> float:
        return (self.total / elapsed_s) if elapsed_s > 0 else 0.0


def format_row(src: str, dst: str, verdict, color: bool = True) -> str:
    flow = f"{src:>15} -> {dst:<15}"
    tag = verdict.describe()
    if not color:
        return f"{flow}  {tag}"
    c = RED if verdict.threats else GREEN
    return f"{DIM}{flow}{RESET}  {c}{tag}{RESET}"


def format_summary(stats: Stats, elapsed_s: float) -> str:
    return (f"pkts {stats.total}  clean {stats.clean}  "
            f"flagged {stats.flagged} ({stats.pct_flagged:.1f}%)  "
            f"bloom {stats.bloom}  escalate {stats.escalations}  "
            f"{stats.rate(elapsed_s):.0f} pkts/s")
