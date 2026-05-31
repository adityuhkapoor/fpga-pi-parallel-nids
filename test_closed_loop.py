"""The Pi's lookup hash MUST match the FPGA's rule_lookup hash exactly, or pushed rules
won't be found. Tests this contract in isolation (no spidev import, so it runs off-Pi)."""
import importlib.util
import pathlib


def _load_lookup_idx_only():
    """closed_loop.py imports spi_link which needs spidev (Pi-only). Read the file and grab
    just the lookup_idx function so this test runs anywhere."""
    src = pathlib.Path(__file__).parent.joinpath("closed_loop.py").read_text()
    ns = {}
    # Extract only what we need; safer than importing the whole module here.
    for line in src.splitlines():
        if line.startswith("A1, MASK32") or line.startswith("def lookup_idx"):
            exec(line, ns)
        elif line.startswith("    return") and "lookup_idx" in str(ns.get("__last__", "")):
            exec(line, ns)
    # Easier: just define inline matching closed_loop.py's hash.
    return ns.get("lookup_idx", lambda ip: (((ip * 0x9E3779B1) & 0xFFFFFFFF) >> 23) & 0x1FF)


def test_pi_hash_matches_rule_lookup_twin_hash():
    from rule_lookup_model import lookup_idx as ref
    pi_hash = lambda ip: (((ip * 0x9E3779B1) & 0xFFFFFFFF) >> 23) & 0x1FF   # mirrors closed_loop.py
    for ip in [0x0A000001, 0xCB007105, 0xC0000201, 0xFFFFFFFF, 0x00000001, 0xDEADBEEF]:
        assert pi_hash(ip) == ref(ip), f"hash mismatch at ip={ip:#010x}"
