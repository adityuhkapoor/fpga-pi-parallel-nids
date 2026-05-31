from thresholds_model import Thresholds, PORT_THRESH, HOST_THRESH, RATE_THRESH


def test_defaults_match_v11():
    t = Thresholds()
    assert t.read(PORT_THRESH) == 5
    assert t.read(HOST_THRESH) == 5
    assert t.read(RATE_THRESH) == 8


def test_write_read_roundtrip():
    t = Thresholds()
    t.write(PORT_THRESH, 12)
    assert t.read(PORT_THRESH) == 12


def test_unknown_id_silently_no_ops_to_match_hdl():
    """thresholds.v's case stmt has a `default:` empty branch for writes and `r_val <= 0`
    for reads. The twin must mirror that to be truly bit-exact."""
    t = Thresholds()
    t.write(0xEE, 0x1234)          # unknown id -> no-op (must not raise)
    assert t.read(0xEE) == 0       # unknown id -> 0
    # known ids untouched
    assert t.read(PORT_THRESH) == 5
