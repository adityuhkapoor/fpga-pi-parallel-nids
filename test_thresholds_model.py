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


def test_unknown_id_raises():
    import pytest
    with pytest.raises(KeyError):
        Thresholds().write(0xEE, 0)
