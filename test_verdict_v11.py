from bloom import BloomFilter
from classifier import Classifier
from verdict import decode_verdict
import scenarios

def _run(seq_hex_list, bloom=None):
    if bloom is None:
        bloom = BloomFilter()  # empty -> isolates the new stages from bloom
    c = Classifier(bloom)
    out = []
    for i, h in enumerate(seq_hex_list):
        out.append(decode_verdict(c.classify(bytes.fromhex(h), seq=(i & 0xFF) + 1, frame_count=i)))
    return out

def test_benign_never_trips_new_stages():
    for v in _run(scenarios.BENIGN):
        assert not v.port_scan and not v.rate_anomaly and not v.bloom_hit
        assert v.severity == 0 and not v.escalate

def test_vertical_scan_trips_on_fifth_syn():
    vs = _run(scenarios.VSCAN)
    assert [v.port_scan for v in vs] == [False, False, False, False, True]
    assert vs[-1].severity == 2 and vs[-1].escalate

def test_flood_trips_on_eighth_packet():
    fs = _run(scenarios.FLOOD)
    assert [v.rate_anomaly for v in fs] == [False]*7 + [True]
    assert fs[-1].severity == 2

def test_horizontal_scan_trips_on_fifth_host():
    vs = _run(scenarios.HSCAN)
    assert [v.port_scan for v in vs] == [False, False, False, False, True]
    assert vs[-1].severity == 2 and vs[-1].escalate

def test_window_boundary_resets_scan():
    # the 5 SYNs straddle the frame-16 epoch boundary -> reset suppresses the trip
    assert all(not v.port_scan for v in _run(scenarios.BOUNDARY))
    # contrast: the same 5 SYNs inside ONE window DO trip on the 5th, proving the
    # ports are scan-worthy and only the boundary reset prevented the trip
    cvs = _run(scenarios.BOUNDARY_ONE_WINDOW)
    assert [v.port_scan for v in cvs] == [False, False, False, False, True]
    assert cvs[-1].severity == 2 and cvs[-1].escalate

def test_combined_bloom_and_rate_sets_multiple_bits():
    b = BloomFilter()
    for ip in (0xC6336401, 0xCB007105, 0xC0000263):
        b.add(ip)
    vs = _run(scenarios.COMBINED, bloom=b)
    assert vs[-1].bloom_hit and vs[-1].rate_anomaly
    assert vs[-1].severity == 3 and vs[-1].escalate
    assert not vs[-1].port_scan
