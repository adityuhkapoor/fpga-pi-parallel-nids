from flow_table_model import FlowTable, bucket, fp
from thresholds_model import Thresholds, RATE_THRESH


def test_bucket_and_fp_use_different_multipliers():
    assert bucket(0xCB007105) == ((0xCB007105 * 0x9E3779B1) & 0xFFFFFFFF) >> 20
    assert fp(0xCB007105)     == (((0xCB007105 * 0x85EBCA77) & 0xFFFFFFFF) >> 12) & 0xFFFF


def test_single_source_counts_then_verdicts():
    t = FlowTable()
    for i in range(8):
        t.update(src_ip=0xCB007105, dst_ip=0x0A000001, dst_port=80, proto=17,
                 tcp_flags=0, pkt_size=60, frame_count=i)
    res = t.update(src_ip=0xCB007105, dst_ip=0x0A000001, dst_port=80, proto=17,
                   tcp_flags=0, pkt_size=60, frame_count=8)
    assert res == (False, True)        # 9 pkts >= RATE_THRESH default 8 -> rate_hit


def test_collision_eviction_does_not_merge():
    """Two sources hashing to same bucket but differing fp: second evicts first; subsequent
    arrival of the first sees a fresh cell, not the merged state v1.1 would have produced."""
    t = FlowTable()
    src_a = 0xCB007105
    src_b = None
    for cand in range(0x0A000000, 0x0A010000):
        if bucket(cand) == bucket(src_a) and fp(cand) != fp(src_a):
            src_b = cand; break
    assert src_b is not None, "couldn't find a colliding bucket in test range"
    for i, p in enumerate([1, 3, 7, 13]):
        t.update(src_ip=src_a, dst_ip=0x0A000020, dst_port=p, proto=6,
                 tcp_flags=0x02, pkt_size=60, frame_count=i)
    # src_b arrives -> evicts src_a's cell
    t.update(src_ip=src_b, dst_ip=0x0A000020, dst_port=21, proto=6,
             tcp_flags=0x02, pkt_size=60, frame_count=4)
    # src_a returns: its state was wiped, only THIS packet's port_fp bit is set
    res_a = t.update(src_ip=src_a, dst_ip=0x0A000020, dst_port=42, proto=6,
                     tcp_flags=0x02, pkt_size=60, frame_count=5)
    assert res_a == (False, False), \
        "step 3 should NOT trip port-scan after eviction; v1.1's silent-merge would have"


def test_lazy_epoch_reset_at_window_boundary():
    t = FlowTable()
    t.update(src_ip=0x0A000001, dst_ip=0x0A000002, dst_port=80, proto=17,
             tcp_flags=0, pkt_size=60, frame_count=0)
    assert t._cell_of(0x0A000001)["pkt_count"] == 1
    t.update(src_ip=0x0A000001, dst_ip=0x0A000002, dst_port=80, proto=17,
             tcp_flags=0, pkt_size=60, frame_count=16)        # epoch 0 -> 1
    assert t._cell_of(0x0A000001)["pkt_count"] == 1           # reset, not +2


def test_runtime_thresholds_change_verdict():
    thr = Thresholds()
    t = FlowTable(thresholds=thr)
    for i in range(5):
        t.update(src_ip=0x0A000010, dst_ip=0x0A000020, dst_port=53,
                 proto=17, tcp_flags=0, pkt_size=60, frame_count=i)
    thr.write(RATE_THRESH, 6)
    _, rh = t.update(src_ip=0x0A000010, dst_ip=0x0A000020, dst_port=53,
                     proto=17, tcp_flags=0, pkt_size=60, frame_count=5)
    assert rh, "after lowering RATE_THRESH to 6, the 6th packet must fire rate_hit"


def test_byte_count_accumulates_with_saturation():
    t = FlowTable()
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=0, proto=17, tcp_flags=0,
             pkt_size=1500, frame_count=0)
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=0, proto=17, tcp_flags=0,
             pkt_size=500,  frame_count=1)
    assert t._cell_of(0x0A000001)["byte_count"] == 2000


def test_syn_count_only_increments_on_syn_no_ack():
    t = FlowTable()
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=80, proto=6, tcp_flags=0x02,
             pkt_size=60, frame_count=0)   # SYN
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=80, proto=6, tcp_flags=0x12,
             pkt_size=60, frame_count=1)   # SYN+ACK -> no count
    t.update(src_ip=0x0A000001, dst_ip=0, dst_port=80, proto=6, tcp_flags=0x10,
             pkt_size=60, frame_count=2)   # ACK -> no count
    assert t._cell_of(0x0A000001)["syn_count"] == 1
