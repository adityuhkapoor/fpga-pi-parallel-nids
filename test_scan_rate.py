from scan_rate import bucket, port_bit, host_bit, epoch, ScanRateTable, A1, A2

def test_hash_constants_and_ranges():
    assert A1 == 0x9E3779B1 and A2 == 0x85EBCA77
    assert bucket(0xC0000201) == ((0xC0000201 * A1) & 0xFFFFFFFF) >> 24
    assert 0 <= bucket(0xDEADBEEF) <= 255
    assert 0 <= port_bit(0x1F90) <= 15
    assert 0 <= host_bit(0x0A000001) <= 15
    assert epoch(0) == 0 and epoch(15) == 0 and epoch(16) == 1 and epoch(255) == ((255 >> 4) & 0xF)

def test_lazy_epoch_reset_clears_stale_entry():
    t = ScanRateTable()
    t.update(src_ip=0x0A000001, dst_ip=0x0A000002, dst_port=80, proto=6, tcp_flags=0x02, frame_count=0)
    e0 = t._entry(0x0A000001)
    assert e0["pkt_count"] == 1
    t.update(src_ip=0x0A000001, dst_ip=0x0A000002, dst_port=80, proto=6, tcp_flags=0x02, frame_count=16)
    e1 = t._entry(0x0A000001)
    assert e1["epoch"] == 1
    assert e1["pkt_count"] == 1  # reset to 0 then +1, NOT 2


# ---------------------------------------------------------------------------
# Task 2: rate-anomaly locking
# ---------------------------------------------------------------------------

def test_rate_anomaly_fires_at_threshold():
    t = ScanRateTable()
    hits = []
    for i in range(10):  # 10 packets, same source, same window (frames 0..9 -> epoch 0)
        _, rate = t.update(src_ip=0xC0000201, dst_ip=0xC0000202, dst_port=53,
                           proto=17, tcp_flags=0x00, frame_count=i)
        hits.append(rate)
    assert hits == [False]*7 + [True]*3   # RATE_THRESH=8 -> first True on 8th packet

def test_rate_resets_across_window():
    t = ScanRateTable()
    for i in range(7):
        t.update(src_ip=0xC0000201, dst_ip=0xC0000202, dst_port=53, proto=17, tcp_flags=0, frame_count=i)
    _, rate = t.update(src_ip=0xC0000201, dst_ip=0xC0000202, dst_port=53, proto=17, tcp_flags=0, frame_count=16)
    assert rate is False


# ---------------------------------------------------------------------------
# Task 3: vertical port-scan locking
# ---------------------------------------------------------------------------

def _distinct_ports_hashing_to_unique_bits(n):
    seen, ports = set(), []
    p = 1
    while len(ports) < n:
        pb = port_bit(p)
        if pb not in seen:
            seen.add(pb); ports.append(p)
        p += 1
    return ports

def test_vertical_port_scan_fires_on_5_distinct_ports():
    t = ScanRateTable()
    ports = _distinct_ports_hashing_to_unique_bits(5)
    hits = []
    for i, dp in enumerate(ports):
        scan, _ = t.update(src_ip=0xCB007105, dst_ip=0xC0000201, dst_port=dp,
                           proto=6, tcp_flags=0x02, frame_count=i)
        hits.append(scan)
    assert hits == [False, False, False, False, True]

def test_non_syn_traffic_does_not_count_as_scan():
    t = ScanRateTable()
    ports = _distinct_ports_hashing_to_unique_bits(6)
    for i, dp in enumerate(ports):
        scan, _ = t.update(src_ip=0xCB007105, dst_ip=0xC0000201, dst_port=dp,
                           proto=6, tcp_flags=0x12, frame_count=i)  # ACK set -> not a probe
    assert scan is False


# ---------------------------------------------------------------------------
# Task 4: horizontal host-scan locking
# ---------------------------------------------------------------------------

def _distinct_hosts_hashing_to_unique_bits(n):
    seen, hosts = set(), []
    h = 0x0A000001
    while len(hosts) < n:
        hb = host_bit(h)
        if hb not in seen:
            seen.add(hb); hosts.append(h)
        h += 1
    return hosts

def test_horizontal_host_scan_fires_on_5_distinct_hosts():
    t = ScanRateTable()
    hosts = _distinct_hosts_hashing_to_unique_bits(5)
    hits = []
    for i, dh in enumerate(hosts):
        scan, _ = t.update(src_ip=0xCB007105, dst_ip=dh, dst_port=445,
                           proto=6, tcp_flags=0x02, frame_count=i)
        hits.append(scan)
    assert hits == [False, False, False, False, True]
