from cms import CountMin, CMS_A, CMS_COLS


def test_column_is_top_12_bits_of_multiply():
    cm = CountMin()
    assert cm.column(0xC0000201, 0) == ((0xC0000201 * CMS_A[0]) & 0xFFFFFFFF) >> 20
    assert all(0 <= cm.column(0xC0000201, j) < CMS_COLS for j in range(5))


def test_single_source_counts_then_point_query():
    cm = CountMin()
    for _ in range(7):
        cm.update(0xCB007105)
    assert cm.point_query(0xCB007105) == 7      # no collision -> exact


def test_counter_saturates_at_14_bits():
    cm = CountMin()
    for _ in range(20000):                      # > 2^14-1
        cm.update(0xC0000263)
    assert cm.point_query(0xC0000263) == 0x3FFF


def test_unseen_key_estimates_zero_or_low():
    cm = CountMin()
    cm.update(0xC0000201)
    assert cm.point_query(0xCB007105) in (0, 1)  # min over banks; tiny collision risk


def test_window_tick_resets_via_epoch():
    cm = CountMin()
    cm.update(0xCB007105)
    cm.update(0xCB007105)
    cm.window_tick()                            # epoch advances -> stale
    assert cm.point_query(0xCB007105) == 0
    cm.update(0xCB007105)
    assert cm.point_query(0xCB007105) == 1
