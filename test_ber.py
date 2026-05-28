from ber import ramp_errors


def test_perfect_echo_zero_errors():
    sent = [bytes([i, (i * 7) & 0xFF]) for i in range(10)]
    # delay-1 echo: received[k] == sent[k-1]; received[0] is zeros (no prior frame)
    received = [bytes(2)] + sent[:-1]
    r = ramp_errors(sent, received, delay=1)
    assert r.frame_errors == 0
    assert r.bit_errors == 0
    assert r.frames_compared == 9   # first frame has no prior to compare


def test_single_bit_flip_counted():
    sent = [bytes([0x00, 0x00]) for _ in range(3)]
    # one bit flipped in the echo of frame 0 (received[1] should equal sent[0])
    received = [bytes(2), bytes([0x00, 0x01]), bytes([0x00, 0x00])]
    r = ramp_errors(sent, received, delay=1)
    assert r.frame_errors == 1
    assert r.bit_errors == 1


def test_multiple_bit_flips_in_one_frame():
    sent = [bytes([0xFF, 0xFF]) for _ in range(2)]
    received = [bytes(2), bytes([0x00, 0xFF])]   # echo of frame 0: top byte all 8 bits wrong
    r = ramp_errors(sent, received, delay=1)
    assert r.frame_errors == 1
    assert r.bit_errors == 8


def test_ber_ratio():
    # 4 frames compared, 16 bits/frame, 1 bit wrong -> BER = 1 / (4*16)
    sent = [bytes([0x00, 0x00]) for _ in range(5)]
    received = [bytes(2)] + [bytes(2), bytes(2), bytes([0x01, 0x00]), bytes(2)]
    r = ramp_errors(sent, received, delay=1)
    assert r.frames_compared == 4
    assert r.bit_errors == 1
    assert abs(r.ber - 1 / (4 * 16)) < 1e-12


def test_delay_two_echo():
    sent = [bytes([i]) for i in range(6)]
    received = [bytes(1), bytes(1)] + sent[:-2]   # delay-2 perfect echo
    r = ramp_errors(sent, received, delay=2)
    assert r.frame_errors == 0
    assert r.frames_compared == 4
