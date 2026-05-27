"""Tests for the bloom builder (CLASSIFIER.md §Bloom stage).

Pure-logic — no hardware. The hashes/packing here MUST match the FPGA bit-for-bit,
so these assert against the spec's locked constants and worked example.
"""
from bloom import BloomFilter, ip_to_int, h1, h2, M_BITS, TEST_C2_SET


def test_ip_to_int_is_big_endian():
    assert ip_to_int("192.0.2.1") == 0xC0000201
    assert ip_to_int("198.51.100.1") == 0xC6336401
    assert ip_to_int("203.0.113.5") == 0xCB007105


def test_hashes_match_spec_worked_example():
    # CLASSIFIER.md: h_i = ((x * A_i) & 0xFFFFFFFF) >> 16, A1=0x9E3779B1 A2=0x85EBCA77.
    x = 0xC6336401  # 198.51.100.1
    assert h1(x) == 0x6E03
    assert h2(x) == 0x00B7


def test_hash_indices_fit_the_bit_array():
    for ip in ("0.0.0.0", "255.255.255.255", "192.0.2.99"):
        x = ip_to_int(ip)
        assert 0 <= h1(x) < M_BITS
        assert 0 <= h2(x) < M_BITS


# CLASSIFIER.md locked test C2 set (single source in bloom.py).
C2_SET = TEST_C2_SET


def test_empty_filter_matches_nothing():
    bf = BloomFilter()
    assert bf.member(ip_to_int("198.51.100.1")) is False


def test_added_ip_is_a_member():
    bf = BloomFilter()
    bf.add(ip_to_int("198.51.100.1"))
    assert bf.member(ip_to_int("198.51.100.1")) is True


def test_from_ips_makes_every_c2_ip_a_member():
    bf = BloomFilter.from_ips(C2_SET)
    for ip in C2_SET:
        assert bf.member(ip_to_int(ip)) is True


def test_clean_ips_not_in_set_do_not_match():
    # documentation IPs deliberately outside the C2 set; none should false-positive here.
    bf = BloomFilter.from_ips(C2_SET)
    for ip in ("192.0.2.1", "198.51.100.200", "203.0.113.250", "10.0.0.1"):
        assert bf.member(ip_to_int(ip)) is False


def _read_mem_bit(words, b):
    """Read bit b from a $readmemh word list exactly as the FPGA does."""
    return (words[b >> 4] >> (b & 0xF)) & 1


def test_mem_is_4096_words_of_4_hex_digits():
    lines = BloomFilter().to_mem().splitlines()
    assert len(lines) == M_BITS // 16  # 4096
    assert all(len(ln) == 4 and int(ln, 16) >= 0 for ln in lines)


def test_empty_mem_is_all_zero_words():
    assert set(BloomFilter().to_mem().splitlines()) == {"0000"}


def test_mem_packing_matches_fpga_read_for_every_bit():
    # The .mem the FPGA loads must agree with member()/_get bit-for-bit.
    bf = BloomFilter.from_ips(C2_SET)
    words = [int(ln, 16) for ln in bf.to_mem().splitlines()]
    set_indices = set()
    for ip in C2_SET:
        x = ip_to_int(ip)
        set_indices |= {h1(x), h2(x)}
    for b in set_indices:
        assert _read_mem_bit(words, b) == 1, f"set bit {b} missing in .mem"
    # spot-check a swath of indices: .mem read must equal the in-memory bit array.
    for b in range(0, M_BITS, 257):
        assert _read_mem_bit(words, b) == (1 if bf._get(b) else 0)
