"""Tests for the CPU reference classifier (CLASSIFIER.md v1 = bloom only).

This is the golden source for the Tier-2 header->verdict vectors and the CPU side of
the FPGA-vs-CPU benchmark. Pure logic, no hardware.
"""
import socket
import struct

from bloom import BloomFilter, TEST_C2_SET
from classifier import classify_header
from verdict import decode_verdict

_TAIL = struct.Struct(">HHBBHI")  # sport,dport,proto,flags,size,reserved (matches packet_capture)


def make_header(src, dst, sport=12345, dport=80, proto=6, flags=0x02, size=60):
    return (socket.inet_aton(src) + socket.inet_aton(dst)
            + _TAIL.pack(sport, dport, proto, flags, size, 0))


def test_clean_packet_gets_a_clean_verdict():
    bf = BloomFilter.from_ips(TEST_C2_SET)
    v = decode_verdict(classify_header(make_header("192.0.2.1", "192.0.2.2"), bf, seq=1))
    assert v.valid is True
    assert v.threats == []
    assert v.severity == 0
    assert v.escalate is False
    assert v.seq == 1


def test_packet_to_a_c2_ip_hits_bloom():
    bf = BloomFilter.from_ips(TEST_C2_SET)
    v = decode_verdict(classify_header(make_header("192.0.2.1", "198.51.100.1"), bf, seq=7))
    assert v.threats == ["bloom"]
    assert v.severity == 3
    assert v.escalate is True
    assert v.seq == 7


def test_packet_from_a_c2_ip_hits_bloom():
    bf = BloomFilter.from_ips(TEST_C2_SET)
    v = decode_verdict(classify_header(make_header("203.0.113.5", "192.0.2.1"), bf, seq=2))
    assert v.threats == ["bloom"]
    assert v.escalate is True


def test_seq_is_passed_through():
    bf = BloomFilter.from_ips(TEST_C2_SET)
    v = decode_verdict(classify_header(make_header("192.0.2.1", "192.0.2.2"), bf, seq=255))
    assert v.seq == 255
