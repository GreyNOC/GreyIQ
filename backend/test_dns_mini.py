"""Tests for the vendored minimal DNS CNAME resolver — packet build + parse, no network."""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import dns_mini  # noqa: E402


def _qname(host: str) -> bytes:
    out = b""
    for label in host.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _response(qhost: str, cname_target: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)  # 1 question, 1 answer
    question = _qname(qhost) + struct.pack(">HH", 5, 1)
    rdata = _qname(cname_target)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 300, len(rdata)) + rdata  # name = ptr to offset 12
    return header + question + answer


class DnsMiniTests(unittest.TestCase):
    def test_encode_qname(self) -> None:
        self.assertEqual(dns_mini._encode_qname("a.example.com"), b"\x01a\x07example\x03com\x00")

    def test_encode_qname_over_length_label_is_internally_consistent(self) -> None:
        # A label > 63 bytes (malformed input, or an IDNA expansion that grows past 63)
        # must have its declared length byte match the bytes actually appended -- before
        # the fix, `len(raw) & 0x3F` (masked to 6 bits) disagreed with `raw[:63]` (always
        # a full 63 bytes), corrupting every label that follows it in the packet.
        over_long = "a" * 70  # 70-byte label
        encoded = dns_mini._encode_qname(f"{over_long}.example.com")
        declared_len = encoded[0]
        self.assertEqual(declared_len, 63)            # truncated to the legal DNS max
        self.assertEqual(encoded[1:1 + declared_len], (over_long.encode("ascii"))[:63])
        # The packet must be a well-formed qname: walking declared lengths from the start
        # must land EXACTLY on the next label ('example'), not mid-garbage.
        next_label_len = encoded[1 + declared_len]
        self.assertEqual(next_label_len, len(b"example"))
        self.assertEqual(encoded[2 + declared_len:2 + declared_len + next_label_len], b"example")

    def test_encode_then_parse_round_trips_for_an_over_length_label(self) -> None:
        # End-to-end: a query built for an over-long-label host must itself be parseable
        # as a valid qname by _read_name (used for both the question and the answer).
        over_long = "b" * 100
        host = f"{over_long}.example.com"
        qname = dns_mini._encode_qname(host)
        name, next_off = dns_mini._read_name(qname, 0)
        self.assertEqual(next_off, len(qname))  # consumed exactly the qname, nothing more
        self.assertEqual(name, f"{('b' * 63)}.example.com")  # truncated label, rest intact

    def test_parse_cname_answer(self) -> None:
        pkt = _response("www.example.com", "abc.s3.amazonaws.com")
        self.assertEqual(dns_mini.parse_cname_response(pkt), ["abc.s3.amazonaws.com"])

    def test_parse_compressed_cname_target(self) -> None:
        # rdata uses a compression pointer back to "example.com" inside the question.
        header = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        question = _qname("host.example.com") + struct.pack(">HH", 5, 1)
        # "example.com" starts at offset 12 + len("\x04host") = 12 + 5 = 17
        rdata = b"\x03cdn" + b"\xc0" + bytes([17])
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 300, len(rdata)) + rdata
        self.assertEqual(dns_mini.parse_cname_response(header + question + answer), ["cdn.example.com"])

    def test_no_answer_returns_empty(self) -> None:
        header = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0)
        self.assertEqual(dns_mini.parse_cname_response(header + _qname("x.example.com") + struct.pack(">HH", 5, 1)), [])

    def test_truncated_packet_is_safe(self) -> None:
        self.assertEqual(dns_mini.parse_cname_response(b"\x00\x00"), [])
        self.assertEqual(dns_mini.parse_cname_response(b""), [])

    def test_resolve_cname_rejects_bad_host_without_network(self) -> None:
        self.assertEqual(dns_mini.resolve_cname(""), [])
        self.assertEqual(dns_mini.resolve_cname("localhost"), [])  # no dot -> rejected before any socket


if __name__ == "__main__":
    unittest.main()
