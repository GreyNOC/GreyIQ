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
