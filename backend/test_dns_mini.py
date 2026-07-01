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


class ReadNameMalformedTests(unittest.TestCase):
    """_read_name is fed attacker-controlled bytes (a DNS response from whatever
    resolver a scanned host happens to use) -- it must never hang or crash on a
    hostile/malformed name, only degrade to a partial/empty result. No dedicated
    coverage of these edge cases before this (only indirect exercise via well-formed
    packets and the >63-byte-label fix)."""

    def test_pointer_to_self_terminates_without_hanging(self) -> None:
        # offset 0 is a compression pointer whose target is offset 0 -- an infinite
        # cycle if unbounded. The `for _ in range(128)` loop guard must still
        # terminate this in bounded time with an empty name.
        data = b"\xc0\x00"
        name, next_off = dns_mini._read_name(data, 0)
        self.assertEqual(name, "")
        self.assertEqual(next_off, 2)  # first (non-jumped) pointer's own 2-byte width

    def test_pointer_cycle_between_two_offsets_terminates(self) -> None:
        # offset 0 points to offset 2, offset 2 points back to offset 0.
        data = b"\xc0\x02\xc0\x00"
        name, next_off = dns_mini._read_name(data, 0)
        self.assertEqual(name, "")
        self.assertEqual(next_off, 2)

    def test_pointer_target_beyond_buffer_end_fails_closed(self) -> None:
        # Pointer claims offset 9999, far past the 2-byte buffer -- must not IndexError.
        data = bytes([0xC0, 0x0F])  # ptr = 0x0F = 15, past len(data) == 2
        name, next_off = dns_mini._read_name(data, 0)
        self.assertEqual(name, "")
        self.assertEqual(next_off, 2)

    def test_forward_pointer_to_a_later_valid_label_still_resolves(self) -> None:
        # Nothing in the wire format actually requires compression pointers to point
        # BACKWARD; a pointer to a later, well-formed label sequence must still parse.
        data = bytes([0xC0, 0x02]) + b"\x03www\x00"
        name, next_off = dns_mini._read_name(data, 0)
        self.assertEqual(name, "www")
        self.assertEqual(next_off, 2)  # caller resumes right after the 2-byte pointer

    def test_unterminated_name_at_end_of_buffer_does_not_crash(self) -> None:
        # length byte claims 3 bytes but only 2 remain, and there's no 0x00 terminator
        # anywhere -- Python slicing clips silently rather than raising, so this must
        # return whatever partial label it could read, not throw.
        data = b"\x03ww"
        name, next_off = dns_mini._read_name(data, 0)
        self.assertEqual(name, "ww")  # clipped label, decoded from what bytes existed

    def test_zero_length_root_name_is_empty_string(self) -> None:
        name, next_off = dns_mini._read_name(b"\x00", 0)
        self.assertEqual(name, "")
        self.assertEqual(next_off, 1)

    def test_offset_at_end_of_buffer_returns_empty_without_crash(self) -> None:
        name, next_off = dns_mini._read_name(b"\x03www\x00", 5)
        self.assertEqual(name, "")
        self.assertEqual(next_off, 5)

    def test_reserved_length_prefix_bits_are_read_as_a_literal_over_length_label(self) -> None:
        # 0x40 has high bits 01 -- neither the 00 (plain label) nor 11 (pointer) forms
        # RFC 1035 defines. _read_name has no explicit rejection for this reserved
        # pattern; it's treated as a literal length byte. Pinning the current
        # (permissive, non-crashing) behavior.
        data = bytes([0x40]) + b"x" * 64 + b"\x00"
        name, next_off = dns_mini._read_name(data, 0)
        self.assertEqual(len(name), 64)
        self.assertEqual(next_off, 66)


if __name__ == "__main__":
    unittest.main()
