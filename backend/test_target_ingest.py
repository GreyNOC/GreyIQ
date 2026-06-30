"""Tests for target/scope ingest (CSV / Burp XML / HAR).

Pure parsing — no network. Covers column detection, headerless scanning, the Burp and
HAR shapes, dedup/normalization, the fail-closed XML entity guard, and that junk cells
(labels, bare words) never become bogus targets.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import target_ingest as ti  # noqa: E402


class CsvTests(unittest.TestCase):
    def test_header_url_column(self) -> None:
        csv = "name,url,status\nAcme,https://app.example.com/login?next=/x,200\nBeta,http://b.example.org/,404\n"
        r = ti.ingest(csv, "csv")
        self.assertTrue(r["ok"])
        self.assertEqual(r["targets"], ["https://app.example.com/login?next=/x", "http://b.example.org/"])
        self.assertIn("app.example.com", r["hosts"])
        self.assertIn("next", r["param_names"])           # query param surfaced

    def test_host_column_normalized_to_url(self) -> None:
        r = ti.ingest("domain\nexample.com\napi.example.com\n", "csv")
        self.assertEqual(r["targets"], ["https://example.com", "https://api.example.com"])
        self.assertEqual(r["hosts"], ["example.com", "api.example.com"])

    def test_headerless_single_column_scanned(self) -> None:
        r = ti.ingest("example.com\nhttps://x.example.net/a\n", "csv")
        self.assertEqual(r["count"], 2)
        self.assertEqual(r["hosts"], ["example.com", "x.example.net"])

    def test_junk_cells_dropped(self) -> None:
        # Header labels + bare words + n/a must NOT become targets; only the dotted host does.
        r = ti.ingest("label,note\nN/A,comment\nexample.com,todo\n", "csv")
        self.assertEqual(r["targets"], ["https://example.com"])

    def test_dedupe(self) -> None:
        r = ti.ingest("url\nexample.com\nexample.com\nhttps://example.com\n", "csv")
        # "example.com" -> https://example.com, the third row is identical -> deduped to one.
        self.assertEqual(r["targets"], ["https://example.com"])

    def test_semicolon_delimiter_sniffed(self) -> None:
        r = ti.ingest("host;port\nexample.com;443\n", "csv")
        self.assertEqual(r["targets"], ["https://example.com"])


class BurpTests(unittest.TestCase):
    BURP = (
        '<?xml version="1.0"?>\n<items burpVersion="2023">'
        '<item><url>https://app.example.com/search?q=1</url><host>app.example.com</host>'
        '<protocol>https</protocol><path>/search?q=1</path><method>GET</method></item>'
        '<item><host>api.example.com</host><protocol>https</protocol><path>/v1/users</path></item>'
        '</items>'
    )

    def test_parses_items(self) -> None:
        r = ti.ingest(self.BURP, "auto")          # auto-detects XML -> burp
        self.assertEqual(r["kind"], "burp")
        self.assertEqual(r["targets"], ["https://app.example.com/search?q=1", "https://api.example.com/v1/users"])
        self.assertIn("q", r["param_names"])

    def test_url_fallback_to_host_path(self) -> None:
        xml = '<items><item><host>h.example.com</host><protocol>http</protocol><path>/p</path></item></items>'
        self.assertEqual(ti.parse_burp_xml(xml)["targets"], ["http://h.example.com/p"])

    def test_doctype_is_refused(self) -> None:
        evil = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x "y">]><items><item><url>example.com</url></item></items>'
        r = ti.ingest(evil, "burp")
        self.assertFalse(r["ok"])
        self.assertIn("entity", r["error"].lower())

    def test_bad_xml_errors_cleanly(self) -> None:
        r = ti.parse_burp_xml("<items><item><url>x")
        self.assertFalse(r["ok"])
        self.assertIn("parse", r["error"].lower())


class HarTests(unittest.TestCase):
    def test_parses_request_urls(self) -> None:
        har = '{"log":{"entries":[{"request":{"url":"https://app.example.com/api?id=7"}},{"request":{"url":"https://app.example.com/home"}}]}}'
        r = ti.ingest(har, "auto")               # auto-detects JSON -> har
        self.assertEqual(r["kind"], "har")
        self.assertEqual(r["count"], 2)
        self.assertIn("id", r["param_names"])

    def test_non_har_json_errors(self) -> None:
        r = ti.ingest('{"hello":"world"}', "har")
        self.assertFalse(r["ok"])
        self.assertIn("HAR", r["error"])


class GuardTests(unittest.TestCase):
    def test_oversized_input_refused(self) -> None:
        big = "example.com\n" * 400_000   # > 4 MB
        r = ti.ingest(big, "csv")
        self.assertFalse(r["ok"])
        self.assertIn("too large", r["error"].lower())

    def test_unknown_kind(self) -> None:
        self.assertFalse(ti.ingest("example.com", "nope")["ok"])

    def test_empty_is_not_ok(self) -> None:
        r = ti.ingest("", "auto")
        self.assertFalse(r["ok"])
        self.assertEqual(r["count"], 0)


if __name__ == "__main__":
    unittest.main()
