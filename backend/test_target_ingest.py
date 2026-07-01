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


class HackerOneScopeCsvTests(unittest.TestCase):
    def test_real_header_synonyms_full_row_kept(self) -> None:
        csv = (
            "asset_identifier,asset_type,eligible_for_submission,eligible_for_bounty,instruction,max_severity\n"
            "*.acme.com,URL,true,true,Web app,critical\n"
            "legacy.acme.com,URL,false,false,Out of scope,none\n"
        )
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        self.assertEqual(r["kind"], "hackerone_scope")
        self.assertEqual(r["scope_count"], 2)
        rows = {e["identifier"]: e for e in r["structured_scope"]}
        self.assertTrue(rows["*.acme.com"]["eligible_for_submission"])
        self.assertTrue(rows["*.acme.com"]["eligible_for_bounty"])
        self.assertEqual(rows["*.acme.com"]["max_severity"], "critical")
        self.assertFalse(rows["legacy.acme.com"]["eligible_for_submission"])

    def test_asset_type_column_before_asset_identifier_does_not_shadow_it(self) -> None:
        # Regression: bare "asset" in _H1_ID_HINTS is a substring of "asset_type", so a
        # naive first-substring-match would pick asset_type as the identifier column when
        # it's listed first — silently discarding the real hostnames. _match_column must
        # prefer an EXACT header match ("asset_identifier") over that substring collision.
        csv = "asset_type,asset_identifier,eligible_for_submission\nWEB,example.com,true\nMOBILE,otherapp.com,true\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        identifiers = {e["identifier"] for e in r["structured_scope"]}
        self.assertEqual(identifiers, {"example.com", "otherapp.com"})
        types = {e["identifier"]: e["asset_type"] for e in r["structured_scope"]}
        self.assertEqual(types["example.com"], "WEB")
        self.assertEqual(r["targets"], ["https://example.com", "https://otherapp.com"])

    def test_human_header_variants_recognized(self) -> None:
        # "Identifier" / "Eligible for submission" / "Eligible for bounty" — the human-readable
        # labels a hand-exported spreadsheet is more likely to carry than raw API attribute names.
        csv = "Identifier,Eligible for submission,Eligible for bounty\napi.acme.com,Yes,No\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        entry = r["structured_scope"][0]
        self.assertEqual(entry["identifier"], "api.acme.com")
        self.assertTrue(entry["eligible_for_submission"])
        self.assertFalse(entry["eligible_for_bounty"])

    def test_missing_columns_defaults_eligible_true(self) -> None:
        csv = "asset_identifier\n*.acme.com\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["structured_scope"][0]["eligible_for_submission"])
        self.assertFalse(r["structured_scope"][0]["eligible_for_bounty"])

    def test_no_recognizable_header_falls_back_to_bare_identifiers(self) -> None:
        r = ti.ingest("*.acme.com\napi.acme.com\n", "hackerone_scope")
        self.assertTrue(r["ok"])
        identifiers = {e["identifier"] for e in r["structured_scope"]}
        self.assertEqual(identifiers, {"*.acme.com", "api.acme.com"})
        self.assertTrue(any("no recognizable header" in n.lower() for n in r["notes"]))

    def test_empty_input_not_ok(self) -> None:
        r = ti.ingest("", "hackerone_scope")
        self.assertFalse(r["ok"])

    def test_bom_prefixed_header_still_matches(self) -> None:
        csv = "﻿asset_identifier,eligible_for_submission\n*.acme.com,true\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        self.assertEqual(r["structured_scope"][0]["identifier"], "*.acme.com")   # no leading BOM artifact

    def test_quoted_field_with_embedded_comma_stays_one_column(self) -> None:
        csv = 'asset_identifier,instruction\n*.acme.com,"Report bugs, then wait for triage"\n'
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        self.assertEqual(r["structured_scope"][0]["identifier"], "*.acme.com")
        self.assertEqual(r["structured_scope"][0]["instruction"], "Report bugs, then wait for triage")

    def test_tab_delimited_is_sniffed(self) -> None:
        csv = "asset_identifier\teligible_for_submission\n*.acme.com\ttrue\nlegacy.acme.com\tfalse\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        self.assertEqual(r["scope_count"], 2)
        rows = {e["identifier"]: e for e in r["structured_scope"]}
        self.assertTrue(rows["*.acme.com"]["eligible_for_submission"])
        self.assertFalse(rows["legacy.acme.com"]["eligible_for_submission"])

    def test_crlf_line_endings(self) -> None:
        csv = "asset_identifier,eligible_for_submission\r\n*.acme.com,true\r\napi.acme.com,true\r\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertTrue(r["ok"])
        identifiers = {e["identifier"] for e in r["structured_scope"]}
        self.assertEqual(identifiers, {"*.acme.com", "api.acme.com"})

    def test_non_host_identifiers_excluded_from_targets(self) -> None:
        csv = "asset_identifier,eligible_for_submission\napi.acme.com,true\nAcmeMobileApp,true\n"
        r = ti.ingest(csv, "hackerone_scope")
        # api.acme.com normalizes to a URL; the dot-less app-name identifier does not -- both
        # stay in structured_scope, but only the URL-shaped one shows up in targets/hosts.
        self.assertEqual(r["scope_count"], 2)
        self.assertEqual(r["targets"], ["https://api.acme.com"])
        self.assertEqual(r["hosts"], ["api.acme.com"])

    def test_dedupes_by_identifier(self) -> None:
        csv = "asset_identifier\napi.acme.com\napi.acme.com\n"
        r = ti.ingest(csv, "hackerone_scope")
        self.assertEqual(r["scope_count"], 1)


if __name__ == "__main__":
    unittest.main()
