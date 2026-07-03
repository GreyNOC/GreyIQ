"""Regression tests for the full-app QAQC fix batch — each locks in a specific verified defect."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service as av  # noqa: E402
from bughunter import dns_mini, ledger  # noqa: E402
from bughunter.ledger import _defang_csv_cell  # noqa: E402
from bughunter.recon_js import _PARAM_RE  # noqa: E402


class CsvDefangTests(unittest.TestCase):
    def test_leading_whitespace_formula_is_defanged(self) -> None:
        self.assertTrue(str(_defang_csv_cell(' =WEBSERVICE("http://evil/")')).startswith("'"))
        self.assertTrue(str(_defang_csv_cell("\t+HYPERLINK(1)")).startswith("'"))

    def test_benign_value_untouched(self) -> None:
        self.assertEqual(_defang_csv_cell("acme.com"), "acme.com")


class DnsReplyMatchTests(unittest.TestCase):
    def _packet(self, qid: int, host: str) -> bytes:
        import struct
        return struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0) + dns_mini._encode_qname(host) + struct.pack(">HH", 5, 1)

    def test_matching_qid_and_name_accepted(self) -> None:
        self.assertTrue(dns_mini._reply_matches(self._packet(0x1234, "sub.acme.com"), 0x1234, "sub.acme.com"))

    def test_wrong_qid_rejected(self) -> None:
        self.assertFalse(dns_mini._reply_matches(self._packet(0x9999, "sub.acme.com"), 0x1234, "sub.acme.com"))

    def test_wrong_question_name_rejected(self) -> None:
        self.assertFalse(dns_mini._reply_matches(self._packet(0x1234, "evil.example"), 0x1234, "sub.acme.com"))


class ReconParamTests(unittest.TestCase):
    def test_single_letter_params_are_mined(self) -> None:
        found = set(_PARAM_RE.findall("/search?q=hi&s=1&page=2&p=3"))
        self.assertEqual({"q", "s", "p", "page"}, found)  # {0,39}: single-letter params restored


class CsrfPerCookieTests(unittest.TestCase):
    _FORM = '<form method="post" action="/transfer"><input name="amount"></form>'

    def _landing(self, cookies):
        return {"body": self._FORM, "cookies": cookies}

    def test_lax_session_plus_unrelated_none_tracker_is_protected(self) -> None:
        # The FP the fix targets: an unrelated SameSite=None tracker must not defeat the Lax skip.
        f = av._check_csrf(self._landing(["sessionid=abc; Path=/; SameSite=Lax", "trk=xyz; SameSite=None"]),
                           "https://app.example.com/")
        self.assertIsNone(f)

    def test_session_cookie_samesite_none_is_medium(self) -> None:
        f = av._check_csrf(self._landing(["sessionid=abc; SameSite=None"]), "https://app.example.com/")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "medium")


class ProgramDeleteCascadeAliasTests(unittest.TestCase):
    def test_cascade_sweeps_domain_keyed_bucket_via_alias(self) -> None:
        d = tempfile.mkdtemp()
        ledger.upsert_findings(d, "acme", "https://acme.com", [
            {"class_id": "rce", "rule_id": "r", "title": "pid", "severity": "critical", "source_url": "https://acme.com/a"}])
        ledger.upsert_findings(d, None, "https://acme.com/x", [
            {"class_id": "xss", "rule_id": "r", "title": "adhoc", "severity": "high", "source_url": "https://acme.com/x"}])
        res = ledger.archive_and_purge_program(d, "acme", also_bucket_ids=["acme.com"])
        self.assertEqual(res, {"archived": 2, "purged": 0})
        self.assertFalse(ledger.list_all(d))                       # both buckets gone
        self.assertEqual(len(ledger.list_archived(d)), 2)          # both High/Crit preserved


if __name__ == "__main__":
    unittest.main()
