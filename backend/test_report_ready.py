"""Tests for the durable "report ready" state in bughunter.ledger (Report Center backing store).

Covers: mark_report_ready persists an orthogonal ready flag + proof presence + artifact index
without moving the pipeline stage; list_all surfaces report_ready/readyable; funnel counts ready;
and marking a not-yet-recorded key is a no-op the caller can detect.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import ledger  # noqa: E402


def _confirmed_item() -> dict:
    return {
        "finding": {
            "class_id": "cors", "rule_id": "web.cors-acao-reflect",
            "title": "CORS misconfiguration", "severity": "high",
            "location": "https://example.com/api/me",
            "proof_evidence": {"request_line": "GET https://example.com/api/me",
                               "response_header": "Access-Control-Allow-Origin: https://evil.example",
                               "response_status": "200"},
        },
        "source_url": "https://example.com/api/me", "proof_status": "confirmed",
        "proof_of_impact": {"status": "confirmed", "observed_result": "ACAO reflects evil origin, ACAC true",
                            "control_result": "no ACAO for a random origin"},
    }


class ReportReadyLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.runtime = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_mark_ready_persists_orthogonally(self) -> None:
        annotated = ledger.upsert_findings(self.runtime, "acme", "https://example.com", [_confirmed_item()])
        key = annotated[0]["dedup_key"]
        # Stage before marking ready.
        rec_before = next(r for r in ledger.list_all(self.runtime) if r["dedup_key"] == key)
        self.assertEqual(rec_before.get("stage"), "confirmed")
        self.assertFalse(rec_before.get("report_ready"))
        self.assertTrue(rec_before.get("readyable"))  # has captured proof

        ok = ledger.mark_report_ready(self.runtime, "acme", "https://example.com", key,
                                      report_index={"platform": "hackerone", "filename": f"report-{key}.md",
                                                    "proof_status": "confirmed"},
                                      proof_flags={"poc": True, "poi": True, "poe": True})
        self.assertTrue(ok)
        rec = next(r for r in ledger.list_all(self.runtime) if r["dedup_key"] == key)
        self.assertTrue(rec.get("report_ready"))
        self.assertEqual(rec.get("report_ready_proof"), {"poc": True, "poi": True, "poe": True})
        self.assertEqual(rec.get("report_index", {}).get("platform"), "hackerone")
        # Orthogonal: the pipeline stage did NOT advance (still 'confirmed', not 'reported').
        self.assertEqual(rec.get("stage"), "confirmed")

    def test_funnel_counts_ready(self) -> None:
        annotated = ledger.upsert_findings(self.runtime, "acme", "https://example.com", [_confirmed_item()])
        key = annotated[0]["dedup_key"]
        self.assertEqual(ledger.funnel(self.runtime)["portfolio"]["ready"], 0)
        ledger.mark_report_ready(self.runtime, "acme", "https://example.com", key,
                                 report_index={}, proof_flags={"poc": True, "poi": True, "poe": True})
        self.assertEqual(ledger.funnel(self.runtime)["portfolio"]["ready"], 1)

    def test_mark_missing_key_is_noop(self) -> None:
        self.assertFalse(ledger.mark_report_ready(self.runtime, "acme", "https://example.com",
                                                  "deadbeefdeadbeef0000", report_index={}, proof_flags={}))

    def test_ready_survives_reload_and_finds_across_buckets(self) -> None:
        # Record under one bucket, then mark ready passing a DIFFERENT program/target: the whole-
        # portfolio fallback search must still locate and flag the record by key.
        annotated = ledger.upsert_findings(self.runtime, "acme", "https://a.example.com", [_confirmed_item()])
        key = annotated[0]["dedup_key"]
        ok = ledger.mark_report_ready(self.runtime, "totally-different", "https://z.example.org", key,
                                      report_index={}, proof_flags={"poc": True, "poi": True, "poe": True})
        self.assertTrue(ok)
        # Fresh read (new _load from disk) still shows it ready — durable across "restart".
        rec = next(r for r in ledger.list_all(self.runtime) if r["dedup_key"] == key)
        self.assertTrue(rec.get("report_ready"))

    def test_candidate_without_proof_is_not_readyable(self) -> None:
        item = {"finding": {"class_id": "headers", "rule_id": "web.missing-csp", "title": "Missing CSP",
                            "severity": "low", "location": "https://example.com/"},
                "source_url": "https://example.com/", "proof_status": "missing"}
        ledger.upsert_findings(self.runtime, "acme", "https://example.com", [item])
        rec = ledger.list_all(self.runtime)[0]
        self.assertFalse(rec.get("readyable"))


if __name__ == "__main__":
    unittest.main()
