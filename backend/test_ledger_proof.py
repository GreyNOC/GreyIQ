"""The durable ledger now persists a confirmed finding's captured EXPLOIT EVIDENCE (request/response,
observed-vs-control differential, live-credential/Firebase proof) — so a report REBUILT from history
after an app restart/cache eviction still shows the concrete proof instead of an empty shell."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import ledger  # noqa: E402


class LedgerProofPersistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()

    def _item(self, proof_status: str, with_proof: bool = True) -> dict:
        finding = {"class_id": "cors", "rule_id": "active.cors", "title": "CORS read", "severity": "high",
                   "location": "https://t/api/me", "proof_status": proof_status}
        item = {"finding": finding, "source_url": "https://t/api/me", "proof_status": proof_status,
                "cvss": {"base_score": 7.5}}
        if with_proof:
            finding["proof_evidence"] = {"request_line": "GET /api/me", "request_header": "Origin: https://evil.example",
                                         "response_header": "Access-Control-Allow-Origin: https://evil.example",
                                         "read_data": '{"email":"victim@example.com"}'}
            item["plan"] = {"proof_of_impact": {"status": "confirmed",
                            "observed_result": "ACAO reflected the attacker origin and the body returned the user's data",
                            "control_result": "a different Origin was not reflected"}}
        return item

    def _rec(self) -> dict:
        rows = ledger.list_all(self.dir)
        return rows[0] if rows else {}

    def test_confirmed_finding_persists_its_captured_proof(self) -> None:
        ledger.upsert_findings(self.dir, "prog", "https://t", [self._item("confirmed")])
        cp = self._rec().get("captured_proof") or {}
        self.assertIn("proof_evidence", cp)
        self.assertEqual(cp["proof_evidence"]["response_header"], "Access-Control-Allow-Origin: https://evil.example")
        self.assertIn("victim@example.com", cp["proof_evidence"]["read_data"])   # the disclosed data survives
        self.assertIn("reflected the attacker origin", cp["proof_of_impact"]["observed_result"])  # the differential survives

    def test_proof_survives_a_reload_from_disk(self) -> None:
        ledger.upsert_findings(self.dir, "prog", "https://t", [self._item("confirmed")])
        # a brand-new read (simulating an app restart — nothing in memory) still has the proof
        reloaded = ledger.list_all(self.dir)[0]
        self.assertTrue((reloaded.get("captured_proof") or {}).get("proof_evidence"))

    def test_field_is_captured_proof_not_proof(self) -> None:
        # must NOT be named 'proof' — the UI treats f.proof as a status STRING; an object there breaks it
        ledger.upsert_findings(self.dir, "prog", "https://t", [self._item("confirmed")])
        rec = self._rec()
        self.assertIn("captured_proof", rec)
        self.assertIsInstance(rec.get("proof_status"), str)     # the status field stays a string


if __name__ == "__main__":
    unittest.main()
