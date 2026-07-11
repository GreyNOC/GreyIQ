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

import greyiq_api as api  # noqa: E402
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


class ReportReadyRoutePocFlagTests(unittest.TestCase):
    """The get_report_ready route's POC readiness flag must reflect whether a REAL runnable
    reproduction exists — a replay.sh/findings.har rebuilt from a captured crafted request, or an
    operator/brain-supplied PoC — NOT read true unconditionally. POI/POE already gate on captured
    proof; POC now does too (the always-present auto-generated repro steps don't count)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = api.RUNTIME_DIR
        api.RUNTIME_DIR = Path(self._tmp.name)
        self.rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)

    def tearDown(self) -> None:
        api.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def _ready(self, req: "api.ReportReadyRequest") -> dict:
        out = api.GreyIQRuntime.get_report_ready(self.rt, req)
        self.assertTrue(out.get("ok"), out)
        return out

    def test_poc_flag_false_without_a_runnable_artifact(self) -> None:
        # Captured response evidence but NO crafted request line and no supplied PoC → nothing
        # runnable to replay, so POC readiness is false even though the report still renders steps.
        req = api.ReportReadyRequest(
            class_id="cors", rule_id="web.cors-acao-reflect", title="CORS misconfiguration",
            severity="high", location="https://example.com/api/me", target="https://example.com",
            proof_evidence=api.ProofEvidenceInput(
                response_header="Access-Control-Allow-Origin: https://evil.example",
                response_status="200"))
        out = self._ready(req)
        self.assertFalse(out["ready"]["poc"])          # no runnable artifact, no supplied PoC
        self.assertEqual(out.get("replay"), "")         # replay.sh could not be rebuilt
        self.assertIsNone(out.get("har"))               # nor findings.har
        self.assertTrue(out["ready"]["poe"])            # response evidence still lights POE

    def test_poc_flag_true_with_a_rebuilt_replay_artifact(self) -> None:
        # An absolute crafted request line lets replay.sh/findings.har be reconstructed → POC true.
        req = api.ReportReadyRequest(
            class_id="cors", rule_id="web.cors-acao-reflect", title="CORS misconfiguration",
            severity="high", location="https://example.com/api/me", target="https://example.com",
            proof_evidence=api.ProofEvidenceInput(
                request_line="GET https://example.com/api/me",
                response_header="Access-Control-Allow-Origin: https://evil.example",
                response_status="200"))
        out = self._ready(req)
        self.assertTrue(out["ready"]["poc"])
        self.assertTrue(out.get("replay"))              # the runnable artifact that earned the flag
        self.assertIsNotNone(out.get("har"))

    def test_poc_flag_false_for_a_multi_step_request_line(self) -> None:
        # A mass-assignment/BFLA finding captures its request_line as a multi-step DESCRIPTION
        # ("PATCH … then GET …"), which is not a single runnable request — so no replay.sh/har is
        # rebuilt and POC readiness is false, not a malformed-artifact false positive.
        req = api.ReportReadyRequest(
            class_id="mass-assignment", rule_id="active.mass-assignment", title="Mass assignment",
            severity="high", location="https://example.com/api/users/1", target="https://example.com",
            proof_evidence=api.ProofEvidenceInput(
                request_line='PATCH https://example.com/api/users/1  (body: {"is_admin": true})  then  GET https://example.com/api/users/1',
                response_status="re-read reflects is_admin=true"))
        out = self._ready(req)
        self.assertFalse(out["ready"]["poc"])          # the multi-step description is not runnable
        self.assertEqual(out.get("replay"), "")
        self.assertIsNone(out.get("har"))

    def test_poc_flag_true_with_a_supplied_poc(self) -> None:
        # No crafted request line (nothing to replay), but the operator/brain supplied a runnable
        # PoC — that IS a real POC artifact, so the flag is true without a rebuilt replay.sh.
        req = api.ReportReadyRequest(
            class_id="xss", rule_id="active.reflected-xss", title="Reflected XSS",
            severity="high", location="https://example.com/q", target="https://example.com",
            poc="<html><body><script>document.location='https://example.com/q?x=<svg/onload=1>'</script></body></html>")
        out = self._ready(req)
        self.assertTrue(out["ready"]["poc"])            # the supplied PoC counts
        self.assertEqual(out.get("replay"), "")         # ...and it was NOT from a rebuilt artifact


if __name__ == "__main__":
    unittest.main()
