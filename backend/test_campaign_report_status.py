"""A finding CONFIRMED during a campaign must read as confirmed in its full submission report — without
a manual re-verify. Covers the whole chain: the campaign streams the active proof (observed-vs-control)
with the finding, the progress layer carries it, and build_finding_report renders it CONFIRMED."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter import campaign  # noqa: E402


class CampaignStreamsProofArtifactTests(unittest.TestCase):
    def test_confirmed_finding_streams_its_proof_detail(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        doc = {
            "findings": [{"ref": "F1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
                          "rule_id": "active.reflected-xss", "location": "https://t.example/q", "cwe": "CWE-79",
                          "proof_evidence": {"request_line": "GET /q?x=<svg/onload=1>",
                                             "request_header": "Origin: https://evil.example",
                                             "response_header": "Access-Control-Allow-Origin: https://evil.example"}}],
            "proof_of_impact": {"F1": {"status": "confirmed",
                                       "observed_result": "the <svg/onload> payload reflected UNENCODED in the HTML body",
                                       "control_result": "a benign marker with no tag did not reflect the payload"}},
            "cvss": {},
        }
        (tmp / "run.json").write_text(json.dumps(doc), encoding="utf-8")

        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves)
        campaign.recon.discover = lambda t, **k: {"urls": [t], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": str(tmp / "run.json"), "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda *a, **k: []
        campaign.progress.start_run("rs-1")
        try:
            campaign.run_campaign("https://t.example/", scope="t.example", authorized=True, coder_cfg=None,
                                  default_reports_dir=tmp, active=True, progress_run_id="rs-1")
        finally:
            campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves = orig

        streamed = campaign.progress.snapshot("rs-1").get("findings") or []
        f1 = next((f for f in streamed if f.get("ref") == "F1"), None)
        self.assertIsNotNone(f1, "the confirmed finding was streamed")
        self.assertEqual(f1.get("proof"), "confirmed")                     # status badge
        pd = f1.get("proof_detail") or {}
        self.assertIn("reflected UNENCODED", pd.get("observed_result", ""))  # the ARTIFACT rode along
        self.assertIn("did not reflect", pd.get("control_result", ""))      # ...both halves of the differential
        pe = f1.get("proof_evidence") or {}
        self.assertEqual(pe.get("request_line"), "GET /q?x=<svg/onload=1>")
        # the SINGULAR header keys (the real schema) must survive compacting — a CORS/redirect report
        # reproduces from exactly these
        self.assertEqual(pe.get("request_header"), "Origin: https://evil.example")
        self.assertEqual(pe.get("response_header"), "Access-Control-Allow-Origin: https://evil.example")

    def test_streamed_proof_detail_makes_the_on_demand_report_confirmed(self) -> None:
        # The drawer passes the streamed proof_detail as `proof`; build_finding_report must render it
        # CONFIRMED (the differential is real) instead of "candidate / validate before submission".
        rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
        proof_detail = {"status": "confirmed",
                        "observed_result": "the <svg/onload> payload reflected UNENCODED in the HTML body",
                        "control_result": "a benign marker with no tag did not reflect"}
        req = api.FindingReportRequest(
            class_id="xss", location="https://t.example/q", target="https://t.example",
            proof=api.ProofInput(**proof_detail))
        pkg = api.GreyIQRuntime.build_finding_report(rt, req)["package"]
        self.assertEqual(pkg["proof_status"], "confirmed")

    def test_candidate_finding_is_not_forced_confirmed(self) -> None:
        # a genuinely unconfirmed finding (no differential) still reads candidate — the fix must not
        # over-promote
        rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
        req = api.FindingReportRequest(class_id="xss", location="https://t.example/q", target="https://t.example",
                                       proof=api.ProofInput(status="candidate", observed_result="reflected but encoded", control_result=""))
        self.assertEqual(api.GreyIQRuntime.build_finding_report(rt, req)["package"]["proof_status"], "candidate")


class CampaignPersistsActiveDifferentialTests(unittest.TestCase):
    """A per-URL finding confirmed by the active pass must persist its observed-vs-control differential
    to the durable ledger, so a report rebuilt from history after a restart keeps the proof that earned
    'confirmed' (regression: the per-URL consolidation carried no differential to the ledger)."""

    def test_confirmed_active_finding_differential_reaches_the_ledger(self) -> None:
        from bughunter import ledger
        tmp = Path(tempfile.mkdtemp())
        rt = Path(tempfile.mkdtemp())
        doc = {
            "findings": [{"ref": "F1", "title": "Reflected XSS", "severity": "high", "class_id": "xss",
                          "rule_id": "active.reflected-xss", "location": "https://t.example/q", "cwe": "CWE-79",
                          "proof_evidence": {"request_line": "GET /q?x=<svg/onload=1>", "response_status": "HTTP 200"}}],
            "proof_of_impact": {"F1": {"status": "confirmed",
                                       "observed_result": "the <svg/onload> payload reflected UNENCODED in the HTML body",
                                       "control_result": "a benign marker with no tag did not reflect"}},
            "cvss": {"F1": {"base_score": 6.1}}, "attack_plans": {},
        }
        (tmp / "run.json").write_text(json.dumps(doc), encoding="utf-8")
        orig = (campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves)
        campaign.recon.discover = lambda t, **k: {"urls": [t], "notes": [], "sources": {}, "js_secrets": [], "tech": [], "params": [], "forms": []}
        campaign.run_bounty_hunt = lambda *a, **k: {"ok": True, "json_path": str(tmp / "run.json"), "report_path": ""}
        campaign.cve_service.scan_known_cves = lambda *a, **k: []
        try:
            campaign.run_campaign("https://t.example/", scope="t.example", authorized=True, coder_cfg=None,
                                  default_reports_dir=tmp, runtime_dir=rt, program="demo", active=True)
        finally:
            campaign.recon.discover, campaign.run_bounty_hunt, campaign.cve_service.scan_known_cves = orig

        rows = ledger.list_all(rt)
        rec = next((r for r in rows if r.get("rule_id") == "active.reflected-xss"), None)
        self.assertIsNotNone(rec, "the confirmed finding was recorded")
        poi = (rec.get("captured_proof") or {}).get("proof_of_impact") or {}
        self.assertIn("reflected UNENCODED", poi.get("observed_result", ""))   # the differential is durable
        self.assertIn("did not reflect", poi.get("control_result", ""))


if __name__ == "__main__":
    unittest.main()
