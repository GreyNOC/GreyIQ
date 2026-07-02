"""Tests for the dashboard/reporting on-demand engine methods on GreyIQRuntime:
reverify_finding, prove_finding, build_finding_report, list_all_findings, aggregate_report.

These wrap heavier machinery (verify_active, screenshots, build_submission) whose own
behavior is covered elsewhere — here we test the NEW wrapper guarantees: fail-closed
authorization + scope gates (no network on refusal), result compacting, on-demand report
synthesis, and durable-history read. The methods touch little instance state, so we bind
them onto a light stub with just the lock + run cache they need."""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


class _Stub:
    """A stand-in `self`: the real unbound methods + the minimal state they read."""
    _active_scope_for = api.GreyIQRuntime._active_scope_for
    _compact_active = staticmethod(api.GreyIQRuntime._compact_active)  # preserve staticmethod-ness
    _capture_proof_screenshot = api.GreyIQRuntime._capture_proof_screenshot
    reverify_finding = api.GreyIQRuntime.reverify_finding
    prove_finding = api.GreyIQRuntime.prove_finding
    build_finding_report = api.GreyIQRuntime.build_finding_report
    list_all_findings = api.GreyIQRuntime.list_all_findings
    aggregate_report = api.GreyIQRuntime.aggregate_report

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.bounty_runs: dict = {}


class ReverifyGateTests(unittest.TestCase):
    def test_refuses_when_not_authorized(self) -> None:
        out = _Stub().reverify_finding(api.ReverifyRequest(url="https://in-scope.example/x", scope="in-scope.example", authorized=False))
        self.assertFalse(out["ok"])
        self.assertIn("authorized", out["error"].lower())

    def test_out_of_scope_url_is_refused_without_network(self) -> None:
        out = _Stub().reverify_finding(api.ReverifyRequest(url="https://attacker.invalid/x", scope="in-scope.example", authorized=True))
        self.assertFalse(out["ok"])
        self.assertFalse(out["in_scope"])


class ProveGateTests(unittest.TestCase):
    def test_prove_refuses_when_not_authorized(self) -> None:
        out = _Stub().prove_finding(api.ProveRequest(url="https://in-scope.example/x", scope="in-scope.example", authorized=False))
        self.assertFalse(out["ok"])
        self.assertIn("authorized", out["error"].lower())

    def test_prove_out_of_scope_refused_without_network(self) -> None:
        out = _Stub().prove_finding(api.ProveRequest(url="https://attacker.invalid/x", scope="in-scope.example", authorized=True, screenshot=False))
        self.assertFalse(out["ok"])
        self.assertFalse(out["in_scope"])


class CompactAndProveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = api.bounty_active_verify.verify_active

    def tearDown(self) -> None:
        api.bounty_active_verify.verify_active = self._orig

    def _fake_confirmed(self, url, findings, **kw):
        results = [{"title": "Reflected XSS", "severity": "high", "rule_id": "xss", "_active_class_hint": "xss",
                    "_active_proof": {"status": "confirmed", "method": "GET", "observed_result": "marker reflected",
                                      "control_result": "no marker", "evidence": "<m>"}}]
        return results, {"in_scope": True, "host": "in-scope.example", "requests_used": 5, "rate_limited": False}

    def test_reverify_compacts(self) -> None:
        api.bounty_active_verify.verify_active = self._fake_confirmed
        out = _Stub().reverify_finding(api.ReverifyRequest(url="https://in-scope.example/x", scope="in-scope.example", authorized=True))
        self.assertTrue(out["ok"])
        self.assertEqual(out["confirmed"], 1)
        self.assertEqual(out["findings"][0]["observed"], "marker reflected")

    def test_prove_without_screenshot_returns_proof(self) -> None:
        api.bounty_active_verify.verify_active = self._fake_confirmed
        out = _Stub().prove_finding(api.ProveRequest(url="https://in-scope.example/x", scope="in-scope.example", authorized=True, screenshot=False))
        self.assertTrue(out["ok"])
        self.assertEqual(out["confirmed"], 1)
        self.assertIsNone(out["screenshot"])  # screenshot disabled -> not attempted


class BuildFindingReportTests(unittest.TestCase):
    def test_builds_a_report_for_a_candidate(self) -> None:
        out = _Stub().build_finding_report(api.FindingReportRequest(
            title="Missing security header", severity="medium", class_name="Security hardening",
            location="https://example.com", cwe="CWE-693", target="https://example.com"))
        self.assertTrue(out["ok"], out)
        self.assertIn("vulnerability_information", out["package"])
        self.assertTrue(out["package"]["vulnerability_information"].strip())

    def test_folds_in_gathered_proof(self) -> None:
        out = _Stub().build_finding_report(api.FindingReportRequest(
            title="Reflected XSS", severity="high", class_name="xss", location="https://example.com/s?q=1",
            cwe="CWE-79", target="https://example.com",
            proof=api.ProofInput(status="confirmed", method="GET reflection",
                                 observed_result="the <svg> marker reflected unencoded in the response body",
                                 control_result="the control request did not reflect the marker",
                                 evidence="response contained the injected marker")))
        self.assertTrue(out["ok"], out)
        body = out["package"]["vulnerability_information"]
        self.assertIn("marker", body.lower())


class HistoryAndAggregateTests(unittest.TestCase):
    def test_list_all_findings_ok_shape(self) -> None:
        out = _Stub().list_all_findings()
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["findings"], list)
        self.assertIn("funnel", out)

    def test_aggregate_needs_a_source(self) -> None:
        out = _Stub().aggregate_report(api.AggregateReportRequest())
        self.assertFalse(out["ok"])

    def test_aggregate_unknown_run_errors(self) -> None:
        out = _Stub().aggregate_report(api.AggregateReportRequest(run_id="does-not-exist"))
        self.assertFalse(out["ok"])
        self.assertIn("cached", out["error"].lower())


if __name__ == "__main__":
    unittest.main()
