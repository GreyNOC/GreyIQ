"""Tests for the dashboard/reporting on-demand engine methods on GreyIQRuntime:
reverify_finding, prove_finding, build_finding_report, list_all_findings, aggregate_report.

These wrap heavier machinery (verify_active, screenshots, build_submission) whose own
behavior is covered elsewhere — here we test the NEW wrapper guarantees: fail-closed
authorization + scope gates (no network on refusal), result compacting, on-demand report
synthesis, and durable-history read. The methods touch little instance state, so we bind
them onto a light stub with just the lock + run cache they need."""
from __future__ import annotations

import sys
import tempfile
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
    _proof_matches_class = staticmethod(api.GreyIQRuntime._proof_matches_class)
    _capture_proof_screenshot = api.GreyIQRuntime._capture_proof_screenshot
    _resolve_run_finding = api.GreyIQRuntime._resolve_run_finding
    _persist_proof_of_impact = api.GreyIQRuntime._persist_proof_of_impact
    reverify_finding = api.GreyIQRuntime.reverify_finding
    prove_finding = api.GreyIQRuntime.prove_finding
    build_finding_report = api.GreyIQRuntime.build_finding_report
    build_submission_package = api.GreyIQRuntime.build_submission_package
    list_all_findings = api.GreyIQRuntime.list_all_findings
    dismiss_finding = api.GreyIQRuntime.dismiss_finding
    restore_finding = api.GreyIQRuntime.restore_finding
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


class PersistProvenProofTests(unittest.TestCase):
    """A proof-of-impact pass that names a cached run finding must PERSIST the captured
    differential onto that run, so the canonical submission package (build_submission) — the
    same thing every rebuilt report and the submit gate read — renders it Confirmed instead of
    leaving it 'candidate' after proof was gathered. Only a class-matched confirmed result is
    persisted; an unrelated class confirmed at the same URL is not."""

    def setUp(self) -> None:
        self._orig = api.bounty_active_verify.verify_active
        self.stub = _Stub()
        self.stub.bounty_runs["run1"] = {
            "ctx": {"target": "https://in-scope.example",
                    "attack_plans": {"F1": {"steps": ["s1", "s2"], "impact": "Credentialed cross-origin read.",
                                            "proof_of_impact": {"status": "candidate"}}}},
            "findings": {"F1": {"ref": "F1", "class_id": "cors", "class_name": "CORS misconfiguration",
                                "title": "CORS trusts arbitrary subdomain Origin with credentials",
                                "location": "https://in-scope.example/api", "severity": "high", "cwe": "CWE-284"}},
        }

    def tearDown(self) -> None:
        api.bounty_active_verify.verify_active = self._orig

    def _fake_confirmed(self, class_hint):
        def _run(url, findings, **kw):
            results = [{"title": "CORS", "severity": "high", "rule_id": "cors", "_active_class_hint": class_hint,
                        "_active_proof": {"status": "confirmed", "method": "OPTIONS+GET carrying a credentialed session",
                                          "observed_result": "an arbitrary Origin was reflected with Allow-Credentials: true",
                                          "control_result": "a different Origin was reflected too — any origin is trusted",
                                          "evidence": "ACAO=https://evil.example; ACAC=true"}}]
            return results, {"in_scope": True, "host": "in-scope.example", "requests_used": 3, "rate_limited": False}
        return _run

    def _req(self):
        return api.ProveRequest(url="https://in-scope.example/api", scope="in-scope.example",
                                authorized=True, screenshot=False, run_id="run1", ref="F1")

    def test_matched_confirmed_proof_persists_and_report_reads_confirmed(self) -> None:
        api.bounty_active_verify.verify_active = self._fake_confirmed("cors")
        out = self.stub.prove_finding(self._req())
        self.assertTrue(out["ok"])
        self.assertTrue(out.get("persisted"))
        # The cached run's plan now carries the confirmed differential...
        poi = self.stub.bounty_runs["run1"]["ctx"]["attack_plans"]["F1"]["proof_of_impact"]
        self.assertEqual(poi["status"], "confirmed")
        self.assertIn("Allow-Credentials", poi["observed_result"])
        # ...so the CANONICAL submission package (what the report + submit gate read) is confirmed.
        pkg = self.stub.build_submission_package(api.SubmissionPackageRequest(run_id="run1", ref="F1", platform="hackerone"))
        self.assertTrue(pkg["ok"], pkg)
        self.assertEqual(pkg["package"]["proof_status"], "confirmed")
        self.assertRegex(pkg["package"]["vulnerability_information"], r"(?i)status:\*\*\s*Confirmed")

    def test_unrelated_class_confirmed_at_same_url_is_not_persisted(self) -> None:
        api.bounty_active_verify.verify_active = self._fake_confirmed("xss")  # different class than the CORS finding
        out = self.stub.prove_finding(self._req())
        self.assertTrue(out["ok"])
        self.assertFalse(out.get("persisted"))
        self.assertEqual(self.stub.bounty_runs["run1"]["ctx"]["attack_plans"]["F1"]["proof_of_impact"]["status"], "candidate")

    def test_no_run_ref_is_a_safe_noop(self) -> None:
        api.bounty_active_verify.verify_active = self._fake_confirmed("cors")
        out = self.stub.prove_finding(api.ProveRequest(url="https://in-scope.example/api", scope="in-scope.example",
                                                       authorized=True, screenshot=False))
        self.assertTrue(out["ok"])
        self.assertNotIn("persisted", out)  # nothing to persist without run_id/ref


class BuildFindingReportTests(unittest.TestCase):
    def test_builds_a_report_for_a_candidate(self) -> None:
        out = _Stub().build_finding_report(api.FindingReportRequest(
            title="Missing security header", severity="medium", class_name="Security hardening",
            location="https://example.com", cwe="CWE-693", target="https://example.com"))
        self.assertTrue(out["ok"], out)
        self.assertIn("vulnerability_information", out["package"])
        self.assertTrue(out["package"]["vulnerability_information"].strip())

    def test_report_always_has_reproduction_steps(self) -> None:
        # Even a bare ledger/dashboard finding (no attack plan of its own) must produce a
        # report with a populated "Steps to reproduce" section + a benign curl repro.
        out = _Stub().build_finding_report(api.FindingReportRequest(
            title="Reflected XSS", severity="high", class_name="xss", class_id="xss",
            location="https://example.com/search?q=1", cwe="CWE-79", target="https://example.com"))
        self.assertTrue(out["ok"], out)
        body = out["package"]["vulnerability_information"]
        self.assertIn("Steps to reproduce", body)
        self.assertIn("curl", body.lower())

    def test_client_confirmed_without_control_caps_at_candidate(self) -> None:
        # A client-supplied proof that claims 'confirmed' but carries no negative control
        # (e.g. just an "HTTP 200" observed_result) must NOT produce a confirmed report.
        out = _Stub().build_finding_report(api.FindingReportRequest(
            title="X", severity="high", class_name="cors", class_id="cors", location="https://example.com",
            target="https://example.com",
            proof=api.ProofInput(status="confirmed", observed_result="HTTP 200 OK returned", control_result="")))
        self.assertTrue(out["ok"], out)
        self.assertNotEqual(out["package"]["proof_status"], "confirmed")

    def test_report_redacts_secret_in_proof_fields(self) -> None:
        # Proof fields (method/actor/etc.) must be redacted before landing in the report body.
        out = _Stub().build_finding_report(api.FindingReportRequest(
            title="X", severity="high", class_name="cors", class_id="cors", location="https://example.com",
            target="https://example.com",
            proof=api.ProofInput(status="candidate", method="probed with AKIAIOSFODNN7EXAMPLE", observed_result="reflected")))
        self.assertTrue(out["ok"], out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out["package"]["vulnerability_information"])

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


class DismissApiTests(unittest.TestCase):
    """The delete-finding wrapper: derive the key, suppress it in the durable history, and
    reject a request that carries no way to identify the finding. Uses a temp RUNTIME_DIR so
    the test never writes to the real ledger."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._prev_rt = api.RUNTIME_DIR
        api.RUNTIME_DIR = Path(self._tmp.name)

    def tearDown(self) -> None:
        api.RUNTIME_DIR = self._prev_rt
        self._tmp.cleanup()

    def _seed_one(self) -> dict:
        from bughunter import ledger
        finding = {"ref": "C1", "class_id": "xss", "rule_id": "r", "location": "https://x/a",
                   "severity": "high", "title": "reflected input"}
        ledger.upsert_findings(str(api.RUNTIME_DIR), "acme", "https://x",
                               [{"finding": finding, "source_url": "https://x/a",
                                 "proof_status": "confirmed", "cvss": {"base_score": 8.0}, "source_json": ""}])
        return finding

    def test_dismiss_from_board_derives_key_and_hides_it(self) -> None:
        self._seed_one()
        self.assertEqual(len(_Stub().list_all_findings()["findings"]), 1)
        out = _Stub().dismiss_finding(api.FindingDismissRequest(
            class_id="xss", rule_id="r", location="https://x/a", title="reflected input"))
        self.assertTrue(out["ok"], out)
        self.assertTrue(out["dedup_key"])
        self.assertEqual(_Stub().list_all_findings()["findings"], [])  # gone from history

    def test_dismiss_without_any_detail_is_rejected(self) -> None:
        out = _Stub().dismiss_finding(api.FindingDismissRequest())
        self.assertFalse(out["ok"])
        self.assertIn("identify", out["error"].lower())

    def test_restore_reverses_a_delete(self) -> None:
        from bughunter import ledger
        finding = self._seed_one()
        key = ledger.dedup_key(finding)
        _Stub().dismiss_finding(api.FindingDismissRequest(dedup_key=key))
        self.assertEqual(_Stub().list_all_findings()["findings"], [])
        out = _Stub().restore_finding(api.FindingRestoreRequest(dedup_key=key))
        self.assertTrue(out["ok"])
        self.assertTrue(out["restored"])
        self.assertEqual(len(_Stub().list_all_findings()["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
