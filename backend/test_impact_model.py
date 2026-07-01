"""Tests for the deterministic impact + proof-of-impact model: every vuln class
has an impact entry, CVSS base scores are computed correctly, and an OFFLINE
(no-brain) report renders a real impact narrative, a finding-specific proof
obligation, and a CVSS line — with the 'confirmed' status gated behind a real
captured artifact (never narrative prose alone)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import impact_model  # noqa: E402
from bughunter import report as report_lib  # noqa: E402
from bughunter.bounty import VULN_CLASSES, _CATEGORY_LABELS, _deterministic_attack_plan  # noqa: E402


class ImpactModelTests(unittest.TestCase):
    def test_every_vuln_class_and_category_has_impact_model(self) -> None:
        for cid in list(VULN_CLASSES) + list(_CATEGORY_LABELS):
            entry = impact_model.IMPACT_MODEL.get(cid)
            self.assertIsNotNone(entry, f"{cid} missing IMPACT_MODEL entry")
            for field in ("attacker_capability", "affected_asset", "business_impact", "proof_obligation", "cvss_vector"):
                self.assertTrue(str(entry[field]).strip(), f"{cid}.{field} empty")

    def test_every_class_has_remediation_and_references(self) -> None:
        # The report's "fix" + "references" floor: present on every class so an
        # offline report is submission-grade.
        for cid in list(VULN_CLASSES) + list(_CATEGORY_LABELS):
            self.assertTrue(impact_model.remediation_for_class(cid).strip(), f"{cid} remediation empty")
            refs = impact_model.references_for_class(cid)
            self.assertTrue(refs, f"{cid} references empty")
            for url in refs:
                self.assertTrue(url.startswith("https://"), f"{cid} reference not https: {url}")

    def test_offline_report_renders_remediation_and_references(self) -> None:
        # An impact_model-class finding with no scanner remediation still gets a
        # Remediation and a References section in the rendered report.
        ctx = {
            "tool": "GreyIQ BugHunter", "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [{
                "ref": "F1", "severity": "high", "confidence": "high", "category": "ssrf",
                "class_id": "ssrf", "class_name": "Server-side request forgery (SSRF)", "cwe": "CWE-918",
                "title": "SSRF sink", "location": "app.py", "rule_id": "py.requests-variable-url",
                "references": impact_model.references_for_class("ssrf"),
            }],
            "attack_plans": {"F1": _deterministic_attack_plan({"location": "app.py", "rule_id": "x"}, "ssrf")},
            "recommended_tools": [], "brain": {"used": False},
        }
        md = report_lib.build_finding_markdown(ctx, ctx["findings"][0])
        self.assertIn("## Remediation", md)
        self.assertIn("## References", md)
        self.assertIn("https://", md)

    def test_cvss_base_scores_match_nvd_reference(self) -> None:
        refs = {
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N": 8.1,
            "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N": 7.7,
            "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
        }
        for vector, expected in refs.items():
            self.assertEqual(impact_model.cvss_base_score(vector)["score"], expected, vector)

    def test_malformed_cvss_vector_is_safe(self) -> None:
        scored = impact_model.cvss_base_score("not-a-vector")
        self.assertEqual(scored["score"], 0.0)
        self.assertEqual(scored["severity"], "None")

    def test_every_class_cvss_vector_scores_above_zero(self) -> None:
        for cid in impact_model.IMPACT_MODEL:
            self.assertGreater(impact_model.cvss_for_class(cid)["base_score"], 0.0, cid)

    def test_cvss_for_class_confirmed_flag(self) -> None:
        # Default (no confirmed=) stays a template estimate — the vector/score don't
        # change on confirmation, only the confidence and its justification.
        estimated = impact_model.cvss_for_class("ssrf")
        self.assertTrue(estimated["estimated"])
        self.assertIn("estimate", estimated["justification"].lower())
        confirmed = impact_model.cvss_for_class("ssrf", confirmed=True)
        self.assertFalse(confirmed["estimated"])
        self.assertIn("confirmed", confirmed["justification"].lower())
        self.assertNotIn("vector is an estimate", confirmed["justification"].lower())
        self.assertEqual(confirmed["vector"], estimated["vector"])
        self.assertEqual(confirmed["base_score"], estimated["base_score"])


class DeterministicProofTests(unittest.TestCase):
    def test_deterministic_plan_carries_impact_proof_and_cvss(self) -> None:
        finding = {"ref": "F1", "class_id": "access-control", "rule_id": "manual.idor", "location": "/api/orders/1"}
        plan = _deterministic_attack_plan(finding, "access-control")
        self.assertTrue(plan["impact"].strip())
        self.assertTrue(plan["proof_of_impact"]["proof_obligation"].strip())
        self.assertEqual(plan["cvss"]["base_severity"], "High")
        self.assertEqual(plan["cvss"]["base_score"], 8.1)
        # A code pattern with no captured artifact is honestly 'missing', never confirmed.
        self.assertEqual(plan["proof_of_impact"]["status"], "missing")

    def test_secret_finding_is_candidate_not_missing(self) -> None:
        finding = {"ref": "F1", "class_id": "secrets", "category": "secret", "rule_id": "secret.aws"}
        plan = _deterministic_attack_plan(finding, "secrets")
        self.assertEqual(plan["proof_of_impact"]["status"], "candidate")

    def test_offline_report_renders_impact_obligation_and_cvss(self) -> None:
        f = {"ref": "F1", "severity": "high", "confidence": "high", "class_id": "access-control",
             "class_name": "Broken access control / IDOR", "title": "IDOR", "location": "/api/orders/1",
             "category": "access-control", "rule_id": "manual.idor"}
        plan = _deterministic_attack_plan(f, "access-control")
        ctx = {"tool": "GreyIQ", "version": "t", "generated_at": "now", "target": "https://x", "kind": "url",
               "profile": {"id": "web-app", "name": "Web"}, "vuln_class": None, "scope": "s", "authorized": True,
               "scanners_run": ["web"], "risk": "high", "score": 0.8, "findings": [f], "attack_plans": {"F1": plan},
               "manual_checklist": ["x"], "recommended_tools": [], "brain": {"used": False}, "next_steps": [], "coverage": {}}
        md = report_lib.build_markdown(ctx)
        self.assertIn("CVSS v3.1", md)
        self.assertIn("Proof obligation (capture this to prove impact)", md)
        self.assertIn("**Impact:**", md)
        jd = report_lib.build_json(ctx)
        self.assertIn("F1", jd["cvss"])
        self.assertEqual(jd["proof_of_impact"]["F1"]["status"], "missing")

    def test_prose_alone_cannot_confirm_only_artifact_can(self) -> None:
        f = {"ref": "F1", "class_id": "access-control", "rule_id": "x"}
        prose = {"proof_of_impact": {"evidence": "an attacker could read another user account; admin data returned"}}
        self.assertEqual(report_lib._proof_of_impact_detail(f, prose)["status"], "candidate")
        artifact = {"proof_of_impact": {"observed_result": "HTTP 200 returned the order owned by account A"}}
        self.assertEqual(report_lib._proof_of_impact_detail(f, artifact)["status"], "confirmed")
        # An explicit 'confirmed' status WITH a real observed_result/control_result
        # differential (what every active-prover check actually produces) stays confirmed.
        explicit_with_artifact = {"proof_of_impact": {
            "status": "confirmed", "evidence": "captured response attached",
            "observed_result": "the payload reflected unescaped", "control_result": "a plain marker reflected too",
        }}
        self.assertEqual(report_lib._proof_of_impact_detail(f, explicit_with_artifact)["status"], "confirmed")

    def test_explicit_confirmed_status_without_artifact_downgrades_to_candidate(self) -> None:
        # A bare explicit 'confirmed' status with no real captured differential (exactly
        # what a hallucinating or prompt-injected brain could emit) must NOT single-
        # handedly flip proof_status — that would bypass the auto-submit confirm gate.
        f = {"ref": "F1", "class_id": "access-control", "rule_id": "x"}
        explicit_no_artifact = {"proof_of_impact": {"status": "confirmed", "evidence": "captured response attached"}}
        self.assertEqual(report_lib._proof_of_impact_detail(f, explicit_no_artifact)["status"], "candidate")

    def test_passive_web_proof_evidence_does_not_satisfy_confirm_gate(self) -> None:
        # A hardening finding carrying only PASSIVE proof_evidence (request line +
        # 'header absent') plus brain prose must stay 'candidate' — passive evidence
        # proves a GET happened, not security impact.
        web_finding = {
            "ref": "F1", "class_id": "headers", "rule_id": "web.missing-header.x",
            "proof_evidence": {"request_line": "GET https://x/", "response_status": "HTTP 200", "matched_value": "X-Frame-Options absent"},
        }
        prose = {"proof_of_impact": {"evidence": "an attacker could read another user account; admin data returned"}}
        self.assertEqual(report_lib._proof_of_impact_detail(web_finding, prose)["status"], "candidate")

    def test_deterministic_plan_always_carries_an_obligation_to_preserve(self) -> None:
        # The merge floor preserves the deterministic proof_obligation when the brain
        # returns a bare-string proof; that only works if the deterministic plan always
        # produces a non-empty obligation in the first place. Assert that for every class.
        for cid in impact_model.IMPACT_MODEL:
            plan = _deterministic_attack_plan({"ref": "F1", "class_id": cid, "rule_id": "x"}, cid)
            self.assertTrue(plan["proof_of_impact"]["proof_obligation"].strip(), cid)


if __name__ == "__main__":
    unittest.main()
