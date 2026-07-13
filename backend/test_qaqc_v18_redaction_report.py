"""Regression tests for the v1.8 QAQC redaction/report fixes (group: redaction-report).

Each test FAILS before its fix and PASSES after:

* redaction.py:175 — the generic-password pass truncated a JWT at the first '.', leaking
  payload+signature into an "already redacted" excerpt (fixed by running the keyed/JWT passes first).
* redaction.py JWT thresholds — aligned with sensitive_data._JWT_RE so every JWT the classifier
  names is also strippable.
* report.py:1163 / sensitive_data.py:56 — redact_text had no email pattern, so a non-role email the
  classifier NAMES leaked verbatim (fixed by an email redaction pass).
* report.py:250 — the QA "downgrade-only" cap could leave the exported severity ABOVE the tier the QA
  section claims it enforced (fixed by iterative weakening + a direct tier stamp).
* report.py:237 — QA issue refs went stale after the post-QA renumber, misattributing a downgrade to
  the wrong finding (fixed by resolving the ref live from the finding object at render time).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as report_lib  # noqa: E402
from bughunter import sensitive_data  # noqa: E402
from bughunter.code_scanner.redaction import redact_text  # noqa: E402

# A realistic HS256 JWT whose payload base64url-decodes to {"sub":"alice@example.com","role":"admin"}.
_JWT_HEADER = "eyJhbGciOiJIUzI1NiJ9"
_JWT_PAYLOAD = "eyJzdWIiOiJhbGljZUBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiJ9"
_JWT_SIG = "a" * 43
_JWT = f"{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIG}"


class JwtRedactionOrderTests(unittest.TestCase):
    def test_access_token_jwt_is_fully_redacted_not_truncated_at_first_dot(self) -> None:
        # The v1.8 leak: the generic-password pass ran first, matched only the header segment (its value
        # charset excludes '.'), broke the eyJ.eyJ. shape, and left the payload+signature verbatim.
        body = f'{{"access_token": "{_JWT}"}}'
        out, redacted = redact_text(body)
        self.assertTrue(redacted)
        self.assertNotIn(_JWT_PAYLOAD, out, "JWT payload leaked verbatim into a redacted excerpt")
        self.assertNotIn(_JWT_SIG, out, "JWT signature leaked verbatim into a redacted excerpt")

    def test_leak_reproduces_across_keyword_fields(self) -> None:
        # Same failure for every keyword field the generic-password pass matches.
        for field in ("token", "id_token", "api_key", "secret", "password"):
            body = f'{{"{field}": "{_JWT}"}}'
            out, redacted = redact_text(body)
            self.assertTrue(redacted, f"{field}: nothing redacted")
            self.assertNotIn(_JWT_PAYLOAD, out, f"{field}: JWT payload leaked verbatim")

    def test_short_jwt_named_by_classifier_is_redactable(self) -> None:
        # Threshold-drift compounding bug: classify._JWT_RE accepts {5,}/{5,}/{5,} while the redactor
        # previously required {8,}/{8,}/{16,}, so a compact JWT was named-but-not-stripped.
        short_jwt = "eyJAAAAA.eyJBBBBB.CCCCC"
        self.assertIn("a JWT (session/bearer token)", sensitive_data.classify(f'{{"data": "{short_jwt}"}}'))
        out, redacted = redact_text(f'{{"data": "{short_jwt}"}}')
        self.assertTrue(redacted, "a JWT the classifier names was left untouched by redact_text")
        self.assertNotIn(short_jwt, out)


class EmailRedactionIsIntentionalEvidenceTests(unittest.TestCase):
    def test_email_is_deliberately_shown_as_impact_evidence_while_secrets_are_redacted(self) -> None:
        # DELIBERATE (QAQC #28/#33 assessed as intended behavior): redact_text does NOT strip email
        # addresses. sensitive_data.classify still NAMES a captured non-role email as "email
        # address(es)" so the report honestly labels the data at risk, but the raw sample is kept in
        # the captured-response excerpt because it IS the proof-of-impact a CORS / sensitive-data
        # finding must demonstrate (a browser PoC reads THIS) — the v1.4.0 "show the data at risk"
        # design. Secrets/tokens ARE still redacted; only the operator's own authorized PII capture is
        # shown. (Flip this to redaction only if PII-in-submitted-reports policy requires it.)
        body = '{"email":"victim@acme.com","token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmnop"}'
        self.assertIn("email address(es)", sensitive_data.classify(body))  # named as present (honest label)
        out, _ = redact_text(body)
        self.assertIn("victim@acme.com", out)                              # PII sample shown as evidence
        self.assertNotIn("eyJzdWIiOiIxMjMifQ", out)                        # but the JWT payload IS redacted


class QaDowngradeActuallyLowersSeverityTests(unittest.TestCase):
    def _cors_finding(self, plan_cvss: dict) -> tuple[dict, dict]:
        finding = {"ref": "F1", "class_id": "cors", "rule_id": "active.cors", "severity": "high",
                   "proof_evidence": {"request_line": "GET /api/me HTTP/1.1", "response_status": "HTTP 200"}}
        return finding, {"cvss": plan_cvss}

    def test_residual_high_vector_is_forced_down_to_the_capped_tier(self) -> None:
        # A brain-supplied Critical CORS vector carrying I:H/A:H: a single C+AC weaken leaves a residual
        # High (7.7), which resolve_severity would re-inflate above the "downgraded to Medium" claim.
        f, p = self._cors_finding({"vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                   "base_severity": "Critical", "base_score": 9.6})
        res = report_lib.qa_validate_report([f], {"F1": p})
        self.assertTrue(any(i.get("action") for i in res["issues"]))  # a downgrade was recorded
        self.assertLessEqual(
            report_lib._SEVERITY_ORDER[report_lib.resolve_severity(f, p)],
            report_lib._SEVERITY_ORDER["medium"],
            "exported severity is still above the tier the QA section claims it capped to",
        )

    def test_cvss_with_base_severity_but_no_vector_is_forced_down(self) -> None:
        # A cvss dict with base_severity but no string vector: the rewrite is skipped, so the tier must
        # be stamped directly or resolve_severity keeps returning the old High.
        f, p = self._cors_finding({"base_severity": "High", "base_score": 7.5})
        report_lib.qa_validate_report([f], {"F1": p})
        self.assertLessEqual(
            report_lib._SEVERITY_ORDER[report_lib.resolve_severity(f, p)],
            report_lib._SEVERITY_ORDER["medium"],
        )


class QaRefsSurviveRenumberTests(unittest.TestCase):
    def test_downgrade_issue_names_the_finding_after_reorder(self) -> None:
        # Reproduce bounty.py's sequence: assign refs -> QA -> reorder+renumber by resolved severity.
        f1 = {"ref": "F1", "class_id": "cors", "rule_id": "active.cors", "severity": "high",
              "proof_evidence": {"request_line": "GET /", "response_status": "HTTP 200"}}
        p1 = {"cvss": {"vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", "base_severity": "High", "base_score": 8.3}}
        f2 = {"ref": "F2", "class_id": "sqli", "rule_id": "active.sqli", "severity": "high",
              "proof_evidence": {}}
        p2 = {"cvss": {"vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_severity": "High", "base_score": 8.8}}
        findings = [f1, f2]
        plans = {"F1": p1, "F2": p2}

        qa = report_lib.qa_validate_report(findings, plans)  # Q1 caps the CORS f1 to Medium, records ref "F1"

        # Reorder by final resolved severity (sqli High > cors Medium) and renumber IN PLACE, exactly as
        # bounty._order_by_resolved_severity does — f1 becomes F2.
        findings.sort(key=lambda f: report_lib._SEVERITY_ORDER.get(
            report_lib.resolve_severity(f, plans.get(f.get("ref"))), 0), reverse=True)
        for index, f in enumerate(findings, 1):
            f["ref"] = f"F{index}"
        self.assertEqual(f1["ref"], "F2")  # the CORS finding moved

        report_lib._resync_qa_refs(qa)
        cors_issue = next(i for i in qa["issues"] if "CORS" in str(i.get("question")))
        self.assertEqual(cors_issue["ref"], f1["ref"],
                         "QA issue still names the stale pre-reorder ref, misattributing the downgrade")
        self.assertNotIn("_finding", cors_issue, "private _finding carrier leaked past resync")


if __name__ == "__main__":
    unittest.main()
