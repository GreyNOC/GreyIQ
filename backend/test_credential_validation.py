"""Firebase / Google API-key credential validation and reporting.

Covers the four things HackerOne demanded for a leaked-key report: exact location + variable name,
that the key is validated LIVE, the specific project/data it grants, and the ACTUAL key shown
(un-redacted) — while the surrounding snippet stays redacted and non-key rules never retain a raw
value. The validator's network layer is mocked; no real request is ever made in the tests.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import credential_validation as cv  # noqa: E402
from bughunter import report_formats as RF  # noqa: E402
from bughunter.bounty import _deterministic_attack_plan  # noqa: E402
from bughunter.code_scanner.redaction import redact_finding_snippets  # noqa: E402
from bughunter.code_scanner.rules.secrets import RULES  # noqa: E402
from bughunter.scan_service import _finding_to_dict  # noqa: E402

_KEY = "AIza" + "B" * 35
_GOOGLE_RULE = next(r for r in RULES if getattr(r, "rule_id", "") == "secret.google-api-key")


class ValidatorInterpretationTests(unittest.TestCase):
    def tearDown(self) -> None:
        import importlib
        importlib.reload(cv)  # restore the real _get after monkeypatching

    def _mock(self, status, body):
        cv._get = lambda url: (status, body)

    def test_live_key_reports_project_and_domains(self) -> None:
        self._mock(200, '{"projectId":"acme-prod","authorizedDomains":["acme.com","acme.firebaseapp.com"]}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIs(r["live"], True)
        self.assertEqual(r["project_id"], "acme-prod")
        self.assertIn("acme.firebaseapp.com", r["authorized_domains"])

    def test_invalid_key_is_not_live(self) -> None:
        self._mock(400, '{"error":{"message":"API key not valid. Please pass a valid API key."}}')
        self.assertIs(cv.validate_firebase_key(_KEY)["live"], False)

    def test_live_but_restricted_still_live_and_extracts_project(self) -> None:
        self._mock(403, '{"error":{"message":"Identity Toolkit API has not been used in project 123456789012 before or it is disabled."}}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIs(r["live"], True)
        self.assertEqual(r["project_id"], "123456789012")

    def test_non_key_is_not_checked(self) -> None:
        r = cv.validate_firebase_key("not-a-google-key")
        self.assertFalse(r["checked"])
        self.assertIsNone(r["live"])

    def test_host_allowlist_blocks_non_google_hosts(self) -> None:
        # The real _get refuses any host not on the Google allowlist.
        self.assertEqual(cv._get("https://evil.example.com/x?key=1")[0], 0)


class SecretCaptureTests(unittest.TestCase):
    def test_variable_name_and_raw_value_captured(self) -> None:
        f = list(_GOOGLE_RULE.scan(path="src/fb.js", text=f'const apiKey = "{_KEY}";'))[0]
        self.assertEqual(f.variable_name, "apiKey")
        self.assertEqual(f.secret_value, _KEY)

    def test_raw_value_survives_redaction_but_snippet_is_redacted(self) -> None:
        findings = list(_GOOGLE_RULE.scan(path="src/fb.js", text=f'apiKey = "{_KEY}"'))
        redacted, rmap = redact_finding_snippets(findings)
        d = _finding_to_dict(redacted[0], redacted=True)
        self.assertIn("REDACTED", d["snippet"])       # the snippet never leaks the key
        self.assertEqual(d.get("secret_value"), _KEY)  # but the raw value is kept for the credential section
        self.assertEqual(d.get("variable_name"), "apiKey")

    def test_non_secret_rule_retains_no_raw_value(self) -> None:
        from bughunter.code_scanner.model import Confidence, Severity
        from bughunter.code_scanner.rules.base import RegexRule
        rule = RegexRule(rule_id="x.t", title="t", description="d", severity=Severity.LOW,
                         confidence=Confidence.LOW, category="headers", pattern=r"AIza\w+")
        f = list(rule.scan(path="c.js", text=f'k="{_KEY}"'))[0]
        self.assertEqual(f.secret_value, "")
        self.assertEqual(f.variable_name, "")


class CredentialReportTests(unittest.TestCase):
    def _render(self, proof):
        finding = {
            "ref": "F1", "title": "Google API key", "severity": "high", "class_id": "secrets",
            "location": "src/firebase.js", "line_start": 12, "rule_id": "secret.google-api-key",
            "cwe": "CWE-798", "description": "A Google Cloud API key is hardcoded.",
            "snippet": 'const apiKey = "AIza...[REDACTED_SECRET:sha256:x]";',
            "variable_name": "apiKey", "secret_value": _KEY, "_credential_proof": proof,
        }
        plan = _deterministic_attack_plan(finding, "secrets")
        ctx = {"tool": "g", "version": "t", "generated_at": "now", "target": "src/firebase.js",
               "scope": "", "attack_plans": {"F1": plan}}
        return RF.render_finding(ctx, finding, "hackerone")

    def test_report_has_all_four_h1_requirements(self) -> None:
        body = self._render({"checked": True, "live": True, "project_id": "acme-prod-42",
                             "authorized_domains": ["acme.com", "acme.firebaseapp.com"],
                             "detail": "LIVE — authenticates to Firebase project acme-prod-42", "http_status": 200})
        self.assertIn("src/firebase.js:12", body)                 # exact location
        self.assertIn("variable `apiKey`", body)                  # variable name
        self.assertIn(_KEY, body)                                 # actual, un-redacted key
        self.assertIn("LIVE", body)                               # validated live
        self.assertIn("acme-prod-42", body)                       # specific project
        self.assertIn("acme.firebaseapp.com", body)               # data/domains it grants
        self.assertIn("UN-REDACTED", body)                        # review-before-sharing warning

    def test_live_credential_reads_as_confirmed(self) -> None:
        body = self._render({"checked": True, "live": True, "project_id": "p", "detail": "LIVE", "http_status": 200})
        self.assertRegex(body, r"(?i)status:\*\*\s*Confirmed")

    def test_dead_credential_is_shown_but_not_confirmed(self) -> None:
        body = self._render({"checked": True, "live": False, "detail": "NOT live", "http_status": 400})
        self.assertIn(_KEY, body)                                 # still shows the key + location
        self.assertNotRegex(body, r"(?i)status:\*\*\s*Confirmed")  # but a dead key is not a confirmed finding


if __name__ == "__main__":
    unittest.main()
