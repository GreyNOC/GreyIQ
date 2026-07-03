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

    def test_live_key_captures_runnable_poc_and_issuer_response(self) -> None:
        self._mock(200, '{"projectId":"acme-prod","authorizedDomains":["acme.com"]}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIn(_KEY, r["poc"])                        # the PoC is a literal, runnable reproduction
        self.assertIn("getProjectConfig", r["poc"])
        self.assertIn("acme-prod", r["response_excerpt"])    # the ACTUAL issuer response is captured as proof

    def test_poc_present_even_when_inconclusive(self) -> None:
        self._mock(0, "Timeout")  # offline / no verdict — the operator still gets the command to run
        r = cv.validate_firebase_key(_KEY)
        self.assertIsNone(r["live"])
        self.assertIn(_KEY, r["poc"])

    def test_storage_exposure_captures_real_object_names(self) -> None:
        cv._get = lambda url: ((200, '{"items":[{"name":"users/secret.json"},{"name":"backups/db.sql"}],"prefixes":["private/"]}')
                               if "firebasestorage" in url else (200, "null"))  # RTDB locked, Storage open
        exps = cv.probe_firebase_exposure("acme-prod")
        storage = next(e for e in exps if e["service"] == "Firebase Cloud Storage")
        self.assertIn("users/secret.json", storage["evidence"])   # concrete object name, not prose
        self.assertIn("private/", storage["detail"])

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


class TokenLivenessTests(unittest.TestCase):
    def tearDown(self) -> None:
        import importlib
        importlib.reload(cv)  # restore the real _get_full after monkeypatching

    def test_github_token_live_names_account_and_scopes(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {"X-OAuth-Scopes": "repo, read:org"}, '{"login":"octocat"}')
        r = cv.validate_github_token("ghp_" + "A" * 36)
        self.assertIs(r["live"], True)
        self.assertEqual(r["principal"], "octocat")           # the account it controls
        self.assertIn("repo", r["scopes"])                    # what it grants
        self.assertIn("api.github.com/user", r["poc"])        # runnable PoC to the issuer

    def test_github_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (401, {}, '{"message":"Bad credentials"}')
        self.assertIs(cv.validate_github_token("ghp_bad")["live"], False)

    def test_slack_token_live_names_workspace(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"ok":true,"team":"acme-corp","user":"deploybot"}')
        r = cv.validate_slack_token("xoxb-1-1")
        self.assertIs(r["live"], True)
        self.assertIn("acme-corp", r["principal"])

    def test_slack_token_dead(self) -> None:
        cv._get_full = lambda url, extra_headers=None: (200, {}, '{"ok":false,"error":"invalid_auth"}')
        self.assertIs(cv.validate_slack_token("xoxb-bad")["live"], False)

    def test_new_issuer_hosts_allowlisted_others_blocked(self) -> None:
        self.assertTrue(cv._host_allowed("api.github.com"))
        self.assertTrue(cv._host_allowed("slack.com"))
        self.assertFalse(cv._host_allowed("evil.example.com"))
        # a token is only ever sent to its allowlisted issuer — never an arbitrary host
        self.assertEqual(cv._get_full("https://evil.example.com/steal")[0], 0)


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

    def test_report_includes_runnable_poc_and_captured_response(self) -> None:
        poc = f"curl -s 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={_KEY}'"
        body = self._render({"checked": True, "live": True, "project_id": "acme-prod-42",
                             "authorized_domains": ["acme.com"], "detail": "LIVE", "http_status": 200,
                             "poc": poc, "response_excerpt": '{"projectId":"acme-prod-42","authorizedDomains":["acme.com"]}'})
        self.assertIn("Proof of concept", body)                       # a PoC section is present
        self.assertIn(f"getProjectConfig?key={_KEY}", body)           # the runnable command, with the real key
        self.assertIn("Issuer response", body)                        # the captured artifact heading
        self.assertIn("acme-prod-42", body)                           # the actual issuer response content

    def test_live_credential_reads_as_confirmed(self) -> None:
        body = self._render({"checked": True, "live": True, "project_id": "p", "detail": "LIVE", "http_status": 200})
        self.assertRegex(body, r"(?i)status:\*\*\s*Confirmed")

    def test_report_renders_github_token_account_scopes_and_confirmed(self) -> None:
        body = self._render({"checked": True, "live": True, "principal": "octocat", "scopes": "repo, read:org",
                             "detail": "LIVE — GitHub account octocat", "http_status": 200,
                             "endpoint": "GitHub api.github.com/user",
                             "poc": "curl -s -H 'Authorization: Bearer ghp_XXX' https://api.github.com/user",
                             "response_excerpt": '{"login":"octocat"}'})
        self.assertIn("octocat", body)                          # the account the token controls
        self.assertIn("repo, read:org", body)                  # granted scopes
        self.assertIn("api.github.com/user", body)             # runnable PoC + generic issuer wording
        self.assertRegex(body, r"(?i)status:\*\*\s*Confirmed")  # a live token is a confirmed finding

    def test_dead_credential_is_shown_but_not_confirmed(self) -> None:
        body = self._render({"checked": True, "live": False, "detail": "NOT live", "http_status": 400})
        self.assertIn(_KEY, body)                                 # still shows the key + location
        self.assertNotRegex(body, r"(?i)status:\*\*\s*Confirmed")  # but a dead key is not a confirmed finding


if __name__ == "__main__":
    unittest.main()
