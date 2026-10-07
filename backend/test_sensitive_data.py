"""Sensitive-data classifier over captured proof bodies: names the high-confidence data a disclosure
finding actually exposed (the "so-what" that raises severity), and stays out of the injection-class
proof blocks. Tier is deliberately conservative — no credit-card/phone/password-heuristic over-claim."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as report_lib  # noqa: E402
from bughunter import sensitive_data  # noqa: E402

_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


class ClassifyTests(unittest.TestCase):
    def test_detects_high_confidence_classes(self) -> None:
        self.assertIn("a JWT (session/bearer token)", sensitive_data.classify(f"tok={_JWT}"))
        self.assertIn("an AWS access key ID", sensitive_data.classify("id AKIAIOSFODNN7EXAMPLE end"))
        self.assertIn("email address(es)", sensitive_data.classify("contact victim@acme.com"))

    def test_summarize_joins_multiple(self) -> None:
        s = sensitive_data.summarize(f"victim@acme.com holds {_JWT}")
        self.assertIn("a JWT (session/bearer token)", s)
        self.assertIn("email address(es)", s)
        self.assertIn(" and ", s)

    def test_conservative_tier_excludes_weak_signals(self) -> None:
        # credit-card-shaped digits, phone numbers, and password-assignment heuristics must NOT be
        # claimed as disclosed sensitive data — they would over-claim a triager can dispute
        self.assertEqual(sensitive_data.classify("total 4155551234567890 call 555-123-4567"), [])
        self.assertEqual(sensitive_data.classify('password = "hunter2please"'), [])
        self.assertEqual(sensitive_data.classify("<html><body>nothing secret here</body></html>"), [])

    def test_empty_input(self) -> None:
        self.assertEqual(sensitive_data.classify(""), [])
        self.assertEqual(sensitive_data.summarize(None), "")

    def test_openai_slug_is_not_a_key(self) -> None:
        # a kebab-case slug beginning sk- must NOT be claimed an OpenAI key (the shared source-scan
        # rule's hyphen-loose pattern false-matches these on an arbitrary body)
        self.assertEqual(sensitive_data.classify("/shop/sk-mens-running-shoes-2024-limited-edition"), [])
        # a real (continuous) OpenAI key IS still detected
        self.assertIn("an OpenAI API key", sensitive_data.classify("sk-proj-AbCdEf0123456789AbCdEf0123"))

    def test_role_account_email_is_not_claimed_as_pii(self) -> None:
        # the site's own public footer address is not exfiltrated PII
        self.assertEqual(sensitive_data.classify("questions? support@acme.com / sales@acme.com"), [])
        # a plausibly-personal address still counts
        self.assertIn("email address(es)", sensitive_data.classify("account owner jane.doe@acme.com"))


class ReportIntegrationTests(unittest.TestCase):
    def _render(self, class_id: str, read_data: str) -> str:
        out: list[str] = []
        finding = {"class_id": class_id, "rule_id": f"web.active.{class_id}",
                   "proof_evidence": {"request_line": "GET /api/me HTTP/1.1", "read_data": read_data}}
        report_lib._append_proof_evidence(out, finding)
        return "\n".join(out)

    def test_disclosure_class_names_exposed_data(self) -> None:
        # The capture names the data, while access and impact remain tied to
        # the actual request and any control rather than presumed universal access.
        body = self._render("disclosure", f"{{\"email\":\"victim@acme.com\",\"session\":\"{_JWT}\"}}")
        self.assertIn("Sensitive data in the response", body)
        self.assertIn("a JWT (session/bearer token)", body)   # the concrete data, named
        self.assertNotIn(_JWT, body)
        self.assertNotIn("[REDACTED_SECRET:[REDACTED_SECRET:", body)

    def test_cors_names_data_but_does_not_claim_completed_theft(self) -> None:
        # A CORS capture is SAME-SITE (curl-equivalent): the data must be NAMED as at-risk, but the
        # honest wording must NOT assert a completed cross-origin exfiltration ("Sensitive data exposed"
        # is reserved for a real disclosure) — a browser PoC is still required.
        body = self._render("cors", f"{{\"email\":\"victim@acme.com\",\"session\":\"{_JWT}\"}}")
        self.assertIn("a JWT (session/bearer token)", body)          # the concrete data, named
        self.assertIn("Sensitive data present in the captured response", body)
        self.assertNotIn("Sensitive data exposed", body)            # no completed-theft claim
        self.assertIn("browser-hosted PoC", body)                   # names the missing evidence
        self.assertNotIn(_JWT, body)
        self.assertNotIn("[REDACTED_SECRET:[REDACTED_SECRET:", body)

    def test_injection_class_does_not_claim_data_exfiltration(self) -> None:
        # for an XSS/SSTI/SQLi proof the body is the payload's own effect, NOT data exfiltrated to an
        # attacker — so the "Sensitive data exposed" claim must be suppressed even if a token appears
        body = self._render("xss", f"<script>x={_JWT}</script>")
        self.assertNotIn("Sensitive data exposed", body)


if __name__ == "__main__":
    unittest.main()
