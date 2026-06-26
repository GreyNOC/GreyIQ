from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as report_lib  # noqa: E402
from bughunter.code_scanner.jwt_exposure import classify_jwt_exposure  # noqa: E402
from bughunter.scan_service import run_code_scan  # noqa: E402


def _b64url(value: dict[str, object] | bytes) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8") if isinstance(value, dict) else value
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jwt(payload: dict[str, object], header: dict[str, object] | None = None) -> str:
    return ".".join(
        [
            _b64url(header or {"alg": "RS256", "typ": "JWT"}),
            _b64url(payload),
            _b64url(b"signature-signature"),
        ]
    )


class JwtExposureTests(unittest.TestCase):
    def test_infomaniak_oauth_return_token_is_informational_not_reported(self) -> None:
        token = _jwt(
            {
                "iss": "https://login.infomaniak.com",
                "aud": "infomaniak-login",
                "u": (
                    "https://manager.infomaniak.com/oauth/authorize?"
                    "client_id=client&response_type=code&scope="
                    "user_password%20user_email%20recovery%20private%20crypt_key"
                ),
            }
        )

        classification = classify_jwt_exposure(token)
        self.assertIsNotNone(classification)
        assert classification is not None
        self.assertIs(classification.finding, False)
        self.assertEqual(classification.severity, "info")
        self.assertEqual(classification.role, "flow_token")
        self.assertFalse(classification.secret_hits)
        self.assertIn("user_password", classification.scope_names)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "login.js"
            path.write_text(f"window.GET_PARAMS = {{ r: '{token}' }};\n", encoding="utf-8")
            result = run_code_scan(str(path), "path")

        self.assertTrue(result["ok"])
        self.assertEqual(
            [finding["rule_id"] for finding in result["findings"] if "jwt" in finding["rule_id"]],
            [],
        )

        markdown = report_lib.build_markdown(
            {
                "tool": "GreyIQ BugHunter",
                "findings": [
                    {
                        "ref": "F1",
                        "rule_id": "secret.jwt",
                        "title": "JWT in source",
                        "severity": "medium",
                        "confidence": "medium",
                        "category": "secret",
                        "impact": "attacker could hijack the session and authenticate as that user",
                    }
                ],
                "attack_plans": {
                    "F1": {"impact": "attacker could hijack the session and authenticate as that user"}
                },
                "profile": {},
                "brain": {},
            }
        )
        self.assertNotIn("hijack the session", markdown)
        self.assertNotIn("JWT in source", markdown)

    def test_identity_token_needs_confirmation_until_replay_is_confirmed(self) -> None:
        token = _jwt({"sub": "user-123", "exp": 2000000000})

        untested = classify_jwt_exposure(token)
        self.assertIsNotNone(untested)
        assert untested is not None
        self.assertEqual(untested.finding, "needs_confirmation")
        self.assertEqual(untested.severity, "info")
        self.assertEqual(untested.impact, "")

        confirmed = classify_jwt_exposure(token, replay_authenticated=True)
        self.assertIsNotNone(confirmed)
        assert confirmed is not None
        self.assertIs(confirmed.finding, True)
        self.assertEqual(confirmed.severity, "high")
        self.assertEqual(confirmed.impact, "Session takeover confirmed by unauthenticated replay.")

    def test_scope_names_are_excluded_from_secret_value_scan(self) -> None:
        token = _jwt(
            {
                "iss": "issuer",
                "aud": "client",
                "u": "https://example.test/cb?scope=user_password%20user_email%20xoxb-1234567890",
            }
        )

        classification = classify_jwt_exposure(token)
        self.assertIsNotNone(classification)
        assert classification is not None
        self.assertIs(classification.finding, False)
        self.assertFalse(classification.secret_hits)
        self.assertIn("user_email", classification.scope_names)

    def test_real_secret_inside_jwt_claim_still_reports_high(self) -> None:
        aws_key = "AKIA" + "1234567890ABCDEF"
        token = _jwt({"iss": "issuer", "aud": "client", "note": aws_key})

        classification = classify_jwt_exposure(token)
        self.assertIsNotNone(classification)
        assert classification is not None
        self.assertIs(classification.finding, True)
        self.assertEqual(classification.severity, "high")
        self.assertEqual(classification.cwe, "CWE-200")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token.js"
            path.write_text(f"const token = '{token}';\n", encoding="utf-8")
            result = run_code_scan(str(path), "path")

        self.assertTrue(result["ok"])
        jwt_findings = [finding for finding in result["findings"] if finding["rule_id"] == "secret.jwt.embedded-secret"]
        self.assertEqual(len(jwt_findings), 1)
        self.assertEqual(jwt_findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
