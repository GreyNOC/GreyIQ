from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.scan_service import run_code_scan  # noqa: E402


class SecretRuleRegressionTests(unittest.TestCase):
    def test_dotenv_rule_does_not_span_across_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env.example"
            path.write_text(
                "GREYIQ_CODE_SCAN_BASE_PATH=\n"
                "GREYIQ_SCAN_ALLOW_PRIVATE_URLS=false\n"
                "GREYIQ_WEB_ALLOWED_PORTS=80,443\n",
                encoding="utf-8",
            )
            result = run_code_scan(str(path), "path")

        self.assertTrue(result["ok"])
        self.assertEqual(
            [finding["rule_id"] for finding in result["findings"] if finding["rule_id"] == "secret.dotenv-committed"],
            [],
        )

    def test_dotenv_rule_still_flags_secret_like_values(self) -> None:
        raw_secret = "ABCDEF1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(f"PROD_API_TOKEN={raw_secret}\n", encoding="utf-8")
            result = run_code_scan(str(path), "path")

        self.assertTrue(result["ok"])
        finding = next(
            finding
            for finding in result["findings"]
            if finding["rule_id"] == "secret.dotenv-committed"
        )
        self.assertTrue(finding["redacted"])
        self.assertNotIn(raw_secret, finding["snippet"])
        self.assertIn("[REDACTED_SECRET", finding["snippet"])


class NewProviderTokenDetectionTests(unittest.TestCase):
    """The GitLab / npm / SendGrid / DigitalOcean tokens each have an unmistakable vendor prefix, so
    detection is HIGH-confidence with a near-zero false-positive rate — the raw material that the live
    issuer-read validators then confirm."""

    def _rule_ids(self, filename: str, text: str) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / filename
            path.write_text(text, encoding="utf-8")
            result = run_code_scan(str(path), "path")
        self.assertTrue(result["ok"])
        return {f["rule_id"] for f in result["findings"]}

    def test_each_provider_token_is_detected(self) -> None:
        cases = {
            "secret.gitlab-pat": 'const t = "glpat-' + "A1b2C3d4E5f6G7h8I9j0" + '";',
            "secret.npm-token": 'const t = "npm_' + "a" * 36 + '";',
            "secret.sendgrid-key": 'const k = "SG.' + "a" * 22 + "." + "b" * 43 + '";',
            "secret.digitalocean-token": 'const t = "dop_v1_' + "0123456789abcdef" * 4 + '";',
        }
        for rule_id, code in cases.items():
            self.assertIn(rule_id, self._rule_ids("config.js", code), rule_id)

    def test_near_miss_prefixes_do_not_fire(self) -> None:
        # too-short / wrong-shape lookalikes must NOT be detected (keeps the FP rate at zero)
        ids = self._rule_ids("config.js",
            'a="glpat-short"; b="npm_short"; c="SG.short.short"; d="dop_v1_nothex";')
        for rule_id in ("secret.gitlab-pat", "secret.npm-token", "secret.sendgrid-key", "secret.digitalocean-token"):
            self.assertNotIn(rule_id, ids, rule_id)


if __name__ == "__main__":
    unittest.main()
