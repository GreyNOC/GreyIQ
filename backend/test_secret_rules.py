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


if __name__ == "__main__":
    unittest.main()
