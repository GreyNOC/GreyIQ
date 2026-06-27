"""Tests for BugHunter submission packaging + the hard-gated HackerOne submit."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import submission  # noqa: E402


def _ctx_and_finding(*, ref: str = "F1", severity: str = "high", cvss: dict | None = None) -> tuple[dict, dict]:
    finding = {
        "ref": ref,
        "title": "Reflected XSS in search",
        "severity": severity,
        "confidence": "high",
        "class_id": "xss",
        "class_name": "Cross-site scripting",
        "cwe": "CWE-79",
        "location": "https://app.example.com/search?q=",
        "rule_id": "web-xss-reflected",
    }
    plan = {"impact": "Run script in a victim session.", "steps": ["..."]}
    if cvss:
        plan["cvss"] = cvss
    ctx = {
        "tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "now",
        "target": "https://app.example.com", "scope": "*.example.com",
        "attack_plans": {ref: plan},
    }
    return ctx, finding


class BuildSubmissionTests(unittest.TestCase):
    def test_package_has_core_fields(self) -> None:
        ctx, finding = _ctx_and_finding()
        pkg = submission.build_submission(ctx, finding)
        self.assertIsNotNone(pkg)
        assert pkg is not None
        self.assertIn("Reflected XSS", pkg["title"])
        self.assertEqual(pkg["weakness"], "79")
        self.assertTrue(pkg["vulnerability_information"].strip())
        self.assertIn(pkg["severity_rating"], {"none", "low", "medium", "high", "critical"})

    def test_severity_rating_prefers_cvss(self) -> None:
        ctx, finding = _ctx_and_finding(severity="low", cvss={"base_severity": "Critical", "vector": "X", "base_score": 9.1})
        self.assertEqual(submission.severity_rating(finding, ctx["attack_plans"]["F1"]), "critical")

    def test_write_package_round_trip(self) -> None:
        ctx, finding = _ctx_and_finding()
        with tempfile.TemporaryDirectory() as tmp:
            written = submission.write_submission_package(ctx, finding, Path(tmp), "sub-01-xss")
            self.assertIsNotNone(written)
            assert written is not None
            self.assertTrue(Path(written["markdown_path"]).is_file())
            self.assertTrue(Path(written["json_path"]).is_file())


class SubmitGateTests(unittest.TestCase):
    """The HackerOne submit must never fire without an explicit confirm, a
    confirmed proof, and real credentials — these never touch the network."""

    def _pkg(self, proof: str = "confirmed") -> dict:
        return {
            "title": "t", "vulnerability_information": "body", "impact": "i",
            "severity_rating": "high", "proof_status": proof,
        }

    def test_refuses_without_confirm(self) -> None:
        with self.assertRaises(submission.SubmissionError):
            submission.submit_to_hackerone(self._pkg(), team_handle="t", api_username="u", api_token="k", confirm=False)

    def test_refuses_unconfirmed_proof(self) -> None:
        with self.assertRaises(submission.SubmissionError):
            submission.submit_to_hackerone(self._pkg("candidate"), team_handle="t", api_username="u", api_token="k", confirm=True)

    def test_refuses_missing_credentials(self) -> None:
        with self.assertRaises(submission.SubmissionError):
            submission.submit_to_hackerone(self._pkg(), team_handle="", api_username="", api_token="", confirm=True)


if __name__ == "__main__":
    unittest.main()
