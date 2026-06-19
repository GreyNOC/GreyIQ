from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as report_lib  # noqa: E402
from bughunter.bounty import list_profiles  # noqa: E402


class BountyReportTests(unittest.TestCase):
    def test_markdown_adds_bounty_submission_sections(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter",
            "version": "test",
            "generated_at": "2026-06-19 12:00 UTC",
            "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "vuln_class": None,
            "scope": "Example program - *.example.test",
            "authorized": True,
            "scanners_run": ["web", "live"],
            "run_live_requested": True,
            "risk": "high",
            "score": 0.8,
            "findings": [
                {
                    "ref": "F1",
                    "severity": "high",
                    "confidence": "high",
                    "class_id": "access-control",
                    "class_name": "Broken access control / IDOR",
                    "title": "Object can be read by another account",
                    "location": "https://example.test/api/orders/123",
                    "rule_id": "manual.idor",
                    "description": "A lower-privileged account can read another user's order.",
                    "snippet": "GET /api/orders/123",
                    "remediation": "Check object ownership server-side.",
                }
            ],
            "attack_plans": {
                "F1": {
                    "steps": ["Log in as account A.", "Replay the request with account B."],
                    "impact": "Cross-tenant order disclosure.",
                }
            },
            "manual_checklist": ["Replay as a lower-privileged account."],
            "recommended_tools": [],
            "brain": {"used": False},
        }

        markdown = report_lib.build_markdown(ctx)
        json_doc = report_lib.build_json(ctx)

        self.assertIn("## Bounty triage", markdown)
        self.assertIn("### Submission preflight", markdown)
        self.assertIn("**Submission readiness**", markdown)
        self.assertIn("### Retest after fix", markdown)
        self.assertEqual(json_doc["class_counts"]["Broken access control / IDOR"], 1)
        self.assertTrue(json_doc["run_live_requested"])
        self.assertIn("submission_checklist", json_doc)

    def test_profiles_expose_expanded_focus_classes(self) -> None:
        payload = list_profiles()
        classes = {item["id"] for item in payload["classes"]}
        web_profile = next(profile for profile in payload["profiles"] if profile["id"] == "web-app")

        self.assertTrue({"csrf", "cors", "redirect", "file-upload", "business-logic", "supply-chain"} <= classes)
        self.assertIn("business-logic", web_profile["classes"])


if __name__ == "__main__":
    unittest.main()
