"""The severity word a finding carries must be IDENTICAL across every output surface.

Before ``resolve_severity`` was the single source of truth, the default report labelled a
finding by its raw scanner ``severity`` while the per-platform report and the HackerOne
``severity_rating`` preferred the modelled CVSS base severity — so the same finding could
read "Medium" in the report the operator pastes and "High" in the API submission beside it.

These tests pin a finding whose raw severity (medium) DISAGREES with its plan's CVSS base
severity (high) and assert every surface now reports the CVSS-derived "high".
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as R  # noqa: E402
from bughunter import report_formats  # noqa: E402
from bughunter import submission  # noqa: E402


def _finding_and_ctx():
    finding = {
        "ref": "F1", "severity": "medium",  # raw scanner label — deliberately lower than the CVSS
        "title": "Server-side request forgery", "class_name": "SSRF", "class_id": "ssrf",
        "category": "ssrf", "confidence": "confirmed", "location": "https://app.example.com/fetch?url=",
        "rule_id": "active.ssrf", "description": "Confirmed blind SSRF via the url param.",
        "proof_of_impact": {"status": "confirmed"},
    }
    plan = {"cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                     "base_score": 9.1, "base_severity": "high", "estimated": True}}
    ctx = {"tool": "GreyIQ", "version": "test", "generated_at": "now",
           "target": "https://app.example.com", "scope": "example.com",
           "findings": [finding], "attack_plans": {"F1": plan}}
    return finding, plan, ctx


class SeverityConsistencyTests(unittest.TestCase):
    def test_resolver_prefers_cvss_over_raw_label(self) -> None:
        finding, plan, _ = _finding_and_ctx()
        self.assertEqual(R.resolve_severity(finding, plan), "high")
        # with no plan it falls back to the raw label
        self.assertEqual(R.resolve_severity(finding, None), "medium")

    def test_all_surfaces_agree_on_high(self) -> None:
        finding, plan, ctx = _finding_and_ctx()
        self.assertEqual(report_formats._base_severity(finding, plan), "high")
        self.assertEqual(submission.severity_rating(finding, plan), "high")
        # the per-platform display label is derived from the same base severity
        self.assertIn("high", report_formats.platform_severity("hackerone", finding, plan).lower())

    def test_default_report_table_shows_the_cvss_severity(self) -> None:
        _, _, ctx = _finding_and_ctx()
        md = R.build_markdown(ctx).lower()
        # the findings table / detail must reflect High, never the raw Medium
        self.assertIn("high", md)
        # the single-finding report agrees too
        single = R.build_finding_markdown(ctx, ctx["findings"][0]).lower()
        self.assertIn("high", single.split("\n")[0])  # the H1 title line carries the severity

    def test_submission_title_prefix_uses_resolved_severity(self) -> None:
        finding, _, ctx = _finding_and_ctx()
        pkg = submission.build_submission(ctx, finding, "hackerone")
        self.assertIsNotNone(pkg)
        self.assertTrue(pkg["title"].startswith("[High]"), pkg["title"])
        self.assertEqual(pkg["severity_rating"], "high")


if __name__ == "__main__":
    unittest.main()
