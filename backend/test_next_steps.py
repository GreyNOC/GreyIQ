"""Tests for the guided next-step planner (bughunter.next_steps).

Severity-resolution consistency: next_steps.build_next_steps must agree with the report/
H1 rating on the SAME finding (both route through report.resolve_severity), so a finding
whose raw scanner label disagrees with its plan's CVSS base_severity is ranked, grouped,
and counted by the CVSS-resolved severity everywhere — not just in the report.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import next_steps  # noqa: E402


def _finding(ref: str, raw_severity: str, *, confidence: str = "high", class_id: str = "ssrf") -> dict:
    return {"ref": ref, "severity": raw_severity, "confidence": confidence, "class_id": class_id,
            "class_name": class_id.upper(), "title": f"{class_id} finding {ref}", "location": "https://x/"}


class SeverityResolutionTests(unittest.TestCase):
    def test_submission_counts_use_cvss_resolved_severity_not_raw_label(self) -> None:
        # Raw label says 'medium'; the plan's CVSS says 'high' (the exact disagreement
        # test_severity_consistency.py pins for the report/H1 surfaces). next_steps'
        # submission-phase counts must agree -- not silently undercount it as medium.
        finding = _finding("F1", "medium")
        plan = {"cvss": {"base_score": 9.1, "base_severity": "high"}}
        ctx = {"findings": [finding], "attack_plans": {"F1": plan}, "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        submit_step = next((s for s in steps if s["phase"] == "Prepare submission"), None)
        self.assertIsNotNone(submit_step)
        self.assertEqual(submit_step["action"], "Write up and submit the high-impact finding(s) first")
        self.assertEqual(submit_step["ref"], "F1")  # the CVSS-high finding is the lead, not skipped

    def test_confirm_step_priority_uses_cvss_resolved_severity(self) -> None:
        finding = _finding("F1", "medium")
        plan = {"cvss": {"base_score": 9.1, "base_severity": "high"}}
        ctx = {"findings": [finding], "attack_plans": {"F1": plan}, "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        confirm_step = next(s for s in steps if s["phase"] == "Confirm findings" and s["ref"] == "F1")
        self.assertEqual(confirm_step["priority"], "high")  # not 'medium' -- the raw label

    def test_ranking_order_follows_cvss_resolved_severity(self) -> None:
        # F1's raw label (low) would normally rank BELOW F2 (medium), but F1's CVSS lifts
        # it to critical -- the confirm-step order must reflect the resolved severity.
        low_raw_critical_cvss = _finding("F1", "low")
        plain_medium = _finding("F2", "medium")
        plans = {"F1": {"cvss": {"base_score": 9.8, "base_severity": "critical"}}}
        ctx = {"findings": [low_raw_critical_cvss, plain_medium], "attack_plans": plans,
               "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        confirm_refs = [s["ref"] for s in steps if s["phase"] == "Confirm findings" and s["ref"]]
        self.assertEqual(confirm_refs[0], "F1")  # the CVSS-critical finding leads, despite the raw 'low' label

    def test_no_plan_falls_back_to_raw_severity(self) -> None:
        finding = _finding("F1", "medium")
        ctx = {"findings": [finding], "attack_plans": {}, "scanners_run": ["web"], "kind": "url"}
        steps = next_steps.build_next_steps(ctx)
        confirm_step = next(s for s in steps if s["phase"] == "Confirm findings" and s["ref"] == "F1")
        self.assertEqual(confirm_step["priority"], "medium")  # no CVSS override available -> raw label stands


if __name__ == "__main__":
    unittest.main()
