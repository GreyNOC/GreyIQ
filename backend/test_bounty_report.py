from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import next_steps as next_steps_lib  # noqa: E402
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

    def test_modern_vuln_classes_present_and_well_formed(self) -> None:
        payload = list_profiles()
        classes = {item["id"]: item["name"] for item in payload["classes"]}
        modern = {"ssti", "xxe", "nosqli", "jwt", "graphql", "prototype-pollution",
                  "race-condition", "request-smuggling", "subdomain-takeover", "cloud-exposure"}
        self.assertTrue(modern <= set(classes), f"missing: {modern - set(classes)}")
        # Every modern class carries a CWE and a non-trivial checklist (3 steps).
        from bughunter.bounty import VULN_CLASSES
        for cid in modern:
            meta = VULN_CLASSES[cid]
            self.assertTrue(meta["cwe"], f"{cid} missing CWE")
            self.assertGreaterEqual(len(meta["checklist"]), 3, f"{cid} thin checklist")
        web = next(p for p in payload["profiles"] if p["id"] == "web-app")
        self.assertTrue({"ssti", "jwt", "graphql", "request-smuggling"} <= set(web["classes"]))

    def test_class_value_floats_high_value_class_within_severity_band(self) -> None:
        ctx = {
            "kind": "url", "scanners_run": ["web"], "profile": {"id": "web-app"},
            "vuln_class": None, "manual_checklist": [], "recommended_tools": [], "attack_plans": {},
            "findings": [
                {"ref": "Fheaders", "severity": "high", "confidence": "high", "class_id": "headers", "title": "weak headers"},
                {"ref": "Fssti", "severity": "high", "confidence": "high", "class_id": "ssti", "title": "template injection"},
            ],
        }
        steps = next_steps_lib.build_next_steps(ctx)
        confirms = [s["ref"] for s in steps if s["phase"] == "Confirm findings"]
        # Same severity + confidence → the higher-value class (SSTI) is acted on first.
        self.assertLess(confirms.index("Fssti"), confirms.index("Fheaders"))

    def test_guided_next_steps_render_in_markdown_and_json(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter", "version": "t", "generated_at": "now",
            "target": "https://example.test", "kind": "url",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "vuln_class": None, "scope": "acme", "authorized": True,
            "scanners_run": ["web"], "run_live_requested": False, "risk": "high", "score": 0.8,
            "findings": [
                {"ref": "F1", "severity": "high", "confidence": "high", "class_id": "access-control",
                 "class_name": "Broken access control / IDOR", "title": "IDOR", "location": "/api/orders/1"},
                {"ref": "F2", "severity": "low", "confidence": "medium", "class_id": "disclosure",
                 "class_name": "Information disclosure", "title": "Stack trace", "location": "/err"},
            ],
            "attack_plans": {"F1": {"steps": ["Locate the issue at /api/orders/1.", "Replay as account B."]}},
            "manual_checklist": ["Replay as a lower-privileged account."],
            "recommended_tools": [{"name": "Burp Suite", "url": "x", "maps_to": ["access-control"], "description": "p"}],
            "brain": {"used": False},
        }
        ctx["next_steps"] = next_steps_lib.build_next_steps(ctx, ["Probe /api/orders with account B."])
        ctx["coverage"] = next_steps_lib.coverage_summary(ctx)

        markdown = report_lib.build_markdown(ctx)
        json_doc = report_lib.build_json(ctx)

        self.assertIn("## Guided next steps", markdown)
        self.assertIn("### Coverage & gaps", markdown)
        self.assertIn("Confirm F1", markdown)
        self.assertTrue(json_doc["next_steps"])
        # Steps are numbered 1..N with no gaps, highest-impact confirm before submission.
        orders = [s["order"] for s in json_doc["next_steps"]]
        self.assertEqual(orders, list(range(1, len(orders) + 1)))
        phases = [s["phase"] for s in json_doc["next_steps"]]
        self.assertLess(phases.index("Confirm findings"), phases.index("Prepare submission"))

    def test_next_steps_high_confidence_medium_outranks_low_confidence_high(self) -> None:
        ctx = {
            "kind": "path", "scanners_run": ["code"], "profile": {"id": "source-code"},
            "vuln_class": None, "manual_checklist": [], "recommended_tools": [], "attack_plans": {},
            "findings": [
                {"ref": "Fhigh", "severity": "high", "confidence": "low", "class_id": "rce", "title": "maybe-rce"},
                {"ref": "Fmed", "severity": "medium", "confidence": "high", "class_id": "secrets", "title": "live-key"},
            ],
        }
        steps = next_steps_lib.build_next_steps(ctx)
        confirms = [s for s in steps if s["phase"] == "Confirm findings"]
        # Severity still dominates: the high (even low-confidence) confirms before the medium.
        self.assertEqual(confirms[0]["ref"], "Fhigh")
        # But the medium with a live, high-confidence secret is not buried — it has its own step.
        self.assertIn("Fmed", [s["ref"] for s in confirms])

    def test_next_steps_focus_unmatched_leads_with_manual_hunt(self) -> None:
        ctx = {
            "kind": "url", "scanners_run": ["web"], "profile": {"id": "web-app"},
            "vuln_class": {"id": "ssrf", "name": "Server-side request forgery (SSRF)"},
            "focus_unmatched": True, "other_findings_count": 3,
            "findings": [], "manual_checklist": [], "recommended_tools": [], "attack_plans": {},
        }
        steps = next_steps_lib.build_next_steps(ctx)
        hunt = next(s for s in steps if s["phase"] == "Hunt by hand")
        self.assertIn("SSRF", hunt["action"])
        self.assertIn("3 finding(s)", hunt["detail"])

    def test_coverage_flags_missing_dynamic_pass(self) -> None:
        cov = next_steps_lib.coverage_summary({"kind": "url", "scanners_run": ["web"]})
        self.assertTrue(any("dynamic" in g.lower() for g in cov["gaps"]))
        self.assertTrue(any("Passive web review" in c for c in cov["covered"]))


if __name__ == "__main__":
    unittest.main()
