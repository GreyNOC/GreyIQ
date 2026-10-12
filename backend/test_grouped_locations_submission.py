"""A grouped duplicate-lead finding must name every location it covers in its SUBMISSION body.

``bounty._group_duplicate_leads`` collapses near-identical leads into one representative carrying
``grouped_locations`` -- so the body's single "Asset / endpoint" row is the representative only.
``report.build_finding_markdown`` lists the rest; ``report_formats.render_finding`` did not, and
it is what writes every per-platform submission package AND (through
``submission.build_submission``) the HackerOne API payload's vulnerability_information. A report
that claims one affected URL where the engine found six understates impact and invites an
"informational" close. Regression.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as bounty_report  # noqa: E402
from bughunter import report_formats as bounty_formats  # noqa: E402
from bughunter import submission as bounty_submission  # noqa: E402
from bughunter.bounty import _group_duplicate_leads  # noqa: E402

LOCATIONS = [f"https://app.example.com/area{i}/config" for i in range(1, 7)]
CTX = {"tool": "GreyIQ BugHunter", "version": "0.0.0", "generated_at": "2026-01-01 00:00 UTC",
       "target": "https://app.example.com", "scope": "app.example.com", "attack_plans": {}}


def _grouped_finding() -> dict:
    """The representative the engine's own grouping produces for six identical leads."""
    leads = [{"class_id": "headers", "rule_id": "web.missing-header.csp", "title": "Missing CSP",
              "severity": "low", "class_name": "Headers", "cwe": "CWE-693", "location": loc,
              "description": "No Content-Security-Policy header.", "confidence": "medium"}
             for loc in LOCATIONS]
    representative = _group_duplicate_leads(leads)[0]
    representative["ref"] = "F1"
    return representative


class GroupedLocationsInSubmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = _grouped_finding()
        # Guard the premise: the engine really did collapse six leads into this one.
        self.assertEqual(self.finding["group_count"], len(LOCATIONS))

    def test_every_platform_body_lists_every_affected_location(self) -> None:
        for platform in ("hackerone", "yeswehack", "bugcrowd", "intigriti", "hackenproof"):
            with self.subTest(platform=platform):
                body = bounty_formats.render_finding(CTX, self.finding, platform)
                for loc in LOCATIONS:
                    self.assertIn(loc, body)

    def test_hackerone_api_payload_lists_every_affected_location(self) -> None:
        package = bounty_submission.build_submission(CTX, self.finding, "hackerone")
        self.assertIsNotNone(package)
        body = package["vulnerability_information"]
        for loc in LOCATIONS:
            self.assertIn(loc, body)
        # The routing field stays a SINGLE asset -- it is what the platform's Asset/endpoint
        # field takes; the extra locations belong in the body, not in that one value.
        self.assertEqual(package["location"], LOCATIONS[0])

    def test_submission_body_agrees_with_the_on_demand_report(self) -> None:
        # The same finding must not read differently depending on which surface rendered it.
        on_demand = bounty_report.build_finding_markdown(CTX, self.finding)
        submission_body = bounty_formats.render_finding(CTX, self.finding, "hackerone")
        for loc in LOCATIONS:
            self.assertIn(loc, on_demand)
            self.assertIn(loc, submission_body)

    def test_an_ungrouped_finding_gains_no_locations_section(self) -> None:
        lone = {"ref": "F1", "class_id": "headers", "rule_id": "web.missing-header.csp",
                "title": "Missing CSP", "severity": "low", "class_name": "Headers",
                "cwe": "CWE-693", "location": LOCATIONS[0], "description": "No CSP.",
                "confidence": "medium"}
        body = bounty_formats.render_finding(CTX, lone, "hackerone")
        self.assertNotIn("Affected locations", body)

    def test_a_long_group_is_bounded_with_an_honest_remainder(self) -> None:
        many = [f"https://app.example.com/p{i}" for i in range(40)]
        finding = dict(self.finding, grouped_locations=many, group_count=len(many))
        body = bounty_formats.render_finding(CTX, finding, "hackerone")
        self.assertIn("40 locations share this root cause", body)
        self.assertIn(many[24], body)
        self.assertNotIn(many[25], body)
        self.assertIn("(+15 more)", body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
