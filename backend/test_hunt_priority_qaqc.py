"""QA/QC regressions for endpoint-specific direct-hunt budget ordering."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402


class EndpointPriorityTests(unittest.TestCase):
    def test_route_priorities_are_not_flattened_across_targets(self) -> None:
        download = "https://app.example/download?file=report.pdf"
        login = "https://app.example/login?returnUrl=%2Fhome"
        plan = {
            "probe_priority": [
                {"endpoint": download, "classes": ["path-traversal", "crlf"]},
                {"endpoint": login, "classes": ["redirect", "jwt"]},
            ]
        }
        indexed = bounty._plan_priorities_by_endpoint(plan)

        download_priority = bounty._priority_for_active_target(download, indexed, ["cors"])
        login_priority = bounty._priority_for_active_target(login, indexed, ["cors"])

        self.assertEqual(download_priority[:2], ["path-traversal", "crlf"])
        self.assertEqual(login_priority[:2], ["redirect", "jwt"])
        self.assertNotIn("path-traversal", login_priority)
        self.assertIn("cors", download_priority)
        self.assertIn("cors", login_priority)

    def test_refinement_precedes_baseline_only_on_its_endpoint(self) -> None:
        first = "https://app.example/search?q=x"
        second = "https://app.example/download?file=x"
        baseline = {first: ["xss", "sqli"], second: ["path-traversal", "crlf"]}
        refinement = {first: ["nosqli", "xss"]}

        merged = bounty._merge_endpoint_priorities(baseline, refinement)

        self.assertEqual(merged[first], ["nosqli", "xss", "sqli"])
        self.assertEqual(merged[second], baseline[second])


if __name__ == "__main__":
    unittest.main()
