"""Cross-component contracts for the web UI and the local API.

These checks cover literal API calls in the renderer. Dynamic URL construction and
runtime response shapes still need their own focused tests.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
BACKEND = (ROOT / "backend" / "greyiq_api.py").read_text(encoding="utf-8")


class AppWiringTests(unittest.TestCase):
    def test_literal_frontend_api_paths_exist_in_backend(self) -> None:
        # A missing route leaves a UI action wired to a 404. Include quoted and
        # template-literal paths; dynamic query strings are intentionally ignored.
        frontend_paths = set(
            re.findall(r"\bapiFetch\(\s*['\"`](/api/[A-Za-z0-9_/-]+)", FRONTEND)
        )
        backend_paths = set(
            re.findall(r"\bpath\s*==\s*['\"](/api/[A-Za-z0-9_/-]+)['\"]", BACKEND)
        )

        self.assertIn("/api/status", frontend_paths)
        self.assertIn("/api/bounty/campaign", frontend_paths)
        self.assertFalse(
            frontend_paths - backend_paths,
            f"Frontend API paths have no backend route: {sorted(frontend_paths - backend_paths)}",
        )


if __name__ == "__main__":
    unittest.main()
