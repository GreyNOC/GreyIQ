"""On-demand reports (ledger/history findings) must carry the class's canonical CWE even when
the finding arrived without one — otherwise HackerOne receives no weakness and infers a wrong
one (it suggested CWE-284 for a CORS report we sent as CWE-16 / none). Regression for that."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter.bounty import cwe_for_class  # noqa: E402


class CweForClassTests(unittest.TestCase):
    def test_known_classes(self) -> None:
        self.assertEqual(cwe_for_class("cors"), "CWE-284")   # the H1-accepted CORS weakness
        self.assertEqual(cwe_for_class("xss"), "CWE-79")
        self.assertEqual(cwe_for_class("CORS"), "CWE-284")   # case-insensitive
        self.assertIn("CWE-284", cwe_for_class("access-control"))

    def test_unknown_class_is_empty_not_fabricated(self) -> None:
        self.assertEqual(cwe_for_class(""), "")
        self.assertEqual(cwe_for_class("not-a-class"), "")


class OnDemandReportCweTests(unittest.TestCase):
    def _pkg(self, *, class_id: str, cwe: str) -> dict:
        rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
        req = api.FindingReportRequest(
            title="CORS reflects attacker Origin with credentials", severity="high",
            class_name="CORS misconfiguration", class_id=class_id,
            location="https://api.example.com/user", cwe=cwe)
        return api.GreyIQRuntime.build_finding_report(rt, req).get("package") or {}

    def test_cors_without_cwe_gets_284(self) -> None:
        pkg = self._pkg(class_id="cors", cwe="")
        self.assertEqual(pkg.get("cwe"), "CWE-284")
        self.assertEqual(pkg.get("weakness"), "284")
        self.assertIn("CWE-284", pkg.get("vulnerability_information", ""))

    def test_explicit_client_cwe_is_preserved(self) -> None:
        # A deliberately-supplied CWE is never overridden by the class fallback.
        self.assertEqual(self._pkg(class_id="cors", cwe="CWE-999").get("weakness"), "999")

    def test_unknown_class_without_cwe_stays_empty(self) -> None:
        pkg = self._pkg(class_id="", cwe="")
        self.assertEqual(pkg.get("cwe"), "")


if __name__ == "__main__":
    unittest.main()
