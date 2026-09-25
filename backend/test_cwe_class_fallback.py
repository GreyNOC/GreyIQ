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


class CrlfClassTests(unittest.TestCase):
    """A confirmed CRLF response-header injection must be filed as header injection, not open redirect.

    The prover can CONFIRM this class (it captures the injected header on its own wire line against a
    no-CRLF control) but the class had no VULN_CLASSES entry, so _check_crlf hinted 'redirect' and the
    report went out as CWE-601 "URL Redirection to Untrusted Site", OWASP A01, with remediation telling
    the team to allowlist redirect targets — the wrong weakness and the wrong fix on a real finding.
    """

    def test_the_class_exists_with_the_right_weakness_and_fix(self) -> None:
        from bughunter import impact_model
        from bughunter.bounty import VULN_CLASSES, cwe_for_class

        self.assertIn("crlf", VULN_CLASSES)
        self.assertIn("113", cwe_for_class("crlf"))          # CWE-113, not CWE-601
        self.assertNotIn("601", cwe_for_class("crlf"))
        self.assertEqual(VULN_CLASSES["crlf"]["owasp"], "A03:2021 Injection")
        self.assertIn("response header", impact_model.remediation_for_class("crlf"))
        self.assertTrue(impact_model.references_for_class("crlf"))
        # Empty categories on purpose: the class only arrives via the check's explicit class hint, so it
        # cannot swallow unrelated 'disclosure' findings.
        self.assertEqual(VULN_CLASSES["crlf"]["categories"], set())

    def test_the_template_score_matches_what_the_prover_demonstrates(self) -> None:
        from bughunter import impact_model

        block = impact_model.cvss_for_class("crlf", confirmed=True)
        # Header injection proven, escalation not yet — the same 6.1 band as open redirect / reflected
        # XSS. An I:H vector here would score a marker header at 9.3 Critical.
        self.assertEqual(block["base_score"], 6.1)
        self.assertEqual(block["base_severity"], "Medium")

    def test_the_crlf_check_hints_the_crlf_class(self) -> None:
        import ast
        import re

        source = (BACKEND_DIR / "bughunter" / "active_verify_service.py").read_text(encoding="utf-8")
        match = re.search(r'_finding\(\s*"active\.crlf".*?\)', source, re.S)
        self.assertIsNotNone(match, "the CRLF check's _finding call moved")
        call = ast.parse(match.group(0).strip(), mode="eval").body
        # _finding(rule_id, title, severity, category, class_hint, ...)
        self.assertEqual(call.args[4].value, "crlf", "the CRLF check must hint its own class")
        self.assertEqual(call.args[3].value, "disclosure", "the scanner category must stay 'disclosure'")

    def test_a_legacy_redirect_classed_crlf_finding_still_reproduces(self) -> None:
        # A ledger finding recorded before CRLF had its own class carries class_id 'redirect' with a crlf
        # rule_id; it must keep producing CRLF reproduction steps rather than falling through.
        from bughunter.bounty import _generic_concrete_repro

        pe = {"request_line": "GET https://t/?next=%0d%0aX-Greyiq-Crlf:mark",
              "response_header": "X-Greyiq-Crlf: mark", "matched_value": "injected response header"}
        for class_id in ("crlf", "redirect"):
            with self.subTest(class_id=class_id):
                steps, _poc = _generic_concrete_repro({"rule_id": "active.crlf"}, class_id,
                                                      "https://t/", pe)
                self.assertTrue(any("response splitting" in s for s in steps))
