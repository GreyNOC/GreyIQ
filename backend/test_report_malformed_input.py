"""Tests for report.py's resilience to malformed finding shapes -- had no dedicated
coverage. _jwt_replay_value crashed (AttributeError) on a non-dict jwt_exposure before
this; _proof_of_impact_detail's non-dict proof handling was already safe (pinned here).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as R  # noqa: E402


class JwtReplayValueMalformedInputTests(unittest.TestCase):
    def test_non_dict_jwt_exposure_does_not_crash(self) -> None:
        # Was an AttributeError ('str' object has no attribute 'get') before the fix --
        # a corrupted run cache or unexpected upstream shape must degrade to None, not
        # crash the whole report render.
        self.assertIsNone(R._jwt_replay_value({"jwt_exposure": "not-a-dict-string"}))
        self.assertIsNone(R._jwt_replay_value({"jwt_exposure": ["a", "list"]}))
        self.assertIsNone(R._jwt_replay_value({"jwt_exposure": 42}))

    def test_no_jwt_exposure_key_at_all_is_none(self) -> None:
        self.assertIsNone(R._jwt_replay_value({}))

    def test_dict_jwt_exposure_with_real_value_is_honored(self) -> None:
        self.assertTrue(R._jwt_replay_value({"jwt_exposure": {"replay_authenticated": True}}))
        self.assertFalse(R._jwt_replay_value({"jwt_exposure": {"replay_authenticated": False}}))

    def test_top_level_replay_authenticated_takes_precedence(self) -> None:
        self.assertTrue(R._jwt_replay_value({"replay_authenticated": True, "jwt_exposure": {"replay_authenticated": False}}))

    def test_non_bool_value_is_none(self) -> None:
        self.assertIsNone(R._jwt_replay_value({"jwt_exposure": {"replay_authenticated": "yes"}}))


class ReportableFindingsMalformedInputTests(unittest.TestCase):
    def test_jwt_credential_finding_with_malformed_jwt_exposure_does_not_crash(self) -> None:
        # rule_id IS in _JWT_CREDENTIAL_RULE_IDS, so _jwt_replay_value is genuinely
        # reached for this finding -- the real crash path the QAQC coverage gap named.
        findings = [{"rule_id": "secret.jwt", "jwt_exposure": "not-a-dict-string"}]
        out = R._reportable_findings(findings)
        self.assertEqual(out, [])  # unconfirmed (non-True replay) -> dropped, not crashed

    def test_jwt_credential_finding_with_confirmed_replay_is_kept(self) -> None:
        findings = [{"rule_id": "secret.jwt", "jwt_exposure": {"replay_authenticated": True}}]
        self.assertEqual(R._reportable_findings(findings), findings)

    def test_non_jwt_findings_pass_through_unconditionally(self) -> None:
        findings = [{"rule_id": "web.missing-header.csp"}]
        self.assertEqual(R._reportable_findings(findings), findings)


class ProofOfImpactDetailMalformedInputTests(unittest.TestCase):
    """_proof_of_impact_detail's non-dict-proof handling was ALREADY safe -- pinning it
    so a future change can't silently reintroduce a crash here."""

    def test_string_proof_does_not_crash(self) -> None:
        finding = {"ref": "F1", "proof_of_impact": "just a narrative string, not a dict"}
        detail = R._proof_of_impact_detail(finding, {})
        self.assertIn(detail["status"], ("missing", "candidate"))

    def test_list_proof_does_not_crash(self) -> None:
        finding = {"ref": "F1", "proof_of_impact": ["not", "a", "dict"]}
        detail = R._proof_of_impact_detail(finding, {})
        self.assertIn(detail["status"], ("missing", "candidate"))

    def test_none_proof_is_missing(self) -> None:
        detail = R._proof_of_impact_detail({"ref": "F1"}, {})
        self.assertEqual(detail["status"], "missing")


class FenceAndCodeAdversarialInputTests(unittest.TestCase):
    """_fence/_code must neutralize Markdown-breaking content from scanned target
    bodies or LLM output (embedded backtick runs, pipes, newlines) -- no dedicated
    coverage before this."""

    def test_fence_longer_than_any_embedded_backtick_run(self) -> None:
        text = "before ```` four backticks ``` three"
        fence = R._fence(text)
        self.assertEqual(fence, "`" * 5)  # longest run (4) + 1
        # the fence itself must not appear verbatim inside the text (else it still breaks out)
        self.assertNotIn(fence, text)

    def test_fence_with_no_backticks_is_the_minimum(self) -> None:
        self.assertEqual(R._fence("plain text"), "```")

    def test_fence_handles_none_and_empty(self) -> None:
        self.assertEqual(R._fence(""), "```")

    def test_code_neutralizes_pipes_and_newlines_for_table_cells(self) -> None:
        value = "a|b\nc|d"
        out = R._code(value)
        self.assertNotIn("\n", out)
        self.assertIn("\\|", out)

    def test_code_pads_when_value_starts_or_ends_with_backtick(self) -> None:
        out = R._code("`leading")
        self.assertTrue(out.startswith("`` `leading"))
        out2 = R._code("trailing`")
        self.assertTrue(out2.endswith("trailing` ``"))

    def test_code_ticks_exceed_embedded_backtick_run(self) -> None:
        value = "x ``` y"
        out = R._code(value)
        inner = out.strip("` ")
        # the surrounding tick run must be longer than the longest embedded run
        leading_ticks = len(out) - len(out.lstrip("`"))
        self.assertGreater(leading_ticks, 3)
        self.assertIn("y", inner)

    def test_code_handles_none(self) -> None:
        self.assertEqual(R._code(None), "``")


class LinkifyAdversarialInputTests(unittest.TestCase):
    def test_linkify_cwe_handles_compound_tokens(self) -> None:
        out = R._linkify_cwe("CWE-639 / CWE-284")
        self.assertIn("[CWE-639](https://cwe.mitre.org/data/definitions/639.html)", out)
        self.assertIn("[CWE-284](https://cwe.mitre.org/data/definitions/284.html)", out)

    def test_linkify_cwe_no_match_is_passthrough(self) -> None:
        self.assertEqual(R._linkify_cwe("no token here"), "no token here")

    def test_linkify_cwe_handles_none(self) -> None:
        self.assertEqual(R._linkify_cwe(None), "")

    def test_linkify_owasp_known_prefix(self) -> None:
        out = R._linkify_owasp("A03:2021 Injection")
        self.assertTrue(out.startswith("[A03:2021 Injection]("))
        self.assertIn("A03_2021-Injection", out)

    def test_linkify_owasp_unknown_prefix_falls_back_to_index(self) -> None:
        out = R._linkify_owasp("A99:2021 Made Up")
        self.assertIn("https://owasp.org/Top10/", out)

    def test_linkify_owasp_no_match_is_passthrough(self) -> None:
        self.assertEqual(R._linkify_owasp("just text"), "just text")

    def test_linkify_owasp_handles_none(self) -> None:
        self.assertEqual(R._linkify_owasp(None), "")


class BuildJsonDroppedFindingsTests(unittest.TestCase):
    """build_json's severity_counts/class_counts/finding_count must reflect only the
    REPORTABLE findings (post _reportable_findings filtering) -- a dropped, unconfirmed
    JWT-credential finding must not inflate the counts or leak into the sidecar."""

    def _ctx(self, findings: list[dict]) -> dict:
        return {
            "tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "now",
            "target": "https://app.example.com", "scope": "*.example.com",
            "authorized": True, "scanners_run": [], "risk": "low", "score": 1,
            "findings": findings, "attack_plans": {},
        }

    def test_dropped_jwt_finding_is_excluded_from_counts_and_findings(self) -> None:
        kept = {"ref": "F1", "rule_id": "web.missing-header.csp", "severity": "low"}
        dropped = {"ref": "F2", "rule_id": "secret.jwt", "severity": "critical",
                   "jwt_exposure": {"replay_authenticated": False}}
        ctx = self._ctx([kept, dropped])
        doc = R.build_json(ctx)
        self.assertEqual(doc["finding_count"], 1)
        self.assertEqual([f["ref"] for f in doc["findings"]], ["F1"])
        self.assertEqual(doc["severity_counts"]["critical"], 0)  # dropped finding's severity must not count
        self.assertNotIn("F2", doc["proof_of_impact"])

    def test_confirmed_jwt_finding_is_kept_and_counted(self) -> None:
        confirmed = {"ref": "F1", "rule_id": "secret.jwt", "severity": "critical",
                     "jwt_exposure": {"replay_authenticated": True}}
        ctx = self._ctx([confirmed])
        doc = R.build_json(ctx)
        self.assertEqual(doc["finding_count"], 1)
        self.assertEqual(doc["severity_counts"]["critical"], 1)

    def test_all_findings_dropped_yields_zero_counts_not_a_crash(self) -> None:
        dropped = {"ref": "F1", "rule_id": "secret.jwt", "severity": "high",
                   "jwt_exposure": "not-a-dict-string"}
        doc = R.build_json(self._ctx([dropped]))
        self.assertEqual(doc["finding_count"], 0)
        self.assertEqual(doc["findings"], [])
        self.assertEqual(sum(doc["severity_counts"].values()), 0)


if __name__ == "__main__":
    unittest.main()
