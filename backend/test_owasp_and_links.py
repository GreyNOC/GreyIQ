"""The OWASP row must survive a rebuilt report, and a reference link must lead where the report says.

Two defects on the same theme — a report that quietly contradicts itself or omits a field the platform
routes on.

**The OWASP field.** ``build_finding_report`` (the on-demand builder for a ledger/history/dashboard
finding) filled the CWE from the class but never the OWASP category, while SIX renderers read
``finding["owasp"]``: the hunt report's finding block and its summary table, and the HackerOne,
Bugcrowd and Intigriti submission bodies. So a report rebuilt from history silently dropped the OWASP
row the same finding had shown during its original hunt — on the report *and* on the filed submission.
The project's own test asserts CWE and OWASP must both be present for the other classification path;
this was the path that was exempt.

**The reference links.** Three classes linked a CWE that is not the CWE their own report declares, so a
triager clicking through landed on a different weakness: ``supply-chain`` declared CWE-1104/CWE-1395
and linked only CWE-1357; ``graphql`` declared CWE-639/CWE-770 and linked only CWE-200;
``cloud-exposure`` declared CWE-732/CWE-668 and linked only CWE-200.

Validated structurally rather than by fetching. This container's network policy denies owasp.org,
cwe.mitre.org and portswigger.net at CONNECT, and a structural check is the stronger one anyway: a
link that resolves but points at the wrong weakness is worse than one that 404s, because it looks
authoritative.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty, impact_model, report  # noqa: E402

API_SOURCE = (BACKEND_DIR / "greyiq_api.py").read_text(encoding="utf-8")

#: Every renderer that reads finding["owasp"]. If this count drops, the field matters less and this
#: suite should be re-read rather than silently guarding fewer places.
_OWASP_READERS = 6


def _linked_cwes(class_id: str) -> set[str]:
    refs = " ".join(impact_model.references_for_class(class_id))
    return set(re.findall(r"cwe\.mitre\.org/data/definitions/(\d+)\.html", refs))


def _declared_cwes(meta: dict) -> set[str]:
    return set(re.findall(r"CWE-(\d+)", str(meta.get("cwe") or "")))


class TheOwaspFieldReachesARebuiltReportTests(unittest.TestCase):
    def test_owasp_for_class_exists_and_mirrors_cwe_for_class(self) -> None:
        self.assertTrue(callable(getattr(bounty, "owasp_for_class", None)),
                        "owasp_for_class is gone, so the on-demand builder has no source for the field")
        # Same contract as its twin: a known class answers, an unknown one returns '' rather than raising.
        self.assertEqual(bounty.owasp_for_class("nope-not-a-class"), "")
        self.assertEqual(bounty.owasp_for_class(""), "")
        self.assertEqual(bounty.owasp_for_class(None), "")

    def test_every_class_with_a_cwe_also_answers_with_an_owasp_category(self) -> None:
        # The invariant the project already asserts for the other classification path.
        missing = [cls for cls, meta in bounty.VULN_CLASSES.items()
                   if meta.get("cwe") and not bounty.owasp_for_class(cls)]
        self.assertEqual(missing, [], f"classes with a CWE but no OWASP category: {missing}")

    def test_the_on_demand_builder_sets_the_field(self) -> None:
        self.assertIn("owasp_for_class", API_SOURCE,
                      "build_finding_report no longer derives the OWASP category")
        self.assertIn('"owasp": owasp', API_SOURCE,
                      "the finding dict build_finding_report assembles has no owasp key")
        # And it must be derived, not left to a client field — FindingReportRequest carries no owasp.
        self.assertNotIn("request.owasp", API_SOURCE)

    def test_the_renderers_that_read_the_field_are_still_there(self) -> None:
        # Anti-vacuity: the fix only matters because these read it.
        readers = 0
        for rel in ("bughunter/report.py", "bughunter/report_formats.py"):
            readers += (BACKEND_DIR / rel).read_text(encoding="utf-8").count("_linkify_owasp(")
        # One definition in report.py plus the call sites.
        self.assertGreaterEqual(readers, _OWASP_READERS,
                               f"only {readers} OWASP render sites found; expected at least "
                               f"{_OWASP_READERS} — re-check what this guard protects")

    def test_a_rebuilt_finding_renders_a_working_top_ten_link(self) -> None:
        for class_id in ("cors", "sqli", "ssrf", "crlf", "secrets", "xss"):
            with self.subTest(class_id=class_id):
                owasp = bounty.owasp_for_class(class_id)
                self.assertTrue(owasp, f"{class_id} has no OWASP category")
                linked = report._linkify_owasp(owasp)
                self.assertRegex(linked, r"^\[A\d\d:2021 .*\]\(https://owasp\.org/Top10/A\d\d_2021-.*\)$",
                                 f"{class_id} does not linkify to a Top-10 category page: {linked}")


class ReferenceLinksLeadWhereTheReportSaysTests(unittest.TestCase):
    def test_every_class_links_at_least_one_cwe_it_declares(self) -> None:
        mismatched = []
        for class_id, meta in bounty.VULN_CLASSES.items():
            declared, linked = _declared_cwes(meta), _linked_cwes(class_id)
            if declared and linked and not (declared & linked):
                mismatched.append((class_id, meta.get("cwe"), sorted(linked)))
        self.assertEqual(mismatched, [],
                         "these classes link a CWE they do not declare, so a triager clicking the "
                         f"reference lands on a different weakness: {mismatched}")

    def test_the_three_classes_that_were_wrong_now_lead_with_their_own_cwes(self) -> None:
        # Named explicitly, so a future edit that reverts one is caught by more than the sweep above.
        for class_id, expected in (("supply-chain", {"1104", "1395"}),
                                   ("graphql", {"639", "770"}),
                                   ("cloud-exposure", {"732", "668"})):
            with self.subTest(class_id=class_id):
                linked = _linked_cwes(class_id)
                self.assertTrue(expected <= linked,
                                f"{class_id} should link {sorted(expected)}; links {sorted(linked)}")

    def test_no_class_links_a_cwe_nobody_declares_as_its_only_reference(self) -> None:
        # A broader statement of the same rule: the FIRST CWE link should be a declared one, because
        # that is the one a reader follows.
        for class_id, meta in bounty.VULN_CLASSES.items():
            declared = _declared_cwes(meta)
            if not declared:
                continue
            ordered = re.findall(r"definitions/(\d+)\.html",
                                 " ".join(impact_model.references_for_class(class_id)))
            if ordered:
                with self.subTest(class_id=class_id):
                    self.assertIn(ordered[0], declared,
                                  f"{class_id}'s first CWE link ({ordered[0]}) is not one it declares "
                                  f"({sorted(declared)})")

    def test_every_owasp_url_matches_its_own_token(self) -> None:
        for token, url in report._OWASP_TOP10_URLS.items():
            with self.subTest(token=token):
                slug = token.split(":")[0]          # A01 … A10
                self.assertIn(f"/{slug}_2021-", url,
                              f"{token} points at {url}, whose slug is a different category")
                self.assertTrue(url.startswith("https://owasp.org/Top10/"))

    def test_every_owasp_token_in_use_has_a_url(self) -> None:
        used = set()
        for table in (bounty.VULN_CLASSES, bounty._CATEGORY_LABELS):
            for meta in table.values():
                match = re.match(r"\s*(A\d\d:2021)", str(meta.get("owasp") or ""))
                if match:
                    used.add(match.group(1))
        self.assertTrue(used, "no class declares an OWASP category — this guard would pass over nothing")
        missing = sorted(used - set(report._OWASP_TOP10_URLS))
        self.assertEqual(missing, [],
                         f"these categories are used but have no URL, so they link to the index: {missing}")

    def test_no_reference_url_is_malformed(self) -> None:
        # Cheap shape check: every reference must be an absolute https URL with no leftover
        # f-string brace, which is how a templated base gets shipped unrendered.
        for class_id in impact_model.IMPACT_MODEL:
            for url in impact_model.references_for_class(class_id):
                with self.subTest(class_id=class_id, url=url):
                    self.assertTrue(url.startswith("https://"), f"not absolute https: {url}")
                    self.assertNotIn("{", url, f"unrendered template in a reference: {url}")
                    self.assertNotIn(" ", url, f"whitespace in a reference: {url}")


if __name__ == "__main__":
    unittest.main()
