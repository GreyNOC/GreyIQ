"""Tests for the known-CVE / outdated-component service — all offline (no network).

Covers version fingerprinting (src filenames + banners, with the jquery-ui false-match
guard), the version comparator's numeric ordering, CVE matching by fixed-in boundary, the
candidate (never "confirmed") finding/plan shape, and the fail-closed scope gate.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import cve_service as cve  # noqa: E402


class VersionMathTests(unittest.TestCase):
    def test_numeric_not_lexical_ordering(self) -> None:
        self.assertTrue(cve._ver_lt("3.9.0", "3.10.0"))      # 9 < 10 numerically
        self.assertFalse(cve._ver_lt("3.10.0", "3.9.0"))
        self.assertTrue(cve._ver_lt("1.8.0", "3.5.0"))
        self.assertFalse(cve._ver_lt("3.5.0", "3.5.0"))      # equal is not lower
        self.assertTrue(cve._ver_lt("3.4", "3.4.1"))          # missing patch -> 3.4.0 < 3.4.1


class DetectComponentsTests(unittest.TestCase):
    def test_src_filename_version(self) -> None:
        body = '<script src="/static/js/jquery-3.4.1.min.js"></script>'
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("jquery"), "3.4.1")

    def test_jquery_ui_and_migrate_do_not_register_as_core_jquery(self) -> None:
        body = ('<script src="/js/jquery-ui-1.12.1.min.js"></script>'
                '<script src="/js/jquery-migrate-3.0.0.min.js"></script>'
                '<script src="/js/jquery.validate-1.19.0.js"></script>')
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertNotIn("jquery", comps)  # none of these are jQuery core

    def test_banner_version(self) -> None:
        body = "/*! jQuery v3.3.1 | (c) JS Foundation */ ;(function(){})();"
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("jquery"), "3.3.1")

    def test_dedup_keeps_lowest_version(self) -> None:
        body = ('<script src="/a/jquery-3.4.1.min.js"></script>'
                '<script src="/b/jquery-1.8.0.min.js"></script>')
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("jquery"), "1.8.0")  # report the most-vulnerable instance

    def test_multiple_libraries(self) -> None:
        body = ('<script src="/lib/lodash-4.17.4.min.js"></script>'
                '<script src="/lib/bootstrap-3.3.7.min.js"></script>')
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("lodash"), "4.17.4")
        self.assertEqual(comps.get("bootstrap"), "3.3.7")


class MatchCvesTests(unittest.TestCase):
    def test_boundary_excludes_fixed_version(self) -> None:
        # jQuery 3.4.1 is < 3.5.0 (CVE-2020-11023) but >= 3.4.0 (CVE-2019-11358 fixed there).
        ids = {c["cve"] for c in cve.match_cves("jquery", "3.4.1")}
        self.assertIn("CVE-2020-11023", ids)
        self.assertNotIn("CVE-2019-11358", ids)

    def test_old_version_matches_all(self) -> None:
        ids = {c["cve"] for c in cve.match_cves("jquery", "1.8.0")}
        self.assertEqual(len(ids), len(cve._KNOWN_CVES["jquery"]))

    def test_up_to_date_matches_nothing(self) -> None:
        self.assertEqual(cve.match_cves("jquery", "3.5.1"), [])
        self.assertEqual(cve.match_cves("lodash", "4.17.21"), [])

    def test_results_sorted_by_score_desc(self) -> None:
        scores = [c["base_score"] for c in cve.match_cves("lodash", "4.0.0")]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertGreaterEqual(scores[0], 9.0)  # CVE-2019-10744 critical heads the list


class FindingShapeTests(unittest.TestCase):
    def _finding(self):
        comp = {"product": "lodash", "version": "4.17.4", "evidence": "/lib/lodash-4.17.4.min.js"}
        cves = cve.match_cves("lodash", "4.17.4")
        return cve._build_finding(comp, cves, "https://app.example.com/"), cves

    def test_finding_is_candidate_grade_not_confirmed(self) -> None:
        finding, cves = self._finding()
        self.assertEqual(finding["confidence"], "medium")
        self.assertEqual(finding["class_id"], "vulnerable-component")
        self.assertEqual(finding["severity"], cves[0]["severity"])  # headline = highest score
        self.assertIn("A06:2021", finding["owasp"])
        # every matched CVE gets an NVD reference
        for c in cves:
            self.assertTrue(any(c["cve"] in r for r in finding["references"]))

    def test_plan_proof_is_candidate_with_obligation(self) -> None:
        finding, cves = self._finding()
        plan = cve.build_plan(finding)
        poi = plan["proof_of_impact"]
        self.assertEqual(poi["status"], "candidate")
        self.assertIn("proof_obligation", poi)
        # the plan CVSS mirrors the headline CVE so resolve_severity stays consistent
        self.assertEqual(plan["cvss"]["base_severity"], cves[0]["severity"])
        self.assertEqual(plan["cvss"]["vector"], cves[0]["vector"])

    def test_no_target_or_user_data_in_snippet(self) -> None:
        finding, _ = self._finding()
        # the snippet is OUR fingerprint of a public library version, never scraped page data
        self.assertIn("Lodash 4.17.4", finding["snippet"])


class ScopeGateTests(unittest.TestCase):
    def test_scan_is_fail_closed_without_scope(self) -> None:
        # empty scope => host_in_active_scope is False => refuse BEFORE any fetch (no network)
        res = cve.scan_known_cves("https://example.com/", scope="")
        self.assertFalse(res["ok"])
        self.assertIn("scope", res["error"].lower())

    def test_missing_host_rejected(self) -> None:
        res = cve.scan_known_cves("", scope="example.com")
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
