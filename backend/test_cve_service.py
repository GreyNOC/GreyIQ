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

    def test_jquery_ui_detected_distinctly_from_core(self) -> None:
        body = ('<script src="/js/jquery-3.6.0.min.js"></script>'
                '<script src="/js/jquery-ui-1.12.1.min.js"></script>')
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("jquery"), "3.6.0")        # core
        self.assertEqual(comps.get("jquery-ui"), "1.12.1")    # separate product

    def test_new_libraries_detected(self) -> None:
        body = ('<script src="/v/axios-0.20.0.min.js"></script>'
                '<script src="/v/underscore-1.10.2.min.js"></script>'
                '<script src="/v/mustache-2.1.0.min.js"></script>')
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("axios"), "0.20.0")
        self.assertEqual(comps.get("underscore"), "1.10.2")
        self.assertEqual(comps.get("mustache"), "2.1.0")

    def test_prismjs_and_marked_detected(self) -> None:
        body = ('<script src="/js/prism-1.25.0.min.js"></script>'
                '<script src="/js/marked-4.0.0.min.js"></script>')
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("prismjs"), "1.25.0")
        self.assertEqual(comps.get("marked"), "4.0.0")

    def test_prism_detected_from_banner(self) -> None:
        # Prism is often served version-less under a CDN path; its "/* PrismJS 1.26.0" banner IDs it.
        comps = {c["product"]: c["version"]
                 for c in cve.detect_components("/* PrismJS 1.26.0\nhttps://prismjs.com/download.html */")}
        self.assertEqual(comps.get("prismjs"), "1.26.0")

    def test_wordpress_from_meta_generator(self) -> None:
        body = '<head><meta name="generator" content="WordPress 5.8.1" /></head>'
        comps = {c["product"]: c["version"] for c in cve.detect_components(body)}
        self.assertEqual(comps.get("wordpress"), "5.8.1")
        self.assertTrue(cve.match_cves("wordpress", "5.8.1"))   # < 5.8.3 -> CVEs apply

    def test_wordpress_from_x_powered_by_header(self) -> None:
        comps = {c["product"]: c["version"]
                 for c in cve.detect_components("", {"X-Powered-By": "WordPress/5.7"})}
        self.assertEqual(comps.get("wordpress"), "5.7")

    def test_server_header_versions_are_not_mapped_to_cves(self) -> None:
        # nginx/Apache/PHP banner versions must NOT produce findings (low-signal, FP risk).
        comps = cve.detect_components("", {"Server": "nginx/1.14.0", "X-Powered-By": "PHP/7.2.1"})
        self.assertEqual([c for c in comps if c["product"] in {"nginx", "apache", "php"}], [])


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

    def test_new_products_and_jquery_cve(self) -> None:
        self.assertIn("CVE-2022-23647", {c["cve"] for c in cve.match_cves("prismjs", "1.25.0")})
        self.assertEqual(cve.match_cves("prismjs", "1.27.0"), [])          # fixed
        self.assertIn("CVE-2022-21681", {c["cve"] for c in cve.match_cves("marked", "4.0.0")})
        self.assertEqual(cve.match_cves("marked", "4.0.10"), [])           # fixed
        self.assertIn("CVE-2020-11022", {c["cve"] for c in cve.match_cves("jquery", "3.4.1")})


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


class ProbeHintTests(unittest.TestCase):
    """A matched advisory names the exact weakness class of the exact library this target serves.
    That is the strongest targeting signal the engine derives, and it used to reach nothing."""

    def _finding(self, product: str) -> dict:
        return {"_cve_list": cve._KNOWN_CVES[product], "cwe": cve._KNOWN_CVES[product][0]["cwe"]}

    def test_every_mapped_class_is_one_the_prover_can_confirm(self) -> None:
        """Steering budget at a class with no check is waste dressed up as intelligence. The
        planner vocabulary exists so that cannot happen by accident; this pins it mechanically."""
        from bughunter.prover_classes import PROVER_CLASSES

        for cwe, class_id in cve._CWE_PROBE_CLASS.items():
            self.assertIn(class_id, PROVER_CLASSES, f"{cwe} maps to unprovable {class_id}")

    def test_an_xss_advisory_prioritises_xss(self) -> None:
        self.assertEqual(cve.cve_probe_hints([self._finding("jquery")]), ["xss"])

    def test_it_reads_every_matched_cve_not_just_the_headline(self) -> None:
        """lodash's headline CVEs are prototype pollution, which has no prover check; its
        CWE-94 template-injection advisory is the one that can actually be chased."""
        self.assertEqual(cve.cve_probe_hints([self._finding("lodash")]), ["rce"])

    def test_a_library_with_no_provable_advisory_yields_nothing(self) -> None:
        """moment's CVEs are ReDoS (CWE-1333). Mapping that to an adjacent class would send the
        prover after something it cannot confirm."""
        self.assertEqual(cve.cve_probe_hints([self._finding("moment")]), [])

    def test_hints_are_ordered_by_the_strongest_advisory_backing_them(self) -> None:
        hints = cve.cve_probe_hints([self._finding("jquery"), self._finding("lodash")])
        self.assertEqual(hints, ["rce", "xss"])   # rce is backed by a 7.2, xss by a 6.1

    def test_it_is_deterministic(self) -> None:
        args = [self._finding("jquery"), self._finding("lodash"), self._finding("bootstrap")]
        self.assertEqual(cve.cve_probe_hints(args), cve.cve_probe_hints(args))

    def test_it_falls_back_to_the_findings_own_cwe(self) -> None:
        self.assertEqual(cve.cve_probe_hints([{"cwe": "CWE-89"}]), ["sqli"])

    def test_a_real_finding_produces_hints(self) -> None:
        finding = cve._build_finding(
            {"product": "jquery", "version": "1.8.0", "evidence": "jquery-1.8.0.min.js"},
            cve.match_cves("jquery", "1.8.0"), "https://app.example/")
        self.assertEqual(cve.cve_probe_hints([finding]), ["xss"])

    def test_malformed_input_never_raises(self) -> None:
        for bad in (None, "nope", 7, [None], ["x"], [{}], [{"_cve_list": "no"}],
                    [{"_cve_list": [{"cwe": "CWE-79", "base_score": "junk"}]}]):
            with self.subTest(value=bad):
                self.assertIsInstance(cve.cve_probe_hints(bad), list)


if __name__ == "__main__":
    unittest.main()
