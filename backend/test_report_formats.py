"""Tests for the platform-shaped submission report formats.

Each platform must render a non-empty, self-contained report; the GATHERED EVIDENCE
(captured request/response + matched value) must appear in EVERY platform's output when
the finding carries it; severity is shown in each platform's own vocabulary; and an
unreportable finding is dropped consistently.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report_formats as rf  # noqa: E402
from bughunter import submission as sub  # noqa: E402


def _ctx_finding():
    plan = {
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "base_score": 6.1, "base_severity": "high"},
        "steps": ["Browse to the endpoint.", "Inject the marker payload in the 'q' parameter.", "Observe it reflected unescaped."],
        "poc": "GET /?q=<svg/onload=alert(1)> HTTP/1.1",
        "impact": "An attacker can run script in a victim's session.",
        "remediation": "Context-encode the parameter on output.",
    }
    ctx = {
        "target": "https://app.example.com/",
        "scope": "app.example.com",
        "generated_at": "2026-06-29 12:00 UTC",
        "tool": "GreyIQ BugHunter",
        "version": "0.27.0",
        "attack_plans": {"F1": plan},
    }
    finding = {
        "ref": "F1",
        "title": "Reflected XSS via 'q' parameter",
        "severity": "high",
        "confidence": "high",
        "class_name": "Cross-site scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "vrt": "cross_site_scripting_xss.reflected",
        "location": "https://app.example.com/?q=",
        "description": "The 'q' parameter is reflected without output encoding.",
        "snippet": "<html>echo <svg/onload=1></html>",
        "proof_evidence": {
            "request_line": "GET https://app.example.com/?q=gq7x4q2v<svg/onload=1>",
            "response_status": "HTTP 200",
            "matched_value": "unescaped reflection of <svg/onload=...>",
        },
        "remediation": "Encode output for the HTML context.",
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    }
    return ctx, finding


class PlatformRegistryTests(unittest.TestCase):
    def test_four_platforms_hackerone_first(self) -> None:
        ids = [p["id"] for p in rf.list_platforms()]
        self.assertEqual(ids, ["hackerone", "yeswehack", "bugcrowd", "intigriti"])

    def test_normalize_platform_falls_back(self) -> None:
        self.assertEqual(rf.normalize_platform("YesWeHack"), "yeswehack")
        self.assertEqual(rf.normalize_platform("nope"), "hackerone")
        self.assertEqual(rf.normalize_platform(None), "hackerone")
        self.assertEqual(rf.normalize_platform(""), "hackerone")

    def test_platform_severity_vocabulary(self) -> None:
        ctx, finding = _ctx_finding()
        plan = ctx["attack_plans"]["F1"]
        self.assertEqual(rf.platform_severity("hackerone", finding, plan), "high")
        self.assertEqual(rf.platform_severity("bugcrowd", finding, plan), "P2 (Severe)")
        self.assertEqual(rf.platform_severity("yeswehack", finding, plan), "High")
        self.assertEqual(rf.platform_severity("intigriti", finding, plan), "High")
        # info maps to the floor of each scale.
        info = {"severity": "info"}
        self.assertEqual(rf.platform_severity("hackerone", info, {}), "none")
        self.assertIn("P5", rf.platform_severity("bugcrowd", info, {}))


class RenderTests(unittest.TestCase):
    def test_every_platform_renders_and_includes_gathered_evidence(self) -> None:
        ctx, finding = _ctx_finding()
        for p in ("hackerone", "yeswehack", "bugcrowd", "intigriti"):
            md = rf.render_finding(ctx, finding, p)
            self.assertTrue(md.strip(), f"{p} produced empty output")
            self.assertIn(rf.platform_name(p), md)                      # platform banner
            self.assertIn("Reflected XSS", md)                           # the title
            # The gathered evidence MUST be present in every format.
            self.assertIn("unescaped reflection", md, f"{p} dropped the matched value")
            self.assertIn("GET https://app.example.com/?q=", md, f"{p} dropped the captured request")
            self.assertIn("Steps to reproduce", md)
            self.assertIn("Impact", md)

    def test_platform_specific_framing(self) -> None:
        ctx, finding = _ctx_finding()
        bug = rf.render_finding(ctx, finding, "bugcrowd")
        self.assertIn("VRT", bug)
        self.assertIn("cross_site_scripting_xss.reflected", bug)
        self.assertIn("P2 (Severe)", bug)
        ywh = rf.render_finding(ctx, finding, "yeswehack")
        self.assertIn("Bug type (CWE)", ywh)
        intig = rf.render_finding(ctx, finding, "intigriti")
        self.assertIn("Type (OWASP)", intig)
        self.assertIn("Recommended fix", intig)
        h1 = rf.render_finding(ctx, finding, "hackerone")
        self.assertIn("Weakness (CWE)", h1)

    def test_unknown_platform_renders_as_hackerone(self) -> None:
        ctx, finding = _ctx_finding()
        self.assertEqual(rf.render_finding(ctx, finding, "bogus"), rf.render_finding(ctx, finding, "hackerone"))

    def test_evidence_section_present_only_when_evidence_exists(self) -> None:
        ctx, finding = _ctx_finding()
        finding.pop("proof_evidence")
        finding.pop("snippet")
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertNotIn("Supporting material / evidence", md)  # no evidence -> no empty section
        self.assertIn("Steps to reproduce", md)                 # the rest still renders

    def test_no_bot_self_identification_by_default(self) -> None:
        # Submitted content must never name the tool/bot unless the operator has
        # explicitly opted in for this program (H1-terms disclosure requirement).
        ctx, finding = _ctx_finding()
        for p in ("hackerone", "yeswehack", "bugcrowd", "intigriti"):
            md = rf.render_finding(ctx, finding, p)
            self.assertNotIn("GreyIQ", md, f"{p} still self-identifies the tool")
            self.assertNotIn("BugHunter", md, f"{p} still self-identifies the tool")
            self.assertNotIn("Formatted for", md, f"{p} still carries the old branded footer")

    def test_disclosure_line_added_when_opted_in(self) -> None:
        ctx, finding = _ctx_finding()
        ctx["disclose_automation"] = True
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertIn("Disclosure:", md)
        self.assertIn("GreyIQ BugHunter", md)  # ctx['tool'] is named here on purpose
        self.assertIn(ctx["version"], md)

    def test_disclosure_omitted_when_flag_false(self) -> None:
        ctx, finding = _ctx_finding()
        ctx["disclose_automation"] = False
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertNotIn("Disclosure:", md)
        self.assertNotIn("GreyIQ", md)


class BuildSubmissionPlatformTests(unittest.TestCase):
    def test_package_carries_platform_fields(self) -> None:
        ctx, finding = _ctx_finding()
        pkg = sub.build_submission(ctx, finding, "bugcrowd")
        self.assertIsNotNone(pkg)
        self.assertEqual(pkg["platform"], "bugcrowd")
        self.assertEqual(pkg["platform_name"], "Bugcrowd")
        self.assertTrue(pkg["platform_severity"].startswith("P"))
        # severity_rating stays the HackerOne API vocabulary (used by the API submit).
        self.assertEqual(pkg["severity_rating"], "high")
        self.assertIn("Bugcrowd submission", pkg["vulnerability_information"])
        self.assertIn("unescaped reflection", pkg["vulnerability_information"])  # evidence present

    def test_default_platform_is_hackerone(self) -> None:
        ctx, finding = _ctx_finding()
        pkg = sub.build_submission(ctx, finding)
        self.assertEqual(pkg["platform"], "hackerone")
        self.assertIn("HackerOne submission", pkg["vulnerability_information"])

    def test_unknown_platform_coerced(self) -> None:
        ctx, finding = _ctx_finding()
        pkg = sub.build_submission(ctx, finding, "totally-made-up")
        self.assertEqual(pkg["platform"], "hackerone")


if __name__ == "__main__":
    unittest.main()
