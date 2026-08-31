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

from bughunter import report as R  # noqa: E402
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
    def test_five_platforms_hackerone_first(self) -> None:
        ids = [p["id"] for p in rf.list_platforms()]
        self.assertEqual(ids, ["hackerone", "yeswehack", "bugcrowd", "intigriti", "hackenproof"])

    def test_normalize_platform_falls_back(self) -> None:
        self.assertEqual(rf.normalize_platform("YesWeHack"), "yeswehack")
        self.assertEqual(rf.normalize_platform("HackenProof"), "hackenproof")
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
        self.assertEqual(rf.platform_severity("hackenproof", finding, plan), "High")
        # info maps to the floor of each scale — HackenProof has no Informational band, so Low.
        info = {"severity": "info"}
        self.assertEqual(rf.platform_severity("hackerone", info, {}), "none")
        self.assertIn("P5", rf.platform_severity("bugcrowd", info, {}))
        self.assertEqual(rf.platform_severity("hackenproof", info, {}), "Low")
        self.assertEqual(rf.platform_severity("hackenproof", {"severity": "critical"}, {}), "Critical")
        # HackenProof defines no "None"/"Informational" band — none must map to a real band (Low),
        # never emit an invented "None" label into a submission report.
        for sev in ("none", "info"):
            self.assertEqual(rf.platform_severity("hackenproof", {"severity": sev}, {}), "Low")
        self.assertNotIn("None", {rf.platform_severity("hackenproof", {"severity": s}, {})
                                  for s in ("critical", "high", "medium", "low", "info", "none")})


class RenderTests(unittest.TestCase):
    def test_every_platform_renders_and_includes_gathered_evidence(self) -> None:
        ctx, finding = _ctx_finding()
        for p in ("hackerone", "yeswehack", "bugcrowd", "intigriti", "hackenproof"):
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
        hp = rf.render_finding(ctx, finding, "hackenproof")
        self.assertIn("Vulnerability category", hp)                 # HackenProof's leading field
        self.assertIn("Cross-site scripting (XSS)", hp)             # ...carries the finding's class name
        self.assertIn("HackenProof submission", hp)                 # platform banner
        self.assertIn("severity **High**", hp)                      # HackenProof Critical..Low vocab

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
        for p in ("hackerone", "yeswehack", "bugcrowd", "intigriti", "hackenproof"):
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


class StepsNumberingTests(unittest.TestCase):
    """Steps to reproduce must render as a clean 1..N numbered list whatever shape the
    brain hands us — a list, a single newline string, or items that already carry their
    own "1."/"-" marker. Garbled or duplicated numbering reads as machine-generated and
    gets the report closed (HackerOne wants clear, numbered reproduction steps)."""

    def test_normalize_steps_shapes(self) -> None:
        self.assertEqual(R.normalize_steps(["a", "b"]), ["a", "b"])
        # a bare string is split on newlines, NOT iterated character by character.
        self.assertEqual(R.normalize_steps("first\nsecond\nthird"), ["first", "second", "third"])
        # existing enumerators are stripped so the renderer's numbering is the only one.
        self.assertEqual(
            R.normalize_steps(["1. first", "2) second", "- third", "* fourth"]),
            ["first", "second", "third", "fourth"],
        )
        self.assertEqual(R.normalize_steps(None), [])
        self.assertEqual(R.normalize_steps(["", "  ", "x"]), ["x"])
        # a genuine decimal that isn't a list marker is preserved.
        self.assertEqual(R.normalize_steps(["3.5x slowdown observed"]), ["3.5x slowdown observed"])

    def test_string_steps_render_numbered_not_per_character(self) -> None:
        ctx, finding = _ctx_finding()
        ctx["attack_plans"]["F1"]["steps"] = "Send a GET to /login.\nObserve the response.\nNote the header."
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertIn("1. Send a GET to /login.", md)
        self.assertIn("2. Observe the response.", md)
        self.assertIn("3. Note the header.", md)
        self.assertNotIn("2. e", md)  # would appear if the string were iterated char-by-char

    def test_prenumbered_steps_not_double_numbered(self) -> None:
        ctx, finding = _ctx_finding()
        ctx["attack_plans"]["F1"]["steps"] = ["1. Send a GET.", "2. Observe.", "3. Note it."]
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertIn("1. Send a GET.", md)
        self.assertNotIn("1. 1. Send a GET.", md)

    def test_default_report_paths_also_number_string_steps(self) -> None:
        # The default HackerOne-flavoured report (report.build_finding_markdown) shares the
        # same normalizer, so a string-shaped steps value is numbered there too.
        ctx, finding = _ctx_finding()
        ctx["attack_plans"]["F1"]["steps"] = "Alpha step.\nBravo step."
        md = R.build_finding_markdown(ctx, finding)
        self.assertIn("1. Alpha step.", md)
        self.assertIn("2. Bravo step.", md)


class ChainRoleInSubmissionTests(unittest.TestCase):
    """The per-platform body is the file the operator pastes into the program's form — it is read on
    its own, so the chain context has to travel with it exactly as it does in the default report."""

    def _chained(self):
        ctx, finding = _ctx_finding()
        ctx["investigation"] = {"attack_chains": [{
            "id": "C1", "title": "Reflected XSS to account takeover", "status": "candidate",
            "projected_impact": "full account takeover", "refs": ["F1"],
            "steps": [{"n": 1, "title": "Reflect script into the victim's session",
                       "evidence_ref": "F1", "state": "projected"}],
        }]}
        return ctx, finding

    def test_every_platform_body_carries_the_chain_role(self) -> None:
        ctx, finding = self._chained()
        for platform in ("hackerone", "yeswehack", "bugcrowd", "intigriti", "hackenproof"):
            md = rf.render_finding(ctx, finding, platform)
            self.assertIn("**Chain role:**", md, platform)
            self.assertIn("this step is *projected*", md, platform)
            self.assertIn("full account takeover", md, platform)
            self.assertIn("a captured artifact the confirm gate accepted", md, platform)  # the legend

    def test_the_chain_role_sits_between_impact_and_the_proof_sections(self) -> None:
        # The canonical position from build_finding_markdown: after the impact prose, BEFORE
        # proof-of-impact/exploitability — not appended after the proof the triager just read.
        ctx, finding = self._chained()
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertLess(md.index("## Impact"), md.index("**Chain role:**"))
        self.assertLess(md.index("**Chain role:**"), md.index("## Proof of impact"))
        self.assertLess(md.index("**Chain role:**"), md.index("## Proof of exploitability"))

    def test_the_submission_package_body_carries_it(self) -> None:
        ctx, finding = self._chained()
        package = sub.build_submission(ctx, finding, "hackerone")
        self.assertIsNotNone(package)
        self.assertIn("this step is *projected*", package["vulnerability_information"])

    def test_a_context_with_no_investigation_renders_no_chain_section(self) -> None:
        ctx, finding = _ctx_finding()
        md = rf.render_finding(ctx, finding, "hackerone")
        self.assertNotIn("**Chain role:**", md)

    def test_the_cached_run_ctx_carries_the_investigation(self) -> None:
        # The chain section is only as good as the ctx it is handed: the API caches a MINIMAL ctx per
        # run, and every per-finding submission body is rendered from that copy. Drop the
        # investigation there and the section above silently renders nothing in the shipped app.
        import threading
        from collections import OrderedDict

        import greyiq_api as api

        runtime = object.__new__(api.GreyIQRuntime)
        runtime.lock = threading.RLock()
        runtime.bounty_runs = OrderedDict()
        ctx, finding = self._chained()
        result = {"ok": True, "generated_at": ctx["generated_at"], "findings": [finding],
                  "attack_plans": ctx["attack_plans"], "investigation": ctx["investigation"]}
        runtime._cache_bounty_run(result, target=ctx["target"], scope=ctx["scope"], program="p")
        package = runtime.build_submission_package(
            api.SubmissionPackageRequest(run_id=result["run_id"], ref="F1", platform="hackerone"))
        self.assertTrue(package["ok"])
        self.assertIn("this step is *projected*", package["package"]["vulnerability_information"])

    def test_both_renderers_produce_the_same_chain_line(self) -> None:
        # Delegation, not a second implementation: the platform body and the default report must
        # print byte-identical chain wording so a clamped status can never drift between them.
        ctx, finding = self._chained()
        platform_line = [ln for ln in rf.render_finding(ctx, finding, "bugcrowd").splitlines()
                         if ln.startswith("- Step 1 of")]
        default_line = [ln for ln in R.build_finding_markdown(ctx, finding).splitlines()
                        if ln.startswith("- Step 1 of")]
        self.assertEqual(platform_line, default_line)
        self.assertTrue(platform_line)


if __name__ == "__main__":
    unittest.main()
