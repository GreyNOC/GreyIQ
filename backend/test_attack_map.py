"""Attack-plan mapper — a graphical (SVG->PNG) diagram of the attack run against a finding.
Verifies the SVG is valid + injection-safe (target-derived proof text can never become live markup or
script), the layout stays bounded on huge input, the map claims exactly what the confirm gate accepted
(a candidate lead must never render as proof), and the PNG renderer fails open (no Playwright ->
no map, never an exception)."""
from __future__ import annotations

import sys
import unittest
import xml.dom.minidom as minidom
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import attack_map as am  # noqa: E402


class AttackSvgTests(unittest.TestCase):
    def _finding(self, **over):
        f = {"title": "Reflected XSS in /search via q", "severity": "high", "class_name": "Reflected XSS",
             "location": "https://t/search?q=x",
             "proof_evidence": {"request_line": "GET https://t/search?q=MARKER", "matched_value": "reflected unescaped"}}
        f.update(over)
        return f

    def _plan(self, **over):
        p = {"proof_of_impact": {"actor": "an unauthenticated attacker",
                                 "observed_result": "the payload was returned raw in the HTML",
                                 "control_result": "a benign marker was returned encoded",
                                 "proof_obligation": "session theft for every viewer"}}
        p.setdefault("proof_of_impact", {}).update(over.pop("poi", {}))
        p.update(over)
        return p

    def test_produces_valid_svg_with_the_stages(self) -> None:
        svg = am.build_attack_svg(self._finding(), self._plan())
        minidom.parseString(svg)  # valid XML or this raises
        self.assertTrue(svg.startswith("<svg"))
        for label in ("ACTOR", "CRAFTED PROBE", "OBSERVED", "NEGATIVE CONTROL", "CONFIRMED"):
            self.assertIn(label, svg)
        self.assertIn("HIGH", svg)  # severity badge

    def test_target_derived_text_cannot_inject_markup_or_script(self) -> None:
        # a proof field carrying markup/script must be XML-escaped, never live in the SVG
        evil = 'x</text><script>alert(1)</script><svg onload=alert(2)>'
        svg = am.build_attack_svg(self._finding(proof_evidence={"request_line": "GET /?q=" + evil, "matched_value": evil}),
                                  self._plan(poi={"observed_result": evil}))
        minidom.parseString(svg)                       # still valid XML
        self.assertNotIn("<script>", svg)              # no live script element
        self.assertNotIn("</text><script", svg)        # the closing-tag breakout is escaped
        self.assertIn("&lt;script&gt;", svg)           # ...present only as escaped text

    def test_huge_fields_stay_bounded(self) -> None:
        # a giant proof field must not produce an unbounded image (wrapping is capped)
        svg = am.build_attack_svg(self._finding(), self._plan(poi={"observed_result": "A" * 50000}))
        minidom.parseString(svg)
        self.assertLess(len(svg), 20000)               # capped, not 50KB+ of text

    def test_missing_control_is_drawn_as_an_outstanding_capture(self) -> None:
        # An absent negative control is what a triager most needs to see; dropping the stage made the
        # map read as though the false-positive check had passed.
        svg = am.build_attack_svg(self._finding(), self._plan(poi={"control_result": ""}))
        self.assertIn("4 · NEGATIVE CONTROL — NOT CAPTURED YET", svg)
        self.assertIn("still to capture:", svg)
        self.assertNotIn("✓ CONFIRMED", svg)           # no control -> the gate never confirmed it

    def test_missing_plan_is_a_clean_default(self) -> None:
        svg = am.build_attack_svg({"title": "X", "severity": "low"}, None)
        minidom.parseString(svg)
        self.assertIn("CANDIDATE — NOT YET CONFIRMED", svg)
        self.assertNotIn("✓ CONFIRMED", svg)

    def test_unconfirmed_passive_lead_is_never_drawn_as_confirmed(self) -> None:
        # The map is embedded in the report and copied into the submission package, so a lead the
        # confirm gate never accepted must not carry a confirmed terminal stage or an observation
        # that was never made.
        lead = {"ref": "F7", "class_id": "headers", "title": "Missing Content-Security-Policy header",
                "severity": "low"}
        svg = am.build_attack_svg(lead, {})
        minidom.parseString(svg)
        self.assertNotIn("✓ CONFIRMED", svg)
        self.assertNotIn("the vulnerable behaviour was observed", svg)
        self.assertIn("CANDIDATE — NOT YET CONFIRMED", svg)
        self.assertIn("3 · OBSERVED — NOT CAPTURED YET", svg)
        self.assertIn("4 · NEGATIVE CONTROL — NOT CAPTURED YET", svg)
        self.assertIn("CANDIDATE (NOT CONFIRMED)", svg)   # ...and in the header eyebrow

    def test_a_bare_confirmed_status_cannot_promote_the_map(self) -> None:
        # ONE confirm authority: report._proof_of_impact_detail caps a status with no captured
        # differential at 'candidate', and the map must read the same gate rather than its own rule.
        svg = am.build_attack_svg(
            self._finding(),
            {"proof_of_impact": {"status": "confirmed", "observed_result": "the endpoint returned data"}})
        self.assertNotIn("✓ CONFIRMED", svg)
        self.assertIn("CANDIDATE — NOT YET CONFIRMED", svg)
        self.assertIn("the endpoint returned data", svg)   # the real capture is still drawn
        self.assertIn("NOT ACCEPTED BY THE CONFIRM GATE", svg)

    def test_the_proof_obligation_names_what_is_still_missing(self) -> None:
        svg = am.build_attack_svg(
            self._finding(),
            {"proof_of_impact": {"proof_obligation": "a cross-account read of another user's order"}})
        self.assertIn("a cross-account read of another user&#x27;s order", svg)
        self.assertIn("still to prove:", svg)

    def test_render_fails_open_without_playwright(self) -> None:
        # if the SVG can't be rasterized, the caller gets ok:False, never an exception
        orig = am.ensure_bundled_browsers_path
        am.ensure_bundled_browsers_path = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            res = am.render_attack_map(self._finding(), self._plan(), BACKEND_DIR / "does-not-exist" / "m.png")
        finally:
            am.ensure_bundled_browsers_path = orig
        self.assertFalse(res["ok"])
        self.assertIn("error", res)


class CampaignWiringTests(unittest.TestCase):
    """The campaign proof pass renders the map into the POC folder when the option is on, independent
    of whether the screenshot succeeds, and skips it when off. Renderer + screenshot stubbed."""

    def _run(self, with_map: bool, tmp):
        from bughunter import campaign
        calls = {"map": [], "shot": []}
        orig = (campaign.attack_map.render_attack_map, campaign.screenshot_service.poc_url_for_finding,
                campaign.screenshot_service.capture_screenshot)
        campaign.attack_map.render_attack_map = lambda f, p, out, settings=None: (
            calls["map"].append(str(out)), {"ok": True, "path": str(out)})[1]
        campaign.screenshot_service.poc_url_for_finding = lambda f, ctx: ""   # no POC -> screenshot skipped
        campaign.screenshot_service.capture_screenshot = lambda *a, **k: calls["shot"].append(1) or {"ok": False}
        items = [{"finding": {"ref": "F1", "title": "X", "severity": "high",
                              "_active_proof": {"observed_result": "o", "control_result": "c"}}, "source_url": "https://t/"}]
        try:
            campaign._capture_proof_screenshots(items, Path(tmp), "https://t/", "t", with_attack_map=with_map)
        finally:
            (campaign.attack_map.render_attack_map, campaign.screenshot_service.poc_url_for_finding,
             campaign.screenshot_service.capture_screenshot) = orig
        return calls, items[0]["finding"]

    def test_map_renders_into_poc_even_without_a_screenshot(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            calls, finding = self._run(True, tmp)
            self.assertEqual(len(calls["map"]), 1)                       # the map rendered
            self.assertTrue(calls["map"][0].endswith("-attack-map.png"))  # ...beside the screenshot name
            self.assertIn("attack_map_path", finding)                    # recorded on the finding

    def test_option_off_renders_no_map(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            calls, finding = self._run(False, tmp)
            self.assertEqual(calls["map"], [])
            self.assertNotIn("attack_map_path", finding)


class ReportEmbedTests(unittest.TestCase):
    def test_report_embeds_the_attack_map_by_basename(self) -> None:
        from bughunter import report
        out: list[str] = []
        report._append_screenshot(out, {"ref": "F1", "attack_map_path": "/run/screenshots/01-F1-attack-map.png",
                                        "screenshot_path": "/run/screenshots/01-F1.png"})
        md = "\n".join(out)
        self.assertIn("## Attack-plan map", md)
        self.assertIn("![Attack-plan map", md)
        self.assertIn("(01-F1-attack-map.png)", md)            # embedded by basename (co-located in the package)
        self.assertIn("(01-F1.png)", md)                       # the screenshot still embeds too

    def test_map_embeds_even_with_no_screenshot(self) -> None:
        from bughunter import report
        out: list[str] = []
        report._append_screenshot(out, {"ref": "F1", "attack_map_path": "/run/screenshots/01-F1-attack-map.png"})
        md = "\n".join(out)
        self.assertIn("## Attack-plan map", md)
        self.assertNotIn("## Screenshot evidence", md)         # no screenshot section when there's no screenshot

    def test_caption_does_not_call_an_unconfirmed_flow_confirmed(self) -> None:
        from bughunter import report
        out: list[str] = []
        report._append_screenshot(out, {"ref": "F7", "title": "Missing CSP header",
                                        "attack_map_path": "/run/screenshots/07-F7-attack-map.png"}, {})
        md = "\n".join(out)
        self.assertNotIn("confirmed attack flow", md)
        self.assertNotIn("used to confirm this finding", md)
        self.assertIn("candidate finding", md)
        self.assertIn("the impact still to prove", md)

    def test_caption_still_says_confirmed_for_a_captured_differential(self) -> None:
        from bughunter import report
        out: list[str] = []
        plan = {"proof_of_impact": {"observed_result": "another tenant's invoice was returned (HTTP 200)",
                                    "control_result": "the same read as the owner account returned 403"}}
        report._append_screenshot(out, {"ref": "F1", "attack_map_path": "/run/screenshots/01-F1-attack-map.png"}, plan)
        md = "\n".join(out)
        self.assertIn("confirmed attack flow", md)


if __name__ == "__main__":
    unittest.main()
