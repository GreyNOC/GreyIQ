"""Regression tests for the v0.66.1 QA/QC fixes.

Each test pins a defect an adversarial QA pass confirmed:
- brain ingestion must not crash the hunt on a wrong-shape LLM response;
- a client proof with no observed-vs-control differential can never read 'confirmed'
  (including when it leaves status empty);
- the SSRF guard classifies CGNAT / 6to4 / IPv4-mapped-IPv6 as private;
- the open-redirect check confirms only on an exact marker-host match;
- a screenshot can be captured from the finding's own URL with no cached run.
"""
from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


class BrainIngestionShapeTests(unittest.TestCase):
    """_ask_brain must degrade to the deterministic report, never raise, on a valid-JSON
    but wrong-shape model response (its documented fallback contract)."""

    def setUp(self) -> None:
        import coder
        self._coder = coder
        # Save the real coder hooks so the fakes below never leak into later tests (a stubbed
        # coder_enabled/generate would make e.g. test_research think a brain is configured).
        self._orig = (coder.coder_enabled, coder.coder_config, coder.generate)

    def tearDown(self) -> None:
        self._coder.coder_enabled, self._coder.coder_config, self._coder.generate = self._orig

    def _run(self, text: str) -> dict:
        import bughunter.bounty as bounty
        self._coder.coder_enabled = lambda cfg: True
        self._coder.coder_config = lambda cfg: {}
        self._coder.generate = lambda msgs, cfg: {"provider": "x", "model": "m", "text": text}
        return bounty._ask_brain({}, "http://t", {"name": "P"}, None, "scope", [{"ref": "F1"}], "pb")

    def test_wrong_shapes_do_not_raise(self) -> None:
        for text in (
            '{"attack_plans": {"F1": {"steps": ["a"], "poc": "p"}}}',  # object keyed by ref
            '{"attack_plans": ["F1", "F2"]}',                            # bare strings
            '{"manual_tests": 5}',                                       # scalar for a list field
            '{"next_steps": 7}',
            '{"attack_plans": [{"ref": "F1", "steps": "one\\ntwo"}, "junk", 42]}',  # valid + junk
        ):
            brain = self._run(text)  # must not raise
            self.assertTrue(brain["used"])
            self.assertIsInstance(brain["attack_plans"], dict)
            self.assertIsInstance(brain["manual_tests"], list)

    def test_valid_plan_survives_alongside_junk(self) -> None:
        brain = self._run('{"attack_plans": [{"ref": "F1", "steps": "one\\ntwo"}, "junk", 42]}')
        self.assertIn("F1", brain["attack_plans"])
        self.assertEqual(brain["attack_plans"]["F1"]["steps"], ["one", "two"])  # string split, not char-by-char


class ForgedConfirmedProofTests(unittest.TestCase):
    """A client/brain proof may only read 'confirmed' with a real observed-vs-control
    differential — leaving status empty must NOT let the report auto-promote."""

    def _status(self, status: str, observed: str, control: str) -> str:
        import greyiq_api as api
        rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
        req = api.FindingReportRequest(
            class_id="idor", location="https://t/api/user/1", target="https://t",
            proof=api.ProofInput(status=status, observed_result=observed, control_result=control),
        )
        return api.GreyIQRuntime.build_finding_report(rt, req)["package"]["proof_status"]

    def test_empty_status_no_control_capped_to_candidate(self) -> None:
        obs = "The endpoint returned HTTP 200 and leaked another account"
        self.assertEqual(self._status("", obs, ""), "candidate")           # the bypass
        self.assertEqual(self._status("confirmed", obs, ""), "candidate")   # the original guard
        self.assertEqual(self._status("", obs, "account A id returned 403"), "confirmed")  # real differential


class SsrfPrivateRangeTests(unittest.TestCase):
    def test_cgnat_sixtofour_and_mapped_are_private(self) -> None:
        import bughunter.web_ingest as web_ingest
        for ip in ("100.64.0.1", "100.127.255.1", "2002:a9fe:a9fe::",
                   "::ffff:169.254.169.254", "::ffff:10.0.0.5", "169.254.169.254", "10.0.0.5"):
            self.assertTrue(web_ingest._address_is_private(ipaddress.ip_address(ip)), ip)
        # 8.8.8.8 is stably public across Python versions. A 6to4-wrapped PUBLIC IP
        # (2002:0808:0808:: -> 8.8.8.8) is classified differently across 3.11 patch releases —
        # blocking it is safe/stricter — so its public-ness is intentionally NOT asserted here.
        self.assertFalse(web_ingest._address_is_private(ipaddress.ip_address("8.8.8.8")))


class OpenRedirectGateTests(unittest.TestCase):
    """The open-redirect check confirms only when the redirect HOST equals the marker,
    never when a same-site subdomain merely begins with the marker label."""

    class _FakeHttp:
        def __init__(self, redirect_for_marker: str) -> None:
            self._redirect = redirect_for_marker

        def fetch(self, url: str) -> dict:
            loc = self._redirect if "greyiq-marker" in url else "/greyiq-control"
            return {"status": 302, "location": loc}

    def test_prefix_subdomain_not_confirmed(self) -> None:
        import bughunter.active_verify_service as av
        http = self._FakeHttp(f"https://{av._MARKER_HOST}.victim.com/login")
        self.assertIsNone(av._check_open_redirect(http, "https://victim.com/go?next=1"))

    def test_exact_marker_host_confirmed(self) -> None:
        import bughunter.active_verify_service as av
        http = self._FakeHttp(f"https://{av._MARKER_HOST}/pwned")
        res = av._check_open_redirect(http, "https://victim.com/go?next=1")
        self.assertIsNotNone(res)


class ScreenshotNoCacheTests(unittest.TestCase):
    """A finding opened from history (no cached run) still captures from its own URL."""

    def test_capture_from_request_url_without_run(self) -> None:
        import greyiq_api as g
        calls: list[dict] = []

        def _fake_capture(url, out_path, *, scope="", authorized=False, full_page=False, **kw):
            calls.append({"url": url, "annotate": kw.get("annotate"), "highlight": kw.get("highlight")})
            return {"ok": True, "path": str(out_path), "shots": [{"path": str(out_path), "kind": "evidence"}],
                    "url": url, "final_url": url, "title": "", "warning": "review before sharing"}

        orig = g.bounty_screenshot.capture_screenshot
        g.bounty_screenshot.capture_screenshot = _fake_capture
        try:
            res = g.runtime.capture_screenshot(g.ScreenshotRequest(
                run_id="", ref="", url="https://app.example.com/leak",
                title="Secret exposed", matched_value="AIza-REDACTED", scope="app.example.com"))
        finally:
            g.bounty_screenshot.capture_screenshot = orig
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["url"], "https://app.example.com/leak")
        self.assertEqual(calls[0]["highlight"], "AIza-REDACTED")           # evidence highlighted
        self.assertEqual(calls[0]["annotate"]["title"], "Secret exposed")   # shot annotated
        self.assertTrue(res["shots"])

    def test_no_url_and_no_run_is_a_clean_error(self) -> None:
        import greyiq_api as g
        res = g.runtime.capture_screenshot(g.ScreenshotRequest(run_id="nope", ref="F1"))
        self.assertFalse(res["ok"])
        self.assertIn("url", res["error"].lower())


if __name__ == "__main__":
    unittest.main()
