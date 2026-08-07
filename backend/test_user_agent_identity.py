"""What GreyIQ calls itself on authorized traffic.

The User-Agent is the app's signature in a program's logs — it is how a triage team attributes a
request to an authorized researcher rather than to an unknown scanner. Two things had drifted:

* the default UA read ``GreyNOC-Slop-Detection/0.1`` — a DIFFERENT GreyNOC product, so every
  in-scope request was misattributed;
* the web-scan UA was pinned at ``/0.1`` while the app shipped 2.6.x.

Both are now derived from the single ``_version`` source. Separately, the four headless-browser
contexts that actually reach a target sent Chromium's own UA and carried no program marker at all.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import _version  # noqa: E402
from bughunter import web_ingest, web_scan_service  # noqa: E402

BUGHUNTER_DIR = BACKEND_DIR / "bughunter"


class UserAgentIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        # The researcher marker is a PROCESS global, not a contextvar, so unlike the suffix it
        # survives across tests and across threads. Pin it to empty for these assertions and restore
        # whatever was there, so this file neither depends on nor disturbs global order.
        self._marker = web_ingest.current_ua_marker()
        web_ingest.set_ua_marker("")

    def tearDown(self) -> None:
        web_ingest.set_ua_suffix("")  # never leak a suffix into another test
        web_ingest.set_ua_marker(self._marker)

    def test_the_app_identifies_itself_as_greyiq(self) -> None:
        self.assertIn("GreyIQ", web_ingest.GREYIQ_UA)
        # The specific regression: a different GreyNOC product's name.
        self.assertNotIn("Slop", web_ingest.GREYIQ_UA)

    def test_the_ua_carries_the_real_app_version(self) -> None:
        self.assertIn(_version.VERSION, web_ingest.GREYIQ_UA)
        self.assertNotIn("/0.1", web_ingest.GREYIQ_UA)

    def test_the_web_scan_ua_is_the_same_single_source(self) -> None:
        # It used to be an independent literal and had drifted six minor versions behind.
        self.assertEqual(web_scan_service._USER_AGENT, web_ingest.GREYIQ_UA)

    def test_the_default_ua_is_the_app_ua(self) -> None:
        self.assertEqual(web_ingest.current_user_agent(), web_ingest.GREYIQ_UA)

    def test_the_researcher_marker_rides_every_request(self) -> None:
        # A program suffix only exists while a saved program's hunt runs; the marker identifies the
        # OPERATOR and must be present even on an ad-hoc hunt with no program at all.
        web_ingest.set_ua_marker("h1-greynoc")
        self.assertIn("h1-greynoc", web_ingest.current_user_agent())
        self.assertTrue(web_ingest.current_user_agent().startswith(web_ingest.GREYIQ_UA))

    def test_the_marker_cannot_inject_a_header(self) -> None:
        web_ingest.set_ua_marker("evil\r\nX-Injected: 1")
        ua = web_ingest.current_user_agent()
        self.assertNotIn("\r", ua)
        self.assertNotIn("\n", ua)

    def test_the_marker_is_length_capped(self) -> None:
        web_ingest.set_ua_marker("x" * 5000)
        self.assertLessEqual(len(web_ingest.current_ua_marker()), 120)

    def test_marker_and_program_suffix_compose(self) -> None:
        web_ingest.set_ua_marker("h1-greynoc")
        token = web_ingest.set_ua_suffix(" -BugBounty-acme-31337 ")
        try:
            ua = web_ingest.current_user_agent()
            self.assertIn("h1-greynoc", ua)
            self.assertIn("-BugBounty-acme-31337", ua)
        finally:
            web_ingest.reset_ua_suffix(token)


class BrowserAttributionTests(unittest.TestCase):
    """Every browser context that reaches a TARGET must be attributable.

    Asserted against the source rather than by launching Chromium: Playwright is a heavy optional
    dependency and is not installed in the plain test environment.
    """

    #: modules whose Playwright context issues real requests to an in-scope host
    NETWORKED = ("screenshot_service.py", "stored_xss_service.py",
                 "live_scan_service.py", "account_login_service.py")

    def _contexts(self, filename: str) -> list[str]:
        src = (BUGHUNTER_DIR / filename).read_text(encoding="utf-8")
        # grab each new_context( ... ) call, which may span lines
        return re.findall(r"new_context\((.*?)\)", src, re.DOTALL)

    def test_networked_browser_contexts_send_our_user_agent(self) -> None:
        for name in self.NETWORKED:
            with self.subTest(module=name):
                calls = self._contexts(name)
                self.assertTrue(calls, f"{name}: expected a new_context( call")
                for call in calls:
                    self.assertIn(
                        "user_agent", call,
                        f"{name}: browser context omits user_agent, so it sends Chromium's own UA "
                        "and carries no program marker",
                    )
                    self.assertIn("current_user_agent", call,
                                  f"{name}: user_agent must resolve through current_user_agent so "
                                  "the program's required suffix rides along")

    def test_the_local_svg_rasterizer_is_deliberately_excluded(self) -> None:
        # attack_map renders a self-contained SVG and aborts every request, so it never touches the
        # network and needs no UA. Documented so nobody "fixes" it later.
        src = (BUGHUNTER_DIR / "attack_map.py").read_text(encoding="utf-8")
        self.assertIn("route.abort()", src)
        self.assertNotIn("user_agent", src)


if __name__ == "__main__":
    unittest.main()
