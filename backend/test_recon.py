"""Tests for bounded recon — pure helpers + the fail-closed guard fallback.

No network: link extraction / scope helpers are pure, and an out-of-policy seed
(a private host with private URLs disallowed) must short-circuit to a seed-only
result without fetching anything.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import recon  # noqa: E402


class ReconHelperTests(unittest.TestCase):
    def test_same_origin(self) -> None:
        self.assertTrue(recon._same_origin("https://example.com/a", "example.com"))
        self.assertFalse(recon._same_origin("https://evil.com/a", "example.com"))

    def test_clean_strips_fragment(self) -> None:
        self.assertEqual(recon._clean("https://x/y#frag"), "https://x/y")

    def test_extract_links_returns_all_candidates(self) -> None:
        # _extract_links returns ALL http(s) links (scope filtering is the caller's job
        # now, via in_scope, so out-of-scope hosts can be counted). Assets + non-http
        # schemes are still skipped.
        body = (
            '<a href="/page1">1</a>'
            '<a href="https://example.com/page2">2</a>'
            '<a href="https://other.com/page3">3</a>'
            '<a href="mailto:x@example.com">m</a>'
            '<link href="/styles.css">'
            '<img src="/logo.png">'
        )
        links = recon._extract_links(body, "https://example.com/")
        self.assertIn("https://example.com/page1", links)
        self.assertIn("https://example.com/page2", links)
        self.assertIn("https://other.com/page3", links)  # candidate — caller applies scope
        self.assertFalse(any(link.endswith((".css", ".png")) for link in links))  # assets skipped
        self.assertFalse(any("mailto" in link for link in links))

    def test_script_extraction(self) -> None:
        scripts = recon._extract_scripts('<script src="/static/main.abc.js"></script><script>x()</script>', "https://example.com/")
        self.assertEqual(scripts, ["https://example.com/static/main.abc.js"])

    def test_html_param_names_from_form_fields(self) -> None:
        # The param names a page's own inputs submit are exactly what the active prover
        # should bite on — even when no link carries them in a query string.
        body = (
            '<form action="/search">'
            '<input type="text" name="kw">'
            "<input name='page' value='1'>"
            '<select name="sort"><option>a</option></select>'
            '<textarea name="comment"></textarea>'
            '<button name="action" value="go">Go</button>'
            '<input type="submit">'  # no name → ignored
            '</form>'
        )
        names = recon._html_param_names(body)
        self.assertEqual(names, {"kw", "page", "sort", "comment", "action"})

    def test_qs_param_names_from_url(self) -> None:
        self.assertEqual(recon._qs_param_names("https://x/a?id=1&ref=home&id=2"), {"id", "ref"})
        self.assertEqual(recon._qs_param_names("https://x/a"), set())


class ReconGuardTests(unittest.TestCase):
    def test_private_seed_short_circuits_without_network(self) -> None:
        from bughunter.settings import get_settings

        settings = get_settings()
        # Force the strict policy regardless of local config.
        try:
            object.__setattr__(settings, "allow_private_urls", False)
        except Exception:  # frozen dataclass fallback
            settings.allow_private_urls = False  # type: ignore[attr-defined]
        result = recon.discover("http://127.0.0.1/", settings=settings, max_pages=5)
        # Fail-closed: only the seed, with a skip note, and no crawl.
        self.assertEqual(result["urls"], ["http://127.0.0.1/"])
        self.assertTrue(any("skipped" in note for note in result["notes"]))
        self.assertEqual(result.get("sources"), {})

    def test_malformed_robots_txt_directive_does_not_crash_discover(self) -> None:
        # Regression: every OTHER urljoin() call site in this file (_extract_links,
        # _extract_scripts) catches ValueError, but the robots.txt Disallow/Allow/
        # Sitemap directive loop did not -- a malformed value (plausible on a real
        # misconfigured server, or trivially plantable by a hostile/red-team
        # authorized target) made urljoin() raise ValueError uncaught, escaping
        # discover() and its only caller, campaign.run_campaign(), entirely.
        original = recon._fetch_raw

        def fake_fetch(url: str):
            if url.endswith("/robots.txt"):
                return {"status": 200, "body": "User-agent: *\nDisallow: http://[::1\nDisallow: /admin\n",
                        "headers": {}, "final_url": url}
            if url.endswith((".xml", "security.txt")):
                return {"status": 404, "body": "", "headers": {}, "final_url": url}
            return {"status": 200, "body": "<html></html>", "headers": {}, "final_url": url}

        recon._fetch_raw = fake_fetch
        try:
            result = recon.discover("https://example.com/", max_pages=5)
        finally:
            recon._fetch_raw = original
        # Must complete normally (no uncaught exception) and still pick up the VALID
        # directive that came after the malformed one.
        self.assertIn("https://example.com/admin", result["urls"])
        self.assertNotIn("http://[::1", " ".join(result["urls"]))


if __name__ == "__main__":
    unittest.main()
