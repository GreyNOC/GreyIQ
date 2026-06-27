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

    def test_extract_links_same_origin_only(self) -> None:
        body = (
            '<a href="/page1">1</a>'
            '<a href="https://example.com/page2">2</a>'
            '<a href="https://other.com/page3">3</a>'
            '<a href="mailto:x@example.com">m</a>'
            '<script src="/app.js"></script>'
            '<link href="/styles.css">'
            '<img src="/logo.png">'
        )
        links = recon._extract_links(body, "https://example.com/", "example.com")
        self.assertIn("https://example.com/page1", links)
        self.assertIn("https://example.com/page2", links)
        self.assertNotIn("https://other.com/page3", links)  # cross-origin dropped
        self.assertFalse(any(link.endswith((".css", ".png")) for link in links))  # assets skipped
        self.assertFalse(any("mailto" in link for link in links))


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


if __name__ == "__main__":
    unittest.main()
